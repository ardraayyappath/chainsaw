// Package os contains collectors that gather forensic evidence from the
// operating system layer of the target machine — shell history, persistence
// mechanisms, and scheduled tasks.
//
// The package name "os" matches the directory convention used across this
// codebase (npm, pypi, os). Importers that also use stdlib "os" should alias
// this package: import osc "github.com/ardraayyappath/chainsaw/internal/collector/os"
package os

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ardraayyappath/chainsaw/internal/evidence"
	"github.com/ardraayyappath/chainsaw/internal/ssh"
	"github.com/ardraayyappath/chainsaw/pkg/iocdb"
)

// ShellCollector reads shell history files from the target machine and creates
// Artifacts for lines that match IOC indicators or exhibit suspicious patterns.
// Only lines that meet the high or critical severity threshold are collected —
// clean history lines are skipped to avoid flooding the store with noise.
type ShellCollector struct {
	reader *ssh.RemoteReader
	store  *evidence.ArtifactStore
	iocs   *iocdb.IOCDatabase
}

// NewShellCollector constructs a ShellCollector.
func NewShellCollector(r *ssh.RemoteReader, s *evidence.ArtifactStore, db *iocdb.IOCDatabase) *ShellCollector {
	return &ShellCollector{reader: r, store: s, iocs: db}
}

// --------------------------------------------------------------------------
// History file registry
// --------------------------------------------------------------------------

type shellKind string

const (
	shellBash   shellKind = "bash"
	shellZsh    shellKind = "zsh"
	shellPython shellKind = "python"
	shellFish   shellKind = "fish"
)

type historyTarget struct {
	relativePath string    // relative to targetHome, no leading slash
	kind         shellKind
	source       string    // collector source label for Artifact.Source
}

var historyTargets = []historyTarget{
	{".bash_history",                          shellBash,   "os/shell/bash"},
	{".zsh_history",                           shellZsh,    "os/shell/zsh"},
	{".python_history",                        shellPython, "os/shell/python"},
	{".local/share/fish/fish_history",         shellFish,   "os/shell/fish"},
}

// --------------------------------------------------------------------------
// Collection entry point
// --------------------------------------------------------------------------

// Collect reads each known shell history file from targetHome, evaluates
// every command line, and adds Artifacts for suspicious or IOC-matched entries.
// Missing history files are skipped silently. Errors on individual files are
// non-fatal — collection continues with the remaining files.
func (c *ShellCollector) Collect(targetHome string) error {
	var collected []*evidence.Artifact

	for _, target := range historyTargets {
		path := targetHome + "/" + target.relativePath
		raw, err := c.reader.ReadFile(path)
		if err != nil {
			continue // file absent or unreadable — normal on many systems
		}
		arts, err := c.processFile(path, target.kind, target.source, raw)
		if err != nil {
			_ = err // non-fatal
			continue
		}
		collected = append(collected, arts...)
	}

	c.linkArtifacts(collected)
	return nil
}

// --------------------------------------------------------------------------
// Per-file processing
// --------------------------------------------------------------------------

// processFile parses raw history file content according to its shell format,
// evaluates each command line, and returns Artifacts for flagged lines.
func (c *ShellCollector) processFile(path string, kind shellKind, source string, raw []byte) ([]*evidence.Artifact, error) {
	var lines []parsedLine

	switch kind {
	case shellZsh:
		lines = parseZshHistory(string(raw))
	case shellFish:
		lines = parseFishHistory(string(raw))
	default:
		// bash and python use plain line-per-command format
		lines = parsePlainHistory(string(raw))
	}

	var arts []*evidence.Artifact
	for _, pl := range lines {
		a := c.evaluateLine(path, source, pl)
		if a == nil {
			continue
		}
		if err := c.store.Add(a); err == nil {
			arts = append(arts, a)
		}
	}
	return arts, nil
}

// --------------------------------------------------------------------------
// Line evaluation
// --------------------------------------------------------------------------

// evaluateLine classifies one history line and returns an Artifact if it
// meets the high or critical severity threshold, or nil if it should be skipped.
func (c *ShellCollector) evaluateLine(path, source string, pl parsedLine) *evidence.Artifact {
	cmd := strings.TrimSpace(pl.cmd)
	if cmd == "" || strings.HasPrefix(cmd, "#") {
		return nil
	}

	// IOC content match — catches domains, UA strings, and other indicators
	// embedded anywhere in the command line.
	iocMatches := c.iocs.MatchContent(cmd)

	// Explicit install-target match — catches "pip install litellm==1.82.7"
	// which MatchContent misses because pip uses "==" while the IOC database
	// stores package specifiers as "name@version".
	installName, installVersion := extractInstallTarget(cmd)
	if installName != "" {
		spec := installName
		if installVersion != "" {
			spec = installName + "@" + installVersion
		}
		iocMatches = append(iocMatches, c.iocs.Match(spec)...)
	}
	iocMatches = dedupeMatches(iocMatches)

	var sev evidence.Severity
	switch {
	case len(iocMatches) > 0:
		sev = evidence.SeverityCritical
	case isSuspicious(cmd):
		sev = evidence.SeverityHigh
	default:
		return nil // skip clean lines
	}

	return &evidence.Artifact{
		ID:             newID(),
		Kind:           evidence.KindShellHistory,
		Ecosystem:      evidence.EcosystemOS,
		Severity:       sev,
		Path:           path,
		PackageName:    installName,
		PackageVersion: installVersion,
		IOCMatches:     iocMatches,
		Timestamp:      pl.ts,
		Inferred:       false, // zsh/fish timestamps are written directly by the shell
		RawContent:     []byte(cmd),
		CollectedAt:    time.Now().UTC(),
		Source:         source,
		Note:           buildNote(pl.lineNum, iocMatches, sev),
	}
}

// --------------------------------------------------------------------------
// Causal linkage
// --------------------------------------------------------------------------

// linkArtifacts links shell history artifacts to related artifacts already in
// the store. Two link types are established:
//
//  1. shell_history → pth_file: when a pip install command names a package
//     whose .pth file is already in the store (e.g. "pip install litellm" →
//     "litellm_init.pth"). Matching is by substring: the pth filename contains
//     the package name.
//
//  2. shell_history → lockfile_entry: when the installed package name matches
//     a lockfile entry already collected (cross-ecosystem correlation).
func (c *ShellCollector) linkArtifacts(arts []*evidence.Artifact) {
	if len(arts) == 0 {
		return
	}

	pthArts := c.store.GetByKind(evidence.KindPthFile)
	lockArts := c.store.GetByKind(evidence.KindLockfileEntry)

	for _, art := range arts {
		if art.PackageName == "" {
			continue
		}
		nameLower := strings.ToLower(art.PackageName)

		// Link to pth_file artifacts whose filename contains the package name.
		// e.g. PackageName "litellm" matches pth PackageName "litellm_init.pth".
		for _, pth := range pthArts {
			if strings.Contains(strings.ToLower(pth.PackageName), nameLower) {
				_ = c.store.LinkArtifacts(art.ID, pth.ID)
			}
		}

		// Link to lockfile entries with the same package name.
		for _, lock := range lockArts {
			if strings.ToLower(lock.PackageName) == nameLower {
				_ = c.store.LinkArtifacts(art.ID, lock.ID)
			}
		}
	}
}

// --------------------------------------------------------------------------
// Format parsers
// --------------------------------------------------------------------------

// parsedLine holds a single command extracted from a history file, plus any
// timestamp that was recorded alongside it.
type parsedLine struct {
	lineNum int
	cmd     string
	ts      *time.Time
}

// parsePlainHistory handles bash and python history files: one command per line,
// no metadata prefix.
func parsePlainHistory(raw string) []parsedLine {
	lines := strings.Split(raw, "\n")
	out := make([]parsedLine, 0, len(lines))
	for i, line := range lines {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, parsedLine{lineNum: i + 1, cmd: t})
		}
	}
	return out
}

// parseZshHistory handles both plain and extended zsh history formats.
//
// Extended format (written when EXTENDED_HISTORY is set):
//
//	: <epoch>:<elapsed>;<command>
//
// Multi-line commands are continued with a leading backslash-newline; they are
// joined into a single command string here so the full invocation is captured.
// Lines not matching the extended prefix are treated as plain commands.
func parseZshHistory(raw string) []parsedLine {
	// zshExtRe matches the ": <epoch>:<elapsed>;<command>" prefix.
	zshExtRe := regexp.MustCompile(`^:\s*(\d+):\d+;(.*)$`)

	rawLines := strings.Split(raw, "\n")
	var out []parsedLine
	var current *parsedLine

	flush := func() {
		if current != nil {
			current.cmd = strings.TrimSpace(current.cmd)
			if current.cmd != "" {
				out = append(out, *current)
			}
			current = nil
		}
	}

	for i, line := range rawLines {
		lineNum := i + 1

		// A trailing backslash means the command continues on the next line.
		if current != nil && strings.HasSuffix(current.cmd, "\\") {
			current.cmd = strings.TrimSuffix(current.cmd, "\\") + " " + strings.TrimSpace(line)
			continue
		}

		flush()

		if m := zshExtRe.FindStringSubmatch(line); m != nil {
			epoch, err := strconv.ParseInt(m[1], 10, 64)
			pl := parsedLine{lineNum: lineNum, cmd: m[2]}
			if err == nil {
				t := time.Unix(epoch, 0).UTC()
				pl.ts = &t
			}
			current = &pl
		} else if t := strings.TrimSpace(line); t != "" {
			current = &parsedLine{lineNum: lineNum, cmd: t}
		}
	}
	flush()
	return out
}

// parseFishHistory handles fish's YAML-ish history format:
//
//	- cmd: <command>
//	  when: <epoch>
//	  paths:
//	    - /some/path
//
// Only "cmd" and "when" fields are extracted; "paths" and other fields are
// ignored. Entries start with "- cmd:"; a "when:" line immediately following
// records the timestamp.
func parseFishHistory(raw string) []parsedLine {
	var out []parsedLine
	var current *parsedLine

	flush := func() {
		if current != nil {
			if t := strings.TrimSpace(current.cmd); t != "" {
				current.cmd = t
				out = append(out, *current)
			}
			current = nil
		}
	}

	for i, line := range strings.Split(raw, "\n") {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(trimmed, "- cmd: "):
			flush()
			cmd := strings.TrimPrefix(trimmed, "- cmd: ")
			current = &parsedLine{lineNum: lineNum, cmd: cmd}

		case current != nil && strings.HasPrefix(trimmed, "when: "):
			epochStr := strings.TrimPrefix(trimmed, "when: ")
			if epoch, err := strconv.ParseInt(epochStr, 10, 64); err == nil {
				t := time.Unix(epoch, 0).UTC()
				current.ts = &t
			}
		}
	}
	flush()
	return out
}

// --------------------------------------------------------------------------
// Suspicious pattern detection
// --------------------------------------------------------------------------

// suspiciousPatterns flags command lines that exhibit attacker techniques
// without necessarily matching a specific IOC. These produce high severity.
var suspiciousPatterns = []*regexp.Regexp{
	// curl/wget with a custom User-Agent — common in C2 beacon traffic
	regexp.MustCompile(`(?i)curl\b.*\s-A\s`),
	regexp.MustCompile(`(?i)curl\b.*--user-agent[\s=]`),
	regexp.MustCompile(`(?i)wget\b.*--user-agent[\s=]`),
	// base64 decode pipelines — dropper staging pattern
	regexp.MustCompile(`\bbase64\s+(?:--decode|-d)\b`),
	regexp.MustCompile(`\|\s*base64\s+-d\b`),
	// download-and-execute — direct code execution from remote source
	regexp.MustCompile(`(?i)(?:curl|wget)\b[^|#\n]*\|\s*(?:bash|sh|python3?)\b`),
	// python one-liner with network activity — common dropper pattern
	regexp.MustCompile(`python3?\s+-c\s+.{0,200}(?:urllib|requests|http\.client|socket\.connect)`),
	// python one-liner with eval/exec
	regexp.MustCompile(`python3?\s+-c\s+.{0,200}(?:exec|eval|compile)\s*\(`),
}

// isSuspicious returns true if cmd matches any of the suspicious patterns.
func isSuspicious(cmd string) bool {
	for _, re := range suspiciousPatterns {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

// --------------------------------------------------------------------------
// Install target extraction
// --------------------------------------------------------------------------

// pipInstallRe matches "pip[3] install [flags] <name>[==<version>]".
// Handles optional flags before the package spec (e.g. --upgrade, --quiet).
// Version separators: ==, ~=, >=, <=, !=, ^= are all captured.
var pipInstallRe = regexp.MustCompile(
	`pip3?\s+install\s+(?:--?[\w-]+(?:\s+\S+)?\s+)*` +
		`['"]?([A-Za-z0-9][A-Za-z0-9._-]*)` +
		`(?:[=~><^!]+([A-Za-z0-9._-]+))?['"]?`)

// npmInstallRe matches "npm install|i [flags] <name>[@<version>]".
// Handles scoped packages (@scope/name).
var npmInstallRe = regexp.MustCompile(
	`npm\s+(?:install|i)\s+(?:--?[\w-]+\s+)*` +
		`(@?[A-Za-z0-9][A-Za-z0-9._/-]*)` +
		`(?:@([A-Za-z0-9._-]+))?`)

// extractInstallTarget returns the package name and version from a pip or npm
// install command. Returns empty strings if the line is not an install command.
func extractInstallTarget(cmd string) (name, version string) {
	if m := pipInstallRe.FindStringSubmatch(cmd); m != nil {
		return m[1], m[2]
	}
	if m := npmInstallRe.FindStringSubmatch(cmd); m != nil {
		name = m[1]
		if len(m) > 2 {
			version = m[2]
		}
		return name, version
	}
	return "", ""
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// buildNote constructs a human-readable annotation for the artifact explaining
// why the line was flagged.
func buildNote(lineNum int, iocMatches []evidence.IOCMatch, sev evidence.Severity) string {
	if len(iocMatches) > 0 {
		ids := make([]string, 0, len(iocMatches))
		seen := make(map[string]bool)
		for _, m := range iocMatches {
			if !seen[m.IndicatorID] {
				seen[m.IndicatorID] = true
				ids = append(ids, m.IndicatorID)
			}
		}
		return fmt.Sprintf("line %d: IOC match (%s)", lineNum, strings.Join(ids, ", "))
	}
	if sev == evidence.SeverityHigh {
		return fmt.Sprintf("line %d: suspicious pattern (curl -A / wget UA / base64 decode / python network one-liner)", lineNum)
	}
	return fmt.Sprintf("line %d", lineNum)
}

// dedupeMatches removes duplicate IOCMatch entries by IndicatorID.
func dedupeMatches(matches []evidence.IOCMatch) []evidence.IOCMatch {
	if len(matches) == 0 {
		return matches
	}
	seen := make(map[string]bool, len(matches))
	out := matches[:0]
	for _, m := range matches {
		if !seen[m.IndicatorID] {
			seen[m.IndicatorID] = true
			out = append(out, m)
		}
	}
	return out
}

// newID returns a random 32-character hex string for use as an Artifact ID.
func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
