package npm

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ardraayyappath/chainsaw/internal/evidence"
	"github.com/ardraayyappath/chainsaw/internal/ssh"
	"github.com/ardraayyappath/chainsaw/pkg/iocdb"
)

// LockfileCollector discovers and parses npm, yarn, and pnpm lockfiles on the
// target machine, creating one Artifact per dependency entry.
type LockfileCollector struct {
	reader *ssh.RemoteReader
	store  *evidence.ArtifactStore
	iocs   *iocdb.IOCDatabase
}

// NewLockfileCollector constructs a LockfileCollector.
func NewLockfileCollector(r *ssh.RemoteReader, s *evidence.ArtifactStore, db *iocdb.IOCDatabase) *LockfileCollector {
	return &LockfileCollector{reader: r, store: s, iocs: db}
}

// Collect discovers lockfiles under targetHome at up to two directory levels
// deep (covers monorepos) and creates Artifacts for every dependency entry found.
// Errors on individual files are non-fatal — collection continues so a single
// corrupted or unreadable lockfile does not abort the run.
func (c *LockfileCollector) Collect(targetHome string) error {
	paths, err := c.discoverLockfiles(targetHome)
	if err != nil {
		return fmt.Errorf("npm/lockfile: discover: %w", err)
	}
	for _, p := range paths {
		if err := c.processLockfile(p); err != nil {
			// TODO: replace with structured logger when added
			_ = err
		}
	}
	return nil
}

// --------------------------------------------------------------------------
// Discovery
// --------------------------------------------------------------------------

var lockfileNames = []string{
	"package-lock.json",
	"yarn.lock",
	"pnpm-lock.yaml",
}

// discoverLockfiles returns paths of all lockfiles within targetHome, up to 6
// directory levels deep (covers deep monorepos). Uses FindByName rather than
// fixed-depth glob patterns so depth doesn't need to be predicted in advance.
func (c *LockfileCollector) discoverLockfiles(targetHome string) ([]string, error) {
	var found []string
	for _, name := range lockfileNames {
		// Prune node_modules: it can contain thousands of subdirectories and
		// lockfiles are never legitimately inside it.
		matches, err := c.reader.FindByName(targetHome, name, 6, "node_modules")
		if err != nil {
			continue // non-fatal: directory may not exist
		}
		found = append(found, matches...)
	}
	return found, nil
}

// --------------------------------------------------------------------------
// Per-file dispatch
// --------------------------------------------------------------------------

func (c *LockfileCollector) processLockfile(path string) error {
	raw, err := c.reader.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %q: %w", path, err)
	}

	switch filepath.Base(path) {
	case "package-lock.json":
		return c.parsePackageLock(path, raw)
	case "yarn.lock":
		return c.parseYarnLock(path, raw)
	case "pnpm-lock.yaml":
		return c.parsePnpmLock(path, raw)
	default:
		return fmt.Errorf("unknown lockfile type: %q", path)
	}
}

// --------------------------------------------------------------------------
// package-lock.json parser (v1, v2, v3)
// --------------------------------------------------------------------------

// pkgLockPackage covers the v2/v3 "packages" map entries.
type pkgLockPackage struct {
	Version   string `json:"version"`
	Integrity string `json:"integrity"`
}

// pkgLockDep covers v1 "dependencies" entries (recursive).
type pkgLockDep struct {
	Version      string                `json:"version"`
	Integrity    string                `json:"integrity"`
	Dependencies map[string]pkgLockDep `json:"dependencies"`
}

type packageLockFile struct {
	LockfileVersion int                        `json:"lockfileVersion"`
	Packages        map[string]pkgLockPackage  `json:"packages"`
	Dependencies    map[string]pkgLockDep      `json:"dependencies"`
}

func (c *LockfileCollector) parsePackageLock(path string, raw []byte) error {
	var lf packageLockFile
	if err := json.Unmarshal(raw, &lf); err != nil {
		return fmt.Errorf("parse package-lock.json %q: %w", path, err)
	}

	if lf.LockfileVersion >= 2 && len(lf.Packages) > 0 {
		// v2/v3: prefer the flat "packages" map; keys are "node_modules/name"
		// or "node_modules/scope/name". Skip the root entry ("").
		for key, pkg := range lf.Packages {
			if key == "" || pkg.Version == "" {
				continue
			}
			name := stripNodeModulesPrefix(key)
			c.addEntry(path, name, pkg.Version, pkg.Integrity)
		}
	} else {
		// v1: recurse through nested "dependencies".
		c.walkV1Deps(path, lf.Dependencies)
	}
	return nil
}

func (c *LockfileCollector) walkV1Deps(path string, deps map[string]pkgLockDep) {
	for name, dep := range deps {
		c.addEntry(path, name, dep.Version, dep.Integrity)
		if len(dep.Dependencies) > 0 {
			c.walkV1Deps(path, dep.Dependencies)
		}
	}
}

// stripNodeModulesPrefix converts "node_modules/foo" or
// "node_modules/@scope/foo" to the bare package name.
func stripNodeModulesPrefix(key string) string {
	const prefix = "node_modules/"
	// Walk past all node_modules/ segments to get the final package name.
	for strings.HasPrefix(key, prefix) {
		key = key[len(prefix):]
		// Scoped packages: keep @scope/name together.
		if idx := strings.Index(key, "/node_modules/"); idx != -1 {
			key = key[idx+len("/node_modules/"):]
		} else {
			break
		}
	}
	return key
}

// --------------------------------------------------------------------------
// yarn.lock parser
// --------------------------------------------------------------------------

// parseYarnLock handles both classic (v1) and Berry (v2+) yarn.lock formats.
// The format is line-oriented: header blocks start with an unindented package
// specifier line ending in ":", followed by indented key-value pairs.
func (c *LockfileCollector) parseYarnLock(path string, raw []byte) error {
	lines := strings.Split(string(raw), "\n")

	var (
		currentName    string
		currentVersion string
		currentInteg   string
	)

	flush := func() {
		if currentName != "" && currentVersion != "" {
			c.addEntry(path, currentName, currentVersion, currentInteg)
		}
		currentName = ""
		currentVersion = ""
		currentInteg = ""
	}

	for _, line := range lines {
		// Skip comments and blank lines.
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Unindented line ending with ":" is a package specifier header.
		// May list multiple specifiers: `"axios@^1.0.0", "axios@1.14.1":`
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			flush()
			// Extract the first specifier to get the package name.
			specifier := strings.TrimSuffix(strings.TrimSpace(line), ":")
			specifier = strings.Trim(strings.Split(specifier, ",")[0], `" `)
			// Name is everything before the last "@" (handles scoped packages).
			if at := strings.LastIndex(specifier, "@"); at > 0 {
				currentName = specifier[:at]
			} else {
				currentName = specifier
			}
			continue
		}

		// Indented key-value lines inside a block.
		if strings.Contains(trimmed, " ") {
			parts := strings.SplitN(trimmed, " ", 2)
			val := strings.Trim(parts[1], `"`)
			switch parts[0] {
			case "version":
				currentVersion = val
			case "integrity":
				currentInteg = val
			}
		}
	}
	flush()
	return nil
}

// --------------------------------------------------------------------------
// pnpm-lock.yaml parser (v6 and v9)
// --------------------------------------------------------------------------

type pnpmLockFile struct {
	LockfileVersion string                        `yaml:"lockfileVersion"`
	Packages        map[string]pnpmPackageEntry   `yaml:"packages"`
}

type pnpmPackageEntry struct {
	Resolution struct {
		Integrity string `yaml:"integrity"`
	} `yaml:"resolution"`
}

func (c *LockfileCollector) parsePnpmLock(path string, raw []byte) error {
	var lf pnpmLockFile
	if err := yaml.Unmarshal(raw, &lf); err != nil {
		return fmt.Errorf("parse pnpm-lock.yaml %q: %w", path, err)
	}

	for key, pkg := range lf.Packages {
		// v6 keys: "/axios@1.14.1"  v9 keys: "axios@1.14.1"
		key = strings.TrimPrefix(key, "/")

		// Extract name and version from "name@version".
		// Scoped packages look like "@scope/name@version".
		name, version := splitPnpmKey(key)
		if name == "" || version == "" {
			continue
		}
		c.addEntry(path, name, version, pkg.Resolution.Integrity)
	}
	return nil
}

// splitPnpmKey splits a pnpm package key like "axios@1.14.1" or
// "@scope/name@1.0.0" into (name, version).
func splitPnpmKey(key string) (name, version string) {
	// For scoped packages the key starts with "@"; find the second "@".
	start := 0
	if strings.HasPrefix(key, "@") {
		start = 1
	}
	at := strings.LastIndex(key[start:], "@")
	if at < 0 {
		return key, ""
	}
	at += start
	return key[:at], key[at+1:]
}

// --------------------------------------------------------------------------
// Artifact creation
// --------------------------------------------------------------------------

// addEntry creates an Artifact for one dependency entry, runs IOC matching,
// sets severity, and adds it to the store.
func (c *LockfileCollector) addEntry(lockfilePath, name, version, integrity string) {
	spec := name + "@" + version

	nameMatches := c.iocs.Match(spec)
	hashMatches := c.iocs.MatchHash(integrity)
	allMatches := append(nameMatches, hashMatches...)

	sev := evidence.SeverityInfo
	if len(allMatches) > 0 {
		sev = evidence.SeverityCritical
	}

	now := time.Now().UTC()
	a := &evidence.Artifact{
		ID:             newID(),
		Kind:           evidence.KindLockfileEntry,
		Ecosystem:      evidence.EcosystemNPM,
		Severity:       sev,
		Path:           lockfilePath,
		PackageName:    name,
		PackageVersion: version,
		IntegrityHash:  integrity,
		IOCMatches:     allMatches,
		CollectedAt:    now,
		Source:         "npm/lockfile",
	}

	// Ignore duplicate-ID errors: with random IDs this should never happen,
	// but we don't want a store error to silently drop evidence.
	_ = c.store.Add(a)
}

// newID returns a random 32-character hex string for use as an Artifact ID.
func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
