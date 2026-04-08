package npm

import (
	"regexp"
	"strings"
	"time"

	"github.com/ardraayyappath/chainsaw/internal/evidence"
	"github.com/ardraayyappath/chainsaw/internal/ssh"
	"github.com/ardraayyappath/chainsaw/pkg/iocdb"
)

// LogCollector scans npm debug logs for install lifecycle events and IOC hits,
// then links resulting Artifacts to any matching lockfile Artifacts in the store
// to form the causal chain: lockfile entry → cache hit → postinstall fired.
type LogCollector struct {
	reader *ssh.RemoteReader
	store  *evidence.ArtifactStore
	iocs   *iocdb.IOCDatabase
}

// NewLogCollector constructs a LogCollector.
func NewLogCollector(r *ssh.RemoteReader, s *evidence.ArtifactStore, db *iocdb.IOCDatabase) *LogCollector {
	return &LogCollector{reader: r, store: s, iocs: db}
}

// Collect globs ~/.npm/_logs/*.log, flags relevant lines, creates Artifacts,
// and links them to lockfile Artifacts for the same package.
func (c *LogCollector) Collect(targetHome string) error {
	logFiles, err := c.reader.Glob(targetHome + "/.npm/_logs/*.log")
	if err != nil {
		return nil // no _logs directory is normal on clean machines
	}

	// First pass: create and store all log artifacts.
	var logged []*evidence.Artifact
	for _, lf := range logFiles {
		arts, err := c.processLogFile(lf)
		if err != nil {
			continue // non-fatal
		}
		logged = append(logged, arts...)
	}

	// Second pass: link log artifacts to lockfile artifacts for the same package.
	// This must happen after all artifacts are in the store so LinkArtifacts can
	// resolve both IDs.
	c.linkToLockfiles(logged)
	return nil
}

// --------------------------------------------------------------------------
// Log file processing
// --------------------------------------------------------------------------

func (c *LogCollector) processLogFile(path string) ([]*evidence.Artifact, error) {
	raw, err := c.reader.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var arts []*evidence.Artifact
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if a := c.processLine(path, line); a != nil {
			if err := c.store.Add(a); err == nil {
				arts = append(arts, a)
			}
		}
	}
	return arts, nil
}

// processLine evaluates one log line and returns an Artifact if the line is
// worth flagging, or nil if it should be skipped.
func (c *LogCollector) processLine(logPath, line string) *evidence.Artifact {
	ts, message := parseLogLine(line)

	iocMatches := c.extractIOCMatches(message)
	isPostinstall := strings.Contains(strings.ToLower(message), "postinstall")
	isGyp := strings.Contains(strings.ToLower(message), "gyp")

	// Skip lines that don't match any flag criteria.
	if len(iocMatches) == 0 && !isPostinstall && !isGyp {
		return nil
	}

	var sev evidence.Severity
	switch {
	case len(iocMatches) > 0:
		sev = evidence.SeverityCritical
	case isPostinstall:
		// postinstall alone is suspicious — supply chain attacks rely on it.
		sev = evidence.SeverityMedium
	default:
		// gyp or other flagged content without a direct IOC hit.
		sev = evidence.SeverityInfo
	}

	name, version := extractFirstPackageSpec(message)

	var tsPtr *time.Time
	if !ts.IsZero() {
		tsPtr = &ts
	}

	return &evidence.Artifact{
		ID:             newID(),
		Kind:           evidence.KindInstallLog,
		Ecosystem:      evidence.EcosystemNPM,
		Severity:       sev,
		Path:           logPath,
		PackageName:    name,
		PackageVersion: version,
		IOCMatches:     iocMatches,
		Timestamp:      tsPtr,
		Inferred:       false, // timestamp is written directly by npm
		RawContent:     []byte(line),
		CollectedAt:    time.Now().UTC(),
		Source:         "npm/logs",
	}
}

// --------------------------------------------------------------------------
// Causal linkage
// --------------------------------------------------------------------------

// linkToLockfiles links each log artifact to any lockfile artifacts in the
// store that share the same PackageName. This builds the causal chain:
//
//	lockfile entry (package recorded) → log entry (postinstall / IOC event)
func (c *LogCollector) linkToLockfiles(logArts []*evidence.Artifact) {
	if len(logArts) == 0 {
		return
	}

	// Build a name → IDs index from all lockfile artifacts currently in the store.
	lockfilesByName := make(map[string][]string)
	for _, a := range c.store.GetByKind(evidence.KindLockfileEntry) {
		if a.PackageName != "" {
			lockfilesByName[strings.ToLower(a.PackageName)] = append(
				lockfilesByName[strings.ToLower(a.PackageName)], a.ID)
		}
	}

	for _, logArt := range logArts {
		if logArt.PackageName == "" {
			continue
		}
		key := strings.ToLower(logArt.PackageName)
		for _, lockID := range lockfilesByName[key] {
			_ = c.store.LinkArtifacts(logArt.ID, lockID)
		}
	}
}

// --------------------------------------------------------------------------
// Line parsing helpers
// --------------------------------------------------------------------------

// parseLogLine splits an npm debug log line into its timestamp and message.
//
// npm log format:
//
//	2026-03-31T00:21:43.123Z verb lifecycle plain-crypto-js@4.2.1~postinstall
//
// Returns a zero Time if the timestamp cannot be parsed.
func parseLogLine(line string) (ts time.Time, message string) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return time.Time{}, line
	}

	// Try RFC3339Nano first (covers .123Z), then plain RFC3339.
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		t, err = time.Parse(time.RFC3339, parts[0])
	}
	if err != nil {
		return time.Time{}, line
	}

	// parts[1] is the log level (verb, info, warn, silly…); include it in
	// message so analysts see the full context in RawContent.
	if len(parts) == 3 {
		return t.UTC(), parts[1] + " " + parts[2]
	}
	return t.UTC(), parts[1]
}

// pkgSpecRe matches npm package specifiers embedded in log lines.
// Handles plain names (axios@1.14.1) and scoped names (@scope/pkg@1.0.0).
// The `~` and `:` terminators cover lifecycle lines like "pkg@1.0.0~postinstall".
var pkgSpecRe = regexp.MustCompile(`(?:@[\w-]+/)?[\w][\w.\-]*@\d+\.\d+\.\d+[\w.+\-]*`)

// extractIOCMatches finds all package specifiers in a log message and runs
// each through the IOC database, returning all hits.
func (c *LogCollector) extractIOCMatches(message string) []evidence.IOCMatch {
	var all []evidence.IOCMatch
	for _, spec := range pkgSpecRe.FindAllString(message, -1) {
		// Strip lifecycle suffix (e.g. "~postinstall", ":install").
		if i := strings.IndexAny(spec, "~:"); i > 0 {
			spec = spec[:i]
		}
		all = append(all, c.iocs.Match(spec)...)
	}
	return all
}

// extractFirstPackageSpec returns the name and version from the first
// package specifier found in the message, used to populate Artifact fields.
func extractFirstPackageSpec(message string) (name, version string) {
	spec := pkgSpecRe.FindString(message)
	if spec == "" {
		return "", ""
	}
	if i := strings.IndexAny(spec, "~:"); i > 0 {
		spec = spec[:i]
	}
	// Split on the last "@" to handle scoped packages (@scope/name@version).
	at := strings.LastIndex(spec, "@")
	if at <= 0 {
		return spec, ""
	}
	return spec[:at], spec[at+1:]
}
