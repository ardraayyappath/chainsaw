package pypi

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ardraayyappath/chainsaw/internal/evidence"
	"github.com/ardraayyappath/chainsaw/internal/ssh"
	"github.com/ardraayyappath/chainsaw/pkg/iocdb"
)

// PthCollector discovers .pth files across all Python site-packages directories
// on the target machine, classifies each line, and flags files that contain
// executable code or match the IOC database.
//
// Background: Python's site.py processes every .pth file in site-packages on
// interpreter startup. Lines beginning with "import" or containing "exec(" are
// executed directly — a fact exploited by the LiteLLM/TeamPCP attack, which
// planted litellm_init.pth in the system site-packages to achieve persistent
// code execution on every Python invocation.
type PthCollector struct {
	reader *ssh.RemoteReader
	store  *evidence.ArtifactStore
	iocs   *iocdb.IOCDatabase
}

// NewPthCollector constructs a PthCollector.
func NewPthCollector(r *ssh.RemoteReader, s *evidence.ArtifactStore, db *iocdb.IOCDatabase) *PthCollector {
	return &PthCollector{reader: r, store: s, iocs: db}
}

// Collect discovers all Python site-packages directories, builds a RECORD
// index to identify orphaned .pth files, reads every .pth file, and adds
// Artifacts for any that are suspicious.
//
// Errors on individual directories or files are non-fatal — collection
// continues so a single permission denial does not abort the run.
func (c *PthCollector) Collect(targetHome string) error {
	sitePkgDirs, err := c.discoverSitePackages(targetHome)
	if err != nil {
		return fmt.Errorf("pypi/pth: discover site-packages: %w", err)
	}
	for _, dir := range sitePkgDirs {
		registeredPths, _ := c.buildRECORDIndex(dir) // non-fatal; empty map → orphan detection disabled
		if err := c.collectDir(dir, registeredPths); err != nil {
			_ = err // non-fatal: log at call site when a logger is wired in
		}
	}
	return nil
}

// --------------------------------------------------------------------------
// Discovery
// --------------------------------------------------------------------------

// discoverSitePackages returns all Python site-packages directories visible on
// the target. It queries the interpreter for the authoritative system/user paths
// and also searches for virtual-environment site-packages under targetHome.
//
// Results are deduplicated so a directory reported by both sources appears once.
func (c *PthCollector) discoverSitePackages(targetHome string) ([]string, error) {
	var dirs []string

	// Ask the interpreter directly. getsitepackages() is absent in some virtualenv
	// builds, so we guard with getattr. getusersitepackages() is always present.
	out, err := c.reader.RunCommand(
		`python3 -c "import site; ` +
			`sp = getattr(site, 'getsitepackages', lambda: [])(); ` +
			`usp = site.getusersitepackages(); ` +
			`print('\n'.join(filter(None, sp + [usp])))" 2>/dev/null`,
	)
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				dirs = append(dirs, line)
			}
		}
	}

	// Also search for site-packages inside venvs created under the user's home.
	// maxdepth 6 covers common venv locations (~/venv, ~/projects/foo/.venv, etc.)
	// without crawling the entire filesystem.
	out2, _ := c.reader.RunCommand(fmt.Sprintf(
		"find %s -maxdepth 6 -type d -name site-packages 2>/dev/null",
		shellQuote(targetHome),
	))
	for _, line := range strings.Split(strings.TrimSpace(string(out2)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			dirs = append(dirs, line)
		}
	}

	return dedup(dirs), nil
}

// --------------------------------------------------------------------------
// RECORD index
// --------------------------------------------------------------------------

// buildRECORDIndex reads all dist-info/RECORD files in siteDir and returns
// the set of .pth basenames that are explicitly registered to an installed package.
//
// RECORD format (PEP 627 / wheel spec): CSV with columns path,hash,size.
// Paths are relative to the site-packages directory. A legitimate .pth entry
// looks like:  litellm-1.82.7.dist-info/../litellm.pth,sha256=...,123
// or simply:   somepackage.pth,sha256=...,42
//
// An empty return map (e.g. because RECORD files are absent on an old
// installation) disables orphan detection — we never false-positive.
func (c *PthCollector) buildRECORDIndex(siteDir string) (map[string]bool, error) {
	registered := make(map[string]bool)

	records, err := c.reader.FindByName(siteDir, "RECORD", 2)
	if err != nil {
		return registered, fmt.Errorf("find RECORD files in %q: %w", siteDir, err)
	}

	for _, recordPath := range records {
		// Only process RECORD files that live inside a *.dist-info directory.
		if !strings.HasSuffix(filepath.Base(filepath.Dir(recordPath)), ".dist-info") {
			continue
		}
		raw, err := c.reader.ReadFile(recordPath)
		if err != nil {
			continue // non-fatal
		}
		for _, line := range strings.Split(string(raw), "\n") {
			// Grab the path field (first CSV column); ignore hash and size.
			parts := strings.SplitN(line, ",", 2)
			if len(parts) == 0 {
				continue
			}
			entryPath := strings.TrimSpace(parts[0])
			// Normalize: RECORD paths may use "../" to escape the dist-info dir;
			// filepath.Base gives us just the filename in all cases.
			if strings.HasSuffix(entryPath, ".pth") {
				registered[filepath.Base(entryPath)] = true
			}
		}
	}
	return registered, nil
}

// --------------------------------------------------------------------------
// Per-directory and per-file collection
// --------------------------------------------------------------------------

// collectDir finds all .pth files directly in siteDir (depth=1) and processes each.
func (c *PthCollector) collectDir(siteDir string, registeredPths map[string]bool) error {
	pthFiles, err := c.reader.FindByName(siteDir, "*.pth", 1)
	if err != nil {
		return fmt.Errorf("find .pth in %q: %w", siteDir, err)
	}
	for _, pthPath := range pthFiles {
		if err := c.processPthFile(pthPath, siteDir, registeredPths); err != nil {
			_ = err // non-fatal
		}
	}
	return nil
}

// processPthFile reads one .pth file, classifies its lines, runs IOC matching,
// and adds an Artifact if the file is suspicious. Clean, registered,
// path-addition-only files (severity info) are skipped to keep the store focused.
func (c *PthCollector) processPthFile(pthPath, siteDir string, registeredPths map[string]bool) error {
	raw, err := c.reader.ReadFile(pthPath)
	if err != nil {
		return fmt.Errorf("read %q: %w", pthPath, err)
	}

	// Stat for mtime — do not error out if this fails; mtime is evidence but not critical.
	var mtime *time.Time
	if info, err := c.reader.Stat(pthPath); err == nil {
		t := info.ModTime
		mtime = &t
	}

	basename := filepath.Base(pthPath)

	// Orphan detection: a .pth file is orphaned if we have a populated RECORD
	// index for this site-packages directory but the file is absent from it.
	// An empty index means we couldn't determine ownership — not a false positive.
	orphaned := len(registeredPths) > 0 && !registeredPths[basename]

	// Line classification.
	lines := strings.Split(string(raw), "\n")
	hasExecLine := false
	for _, line := range lines {
		if classifyLine(line) == pthLineImportExec {
			hasExecLine = true
			break
		}
	}

	// IOC matching:
	//   - Filename: exact match via Match() — catches known-bad .pth names
	//     (e.g. litellm_init.pth → teampcp-pth-litellm-init).
	//   - Line content: substring match via MatchContent() — catches domain,
	//     UA, and path indicators embedded in exec/import lines
	//     (e.g. "models.litellm.cloud" inside an exec(urlopen(...)) call).
	//     Match() would miss these because domain matching is exact.
	allMatches := c.iocs.Match(basename)
	for _, line := range lines {
		if classifyLine(line) == pthLineImportExec {
			allMatches = append(allMatches, c.iocs.MatchContent(strings.TrimSpace(line))...)
		}
	}

	sev := pthSeverity(hasExecLine, orphaned, len(allMatches) > 0)

	// Skip benign, registered, path-only files — they are expected and numerous.
	if sev == evidence.SeverityInfo {
		return nil
	}

	a := &evidence.Artifact{
		ID:          newID(),
		Kind:        evidence.KindPthFile,
		Ecosystem:   evidence.EcosystemPyPI,
		Severity:    sev,
		Path:        pthPath,
		RawContent:  raw,
		Timestamp:   mtime,
		Inferred:    false, // mtime is read directly from the filesystem
		PackageName: basename, // .pth files have no version; filename is the identity
		IOCMatches:  allMatches,
		CollectedAt: time.Now().UTC(),
		Source:      "pypi/pth",
		Note:        pthNote(basename, siteDir, hasExecLine, orphaned),
	}
	_ = c.store.Add(a)
	return nil
}

// --------------------------------------------------------------------------
// Line classification
// --------------------------------------------------------------------------

// pthLineKind classifies a single line from a .pth file.
type pthLineKind string

const (
	pthLineBlank      pthLineKind = "blank"
	pthLineComment    pthLineKind = "comment"
	pthLinePathAdd    pthLineKind = "path_addition" // normal: bare directory path added to sys.path
	pthLineImportExec pthLineKind = "import_exec"   // suspicious: executed by site.py on startup
)

// classifyLine classifies a single .pth line according to CPython's site.py rules
// (see Lib/site.py, process_pth_file):
//
//   - blank lines and lines starting with '#' are skipped at runtime
//   - lines starting with "import" (followed by whitespace) are exec'd
//   - all other non-blank lines are treated as path entries
//
// The exec() form is not in CPython's site.py but is commonly injected by
// malware authors as an alternative execution vector (Python evaluates it
// as a path_addition line, then the OS loader catches it — or the attacker
// relies on a patched site.py). We flag it regardless.
func classifyLine(line string) pthLineKind {
	t := strings.TrimSpace(line)
	switch {
	case t == "":
		return pthLineBlank
	case strings.HasPrefix(t, "#"):
		return pthLineComment
	case strings.HasPrefix(t, "import "), strings.HasPrefix(t, "import\t"):
		return pthLineImportExec
	case strings.Contains(t, "exec("):
		return pthLineImportExec
	default:
		return pthLinePathAdd
	}
}

// --------------------------------------------------------------------------
// Severity and note helpers
// --------------------------------------------------------------------------

// pthSeverity returns the forensic severity for a .pth file based on three
// independent signals:
//
//	IOC match (filename or content)          → critical  (known-bad artifact)
//	executable line + orphaned               → critical  (unregistered code execution)
//	orphaned only                            → high      (unregistered file — warrants investigation)
//	executable line, registered in RECORD    → info      (skipped — exec lines are standard in
//	                                                      namespace packages, e.g. zope, setuptools;
//	                                                      a registered owner means no forensic signal)
//	none of the above                        → info      (benign; skipped by the caller)
func pthSeverity(hasExecLine, orphaned, iocMatch bool) evidence.Severity {
	switch {
	case iocMatch:
		return evidence.SeverityCritical
	case hasExecLine && orphaned:
		return evidence.SeverityCritical
	case orphaned:
		return evidence.SeverityHigh
	default:
		return evidence.SeverityInfo
	}
}

// pthNote constructs a human-readable annotation summarising why the file was flagged.
func pthNote(basename, siteDir string, hasExecLine, orphaned bool) string {
	var findings []string
	if hasExecLine {
		findings = append(findings, "contains executable line (import/exec)")
	}
	if orphaned {
		findings = append(findings, "not registered in any dist-info/RECORD (orphaned)")
	}
	if len(findings) == 0 {
		return ""
	}
	return fmt.Sprintf("%s in %s: %s", basename, siteDir, strings.Join(findings, "; "))
}

// --------------------------------------------------------------------------
// Package-level helpers
// --------------------------------------------------------------------------

// dedup returns ss with duplicate strings removed, preserving first-occurrence order.
func dedup(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// shellQuote wraps s in single quotes and escapes any embedded single quotes.
// Mirrors the unexported shellQuote in internal/ssh/reader.go — duplicated here
// because it is not exported from that package.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// newID returns a random 32-character hex string for use as an Artifact ID.
func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
