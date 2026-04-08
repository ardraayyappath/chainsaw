package npm

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ardraayyappath/chainsaw/internal/evidence"
	"github.com/ardraayyappath/chainsaw/internal/ssh"
	"github.com/ardraayyappath/chainsaw/pkg/iocdb"
)

// CacheCollector walks npm's _cacache and creates Artifacts for every indexed
// package entry, reading tarball bytes only for IOC-matched entries.
//
// _cacache layout:
//
//	~/.npm/_cacache/
//	├── content-v2/sha512/<hex[0:2]>/<hex[2:4]>/<hex[4:]>   ← tarball bytes
//	└── index-v5/<h[0:2]>/<h[2:4]>/<h[4:]>                  ← NDJSON metadata
type CacheCollector struct {
	reader *ssh.RemoteReader
	store  *evidence.ArtifactStore
	iocs   *iocdb.IOCDatabase
}

// NewCacheCollector constructs a CacheCollector.
func NewCacheCollector(r *ssh.RemoteReader, s *evidence.ArtifactStore, db *iocdb.IOCDatabase) *CacheCollector {
	return &CacheCollector{reader: r, store: s, iocs: db}
}

// Collect walks ~/.npm/_cacache/index-v5, reads every metadata bucket, and
// creates Artifacts. Tarball bytes are fetched only for IOC-matched entries.
func (c *CacheCollector) Collect(targetHome string) error {
	cacheDir := targetHome + "/.npm/_cacache"
	indexDir := cacheDir + "/index-v5"

	// index-v5 entries sit exactly 3 levels deep: <h[0:2]>/<h[2:4]>/<h[4:]>
	// Use FindAtDepth instead of a glob pattern — find -path with '*' has
	// inconsistent '/' matching behaviour across GNU and BSD find versions.
	buckets, err := c.reader.FindAtDepth(indexDir, 3, 3)
	if err != nil {
		return fmt.Errorf("npm/cache: find index-v5: %w", err)
	}

	for _, bucket := range buckets {
		if err := c.processBucket(cacheDir, bucket); err != nil {
			// Non-fatal: skip unreadable or corrupt buckets.
			continue
		}
	}

	c.linkToLockfiles()
	return nil
}

// linkToLockfiles links each cache_hit artifact to every lockfile_entry artifact
// that shares the same IntegrityHash. This builds the chain:
//
//	lockfile_entry (integrity recorded) → cache_hit (tarball recovered from cache)
func (c *CacheCollector) linkToLockfiles() {
	lockfiles := c.store.GetByKind(evidence.KindLockfileEntry)
	cacheHits := c.store.GetByKind(evidence.KindCacheHit)

	// Index lockfile artifacts by IntegrityHash for O(1) lookup.
	byHash := make(map[string][]string) // hash → []artifact ID
	for _, lf := range lockfiles {
		if lf.IntegrityHash != "" {
			byHash[lf.IntegrityHash] = append(byHash[lf.IntegrityHash], lf.ID)
		}
	}

	for _, hit := range cacheHits {
		if hit.IntegrityHash == "" {
			continue
		}
		for _, lfID := range byHash[hit.IntegrityHash] {
			_ = c.store.LinkArtifacts(hit.ID, lfID)
		}
	}
}

// --------------------------------------------------------------------------
// Bucket parsing
// --------------------------------------------------------------------------

// cacheIndexEntry mirrors the JSON stored in each index-v5 bucket line.
type cacheIndexEntry struct {
	Key       string `json:"key"`
	Integrity string `json:"integrity"`
	Time      int64  `json:"time"` // milliseconds since Unix epoch (JavaScript Date.now())
	Size      int64  `json:"size"`
}

// processBucket reads one index-v5 bucket file and processes every valid entry.
// Each bucket is NDJSON: lines of the form "<hash>\t<json>", with possible
// leading newlines used as separators between entries.
func (c *CacheCollector) processBucket(cacheDir, bucketPath string) error {
	raw, err := c.reader.ReadFile(bucketPath)
	if err != nil {
		return fmt.Errorf("read bucket %q: %w", bucketPath, err)
	}

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// cacache index-v5 format varies by npm version:
		//   npm 6 / cacache <15:  "<sha>\t<json>"
		//   npm 7+ / cacache 15+: plain JSON per line (no hash prefix)
		var jsonPart string
		if tab := strings.IndexByte(line, '\t'); tab >= 0 {
			jsonPart = line[tab+1:]
		} else if strings.HasPrefix(line, "{") {
			jsonPart = line
		} else {
			continue
		}

		var entry cacheIndexEntry
		if err := json.Unmarshal([]byte(jsonPart), &entry); err != nil {
			continue
		}
		if entry.Integrity == "" || entry.Key == "" {
			continue
		}

		c.processEntry(cacheDir, entry)
	}
	return nil
}

// --------------------------------------------------------------------------
// Per-entry logic
// --------------------------------------------------------------------------

func (c *CacheCollector) processEntry(cacheDir string, entry cacheIndexEntry) {
	name, version := extractNameVersion(entry.Key)

	// Match by integrity hash (primary — survives registry removal).
	hits := c.iocs.MatchHash(entry.Integrity)
	// Also match by name@version when sha512 slots in iocs.yaml are not yet
	// populated, or as a corroborating signal when they are.
	if name != "" && version != "" {
		hits = append(hits, c.iocs.Match(name+"@"+version)...)
	}
	sev := evidence.SeverityInfo
	if len(hits) > 0 {
		sev = evidence.SeverityCritical
	}

	var rawContent []byte
	if len(hits) > 0 {
		// Slurp the tarball only for IOC-flagged entries.
		contentPath, err := deriveContentPath(cacheDir, entry.Integrity)
		if err == nil {
			rawContent, _ = c.reader.ReadFile(contentPath)
		}
	}

	var ts *time.Time
	if entry.Time > 0 {
		t := time.UnixMilli(entry.Time).UTC()
		ts = &t
	}

	a := &evidence.Artifact{
		ID:             newID(),
		Kind:           evidence.KindCacheHit,
		Ecosystem:      evidence.EcosystemNPM,
		Severity:       sev,
		Path:           cacheDir,
		PackageName:    name,
		PackageVersion: version,
		IntegrityHash:  entry.Integrity,
		IOCMatches:     hits,
		Timestamp:      ts,
		Inferred:       false, // time field is directly recorded by npm at install time
		RawContent:     rawContent,
		CollectedAt:    time.Now().UTC(),
		Source:         "npm/cache",
	}

	_ = c.store.Add(a)
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// deriveContentPath converts a "sha512-<base64>" integrity value into the
// corresponding path under _cacache/content-v2.
//
// Algorithm (matches cacache's own path derivation):
//  1. Decode the base64 digest to bytes
//  2. Hex-encode the bytes
//  3. Path = content-v2/sha512/<hex[0:2]>/<hex[2:4]>/<hex[4:]>
func deriveContentPath(cacheDir, integrity string) (string, error) {
	const prefix = "sha512-"
	if !strings.HasPrefix(integrity, prefix) {
		return "", fmt.Errorf("unsupported integrity algorithm in %q", integrity)
	}
	b64 := strings.TrimPrefix(integrity, prefix)
	hashBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// Some base64 values use URL-safe encoding.
		hashBytes, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			return "", fmt.Errorf("decode base64 digest: %w", err)
		}
	}
	h := fmt.Sprintf("%x", hashBytes)
	if len(h) < 4 {
		return "", fmt.Errorf("hash too short: %q", h)
	}
	return filepath.Join(cacheDir, "content-v2", "sha512", h[0:2], h[2:4], h[4:]), nil
}

// extractNameVersion parses a package name and version from an npm cache key.
//
// Key format:
//
//	make-fetch-happen:request-cache:https://registry.npmjs.org/<name>/-/<file>-<version>.tgz
//
// Scoped packages:
//
//	make-fetch-happen:request-cache:https://registry.npmjs.org/@scope/<name>/-/<name>-<version>.tgz
func extractNameVersion(key string) (name, version string) {
	// Strip the make-fetch-happen prefix to get the raw URL.
	// Strip known cache-key prefixes to get a bare URL.
	url := key
	for _, prefix := range []string{
		"make-fetch-happen:request-cache:", // npm 6
		"pacote:tarball:",                  // npm 7+ / pacote
	} {
		if strings.HasPrefix(key, prefix) {
			url = key[len(prefix):]
			break
		}
	}

	// The /-/ separator divides the package name path from the tarball filename.
	const sep = "/-/"
	idx := strings.Index(url, sep)
	if idx < 0 {
		return "", ""
	}

	namePath := url[:idx]  // e.g. "https://registry.npmjs.org/axios"
	filename := url[idx+3:] // e.g. "axios-1.14.1.tgz"

	// Strip the registry URL prefix to isolate the package name.
	for _, registry := range []string{
		"https://registry.npmjs.org/",
		"https://registry.yarnpkg.com/",
	} {
		if strings.HasPrefix(namePath, registry) {
			namePath = strings.TrimPrefix(namePath, registry)
			break
		}
	}
	namePath = strings.TrimPrefix(namePath, "/")
	name = namePath // e.g. "axios" or "@babel/core"

	// Filename is "<shortname>-<version>.tgz". The short name is the final
	// path segment (drops the @scope/ prefix for scoped packages).
	filename = strings.TrimSuffix(filename, ".tgz")
	shortname := name
	if i := strings.LastIndex(name, "/"); i >= 0 {
		shortname = name[i+1:]
	}
	if strings.HasPrefix(filename, shortname+"-") {
		version = filename[len(shortname)+1:]
	}

	return name, version
}
