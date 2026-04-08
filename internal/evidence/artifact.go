package evidence

import (
	"time"
)

// ArtifactKind identifies the type of forensic artifact collected.
type ArtifactKind string

const (
	KindLockfileEntry ArtifactKind = "lockfile_entry"
	KindCacheHit      ArtifactKind = "cache_hit"
	KindInstallLog    ArtifactKind = "install_log"
	KindPthFile       ArtifactKind = "pth_file"
	KindPersistence   ArtifactKind = "persistence"
	KindShellHistory  ArtifactKind = "shell_history"
	KindNetworkIOC    ArtifactKind = "network_ioc"
	KindTempFile      ArtifactKind = "temp_file"
)

// Ecosystem identifies the package ecosystem or system layer an artifact belongs to.
type Ecosystem string

const (
	EcosystemNPM     Ecosystem = "npm"
	EcosystemPyPI    Ecosystem = "pypi"
	EcosystemOS      Ecosystem = "os"
	EcosystemNetwork Ecosystem = "network"
)

// Severity indicates the forensic significance of an artifact.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// IOCMatch records a hit against the embedded IOC database.
type IOCMatch struct {
	// IndicatorID is the unique identifier from iocs.yaml.
	IndicatorID string

	// IndicatorType describes what kind of IOC matched (hash, domain, path, email, ua).
	IndicatorType string

	// MatchedValue is the exact value from the artifact that triggered the match.
	MatchedValue string

	// Description is the human-readable label from the IOC database entry.
	Description string

	// Campaign associates the IOC with a known threat campaign (e.g. "UNC1069", "TeamPCP").
	Campaign string
}

// Artifact is the core forensic unit — every piece of evidence collected from a
// target machine is normalized into this struct before entering the correlation engine.
type Artifact struct {
	// ID is a UUID assigned at collection time, used for cross-referencing.
	ID string

	// Kind classifies the artifact by its forensic role.
	Kind ArtifactKind

	// Ecosystem is the package manager or system layer this artifact came from.
	Ecosystem Ecosystem

	// Severity is the assessed forensic significance.
	Severity Severity

	// Path is the absolute path on the target machine where this artifact was found.
	// Empty for artifacts reconstructed entirely from log entries.
	Path string

	// RawContent holds the raw bytes collected from the target (file content, log line, etc.).
	// Kept in memory during a run; serialized to raw/ in the output bundle.
	RawContent []byte

	// Timestamp is the directly-observed event time, if available.
	// Nil means the time is unknown or was reconstructed — see Inferred.
	Timestamp *time.Time

	// Inferred indicates the Timestamp was reconstructed by the correlation engine
	// rather than directly read from the target. Critical for forensic methodology claims.
	Inferred bool

	// PackageName is set for ecosystem artifacts (lockfile entries, cache hits, install logs).
	PackageName string

	// PackageVersion is the version string associated with PackageName.
	PackageVersion string

	// IntegrityHash is the sha512 integrity field from lockfiles / npm _cacache content-v2.
	// Used to locate cached tarballs even after registry removal.
	IntegrityHash string

	// IOCMatches holds all hits from the IOC database for this artifact.
	IOCMatches []IOCMatch

	// LinkedIDs contains IDs of causally related artifacts (e.g. lockfile entry → cache hit).
	LinkedIDs []string

	// CollectedAt is the wall-clock time on the forensic workstation when this
	// artifact was collected. Always set; never nil.
	CollectedAt time.Time

	// Source identifies which collector produced this artifact (e.g. "npm/lockfile").
	Source string

	// Note is a free-text field for analyst annotations added during correlation.
	Note string
}
