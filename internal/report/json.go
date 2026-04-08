package report

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ardraayyappath/chainsaw/internal/evidence"
)

// WriteJSON writes evidence.json to outputDir.
func WriteJSON(data *ReportData, outputDir string) error {
	bundle := toBundle(data)
	b, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	out := filepath.Join(outputDir, "evidence.json")
	if err := os.WriteFile(out, b, 0644); err != nil {
		return fmt.Errorf("write %q: %w", out, err)
	}
	return nil
}

// --------------------------------------------------------------------------
// Wire types — snake_case fields for SIEM ingestion
// --------------------------------------------------------------------------

type jBundle struct {
	Meta      jMeta      `json:"meta"`
	Campaigns []jCampaign `json:"campaigns"`
	Chains    []*jNode    `json:"chains"`
	Artifacts []jArtifact `json:"artifacts"`
}

type jMeta struct {
	Hostname       string `json:"hostname"`
	CollectedAt    string `json:"collected_at"`
	DurationMs     int64  `json:"duration_ms"`
	Version        string `json:"version"`
	TotalArtifacts int    `json:"total_artifacts"`
	CriticalCount  int    `json:"critical_count"`
	HighCount      int    `json:"high_count"`
	CampaignCount  int    `json:"campaign_count"`
}

type jCampaign struct {
	ID             string       `json:"id"`
	Description    string       `json:"description"`
	KindCounts     []jKindCount `json:"kind_counts"`
	TotalArtifacts int          `json:"total_artifacts"`
	ConfidencePct  int          `json:"confidence_pct"`
}

type jKindCount struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

type jNode struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Identity   string   `json:"identity"`
	Severity   string   `json:"severity"`
	Source     string   `json:"source"`
	IOCMatches []jMatch `json:"ioc_matches,omitempty"`
	Children   []*jNode `json:"children,omitempty"`
}

type jArtifact struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"`
	Ecosystem      string   `json:"ecosystem"`
	Severity       string   `json:"severity"`
	Path           string   `json:"path"`
	RawContentB64  string   `json:"raw_content_b64,omitempty"`
	Timestamp      *string  `json:"timestamp,omitempty"`
	Inferred       bool     `json:"inferred"`
	PackageName    string   `json:"package_name,omitempty"`
	PackageVersion string   `json:"package_version,omitempty"`
	IntegrityHash  string   `json:"integrity_hash,omitempty"`
	IOCMatches     []jMatch `json:"ioc_matches,omitempty"`
	LinkedIDs      []string `json:"linked_ids,omitempty"`
	CollectedAt    string   `json:"collected_at"`
	Source         string   `json:"source"`
	Note           string   `json:"note,omitempty"`
}

type jMatch struct {
	IndicatorID   string `json:"indicator_id"`
	IndicatorType string `json:"indicator_type"`
	MatchedValue  string `json:"matched_value"`
	Description   string `json:"description"`
	Campaign      string `json:"campaign"`
}

// --------------------------------------------------------------------------
// Conversion
// --------------------------------------------------------------------------

func toBundle(data *ReportData) jBundle {
	return jBundle{
		Meta:      toMeta(data),
		Campaigns: toCampaigns(data.Campaigns),
		Chains:    toNodes(data.Chains),
		Artifacts: toArtifacts(data.All),
	}
}

func toMeta(data *ReportData) jMeta {
	return jMeta{
		Hostname:       data.Meta.Target,
		CollectedAt:    data.Meta.CollectedAt.UTC().Format(time.RFC3339),
		DurationMs:     data.Meta.Duration.Milliseconds(),
		Version:        data.Meta.Version,
		TotalArtifacts: data.TotalArtifacts,
		CriticalCount:  data.CriticalCount,
		HighCount:      data.HighCount,
		CampaignCount:  data.CampaignCount,
	}
}

func toCampaigns(cs []CampaignSummary) []jCampaign {
	out := make([]jCampaign, len(cs))
	for i, c := range cs {
		kcs := make([]jKindCount, len(c.KindList))
		for j, kc := range c.KindList {
			kcs[j] = jKindCount{Kind: kc.Kind, Count: kc.Count}
		}
		out[i] = jCampaign{
			ID:             c.ID,
			Description:    c.Description,
			KindCounts:     kcs,
			TotalArtifacts: c.TotalArtifacts,
			ConfidencePct:  c.ConfidencePct,
		}
	}
	return out
}

func toNodes(chains []*ChainNode) []*jNode {
	out := make([]*jNode, len(chains))
	for i, n := range chains {
		out[i] = toNode(n)
	}
	return out
}

func toNode(n *ChainNode) *jNode {
	node := &jNode{
		ID:         n.Artifact.ID,
		Kind:       string(n.Artifact.Kind),
		Identity:   n.Identity,
		Severity:   string(n.Artifact.Severity),
		Source:     n.Artifact.Source,
		IOCMatches: toMatches(n.Artifact.IOCMatches),
	}
	if len(n.Children) > 0 {
		node.Children = make([]*jNode, len(n.Children))
		for i, c := range n.Children {
			node.Children[i] = toNode(c)
		}
	}
	return node
}

func toArtifacts(all []*evidence.Artifact) []jArtifact {
	out := make([]jArtifact, len(all))
	for i, a := range all {
		out[i] = toArtifact(a)
	}
	return out
}

func toArtifact(a *evidence.Artifact) jArtifact {
	ja := jArtifact{
		ID:             a.ID,
		Kind:           string(a.Kind),
		Ecosystem:      string(a.Ecosystem),
		Severity:       string(a.Severity),
		Path:           a.Path,
		Inferred:       a.Inferred,
		PackageName:    a.PackageName,
		PackageVersion: a.PackageVersion,
		IntegrityHash:  a.IntegrityHash,
		IOCMatches:     toMatches(a.IOCMatches),
		LinkedIDs:      a.LinkedIDs,
		CollectedAt:    a.CollectedAt.UTC().Format(time.RFC3339),
		Source:         a.Source,
		Note:           a.Note,
	}
	if len(a.RawContent) > 0 {
		ja.RawContentB64 = base64.StdEncoding.EncodeToString(a.RawContent)
	}
	if a.Timestamp != nil {
		ts := a.Timestamp.UTC().Format(time.RFC3339)
		ja.Timestamp = &ts
	}
	return ja
}

func toMatches(ms []evidence.IOCMatch) []jMatch {
	if len(ms) == 0 {
		return nil
	}
	out := make([]jMatch, len(ms))
	for i, m := range ms {
		out[i] = jMatch{
			IndicatorID:   m.IndicatorID,
			IndicatorType: m.IndicatorType,
			MatchedValue:  m.MatchedValue,
			Description:   m.Description,
			Campaign:      m.Campaign,
		}
	}
	return out
}
