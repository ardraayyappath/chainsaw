// Package report generates the HTML and JSON output bundles from a completed
// chainsaw collection run.
package report

import (
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ardraayyappath/chainsaw/internal/evidence"
	"github.com/ardraayyappath/chainsaw/pkg/iocdb"
)

// ReportMeta holds collection-level metadata passed in from main.
type ReportMeta struct {
	Target      string
	CollectedAt time.Time
	Duration    time.Duration
	Version     string
}

// KindCount pairs an artifact kind name with a corroborating count.
type KindCount struct {
	Kind  string
	Count int
}

// CampaignSummary aggregates corroboration evidence for one threat campaign.
type CampaignSummary struct {
	ID             string
	Description    string
	KindList       []KindCount // sorted by kind name
	TotalArtifacts int
	ConfidencePct  int // 20 per distinct corroborating kind, capped at 100
}

// ChainNode is one node in a linked evidence chain tree.
type ChainNode struct {
	Artifact *evidence.Artifact
	Identity string // pre-computed display name
	Children []*ChainNode
}

// ReportData is the complete data structure consumed by both generators.
type ReportData struct {
	Meta           ReportMeta
	Campaigns      []CampaignSummary
	Chains         []*ChainNode
	Unlinked       []*evidence.Artifact // IOC hits not in any chain
	All            []*evidence.Artifact // every artifact, severity-desc sorted
	TotalArtifacts int
	CriticalCount  int
	HighCount      int
	CampaignCount  int
}

// Build constructs ReportData from the artifact store and IOC database.
func Build(store *evidence.ArtifactStore, iocDB *iocdb.IOCDatabase, meta ReportMeta) *ReportData {
	all := store.All()

	sort.Slice(all, func(i, j int) bool {
		ri, rj := severityRank(all[i].Severity), severityRank(all[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if all[i].Kind != all[j].Kind {
			return all[i].Kind < all[j].Kind
		}
		return all[i].PackageName < all[j].PackageName
	})

	var critCount, highCount int
	for _, a := range all {
		switch a.Severity {
		case evidence.SeverityCritical:
			critCount++
		case evidence.SeverityHigh:
			highCount++
		}
	}

	chains := buildChains(all)
	campaigns := buildCampaignSummaries(all, iocDB)

	chainSet := chainedIDs(chains)
	var unlinked []*evidence.Artifact
	for _, a := range all {
		if len(a.IOCMatches) > 0 && !chainSet[a.ID] {
			unlinked = append(unlinked, a)
		}
	}

	return &ReportData{
		Meta:           meta,
		Campaigns:      campaigns,
		Chains:         chains,
		Unlinked:       unlinked,
		All:            all,
		TotalArtifacts: len(all),
		CriticalCount:  critCount,
		HighCount:      highCount,
		CampaignCount:  len(campaigns),
	}
}

// ArtifactIdentity returns a concise display name for an artifact.
func ArtifactIdentity(a *evidence.Artifact) string {
	if a.PackageName != "" {
		if a.PackageVersion != "" {
			return a.PackageName + "@" + a.PackageVersion
		}
		return a.PackageName
	}
	if len(a.RawContent) > 0 {
		cmd := strings.TrimSpace(string(a.RawContent))
		if len(cmd) > 60 {
			return cmd[:57] + "..."
		}
		return cmd
	}
	if a.Path != "" {
		return filepath.Base(a.Path)
	}
	return string(a.Kind)
}

// --------------------------------------------------------------------------
// Chain construction
// --------------------------------------------------------------------------

func buildChains(all []*evidence.Artifact) []*ChainNode {
	byID := make(map[string]*evidence.Artifact, len(all))
	for _, a := range all {
		byID[a.ID] = a
	}

	var roots []*evidence.Artifact
	for _, a := range all {
		if len(a.LinkedIDs) == 0 {
			continue
		}
		isRoot := true
		for _, id := range a.LinkedIDs {
			if n, ok := byID[id]; ok && kindRank(n.Kind) <= kindRank(a.Kind) {
				isRoot = false
				break
			}
		}
		if isRoot {
			roots = append(roots, a)
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].PackageName < roots[j].PackageName })

	out := make([]*ChainNode, 0, len(roots))
	for _, r := range roots {
		out = append(out, buildNode(r, byID, make(map[string]bool)))
	}
	return out
}

func buildNode(a *evidence.Artifact, byID map[string]*evidence.Artifact, visited map[string]bool) *ChainNode {
	visited[a.ID] = true
	node := &ChainNode{Artifact: a, Identity: ArtifactIdentity(a)}
	for _, id := range a.LinkedIDs {
		child, ok := byID[id]
		if !ok || visited[id] || kindRank(child.Kind) <= kindRank(a.Kind) {
			continue
		}
		node.Children = append(node.Children, buildNode(child, byID, visited))
	}
	return node
}

func chainedIDs(chains []*ChainNode) map[string]bool {
	set := make(map[string]bool)
	var walk func(*ChainNode)
	walk = func(n *ChainNode) {
		set[n.Artifact.ID] = true
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, root := range chains {
		walk(root)
	}
	return set
}

// --------------------------------------------------------------------------
// Campaign summaries
// --------------------------------------------------------------------------

func buildCampaignSummaries(all []*evidence.Artifact, iocDB *iocdb.IOCDatabase) []CampaignSummary {
	campaignKinds := make(map[string]map[string]int)
	for _, a := range all {
		for _, m := range a.IOCMatches {
			if campaignKinds[m.Campaign] == nil {
				campaignKinds[m.Campaign] = make(map[string]int)
			}
			campaignKinds[m.Campaign][string(a.Kind)]++
		}
	}

	var out []CampaignSummary
	for _, camp := range iocDB.Campaigns() {
		kinds, ok := campaignKinds[camp.ID]
		if !ok {
			continue
		}
		var kindList []KindCount
		total := 0
		for k, n := range kinds {
			kindList = append(kindList, KindCount{Kind: k, Count: n})
			total += n
		}
		sort.Slice(kindList, func(i, j int) bool { return kindList[i].Kind < kindList[j].Kind })

		confPct := len(kinds) * 20
		if confPct > 100 {
			confPct = 100
		}
		out = append(out, CampaignSummary{
			ID:             camp.ID,
			Description:    strings.TrimSpace(camp.Description),
			KindList:       kindList,
			TotalArtifacts: total,
			ConfidencePct:  confPct,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// --------------------------------------------------------------------------
// Shared utilities
// --------------------------------------------------------------------------

func kindRank(k evidence.ArtifactKind) int {
	switch k {
	case evidence.KindLockfileEntry:
		return 0
	case evidence.KindCacheHit:
		return 1
	case evidence.KindInstallLog:
		return 2
	case evidence.KindPthFile:
		return 3
	case evidence.KindPersistence:
		return 4
	case evidence.KindShellHistory:
		return 5
	case evidence.KindNetworkIOC:
		return 6
	case evidence.KindTempFile:
		return 7
	default:
		return 99
	}
}

func severityRank(s evidence.Severity) int {
	switch s {
	case evidence.SeverityCritical:
		return 4
	case evidence.SeverityHigh:
		return 3
	case evidence.SeverityMedium:
		return 2
	case evidence.SeverityLow:
		return 1
	default:
		return 0
	}
}
