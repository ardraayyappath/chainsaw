// Temporary test harness for the npm collector layer.
// Run against the post-compromise VM snapshot to validate collection.
// Replace with full cobra CLI once all collectors are built.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	osc "github.com/ardraayyappath/chainsaw/internal/collector/os"
	"github.com/ardraayyappath/chainsaw/internal/collector/npm"
	"github.com/ardraayyappath/chainsaw/internal/collector/pypi"
	"github.com/ardraayyappath/chainsaw/internal/evidence"
	"github.com/ardraayyappath/chainsaw/internal/report"
	sshconn "github.com/ardraayyappath/chainsaw/internal/ssh"
	"github.com/ardraayyappath/chainsaw/pkg/iocdb"
)

const (
	host       = "192.168.64.3"
	port       = 22
	user       = "ardra"
	keyPath    = "~/.ssh/chainsaw_research"
	targetHome = "~"
)

func main() {
	verbose := flag.Bool("v", false, "print diagnostics before running collectors")
	outputDir := flag.String("output", "", "write HTML + JSON report to this directory (skipped if empty)")
	flag.Parse()
	if err := run(*verbose, *outputDir); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(verbose bool, outputDir string) error {
	start := time.Now()
	// ── IOC database ────────────────────────────────────────────────────────
	db, err := iocdb.Load()
	if err != nil {
		return fmt.Errorf("load IOC database: %w", err)
	}
	fmt.Printf("IOC database loaded (%d campaigns)\n\n", len(db.Campaigns()))

	// ── SSH connection ───────────────────────────────────────────────────────
	expandedKey := expandHome(keyPath)
	fmt.Printf("Connecting to %s:%d as %s (key: %s)\n", host, port, user, expandedKey)

	conn, err := sshconn.NewRemoteConnector(host, port, user, expandedKey)
	if err != nil {
		return fmt.Errorf("ssh connect: %w", err)
	}
	defer conn.Close()
	fmt.Printf("Connected to %s\n\n", conn.Target())

	reader := sshconn.NewRemoteReader(conn)

	// Resolve "~" to the real path on the remote — find/cat/stat won't expand
	// a tilde that's inside single quotes.
	remoteHome, err := reader.ResolveHome()
	if err != nil {
		return fmt.Errorf("resolve remote home: %w", err)
	}
	fmt.Printf("Remote home: %s\n\n", remoteHome)

	// ── Diagnostics ──────────────────────────────────────────────────────────
	if verbose {
		runDiagnostics(reader, remoteHome)
	}

	// ── Artifact store ───────────────────────────────────────────────────────
	store := evidence.NewArtifactStore()

	// ── npm collectors ───────────────────────────────────────────────────────
	fmt.Println("Running npm collectors...")

	lockfileC := npm.NewLockfileCollector(reader, store, db)
	cacheC := npm.NewCacheCollector(reader, store, db)
	logC := npm.NewLogCollector(reader, store, db)

	collectors := []struct {
		name string
		fn   func(string) error
	}{
		{"npm/lockfile", func(h string) error { return lockfileC.Collect(h) }},
		{"npm/cache", func(h string) error { return cacheC.Collect(h) }},
		{"npm/logs", func(h string) error { return logC.Collect(h) }},
	}

	for _, c := range collectors {
		fmt.Printf("  %-18s running...\n", c.name)
		before := store.Len()
		if err := c.fn(remoteHome); err != nil {
			fmt.Printf("  %-18s ERROR: %v\n", c.name, err)
			continue
		}
		fmt.Printf("  %-18s +%d artifacts\n", c.name, store.Len()-before)
	}

	fmt.Println()

	// ── pypi collectors ──────────────────────────────────────────────────────
	fmt.Println("Running pypi collectors...")

	pthC := pypi.NewPthCollector(reader, store, db)

	pypiCollectors := []struct {
		name string
		fn   func(string) error
	}{
		{"pypi/pth", func(h string) error { return pthC.Collect(h) }},
	}

	for _, c := range pypiCollectors {
		fmt.Printf("  %-18s running...\n", c.name)
		before := store.Len()
		if err := c.fn(remoteHome); err != nil {
			fmt.Printf("  %-18s ERROR: %v\n", c.name, err)
			continue
		}
		fmt.Printf("  %-18s +%d artifacts\n", c.name, store.Len()-before)
	}

	fmt.Println()

	// ── os collectors ────────────────────────────────────────────────────────
	fmt.Println("Running os collectors...")

	shellC := osc.NewShellCollector(reader, store, db)

	osCollectors := []struct {
		name string
		fn   func(string) error
	}{
		{"os/shell", func(h string) error { return shellC.Collect(h) }},
	}

	for _, c := range osCollectors {
		fmt.Printf("  %-18s running...\n", c.name)
		before := store.Len()
		if err := c.fn(remoteHome); err != nil {
			fmt.Printf("  %-18s ERROR: %v\n", c.name, err)
			continue
		}
		fmt.Printf("  %-18s +%d artifacts\n", c.name, store.Len()-before)
	}

	fmt.Println()

	// ── Summary ──────────────────────────────────────────────────────────────
	printSummary(store)

	// ── Report generation ────────────────────────────────────────────────────
	if outputDir != "" {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("create output dir: %w", err)
		}
		hostname, _ := os.Hostname()
		meta := report.ReportMeta{
			Target:      conn.Target(),
			CollectedAt: time.Now().UTC(),
			Duration:    time.Since(start),
			Version:     hostname,
		}
		data := report.Build(store, db, meta)
		fmt.Printf("\nWriting report to %s ...\n", outputDir)
		if err := report.WriteHTML(data, outputDir); err != nil {
			return fmt.Errorf("write HTML report: %w", err)
		}
		if err := report.WriteJSON(data, outputDir); err != nil {
			return fmt.Errorf("write JSON report: %w", err)
		}
		fmt.Printf("  report.html\n  evidence.json\n")
	}
	return nil
}

func printSummary(store *evidence.ArtifactStore) {
	all := store.All()

	fmt.Printf("═══════════════════════════════════════════════════════\n")
	fmt.Printf("  CHAINSAW COLLECTION SUMMARY\n")
	fmt.Printf("═══════════════════════════════════════════════════════\n")
	fmt.Printf("  Total artifacts: %d\n\n", len(all))

	// ── By Kind ──────────────────────────────────────────────────────────────
	kindCounts := make(map[evidence.ArtifactKind]int)
	for _, a := range all {
		kindCounts[a.Kind]++
	}
	// Print in a stable order.
	kinds := []evidence.ArtifactKind{
		evidence.KindLockfileEntry,
		evidence.KindCacheHit,
		evidence.KindInstallLog,
		evidence.KindPthFile,
		evidence.KindPersistence,
		evidence.KindShellHistory,
		evidence.KindNetworkIOC,
		evidence.KindTempFile,
	}
	fmt.Println("  Artifacts by Kind:")
	for _, k := range kinds {
		n := kindCounts[k]
		if n == 0 {
			continue
		}
		fmt.Printf("    %-20s %d\n", k, n)
	}
	fmt.Println()

	// ── IOC Matches ──────────────────────────────────────────────────────────
	var iocHits []*evidence.Artifact
	for _, a := range all {
		if len(a.IOCMatches) > 0 {
			iocHits = append(iocHits, a)
		}
	}

	fmt.Printf("  IOC Matches (%d artifacts):\n", len(iocHits))
	if len(iocHits) == 0 {
		fmt.Println("    (none)")
	} else {
		// Sort by severity desc, then by package name.
		sort.Slice(iocHits, func(i, j int) bool {
			ri := severityRank(iocHits[i].Severity)
			rj := severityRank(iocHits[j].Severity)
			if ri != rj {
				return ri > rj
			}
			return iocHits[i].PackageName < iocHits[j].PackageName
		})
		for _, a := range iocHits {
			campaigns := uniqueCampaigns(a.IOCMatches)
			identity := a.PackageName
			if a.PackageVersion != "" {
				identity += "@" + a.PackageVersion
			}
			if identity == "" && len(a.RawContent) > 0 {
				// No package identity (e.g. curl/wget history lines) — show a
				// truncated version of the raw command so the analyst can see
				// what triggered the hit without reading the IOC match lines.
				cmd := strings.TrimSpace(string(a.RawContent))
				if len(cmd) > 60 {
					cmd = cmd[:57] + "..."
				}
				identity = cmd
			}
			fmt.Printf("    [%s] %-12s  %s\n",
				strings.ToUpper(string(a.Severity)),
				a.Kind,
				identity,
			)
			for _, m := range a.IOCMatches {
				fmt.Printf("          → %s (%s)  campaign: %s\n",
					m.MatchedValue, m.IndicatorType, m.Campaign)
			}
			_ = campaigns
		}
	}
	fmt.Println()

	// ── Linked Chains ────────────────────────────────────────────────────────
	// Find root nodes: artifacts with links but not themselves linked-to.
	byID := make(map[string]*evidence.Artifact, len(all))
	for _, a := range all {
		byID[a.ID] = a
	}

	// LinkArtifacts is bidirectional, so every linked artifact appears in
	// every other's LinkedIDs — "not linked-to" finds nothing. Instead,
	// a root is an artifact whose kind rank is lower than all its neighbours.
	var roots []*evidence.Artifact
	for _, a := range all {
		if len(a.LinkedIDs) == 0 {
			continue
		}
		myRank := kindRank(a.Kind)
		isRoot := true
		for _, id := range a.LinkedIDs {
			if neighbour, ok := byID[id]; ok {
				if kindRank(neighbour.Kind) <= myRank {
					isRoot = false
					break
				}
			}
		}
		if isRoot {
			roots = append(roots, a)
		}
	}
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].PackageName < roots[j].PackageName
	})

	fmt.Printf("  Linked Chains (%d root nodes):\n", len(roots))
	if len(roots) == 0 {
		fmt.Println("    (none)")
	} else {
		for _, root := range roots {
			printChain(root, byID, 0, make(map[string]bool))
		}
	}

	fmt.Printf("═══════════════════════════════════════════════════════\n")
}

func printChain(a *evidence.Artifact, byID map[string]*evidence.Artifact, depth int, visited map[string]bool) {
	if visited[a.ID] {
		return
	}
	visited[a.ID] = true

	indent := strings.Repeat("  ", depth)
	iocFlag := ""
	if len(a.IOCMatches) > 0 {
		iocFlag = " *** IOC HIT ***"
	}
	identity := a.PackageName
	if a.PackageVersion != "" {
		identity += "@" + a.PackageVersion
	}
	fmt.Printf("    %s[%s] %s  (%s)%s\n",
		indent, a.Kind, identity, a.Source, iocFlag)

	// Only follow links to higher-rank kinds (forward in the causal chain).
	myRank := kindRank(a.Kind)
	for _, id := range a.LinkedIDs {
		if child, ok := byID[id]; ok && kindRank(child.Kind) > myRank {
			printChain(child, byID, depth+1, visited)
		}
	}
}

// ── Diagnostics ──────────────────────────────────────────────────────────────

// runDiagnostics probes the remote filesystem to show exactly what's present
// before the collectors run. Helps identify wrong paths or unexpected layouts.
func runDiagnostics(reader *sshconn.RemoteReader, home string) {
	fmt.Println("── Diagnostics ──────────────────────────────────────────────")

	probes := []struct {
		label string
		cmd   string
	}{
		{
			"package-lock.json files (maxdepth 6)",
			fmt.Sprintf("find %s -maxdepth 6 -name 'package-lock.json' 2>/dev/null", shellQ(home)),
		},
		{
			"yarn.lock files (maxdepth 6)",
			fmt.Sprintf("find %s -maxdepth 6 -name 'yarn.lock' 2>/dev/null", shellQ(home)),
		},
		{
			"_cacache directory listing",
			fmt.Sprintf("ls %s/.npm/_cacache/ 2>/dev/null", shellQ(home)),
		},
		{
			"index-v5 sample (first 5 entries)",
			fmt.Sprintf("find %s/.npm/_cacache/index-v5/ -type f 2>/dev/null | head -5", shellQ(home)),
		},
		{
			"npm cache location (npm config)",
			"npm config get cache 2>/dev/null",
		},
		{
			"home directory listing",
			fmt.Sprintf("ls %s/ 2>/dev/null", shellQ(home)),
		},
	}

	for _, p := range probes {
		out, err := reader.RunCommand(p.cmd)
		result := strings.TrimSpace(string(out))
		if err != nil || result == "" {
			result = "(empty or error)"
		}
		fmt.Printf("  %s:\n", p.label)
		for _, line := range strings.Split(result, "\n") {
			fmt.Printf("    %s\n", line)
		}
	}
	fmt.Println()
}

// shellQ is a local alias for single-quote escaping used in diagnostic commands.
func shellQ(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// ── Utilities ────────────────────────────────────────────────────────────────

func expandHome(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}

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
	case evidence.SeverityInfo:
		return 0
	case evidence.SeverityLow:
		return 1
	case evidence.SeverityMedium:
		return 2
	case evidence.SeverityHigh:
		return 3
	case evidence.SeverityCritical:
		return 4
	default:
		return -1
	}
}

func uniqueCampaigns(matches []evidence.IOCMatch) []string {
	seen := make(map[string]bool)
	var out []string
	for _, m := range matches {
		if !seen[m.Campaign] {
			seen[m.Campaign] = true
			out = append(out, m.Campaign)
		}
	}
	return out
}
