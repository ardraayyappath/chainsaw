package report

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ardraayyappath/chainsaw/internal/evidence"
)

// WriteHTML renders report.html into outputDir.
func WriteHTML(data *ReportData, outputDir string) error {
	t, err := template.New("report").Funcs(templateFuncs()).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse HTML template: %w", err)
	}
	out := filepath.Join(outputDir, "report.html")
	f, err := os.Create(out)
	if err != nil {
		return fmt.Errorf("create %q: %w", out, err)
	}
	defer f.Close()
	if err := t.ExecuteTemplate(f, "main", data); err != nil {
		return fmt.Errorf("render HTML: %w", err)
	}
	return nil
}

// --------------------------------------------------------------------------
// Template functions
// --------------------------------------------------------------------------

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"severityClass": func(sev evidence.Severity) string {
			switch sev {
			case evidence.SeverityCritical:
				return "critical"
			case evidence.SeverityHigh:
				return "high"
			case evidence.SeverityMedium:
				return "medium"
			default:
				return "info"
			}
		},
		"upper": strings.ToUpper,
		"pillClass": func(indicatorType string) string {
			switch indicatorType {
			case "package":
				return "pill-package"
			case "domain":
				return "pill-domain"
			case "ua":
				return "pill-ua"
			case "pth":
				return "pill-pth"
			case "path":
				return "pill-path"
			case "email":
				return "pill-email"
			default:
				return "pill-other"
			}
		},
		// pillLabel returns a short display string for an IOC match pill.
		// MatchedValue is the full string that triggered the hit (may be an
		// entire shell command line for MatchContent hits). When it's short
		// enough, show it directly; otherwise derive a label from the indicator ID.
		"pillLabel": func(m evidence.IOCMatch) template.HTML {
			if m.IndicatorType == "ua" {
				return "UA"
			}
			if len(m.MatchedValue) <= 40 {
				return safeIdent(m.MatchedValue)
			}
			// Long content match — derive from the indicator ID.
			// Convention: <campaign>-<type>-<name…>  →  take the name portion.
			parts := strings.Split(m.IndicatorID, "-")
			if len(parts) >= 3 {
				return safeIdent(strings.Join(parts[2:], "-"))
			}
			return template.HTML(m.IndicatorType)
		},
		"formatTime": func(t time.Time) string {
			return t.UTC().Format("2006-01-02 15:04:05 UTC")
		},
		"formatTimePtr": func(t *time.Time) string {
			if t == nil {
				return "—"
			}
			return t.UTC().Format("2006-01-02 15:04:05 UTC")
		},
		"formatDuration": func(d time.Duration) string {
			if d < time.Second {
				return fmt.Sprintf("%dms", d.Milliseconds())
			}
			if d < time.Minute {
				return fmt.Sprintf("%.1fs", d.Seconds())
			}
			return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
		},
		"artifactIdentity": func(a *evidence.Artifact) template.HTML {
			return safeIdent(ArtifactIdentity(a))
		},
		"safeIdent": func(s string) template.HTML {
			return safeIdent(s)
		},
		// string converts any fmt.Stringer or underlying string type to string,
		// needed because Go templates don't support type conversions directly.
		"string": func(v interface{}) string {
			switch t := v.(type) {
			case evidence.Severity:
				return string(t)
			case evidence.ArtifactKind:
				return string(t)
			case evidence.Ecosystem:
				return string(t)
			case fmt.Stringer:
				return t.String()
			default:
				return fmt.Sprintf("%v", v)
			}
		},
		// truncate clips s to n runes, appending "…" if clipped.
		"truncate": func(s string, n int) string {
			r := []rune(s)
			if len(r) <= n {
				return s
			}
			return string(r[:n-1]) + "…"
		},
	}
}

// safeIdent HTML-escapes s and then replaces "@" with "&#64;" so that
// Cloudflare's email-obfuscation proxy does not mangle package specifiers
// like "axios@1.14.1" into "[email protected]".
// Returning template.HTML tells html/template the value is already safe and
// must not be double-escaped.
func safeIdent(s string) template.HTML {
	escaped := template.HTMLEscapeString(s)
	return template.HTML(strings.ReplaceAll(escaped, "@", "&#64;"))
}

// --------------------------------------------------------------------------
// HTML template
// --------------------------------------------------------------------------

var htmlTemplate = `
{{define "main"}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CHAINSAW // {{.Meta.Target}}</title>
<style>
:root {
  --bg:       #0d1117;
  --bg2:      #161b22;
  --bg3:      #21262d;
  --border:   #30363d;
  --text:     #e6edf3;
  --muted:    #8b949e;
  --link:     #58a6ff;
  --critical: #da3633;
  --crit-bg:  rgba(218,54,51,.15);
  --high:     #d29922;
  --high-bg:  rgba(210,153,34,.15);
  --medium:   #388bfd;
  --med-bg:   rgba(56,139,253,.15);
  --info:     #6e7681;
  --info-bg:  rgba(110,118,129,.15);
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;font-size:14px;line-height:1.6}
.mono{font-family:ui-monospace,SFMono-Regular,"SF Mono",Consolas,"Liberation Mono",Menlo,monospace;font-size:13px}

/* ── Header ── */
.hdr{background:var(--bg2);border-bottom:1px solid var(--border);padding:10px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.hdr-brand{font-family:ui-monospace,monospace;font-size:17px;font-weight:700;letter-spacing:.15em;color:var(--text)}
.hdr-brand span{color:var(--critical)}
.hdr-meta{color:var(--muted);font-size:12px;font-family:ui-monospace,monospace}
.hdr-sep{margin:0 8px;opacity:.4}

/* ── Summary strip ── */
.strip{display:grid;grid-template-columns:repeat(4,1fr);background:var(--border);border-bottom:1px solid var(--border)}
.strip-box{background:var(--bg2);padding:18px 24px;text-align:center}
.strip-val{font-size:30px;font-weight:700;font-family:ui-monospace,monospace;line-height:1}
.strip-val.c{color:var(--critical)}
.strip-lbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;margin-top:5px}

/* ── Layout ── */
.container{max-width:1180px;margin:0 auto;padding:32px 24px}
.section{margin-bottom:40px}
.sec-title{font-size:15px;font-weight:600;color:var(--text);padding-bottom:8px;border-bottom:1px solid var(--border);margin-bottom:16px;display:flex;align-items:center;gap:8px}

/* ── Campaign cards ── */
.camp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:16px}
.camp-card{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:16px 20px}
.camp-id{font-family:ui-monospace,monospace;font-size:14px;font-weight:600;margin-bottom:5px}
.camp-desc{font-size:12px;color:var(--muted);margin-bottom:12px;line-height:1.5}
.kind-chips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px}
.kind-chip{background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:2px 8px;font-family:ui-monospace,monospace;font-size:12px;color:var(--text)}
.conf-bar{height:4px;background:var(--bg3);border-radius:2px;overflow:hidden;margin-bottom:5px}
.conf-fill{height:100%;background:linear-gradient(90deg,#1f6feb,#da3633);border-radius:2px}
.conf-lbl{font-size:11px;color:var(--muted)}

/* ── Severity badges ── */
.badge{display:inline-block;padding:2px 7px;border-radius:4px;font-family:ui-monospace,monospace;font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;white-space:nowrap}
.badge.critical{background:var(--crit-bg);color:var(--critical);border:1px solid var(--critical)}
.badge.high    {background:var(--high-bg);color:var(--high);border:1px solid var(--high)}
.badge.medium  {background:var(--med-bg);color:var(--medium);border:1px solid var(--medium)}
.badge.info    {background:var(--info-bg);color:var(--info);border:1px solid var(--info)}

/* ── Kind tags ── */
.ktag{display:inline-block;background:var(--bg3);border:1px solid var(--border);border-radius:3px;padding:1px 6px;font-family:ui-monospace,monospace;font-size:11px;color:var(--muted);white-space:nowrap}

/* ── IOC pills ── */
.pill{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;font-family:ui-monospace,monospace;margin:1px 2px;white-space:nowrap}
.pill-package{background:rgba(137,87,229,.2);color:#d2a8ff;border:1px solid #8957e5}
.pill-domain {background:rgba(63,185,80,.2); color:#7ee787;border:1px solid #3fb950}
.pill-ua     {background:rgba(210,153,34,.2);color:#e3b341;border:1px solid #d29922}
.pill-pth    {background:rgba(247,120,186,.2);color:#f778ba;border:1px solid #db61a2}
.pill-path   {background:rgba(61,201,176,.2);color:#56d364;border:1px solid #3dc9b0}
.pill-email  {background:rgba(56,139,253,.2);color:#79c0ff;border:1px solid #388bfd}
.pill-other  {background:var(--bg3);color:var(--muted);border:1px solid var(--border)}

/* ── Chain tree ── */
.chain-root{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:16px;margin-bottom:16px}
.chain-node{margin:4px 0}
.node-wrap{background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:8px 12px;display:inline-block;max-width:100%}
.node-wrap.critical{border-left:3px solid var(--critical)}
.node-wrap.high    {border-left:3px solid var(--high)}
.node-wrap.medium  {border-left:3px solid var(--medium)}
.node-hdr{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.node-name{font-weight:600;color:var(--text)}
.node-src{color:var(--muted);font-size:12px}
.node-ioc{margin-top:5px;font-size:12px;color:var(--muted)}
.ioc-label{font-family:ui-monospace,monospace;margin-right:4px}
.chain-children{margin-left:20px;padding-left:16px;border-left:2px solid var(--border);margin-top:8px}
.chain-children>.chain-node{position:relative;padding-left:16px}
.chain-children>.chain-node::before{content:'';position:absolute;left:-2px;top:16px;width:18px;height:2px;background:var(--border)}

/* ── Unlinked artifact rows ── */
.urow{background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:10px 14px;margin-bottom:8px}
.urow-hdr{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px}
.urow-path{font-size:12px;color:var(--muted);margin-top:3px}

/* ── Collapsible sections ── */
.col-hdr{cursor:pointer;display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border);margin-bottom:0;user-select:none}
.col-hdr:hover .sec-title{color:var(--link)}
.tog{color:var(--muted);font-size:11px;transition:transform .2s;flex-shrink:0}
.col-body{padding-top:16px}
.cnt-badge{background:var(--bg3);border:1px solid var(--border);border-radius:10px;padding:1px 8px;font-size:12px;font-weight:500;color:var(--muted)}

/* ── Artifact table ── */
table{width:100%;border-collapse:collapse;font-size:13px}
thead{position:sticky;top:45px;z-index:10}
th{background:var(--bg3);color:var(--muted);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;padding:8px 12px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap}
th.sort{cursor:pointer}
th.sort:hover{color:var(--text)}
th.sort::after{content:' \21D5';color:var(--border)}
td{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:top}
tr:hover td{background:var(--bg2)}
.td-path{max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted);font-size:12px}
.muted{color:var(--muted)}
</style>
</head>
<body>

<!-- ── Header ─────────────────────────────────────────────────────────── -->
<header class="hdr">
  <div class="hdr-brand"><span>⬡</span> CHAINSAW</div>
  <div class="hdr-meta">
    {{.Meta.Target}}<span class="hdr-sep">·</span>{{formatTime .Meta.CollectedAt}}<span class="hdr-sep">·</span>v{{.Meta.Version}}
  </div>
</header>

<!-- ── Summary strip ──────────────────────────────────────────────────── -->
<div class="strip">
  <div class="strip-box">
    <div class="strip-val">{{.TotalArtifacts}}</div>
    <div class="strip-lbl">Total Artifacts</div>
  </div>
  <div class="strip-box">
    <div class="strip-val c">{{.CampaignCount}}</div>
    <div class="strip-lbl">Campaigns Detected</div>
  </div>
  <div class="strip-box">
    <div class="strip-val c">{{.CriticalCount}}</div>
    <div class="strip-lbl">Critical Hits</div>
  </div>
  <div class="strip-box">
    <div class="strip-val">{{formatDuration .Meta.Duration}}</div>
    <div class="strip-lbl">Collection Duration</div>
  </div>
</div>

<main class="container">

<!-- ── Campaign cards ─────────────────────────────────────────────────── -->
<section class="section">
  <h2 class="sec-title">Campaign Corroboration</h2>
  <div class="camp-grid">
    {{range .Campaigns}}
    <div class="camp-card">
      <div class="camp-id mono">{{.ID}}</div>
      <div class="camp-desc">{{truncate .Description 160}}</div>
      <div class="kind-chips">
        {{range .KindList}}<span class="kind-chip">{{.Kind}} ×{{.Count}}</span>{{end}}
      </div>
      <div class="conf-bar"><div class="conf-fill" style="width:{{.ConfidencePct}}%"></div></div>
      <div class="conf-lbl">{{len .KindList}} artifact kind{{if gt (len .KindList) 1}}s{{end}} corroborate &nbsp;·&nbsp; {{.TotalArtifacts}} total hits</div>
    </div>
    {{end}}
  </div>
</section>

<!-- ── Evidence chains ────────────────────────────────────────────────── -->
<section class="section">
  <h2 class="sec-title">Evidence Chains <span class="cnt-badge">{{len .Chains}}</span></h2>
  {{if .Chains}}
    {{range .Chains}}
    <div class="chain-root">{{template "chainNode" .}}</div>
    {{end}}
  {{else}}
    <p class="muted">No linked evidence chains detected.</p>
  {{end}}
</section>

<!-- ── Unlinked IOC hits ──────────────────────────────────────────────── -->
<section class="section">
  <div class="col-hdr" onclick="toggle('unlinked','tog-unlinked')">
    <h2 class="sec-title">Unlinked IOC Hits <span class="cnt-badge">{{len .Unlinked}}</span></h2>
    <span class="tog" id="tog-unlinked">&#9654;</span>
  </div>
  <div class="col-body" id="unlinked" style="display:none">
    {{if .Unlinked}}
      {{range .Unlinked}}
      <div class="urow">
        <div class="urow-hdr">
          <span class="badge {{severityClass .Severity}}">{{upper (string .Severity)}}</span>
          <span class="ktag">{{.Kind}}</span>
          <span class="mono node-name">{{artifactIdentity .}}</span>
          <span class="muted" style="font-size:12px">({{.Source}})</span>
        </div>
        <div>{{range .IOCMatches}}<span class="pill {{pillClass .IndicatorType}}">{{pillLabel .}}</span>{{end}}</div>
        <div class="urow-path mono">{{.Path}}</div>
      </div>
      {{end}}
    {{else}}
      <p class="muted">None.</p>
    {{end}}
  </div>
</section>

<!-- ── Full artifact inventory ────────────────────────────────────────── -->
<section class="section">
  <div class="col-hdr" onclick="toggle('inventory','tog-inv')">
    <h2 class="sec-title">Artifact Inventory <span class="cnt-badge">{{.TotalArtifacts}}</span></h2>
    <span class="tog" id="tog-inv">&#9654;</span>
  </div>
  <div class="col-body" id="inventory" style="display:none">
    <table id="tbl">
      <thead><tr>
        <th class="sort" data-col="0">Severity</th>
        <th class="sort" data-col="1">Kind</th>
        <th class="sort" data-col="2">Ecosystem</th>
        <th class="sort" data-col="3">Identity</th>
        <th class="sort" data-col="4">Source</th>
        <th class="sort" data-col="5">Timestamp</th>
        <th>IOC Matches</th>
        <th>Path</th>
      </tr></thead>
      <tbody>
        {{range .All}}
        <tr>
          <td><span class="badge {{severityClass .Severity}}">{{upper (string .Severity)}}</span></td>
          <td><span class="ktag">{{.Kind}}</span></td>
          <td class="muted">{{.Ecosystem}}</td>
          <td class="mono">{{artifactIdentity .}}</td>
          <td class="muted" style="font-size:12px">{{.Source}}</td>
          <td class="mono muted" style="font-size:12px">{{formatTimePtr .Timestamp}}</td>
          <td>{{range .IOCMatches}}<span class="pill {{pillClass .IndicatorType}}">{{pillLabel .}}</span>{{end}}</td>
          <td class="td-path mono">{{.Path}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>
</section>

</main>

<script>
(function(){
  // Collapsible sections
  function toggle(bodyID, togID) {
    var body = document.getElementById(bodyID);
    var tog  = document.getElementById(togID);
    if (body.style.display === 'none') {
      body.style.display = '';
      tog.innerHTML = '&#9660;';
    } else {
      body.style.display = 'none';
      tog.innerHTML = '&#9654;';
    }
  }
  window.toggle = toggle;

  // Sortable table
  document.querySelectorAll('th[data-col]').forEach(function(th){
    th.addEventListener('click', function(){
      var col  = parseInt(th.getAttribute('data-col'));
      var asc  = th.getAttribute('data-asc') !== '1';
      document.querySelectorAll('th[data-col]').forEach(function(h){
        h.removeAttribute('data-asc');
      });
      th.setAttribute('data-asc', asc ? '1' : '0');
      var tbody = document.querySelector('#tbl tbody');
      var rows  = Array.from(tbody.querySelectorAll('tr'));
      rows.sort(function(a, b){
        var av = a.cells[col].textContent.trim();
        var bv = b.cells[col].textContent.trim();
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
      });
      rows.forEach(function(r){ tbody.appendChild(r); });
    });
  });
})();
</script>
</body>
</html>
{{end}}

{{define "chainNode"}}
<div class="chain-node">
  <div class="node-wrap {{severityClass .Artifact.Severity}}">
    <div class="node-hdr">
      <span class="badge {{severityClass .Artifact.Severity}}">{{upper (string .Artifact.Severity)}}</span>
      <span class="ktag">{{.Artifact.Kind}}</span>
      <span class="node-name mono">{{safeIdent .Identity}}</span>
      <span class="node-src">({{.Artifact.Source}})</span>
    </div>
    {{if .Artifact.IOCMatches}}
    <div class="node-ioc">
      <span class="ioc-label">IOC:</span>{{range .Artifact.IOCMatches}}<span class="pill {{pillClass .IndicatorType}}">{{pillLabel .}}</span>{{end}}
    </div>
    {{end}}
  </div>
  {{if .Children}}
  <div class="chain-children">
    {{range .Children}}{{template "chainNode" .}}{{end}}
  </div>
  {{end}}
</div>
{{end}}
`
