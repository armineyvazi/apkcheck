// Package htmlreport generates a self-contained interactive method browser.
package htmlreport

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"strings"

	"github.com/armin/apkcheck/pkg/model"
)

// WriteFile writes a self-contained HTML report with Smali|JADX|CFR|FernFlower browser.
func WriteFile(path string, r *model.AnalysisResult) error {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>APKCheck Method Browser</title>
<style>
:root {
  --bg: #0f1419; --panel: #1a2332; --text: #e7ecf3; --muted: #8b9bb4;
  --accent: #3d9cf0; --ok: #3dd68c; --warn: #f5a524; --bad: #f31260;
  --border: #2a3548; --mono: "JetBrains Mono","SF Mono",ui-monospace,monospace;
  --sans: "IBM Plex Sans","Segoe UI",sans-serif;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font-family: var(--sans); line-height: 1.5; }
header { padding: 1.5rem 2rem; background: linear-gradient(135deg,#132033,#0f1419 70%); border-bottom: 1px solid var(--border); }
header h1 { margin: 0; font-size: 1.5rem; }
header .meta { color: var(--muted); margin-top: .4rem; font-size: .9rem; }
.layout { display: grid; grid-template-columns: 340px 1fr; min-height: calc(100vh - 110px); }
nav { border-right: 1px solid var(--border); background: var(--panel); padding: 1rem; overflow: auto; max-height: calc(100vh - 110px); }
nav h2 { font-size: .7rem; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); margin: 1rem 0 .4rem; }
input[type=search] { width: 100%; background: #0b1017; border: 1px solid var(--border); color: var(--text); padding: .45rem .6rem; border-radius: 6px; }
.filters button, .findings button {
  display: block; width: 100%; text-align: left; margin: .25rem 0;
  background: transparent; border: 1px solid var(--border); color: var(--text);
  padding: .4rem .6rem; border-radius: 6px; cursor: pointer; font-size: .8rem;
}
.filters button.active, .filters button:hover, .findings button:hover { border-color: var(--accent); }
.method-list { list-style: none; padding: 0; margin: .5rem 0 0; }
.method-list li { padding: .45rem .35rem; border-bottom: 1px solid var(--border); cursor: pointer; font-size: .8rem; }
.method-list li:hover, .method-list li.active { background: #243044; }
.badge { display: inline-block; font-size: .65rem; padding: .1rem .3rem; border-radius: 4px; font-family: var(--mono); }
.badge.ok { background: #143528; color: var(--ok); }
.badge.warn { background: #3a2a12; color: var(--warn); }
.badge.bad { background: #3a1220; color: var(--bad); }
.badge.muted { background: #222833; color: var(--muted); }
main { padding: 1.2rem 1.5rem; overflow: auto; max-height: calc(100vh - 110px); }
.cards { display: grid; grid-template-columns: repeat(auto-fit,minmax(110px,1fr)); gap: .75rem; margin-bottom: 1rem; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: .8rem; }
.card .n { font-size: 1.4rem; font-weight: 600; }
.card .l { color: var(--muted); font-size: .75rem; }
.panes { display: grid; grid-template-columns: repeat(2,1fr); gap: .75rem; margin-top: 1rem; }
@media (min-width: 1400px) { .panes { grid-template-columns: repeat(4,1fr); } }
.pane { background: #0b1017; border: 1px solid var(--border); border-radius: 8px; min-height: 220px; display: flex; flex-direction: column; }
.pane h4 { margin: 0; padding: .5rem .7rem; border-bottom: 1px solid var(--border); font-size: .75rem; color: var(--accent); display: flex; justify-content: space-between; }
.pane pre { margin: 0; padding: .7rem; overflow: auto; flex: 1; font-family: var(--mono); font-size: .72rem; white-space: pre-wrap; }
.issue { margin: .35rem 0; padding: .45rem .6rem; border-left: 3px solid var(--warn); background: #1b2230; font-size: .85rem; }
.tabs { display: flex; gap: .4rem; flex-wrap: wrap; margin: .8rem 0; }
.tabs button { background: var(--panel); border: 1px solid var(--border); color: var(--text); padding: .3rem .65rem; border-radius: 6px; cursor: pointer; }
.tabs button.active { border-color: var(--accent); color: var(--accent); }
.diff-hl { background: #3a2a12; }
footer { color: var(--muted); font-size: .75rem; margin-top: 1.5rem; }
@media (max-width: 900px) { .layout { grid-template-columns: 1fr; } .panes { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<header>
  <h1>APKCheck — Method Browser</h1>
  <div class="meta">`)
	fmt.Fprintf(&b, `v%s · schema %s · %s`,
		html.EscapeString(r.ToolVersion), html.EscapeString(r.SchemaVersion),
		html.EscapeString(r.GeneratedAt.Format("2006-01-02 15:04:05 UTC")))
	b.WriteString(`</div>
  <div class="meta">`)
	fmt.Fprintf(&b, `%s · SHA-256 %s`, html.EscapeString(r.APK.Path), html.EscapeString(truncate(r.APK.SHA256, 16)))
	if r.APK.Package != "" {
		fmt.Fprintf(&b, ` · %s %s`, html.EscapeString(r.APK.Package), html.EscapeString(r.APK.VersionName))
	}
	b.WriteString(`</div>
  <div class="meta">DEX/Smali = ground truth · Decompilers = reconstructions · Runtime = partial observation</div>
</header>
<div class="layout">
<nav>
  <input type="search" id="search" placeholder="Search class/method…" />
  <h2>Filters</h2>
  <div class="filters">
    <button class="active" data-filter="all">All</button>
    <button data-filter="DISAGREEMENT" id="btnDisagg">Show Disagreements</button>
    <button data-filter="security">Security-sensitive</button>
    <button data-filter="native">Native bridge</button>
    <button data-filter="semantic_low">Low semantic confidence</button>
    <button data-filter="CONSISTENT">Consistent</button>
    <button data-filter="PARTIALLY_CONSISTENT">Partial</button>
  </div>
  <h2>Findings</h2>
  <div class="findings" id="findings">`)
	for i, f := range r.Findings {
		if i >= 80 {
			break
		}
		fmt.Fprintf(&b, `<button data-finding="%d" title="%s">[%s] %s</button>`,
			i, html.EscapeString(f.Summary), html.EscapeString(string(f.Severity)),
			html.EscapeString(truncate(f.Title, 42)))
	}
	b.WriteString(`</div>
  <h2>Methods</h2>
  <ul class="method-list" id="methodList">
`)
	for i, m := range r.Methods {
		cls := badgeClass(m.Status)
		attrs := fmt.Sprintf(`data-idx="%d" data-status="%s"`, i, m.Status)
		if m.SecurityRelevant {
			attrs += ` data-sec="1"`
		}
		if m.NativeBridge {
			attrs += ` data-native="1"`
		}
		if m.SemanticConfidence == model.SemanticLow || m.SemanticConfidence == model.SemanticUncertain {
			attrs += ` data-semlow="1"`
		}
		fmt.Fprintf(&b, `<li %s><span class="badge %s">%s</span> %s</li>`,
			attrs, cls, html.EscapeString(string(m.Status)),
			html.EscapeString(truncate(m.Ref.Class+"."+m.Ref.Name, 46)))
		b.WriteByte('\n')
	}
	b.WriteString(`</ul>
</nav>
<main>
  <div class="cards">
`)
	b.WriteString(card("Analyzed", r.Summary.MethodsAnalyzed))
	b.WriteString(card("Consistent", r.Summary.MethodsConsistent))
	b.WriteString(card("Disagreement", r.Summary.MethodsDisagreement))
	b.WriteString(card("Findings", len(r.Findings)))
	b.WriteString(card("Native libs", len(r.Native)))
	b.WriteString(card("JNI maps", len(r.JNI)))
	b.WriteString(`</div>
  <section id="detail"><p style="color:var(--muted)">Select a method or finding.</p></section>
  <footer>
    <p>Never present INFERENCE as fact. NOT OBSERVED ≠ ABSENT. AI reasons over evidence — AI is not ground truth.</p>
  </footer>
</main>
</div>
<script>
const methods = `)
	payload := make([]map[string]any, 0, len(r.Methods))
	for _, m := range r.Methods {
		payload = append(payload, map[string]any{
			"ref": m.Ref, "status": m.Status, "verdict": m.Verdict,
			"security": m.SecurityRelevant, "tags": m.SecurityTags,
			"smali": m.Smali, "decompilers": m.Decompilers, "issues": m.Issues,
			"semantic": m.SemanticConfidence, "semantic_note": m.SemanticNote,
			"native": m.NativeBridge,
		})
	}
	enc, err := encodeJSON(payload)
	if err != nil {
		return err
	}
	b.WriteString(enc)
	b.WriteString(`;
const findings = `)
	fenc, err := encodeJSON(r.Findings)
	if err != nil {
		return err
	}
	b.WriteString(fenc)
	b.WriteString(`;
function badge(st) {
  if (st === 'CONSISTENT' || st === 'HIGH') return 'ok';
  if (st === 'DISAGREEMENT' || st === 'LOW' || st === 'critical' || st === 'high') return 'bad';
  if (st === 'PARTIALLY_CONSISTENT' || st === 'MEDIUM') return 'warn';
  return 'muted';
}
function escapeHtml(s) {
  return String(s||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function pane(title, status, body) {
  return '<div class="pane"><h4><span>'+escapeHtml(title)+'</span><span class="badge '+badge(status)+'">'+escapeHtml(status||'')+'</span></h4><pre>'+escapeHtml(body)+'</pre></div>';
}
function render(i) {
  const m = methods[i];
  if (!m) return;
  let html = '<h2>'+escapeHtml(m.ref.class+'.'+m.ref.method)+'</h2>';
  html += '<p><span class="badge '+badge(m.status)+'">'+m.status+'</span>';
  if (m.semantic) html += ' <span class="badge '+badge(m.semantic)+'">SEMANTIC_CONFIDENCE: '+m.semantic+'</span>';
  if (m.security) html += ' <span class="badge warn">security</span>';
  if (m.native) html += ' <span class="badge bad">native bridge</span>';
  html += '</p><p>'+escapeHtml(m.verdict||'')+'</p>';
  if (m.semantic_note) html += '<p style="color:var(--muted)">'+escapeHtml(m.semantic_note)+'</p>';
  if (m.tags && m.tags.length) html += '<p>Tags: '+m.tags.map(t=>'<code>'+escapeHtml(t)+'</code>').join(' ')+'</p>';

  let smaliBody = 'SOURCE OF TRUTH\n';
  if (m.smali) {
    smaliBody += 'instructions: '+m.smali.instructions+'\nbasic_blocks: '+m.smali.basic_blocks+
      '\nbranches: '+m.smali.branches+'\ncalls: '+m.smali.calls+
      '\nreturns: '+m.smali.returns+'\nexceptions: '+m.smali.exceptions;
  }
  (m.issues||[]).forEach(iss => {
    smaliBody += '\n• ['+iss.severity+'] '+iss.message;
    if (iss.evidence) smaliBody += '\n  '+iss.evidence;
  });

  const dec = m.decompilers || {};
  const order = ['jadx','cfr','fernflower'];
  html += '<div class="panes">';
  html += pane('Smali / DEX', 'SOURCE_OF_TRUTH', smaliBody);
  order.forEach(name => {
    const d = dec[name] || {status:'UNRESOLVED', note:'not run', issues:[]};
    let body = (d.note||'')+'\nstatus: '+(d.status||'');
    if (d.source_path) body += '\npath: '+d.source_path;
    (d.issues||[]).forEach(iss => {
      body += '\n• ['+iss.severity+'] '+iss.message;
      if (iss.evidence) body += '\n  '+iss.evidence;
    });
    html += pane(name.toUpperCase(), d.status||'', body);
  });
  html += '</div>';
  html += '<p style="color:var(--muted);font-size:.85rem;margin-top:1rem">Syntactically valid reconstruction ≠ behaviorally equivalent reconstruction.</p>';
  document.getElementById('detail').innerHTML = html;
  document.querySelectorAll('.method-list li').forEach(el => el.classList.remove('active'));
  const li = document.querySelector('.method-list li[data-idx="'+i+'"]');
  if (li) { li.classList.add('active'); li.scrollIntoView({block:'nearest'}); }
}
function renderFinding(i) {
  const f = findings[i];
  if (!f) return;
  let html = '<h2>'+escapeHtml(f.id)+' — '+escapeHtml(f.title)+'</h2>';
  html += '<p><span class="badge '+badge(f.severity)+'">'+f.severity+'</span> ';
  html += '<span class="badge muted">'+escapeHtml(f.evidence_class)+'</span> ';
  html += '<span class="badge muted">'+escapeHtml(f.confidence)+'</span></p>';
  html += '<p><strong>Summary:</strong> '+escapeHtml(f.summary)+'</p>';
  html += '<p><strong>Why:</strong> '+escapeHtml(f.why)+'</p>';
  html += '<h3>Evidence</h3>';
  (f.evidence||[]).forEach(e => {
    html += '<div class="issue">class=<code>'+escapeHtml(e.class||'')+'</code> method=<code>'+escapeHtml(e.method||'')+
      '</code><br/>smali=<code>'+escapeHtml(e.smali_instruction||'')+'</code><br/>manifest=<code>'+escapeHtml(e.manifest_entry||'')+'</code></div>';
  });
  if (f.manual_check) html += '<p class="badge warn">manual check required — may be INFERENCE</p>';
  // Navigate to related method if possible
  const rel = (f.related_method_keys||[])[0] || '';
  const idx = methods.findIndex(m => (m.ref.class+'->'+m.ref.method) === rel ||
    (m.ref.class === ((f.evidence||[])[0]||{}).class && m.ref.method === ((f.evidence||[])[0]||{}).method));
  if (idx >= 0) {
    html += '<div class="tabs"><button onclick="render('+idx+')">Open related method</button></div>';
  }
  document.getElementById('detail').innerHTML = html;
}
document.getElementById('methodList').addEventListener('click', e => {
  const li = e.target.closest('li'); if (!li) return; render(li.dataset.idx);
});
document.getElementById('findings').addEventListener('click', e => {
  const btn = e.target.closest('button[data-finding]'); if (!btn) return; renderFinding(btn.dataset.finding);
});
function applyFilter(f, q) {
  document.querySelectorAll('.method-list li').forEach(li => {
    let show = true;
    if (f === 'security') show = li.dataset.sec === '1';
    else if (f === 'native') show = li.dataset.native === '1';
    else if (f === 'semantic_low') show = li.dataset.semlow === '1';
    else if (f !== 'all') show = li.dataset.status === f;
    if (q) {
      const t = li.textContent.toLowerCase();
      if (!t.includes(q)) show = false;
    }
    li.style.display = show ? '' : 'none';
  });
}
let curFilter = 'all';
document.querySelectorAll('.filters button').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filters button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    curFilter = btn.dataset.filter;
    applyFilter(curFilter, document.getElementById('search').value.trim().toLowerCase());
    if (curFilter === 'DISAGREEMENT') {
      const first = document.querySelector('.method-list li[data-status="DISAGREEMENT"]');
      if (first && first.style.display !== 'none') render(first.dataset.idx);
    }
  });
});
document.getElementById('search').addEventListener('input', e => {
  applyFilter(curFilter, e.target.value.trim().toLowerCase());
});
if (methods.length) render(0);
</script>
</body></html>`)
	return os.WriteFile(path, []byte(b.String()), 0o640)
}

func card(label string, n int) string {
	return fmt.Sprintf(`<div class="card"><div class="n">%d</div><div class="l">%s</div></div>`, n, html.EscapeString(label))
}

func badgeClass(c model.Confidence) string {
	switch c {
	case model.ConfidenceConsistent:
		return "ok"
	case model.ConfidenceDisagreement:
		return "bad"
	case model.ConfidencePartiallyConsistent:
		return "warn"
	default:
		return "muted"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func encodeJSON(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
