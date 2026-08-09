"""HTML report.

A second, equally first-class output format alongside the PDF. It renders from
exactly the same ``ScanContext`` the PDF renderer consumes — the data-gathering
step is not forked, only the rendering — and it follows the same reading order
(cover -> executive summary -> category scores -> technology -> attack surface
-> remediation order -> findings by severity/type -> detailed findings ->
checks passed -> appendices).

Being HTML, it adds what the page format is good at: a single self-contained
file (inline CSS/JS, no external assets), a summary dashboard, and detailed
findings that can be collapsed, filtered by severity/confidence/type and
free-text searched. A ``@media print`` stylesheet keeps it printable, so a user
can still save-to-PDF from the browser.
"""

from __future__ import annotations

import datetime
import html
import json
from collections import Counter, defaultdict

from ..core.correlate import summarize
from ..core.knowledge import GROUP_ORDER
from ..core.models import (CONFIDENCE_HEX, SCORE_AREAS, SEVERITY_HEX,
                           Confidence, FindingType, Severity)
from ..core.scoring import weakest_areas

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
              Severity.LOW, Severity.INFO]

_TYPE_ORDER = [FindingType.CONFIRMED_VULN, FindingType.POTENTIAL_VULN,
               FindingType.MISCONFIGURATION, FindingType.EXPOSURE,
               FindingType.INVENTORY, FindingType.INFORMATIONAL]

_CONF_ORDER = [Confidence.CONFIRMED, Confidence.HIGH, Confidence.MEDIUM,
               Confidence.LOW, Confidence.INFORMATIONAL]

_GRADE_HEX = {"A": "#15803d", "B": "#65a30d", "C": "#ca8a04",
              "D": "#ea580c", "F": "#b91c1c", "—": "#94a3b8"}


def default_report_name(target: str) -> str:
    host = target.replace("https://", "").replace("http://", "").strip("/")
    host = host.replace("/", "_").replace(":", "_")
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"lopata_report_{host}_{ts}.html"


def generate_html_report(ctx, path: str, meta: dict) -> None:
    findings = list(ctx.findings)
    scores = ctx.scores or {}

    # stamp a stable index on each finding so the remediation table can link it
    _stamp_indices(findings)

    parts: list[str] = []
    parts.append(_head(ctx))
    parts.append('<body><main class="page">')
    _cover(parts, ctx, findings, meta, scores)
    _executive_summary(parts, ctx, findings, scores)
    _score_section(parts, scores)
    _technology_section(parts, ctx)
    _attack_surface_section(parts, ctx)
    _priorities(parts, findings)
    _findings_overview(parts, findings)
    _details(parts, findings)
    _passed_checks(parts, ctx)
    _appendix(parts, ctx, meta)
    parts.append("</main>")
    parts.append(_script())
    parts.append("</body></html>")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(parts))



def _esc(text) -> str:
    return html.escape(str(text if text is not None else ""))


def _multiline(text) -> str:
    return _esc(text).replace("\n", "<br/>")


def _sev_badge(sev: Severity) -> str:
    return (f'<span class="badge" style="background:{SEVERITY_HEX[sev]}">'
            f'{_esc(sev.label)}</span>')


def _conf_badge(conf: Confidence) -> str:
    return (f'<span class="pill" style="color:{CONFIDENCE_HEX[conf]};'
            f'border-color:{CONFIDENCE_HEX[conf]}">{_esc(conf.label)} confidence'
            "</span>")


def _finding_slug(index: int) -> str:
    return f"finding-{index}"



def _head(ctx) -> str:
    title = f"lopata assessment — {ctx.target}"
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{_esc(title)}</title><style>{_CSS}</style></head>"
    )


_CSS = """
:root{
  --ink:#0f172a; --muted:#64748b; --rule:#e2e8f0; --panel:#f8fafc;
  --bg:#ffffff; --accent:#0f172a; --mono:#f1f5f9;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:#eef2f6;color:var(--ink);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
.page{max-width:1040px;margin:0 auto;background:var(--bg);
  padding:40px 48px 80px;box-shadow:0 1px 3px rgba(15,23,42,.12);}
h1{font-size:15px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);
  margin:44px 0 14px;font-weight:700;border-bottom:1px solid var(--rule);padding-bottom:6px;}
h2{font-size:18px;margin:26px 0 10px;color:var(--ink);}
h3{font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);
  margin:16px 0 4px;font-weight:700;}
a{color:#2563eb;text-decoration:none}
a:hover{text-decoration:underline}
p{margin:8px 0}
.title{font-size:30px;font-weight:800;margin:0}
.subtitle{color:var(--muted);font-size:16px;margin:2px 0 0}
.hr{height:1px;background:#cbd5e1;margin:14px 0}
.small{font-size:12.5px;color:#475569}
.muted{color:var(--muted)}

.cover{display:flex;gap:24px;align-items:stretch;flex-wrap:wrap;margin-top:14px}
.cover .meta{flex:1 1 460px}
.cover table.kv{width:100%;border-collapse:collapse}
.cover table.kv td{padding:5px 6px;border-bottom:1px solid var(--rule);
  vertical-align:top;font-size:13px}
.cover table.kv td.k{width:120px;font-weight:700;color:#334155}
.scorecard{flex:0 0 200px;background:var(--panel);border:1px solid var(--rule);
  border-radius:10px;display:flex;flex-direction:column;align-items:center;
  justify-content:center;padding:18px;text-align:center}
.scorecard .num{font-size:52px;font-weight:800;line-height:1}
.scorecard .den{font-size:15px;color:#94a3b8}
.scorecard .grade{margin-top:6px;font-size:13px;color:#64748b}

.sevbar{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin:16px 0}
.sevbar .cell{background:var(--panel);border:1px solid var(--rule);border-radius:8px;
  padding:10px;text-align:center}
.sevbar .cell .n{font-size:26px;font-weight:800;line-height:1}
.sevbar .cell .l{font-size:11px;text-transform:uppercase;letter-spacing:.05em;
  color:var(--muted);margin-top:4px}

table.data{width:100%;border-collapse:collapse;margin:10px 0;font-size:13px}
table.data th{background:var(--ink);color:#fff;text-align:left;padding:7px 9px;
  font-weight:600;position:relative}
table.data td{padding:6px 9px;border:1px solid var(--rule);vertical-align:top}
table.data tbody tr:nth-child(even){background:var(--panel)}
table.data.sortable th{cursor:pointer;user-select:none}
table.data.sortable th::after{content:"\\2195";opacity:.35;margin-left:6px;font-size:10px}

.badge{display:inline-block;color:#fff;border-radius:5px;padding:1px 8px;
  font-size:11px;font-weight:700;letter-spacing:.02em}
.pill{display:inline-block;border:1px solid;border-radius:20px;padding:0 9px;
  font-size:11px;font-weight:600}
.tag{display:inline-block;background:var(--panel);border:1px solid var(--rule);
  border-radius:5px;padding:0 7px;font-size:11px;color:#475569;margin:0 2px 2px 0}

.meter{height:9px;border-radius:5px;background:#e5edf5;overflow:hidden;min-width:120px}
.meter>span{display:block;height:100%}

.summary-tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));
  gap:10px;margin:14px 0}
.incomplete-banner{background:#fef3c7;border:1px solid #f59e0b;
  border-left:5px solid #f59e0b;border-radius:8px;padding:12px 14px;
  margin:14px 0;color:#78350f;font-size:13px}
.coverage-flag{display:inline-block;background:#fef3c7;color:#78350f;
  border:1px solid #f59e0b;border-radius:6px;padding:1px 6px;font-size:11px;
  font-weight:700;margin-left:6px}
.tile{background:var(--panel);border:1px solid var(--rule);border-radius:10px;
  padding:12px 14px}
.tile .n{font-size:24px;font-weight:800;line-height:1}
.tile .l{font-size:11px;color:var(--muted);text-transform:uppercase;
  letter-spacing:.04em;margin-top:4px}

.controls{position:sticky;top:0;z-index:5;background:var(--bg);
  border:1px solid var(--rule);border-radius:10px;padding:12px 14px;margin:12px 0;
  box-shadow:0 1px 4px rgba(15,23,42,.06)}
.controls .row{display:flex;gap:14px;flex-wrap:wrap;align-items:center}
.controls label{font-size:12px;color:#475569;display:flex;align-items:center;gap:5px}
.controls .segs{display:inline-flex;gap:4px;flex-wrap:wrap}
.seg{border:1px solid var(--rule);border-radius:20px;padding:2px 10px;font-size:12px;
  cursor:pointer;user-select:none;background:#fff}
.seg.off{opacity:.4}
.controls input[type=search]{border:1px solid var(--rule);border-radius:8px;
  padding:6px 10px;font-size:13px;min-width:200px;flex:1}
.controls select{border:1px solid var(--rule);border-radius:8px;padding:5px 8px;font-size:13px}
#matchcount{font-size:12px;color:var(--muted)}

.finding{border:1px solid var(--rule);border-left-width:5px;border-radius:8px;
  margin:12px 0;overflow:hidden;background:#fff}
.finding>summary{cursor:pointer;list-style:none;padding:12px 14px;
  display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.finding>summary::-webkit-details-marker{display:none}
.finding>summary .fname{font-weight:700;font-size:15px;flex:1 1 300px}
.finding>summary .fnum{color:#94a3b8;font-weight:700;margin-right:2px}
.finding .body{padding:2px 16px 16px;border-top:1px solid var(--rule)}
.finding .metaline{font-size:12px;color:#475569;margin:8px 0}
.finding .metaline span{margin-right:6px}
pre.evi{background:var(--mono);border:1px solid var(--rule);border-radius:6px;
  padding:9px 11px;font-size:12px;overflow-x:auto;white-space:pre-wrap;
  word-break:break-word;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
ul.steps{margin:6px 0 6px 2px;padding-left:18px}
ul.steps li{margin:3px 0}
.reasons{margin:6px 0 6px 2px;padding-left:18px}
.reasons li{margin:2px 0;font-size:13px;color:#334155}
.kv-inline{font-size:13px;margin:6px 0}
.kv-inline b{color:#334155}
.appendix pre{max-height:420px;overflow:auto}
details.raw{border:1px solid var(--rule);border-radius:8px;margin:8px 0;padding:0 12px}
details.raw>summary{cursor:pointer;padding:10px 0;font-weight:600}
.note{background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:8px 12px;
  font-size:12.5px;margin:8px 0}
.footer{margin-top:40px;border-top:1px solid var(--rule);padding-top:10px;
  font-size:11px;color:#94a3b8;text-align:center}

@media (max-width:720px){.page{padding:22px 16px 60px}.cover .scorecard{flex-basis:100%}}

@media print{
  body{background:#fff}
  .page{box-shadow:none;max-width:none;padding:0}
  .controls{display:none !important}
  a{color:var(--ink)}
  .finding{break-inside:avoid;border-left-width:4px}
  .finding .body{display:block !important}
  table.data th{background:#334155 !important;-webkit-print-color-adjust:exact;
    print-color-adjust:exact}
  .badge,.meter>span,.scorecard{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
"""



def _cover(parts, ctx, findings, meta, scores) -> None:
    overall = scores.get("overall")
    grade = scores.get("grade", "—")
    started = meta.get("started_at")
    counts = Counter(f.severity for f in findings)
    actionable = [f for f in findings if f.severity >= Severity.MEDIUM
                  and f.confidence >= Confidence.MEDIUM]
    confirmed = sum(1 for f in findings if f.confidence == Confidence.CONFIRMED)
    tools_used = sum(1 for t in ctx.tools.values() if t.available)

    parts.append('<header><p class="title">Security Assessment</p>'
                 f'<p class="subtitle">{_esc(ctx.target)}</p><div class="hr"></div>'
                 "</header>")

    rows = [
        ("Target", ctx.target),
        ("Assessed", started.strftime("%Y-%m-%d %H:%M UTC") if started else "—"),
        ("Duration", f"{meta.get('duration_seconds', 0):.1f} s"),
        ("Checks run", f"{len(ctx.modules_run)} module(s), {tools_used} external tool(s)"),
        ("Surface", f"{len(ctx.discovered_urls)} URL(s), {len(ctx.services)} "
                    f"open port(s), {len(ctx.subdomains)} subdomain(s)"),
        ("Findings", f"{len(findings)} total · {len(actionable)} actionable · "
                     f"{confirmed} confirmed"),
    ]
    kv = "".join(f'<tr><td class="k">{_esc(k)}</td><td>{_esc(v)}</td></tr>'
                 for k, v in rows)
    grade_hex = _GRADE_HEX.get(grade, "#64748b")
    parts.append(
        '<div class="cover"><div class="meta"><table class="kv">'
        f"{kv}</table></div>"
        f'<div class="scorecard"><div class="num" style="color:{grade_hex}">'
        f'{overall if overall is not None else "—"}</div>'
        '<div class="den">/ 100</div>'
        f'<div class="grade">grade {_esc(grade)} · {_esc(scores.get("band", "n/a"))}</div>'
        "</div></div>")

    parts.append('<div class="sevbar">')
    for sev in _SEV_ORDER:
        parts.append(
            f'<div class="cell"><div class="n" style="color:{SEVERITY_HEX[sev]}">'
            f'{counts.get(sev, 0)}</div><div class="l">{_esc(sev.label)}</div></div>')
    parts.append("</div>")
    parts.append(
        '<p class="small">This report is the product of authorized security '
        "testing. Findings are graded by evidence: only items lopata reproduced "
        "itself are marked Confirmed, and severity is capped where the evidence "
        "does not support a stronger claim.</p>")


def _executive_summary(parts, ctx, findings, scores) -> None:
    parts.append("<h1>Executive Summary</h1>")

    # completeness first: everything below is only as good as the coverage
    completeness = scores.get("scan_completeness") or {}
    banner = completeness.get("banner")
    if banner:
        parts.append(f'<div class="incomplete-banner"><b>Incomplete scan</b><br/>'
                     f'{_esc(banner)}</div>')

    confirmed_vulns = [f for f in findings if f.ftype is FindingType.CONFIRMED_VULN]
    potential = [f for f in findings if f.ftype is FindingType.POTENTIAL_VULN]
    exposures = [f for f in findings if f.ftype is FindingType.EXPOSURE]
    misconfigs = [f for f in findings if f.ftype is FindingType.MISCONFIGURATION]
    top = [f for f in findings if f.severity >= Severity.HIGH
           and f.confidence >= Confidence.MEDIUM]

    overall = scores.get("overall")
    weak = weakest_areas(scores, 2)
    weak_text = ", ".join(f"{area} ({data['score']}/100)" for area, data in weak)

    if confirmed_vulns:
        verdict = (f"{len(confirmed_vulns)} vulnerability(ies) were reproduced "
                   "directly against the target and should be treated as present, "
                   "not suspected.")
    elif top:
        verdict = (f"No vulnerability was reproduced, but {len(top)} high-severity "
                   "issue(s) carry enough evidence to warrant prompt action.")
    else:
        verdict = ("Nothing was reproduced as exploitable during this assessment. "
                   "The findings below are hardening gaps and exposure observations.")

    parts.append(
        f"<p>lopata assessed <b>{_esc(ctx.target)}</b> across "
        f"{len(ctx.modules_run)} check module(s), reaching "
        f"{len(ctx.discovered_urls)} URL(s)"
        + (f" and {len(ctx.services)} network service(s)" if ctx.services else "")
        + f". The overall security score is <b>{overall}/100</b> "
        f"(grade {_esc(scores.get('grade', '—'))}, {_esc(scores.get('band', 'n/a'))})"
        + (f", held down primarily by {_esc(weak_text)}." if weak_text else ".")
        + f" {_esc(verdict)}</p>")

    summ = summarize(findings)
    tiles = [
        ("Confirmed vulns", len(confirmed_vulns)),
        ("Potential vulns", len(potential)),
        ("Misconfigurations", len(misconfigs)),
        ("Exposures", len(exposures)),
        ("Quick wins", summ.get("quick_wins", 0)),
        ("Checks passed", len(ctx.passed_checks)),
    ]
    parts.append('<div class="summary-tiles">')
    for label, n in tiles:
        parts.append(f'<div class="tile"><div class="n">{n}</div>'
                     f'<div class="l">{_esc(label)}</div></div>')
    parts.append("</div>")

    meanings = [
        ("Confirmed vulnerabilities", len(confirmed_vulns),
         "Reproduced by lopata during the scan; treat as present."),
        ("Potential vulnerabilities", len(potential),
         "Credible evidence, not reproduced — needs manual confirmation."),
        ("Misconfigurations", len(misconfigs),
         "Settings that weaken defences without being exploitable alone."),
        ("Security exposures", len(exposures),
         "Reachable surface that should be restricted or justified."),
        ("Checks passed", len(ctx.passed_checks),
         "Controls tested and found working — including tool checks that "
         "returned negative."),
    ]
    parts.append('<table class="data"><thead><tr><th>Category</th><th>Count</th>'
                 "<th>What it means</th></tr></thead><tbody>")
    for label, n, meaning in meanings:
        parts.append(f"<tr><td><b>{_esc(label)}</b></td><td>{n}</td>"
                     f"<td>{_esc(meaning)}</td></tr>")
    parts.append("</tbody></table>")

    if top:
        parts.append("<h2>Principal risks</h2><ul class='steps'>")
        for f in sorted(top, key=lambda f: -f.priority)[:5]:
            parts.append(
                f"<li>{_sev_badge(f.severity)} <b>{_esc(f.name)}</b> "
                f'<span class="muted small">({_esc(f.confidence.label)} '
                f"confidence)</span><br/>{_esc(f.summary)}</li>")
        parts.append("</ul>")



def _score_section(parts, scores) -> None:
    categories = scores.get("categories") or {}
    if not categories:
        return
    parts.append("<h1>Security Score by Category</h1>")
    parts.append(
        '<p class="small">Each finding is charged against the area it belongs to. '
        "The overall score is a weighted average of the areas that were actually "
        "assessed — an area nobody tested is shown as not assessed rather than "
        "scored perfect.</p>")

    ceiling = scores.get("ceiling_reason")
    if ceiling:
        parts.append(f'<div class="note"><b>Note:</b> the overall score is capped '
                     f"because {_esc(ceiling)}.</div>")

    weights = scores.get("weights", {})
    parts.append('<table class="data"><thead><tr><th>Category</th><th>Score</th>'
                 "<th>Grade</th><th>Distribution</th><th>Weight</th><th>Findings</th>"
                 "<th>Largest contributor</th></tr></thead><tbody>")
    for area in SCORE_AREAS:
        data = categories.get(area, {})
        score = data.get("score")
        grade = data.get("grade", "—")
        ghex = _GRADE_HEX.get(grade, "#94a3b8")
        if score is not None:
            meter = (f'<div class="meter"><span style="width:{score}%;'
                     f'background:{ghex}"></span></div>')
            score_txt = f"{score}/100"
        else:
            meter = '<span class="muted">not assessed</span>'
            score_txt = "—"
        parts.append(
            f"<tr><td>{_esc(area)}</td><td>{score_txt}</td>"
            f'<td style="color:{ghex};font-weight:700">{_esc(grade)}</td>'
            f"<td>{meter}</td><td>{int(weights.get(area, 0) * 100)}%</td>"
            f"<td>{data.get('findings', 0)}</td>"
            f"<td>{_esc(data.get('top_issue', '') or '—')}</td></tr>")
    parts.append("</tbody></table>")



def _technology_section(parts, ctx) -> None:
    if not ctx.technologies:
        return
    parts.append("<h1>Technology Summary</h1>")
    grouped = defaultdict(list)
    for tech in ctx.technologies.values():
        grouped[tech.category].append(tech)

    parts.append('<table class="data"><thead><tr><th>Category</th><th>Component</th>'
                 "<th>Version</th><th>Confidence</th><th>Detected by</th></tr></thead>"
                 "<tbody>")
    for category in sorted(grouped):
        for tech in sorted(grouped[category], key=lambda t: t.name.lower()):
            parts.append(
                f"<tr><td>{_esc(category)}</td><td>{_esc(tech.name)}</td>"
                f"<td>{_esc(tech.version or '—')}</td>"
                f"<td>{_esc(tech.confidence.label)}</td>"
                f"<td>{_esc(', '.join(tech.sources) or '—')}</td></tr>")
    parts.append("</tbody></table>")
    parts.append(
        '<p class="small">Confidence reflects how the component was identified: '
        "banner-only detections are Low because banners are self-reported and "
        "often wrong; components seen by two independent methods are promoted to "
        "High.</p>")


def _attack_surface_section(parts, ctx) -> None:
    if not ctx.services and not ctx.subdomains:
        return
    parts.append("<h1>Attack Surface Summary</h1>")

    if ctx.services:
        external = [s for s in ctx.services if not s.internal]
        internal = [s for s in ctx.services if s.internal]
        parts.append(
            f"<p>{len(external)} service(s) on externally routable addresses and "
            f"{len(internal)} on internal address space, grouped by function:</p>")

        grouped = defaultdict(list)
        for service in ctx.services:
            grouped[service.group].append(service)

        parts.append('<table class="data"><thead><tr><th>Group</th>'
                     "<th>Endpoints</th><th>Service / version</th><th>Scope</th>"
                     "</tr></thead><tbody>")
        for group in GROUP_ORDER:
            services = grouped.get(group)
            if not services:
                continue
            services.sort(key=lambda s: s.port)
            endpoints = ", ".join(f"{s.port}/{s.proto}" for s in services)
            banners = "; ".join(sorted({(s.banner or s.name) for s in services}))
            scope = "external" if any(not s.internal for s in services) else "internal"
            parts.append(f"<tr><td>{_esc(group)}</td><td>{_esc(endpoints)}</td>"
                         f"<td>{_esc(banners)}</td><td>{_esc(scope)}</td></tr>")
        parts.append("</tbody></table>")

    if ctx.subdomains:
        shown = sorted(ctx.subdomains)[:60]
        more = " …" if len(ctx.subdomains) > 60 else ""
        parts.append(f"<p class='small'><b>Subdomains ({len(ctx.subdomains)}):</b> "
                     + ", ".join(_esc(s) for s in shown) + more + "</p>")



def _priorities(parts, findings) -> None:
    actionable = [f for f in findings if f.severity >= Severity.LOW
                  and f.confidence >= Confidence.MEDIUM]
    if not actionable:
        return
    parts.append("<h1>Recommended Remediation Order</h1>")
    quick = [f for f in actionable if f.quick_win]
    if quick:
        parts.append(
            f"<p><b>Quick wins ({len(quick)}):</b> these are Medium severity or "
            "above and take a configuration change rather than a code change. "
            "Doing them first buys the largest security improvement per hour "
            "spent.</p>")

    parts.append('<table class="data sortable"><thead><tr><th>#</th><th>Finding</th>'
                 "<th>Severity</th><th>Confidence</th><th>Effort</th>"
                 "<th>Business impact</th><th>Quick win</th></tr></thead><tbody>")
    for i, f in enumerate(sorted(actionable, key=lambda f: -f.priority)[:40], start=1):
        qw = ('<span style="color:#15803d;font-weight:700">yes</span>'
              if f.quick_win else "")
        parts.append(
            f'<tr><td data-sort="{i}">{i}</td>'
            f'<td><a href="#{_finding_slug_for(findings, f)}">{_esc(f.name)}</a></td>'
            f'<td data-sort="{int(f.severity)}" style="color:{SEVERITY_HEX[f.severity]};'
            f'font-weight:700">{_esc(f.severity.label)}</td>'
            f'<td data-sort="{int(f.confidence)}" style="color:{CONFIDENCE_HEX[f.confidence]}">'
            f'{_esc(f.confidence.label)}</td>'
            f'<td data-sort="{int(f.effort)}">{_esc(f.effort.label)}</td>'
            f'<td data-sort="{int(f.business_impact)}">{_esc(f.business_impact.label)}</td>'
            f'<td data-sort="{1 if f.quick_win else 0}">{qw}</td></tr>')
    parts.append("</tbody></table>")


def _findings_overview(parts, findings) -> None:
    if not findings:
        return
    parts.append("<h1>Findings by Severity, Type and Category</h1>")
    counts = Counter(f.severity for f in findings)
    conf_counts = Counter(f.confidence for f in findings)
    total = len(findings)

    parts.append('<table class="data"><thead><tr><th>Severity</th><th>Count</th>'
                 "<th>Distribution</th></tr></thead><tbody>")
    for sev in _SEV_ORDER:
        n = counts.get(sev, 0)
        pct = int(100 * n / total) if total else 0
        parts.append(
            f'<tr><td style="color:{SEVERITY_HEX[sev]};font-weight:700">'
            f"{_esc(sev.label)}</td><td>{n}</td>"
            f'<td><div class="meter"><span style="width:{pct}%;'
            f'background:{SEVERITY_HEX[sev]}"></span></div></td></tr>')
    parts.append("</tbody></table>")

    parts.append("<p class='small'><b>By confidence:</b> " + " · ".join(
        f'<span style="color:{CONFIDENCE_HEX[c]}">{_esc(c.label)} '
        f"{conf_counts.get(c, 0)}</span>" for c in _CONF_ORDER) + "</p>")

    by_type = defaultdict(list)
    for f in findings:
        by_type[f.ftype].append(f)
    parts.append('<table class="data"><thead><tr><th>Type</th><th>Count</th>'
                 "<th>Categories</th></tr></thead><tbody>")
    for ftype in _TYPE_ORDER:
        items = by_type.get(ftype)
        if not items:
            continue
        cats = Counter(f.resolved_category() for f in items)
        cat_txt = ", ".join(f"{name} ({n})" for name, n in cats.most_common())
        parts.append(f"<tr><td>{_esc(ftype.label)}</td><td>{len(items)}</td>"
                     f"<td>{_esc(cat_txt)}</td></tr>")
    parts.append("</tbody></table>")



_INDEX_ATTR = "_html_index"


def _ordered_findings(findings) -> list:
    """Findings in the order the Detailed Findings section renders them:
    grouped by type (strongest first), then by priority within a type."""
    by_type = defaultdict(list)
    for f in findings:
        by_type[f.ftype].append(f)
    ordered: list = []
    for ftype in _TYPE_ORDER:
        ordered.extend(sorted(by_type.get(ftype, []), key=lambda f: -f.priority))
    return ordered


def _stamp_indices(findings) -> None:
    for idx, f in enumerate(_ordered_findings(findings), start=1):
        setattr(f, _INDEX_ATTR, idx)


def _finding_slug_for(findings, target) -> str:
    idx = getattr(target, _INDEX_ATTR, None)
    return _finding_slug(idx if idx is not None else 0)


def _details(parts, findings) -> None:
    if not findings:
        return
    parts.append("<h1>Detailed Findings</h1>")
    parts.append(
        '<p class="small">Findings are grouped by type: reproduced vulnerabilities '
        "first, then unconfirmed leads, then configuration and exposure "
        "observations, then inventory. Use the controls to filter and search.</p>")

    _controls(parts)

    parts.append('<div id="findings-list">')
    for f in _ordered_findings(findings):
        _one_finding(parts, getattr(f, _INDEX_ATTR, 0), f)
    parts.append("</div>")
    parts.append('<p id="noresults" class="muted" style="display:none">'
                 "No findings match the current filters.</p>")


def _controls(parts) -> None:
    sev_segs = "".join(
        f'<span class="seg" data-filter="sev" data-value="{sev.name}" '
        f'style="border-color:{SEVERITY_HEX[sev]};color:{SEVERITY_HEX[sev]}">'
        f"{_esc(sev.label)}</span>" for sev in _SEV_ORDER)
    conf_opts = "".join(f'<option value="{int(c)}">{_esc(c.label)}</option>'
                        for c in _CONF_ORDER)
    type_opts = "".join(f'<option value="{t.name}">{_esc(t.label)}</option>'
                        for t in _TYPE_ORDER)
    parts.append(
        '<div class="controls"><div class="row">'
        '<input type="search" id="search" placeholder="Search findings (name, '
        'location, evidence)…" aria-label="Search findings">'
        f'<span id="matchcount"></span></div>'
        '<div class="row"><span class="segs" id="sevsegs">'
        f'<span class="small muted" style="margin-right:4px">Severity:</span>{sev_segs}</span>'
        '</div><div class="row">'
        f'<label>Min confidence <select id="conf"><option value="">any</option>'
        f'{conf_opts}</select></label>'
        f'<label>Type <select id="type"><option value="">all</option>'
        f'{type_opts}</select></label>'
        '<label><input type="checkbox" id="onlyvulns"> Vulnerabilities only</label>'
        '<label><input type="checkbox" id="expandall"> Expand all</label>'
        '<span class="seg" id="reset">Reset</span>'
        "</div></div>")


def _one_finding(parts, index, f) -> None:
    sev_hex = SEVERITY_HEX[f.severity]
    text_blob = " ".join(str(x) for x in (
        f.name, f.summary, f.location, " ".join(f.all_locations()),
        f.description, f.evidence, f.resolved_category(),
        " ".join(f.sources))).lower()
    parts.append(
        f'<details class="finding" id="{_finding_slug(index)}" '
        f'style="border-left-color:{sev_hex}" '
        f'data-sev="{f.severity.name}" data-sevrank="{int(f.severity)}" '
        f'data-conf="{f.confidence.name}" data-confrank="{int(f.confidence)}" '
        f'data-type="{f.ftype.name}" data-vuln="{1 if f.is_vulnerability else 0}" '
        f'data-text="{_esc(text_blob)}">')
    coverage_flag = ('<span class="coverage-flag">incomplete evidence</span>'
                     if f.incomplete_coverage else "")
    parts.append(
        f'<summary><span class="fnum">{index}.</span>'
        f'<span class="fname">{_esc(f.name)}</span>{_sev_badge(f.severity)}'
        f"{_conf_badge(f.confidence)}{coverage_flag}</summary>")
    parts.append('<div class="body">')

    parts.append(
        f'<div class="metaline"><span>{_esc(f.ftype.label)}</span>·'
        f'<span>{_esc(f.resolved_category())}</span>·'
        f'<span>effort: {_esc(f.effort.label)}</span>·'
        f'<span>business impact: {_esc(f.business_impact.label)}</span>'
        + (f'·<span>CVSS {f.cvss:.1f}</span>' if f.cvss else "") + "</div>")

    _kv(parts, "Affected", "\n".join(f.all_locations()))
    if f.summary:
        _kv(parts, "Summary", f.summary)
    if f.description:
        _block(parts, "Technical detail", f.description)
    if f.risk:
        _block(parts, "Why it matters", f.risk)
    if f.impact:
        _block(parts, "Potential impact", f.impact)

    if f.severity_reasons:
        parts.append("<h3>Severity rationale</h3><ul class='reasons'>")
        for reason in f.severity_reasons:
            parts.append(f"<li>{_esc(reason)}</li>")
        parts.append("</ul>")

    if f.request or f.response or f.evidence:
        parts.append("<h3>Evidence</h3>")
        for value in (f.request, f.response, f.evidence):
            if value:
                parts.append(f'<pre class="evi">{_esc(value)}</pre>')

    if f.verified_by:
        _kv(parts, "Verification performed", f.verified_by)

    if f.remediation_steps:
        parts.append("<h3>Remediation</h3><ul class='steps'>")
        for step in f.remediation_steps:
            parts.append(f"<li>{_esc(step)}</li>")
        parts.append("</ul>")
    elif f.remediation:
        _block(parts, "Remediation", f.remediation)

    if f.verification:
        _block(parts, "How to verify the fix", f.verification)

    if f.references:
        parts.append("<p class='small'><b>References:</b><br/>" + "<br/>".join(
            f'<a href="{_esc(r)}" rel="noopener noreferrer">{_esc(r)}</a>'
            for r in f.references) + "</p>")
    if f.sources:
        parts.append(f"<p class='small muted'>Reported by: "
                     f"{_esc(', '.join(f.sources))}</p>")

    parts.append("</div></details>")


def _kv(parts, label, value) -> None:
    parts.append(f'<p class="kv-inline"><b>{_esc(label)}:</b> {_multiline(value)}</p>')


def _block(parts, label, text) -> None:
    parts.append(f"<h3>{_esc(label)}</h3><p>{_multiline(text)}</p>")



def _passed_checks(parts, ctx) -> None:
    if not ctx.passed_checks:
        return
    parts.append("<h1>Checks Passed</h1>")
    parts.append(
        '<p class="small">Controls that were tested and found working. These are '
        "listed because a negative result is a result: they are also where "
        'scanner output reporting "NOT VULNERABLE" ends up, instead of being '
        "converted into a finding.</p>")
    parts.append('<table class="data"><thead><tr><th>Check</th><th>Detail</th>'
                 "<th>Source</th></tr></thead><tbody>")
    for check in ctx.passed_checks:
        parts.append(f"<tr><td>{_esc(check.name)}</td><td>{_esc(check.detail)}</td>"
                     f"<td>{_esc(check.source)}</td></tr>")
    parts.append("</tbody></table>")


def _appendix(parts, ctx, meta) -> None:
    parts.append('<div class="appendix">')
    parts.append("<h1>Appendix A — Tooling</h1>")
    parts.append('<table class="data"><thead><tr><th>Tool</th><th>Status</th>'
                 "<th>Version / note</th></tr></thead><tbody>")
    for name, info in sorted(ctx.tools.items()):
        status = "used" if info.available else "skipped"
        parts.append(f"<tr><td>{_esc(name)}</td><td>{_esc(status)}</td>"
                     f"<td>{_esc(info.version or info.note or '—')}</td></tr>")
    parts.append("</tbody></table>")

    notes = meta.get("notes") or []
    if notes:
        parts.append("<h2>Scan notes</h2><ul class='steps'>")
        for note in notes[:60]:
            parts.append(f"<li class='small'>{_esc(note)}</li>")
        parts.append("</ul>")

    if ctx.discovered_urls:
        listing = sorted(ctx.discovered_urls)
        parts.append(f"<h1>Appendix B — Discovered URLs ({len(listing)})</h1>")
        shown = listing[:400]
        parts.append('<pre class="evi">' + "\n".join(_esc(u) for u in shown)
                     + (f"\n… and {len(listing) - 400} more"
                        if len(listing) > 400 else "") + "</pre>")

    spa = list(getattr(ctx, "spa_routes", []) or [])
    if spa:
        parts.append("<h1>Appendix C — Client-side routes</h1>")
        parts.append('<pre class="evi">' + "\n".join(_esc(r) for r in spa[:200])
                     + "</pre>")

    if ctx.raw_outputs:
        parts.append("<h1>Appendix D — Raw Scanner Output</h1>")
        parts.append(
            '<p class="small">Verbatim output from each external tool, so any '
            "interpretation made in this report can be checked against its "
            "source.</p>")
        for tool, text in sorted(ctx.raw_outputs.items()):
            parts.append(f'<details class="raw"><summary>{_esc(tool)}</summary>'
                         f'<pre class="evi">{_esc(text[:20000])}</pre></details>')
    parts.append("</div>")
    parts.append('<div class="footer">lopata — confidential security assessment · '
                 "generated " + _esc(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
                 + "</div>")



def _script() -> str:
    return "<script>" + _JS + "</script>"


_JS = r"""
(function(){
  var list = document.getElementById('findings-list');
  if(!list) return;
  var cards = Array.prototype.slice.call(list.querySelectorAll('.finding'));
  var search = document.getElementById('search');
  var confSel = document.getElementById('conf');
  var typeSel = document.getElementById('type');
  var onlyVulns = document.getElementById('onlyvulns');
  var expandAll = document.getElementById('expandall');
  var reset = document.getElementById('reset');
  var matchcount = document.getElementById('matchcount');
  var noresults = document.getElementById('noresults');
  var sevOff = {};

  document.querySelectorAll('#sevsegs .seg').forEach(function(seg){
    seg.addEventListener('click', function(){
      var v = seg.getAttribute('data-value');
      sevOff[v] = !sevOff[v];
      seg.classList.toggle('off', !!sevOff[v]);
      apply();
    });
  });

  function apply(){
    var q = (search.value || '').trim().toLowerCase();
    var minConf = confSel.value !== '' ? parseInt(confSel.value, 10) : -1;
    var wantType = typeSel.value;
    var vulnsOnly = onlyVulns.checked;
    var shown = 0;
    cards.forEach(function(c){
      var ok = true;
      if(sevOff[c.dataset.sev]) ok = false;
      if(ok && minConf >= 0 && parseInt(c.dataset.confrank,10) < minConf) ok = false;
      if(ok && wantType && c.dataset.type !== wantType) ok = false;
      if(ok && vulnsOnly && c.dataset.vuln !== '1') ok = false;
      if(ok && q && c.dataset.text.indexOf(q) === -1) ok = false;
      c.style.display = ok ? '' : 'none';
      if(ok) shown++;
    });
    matchcount.textContent = shown + ' of ' + cards.length + ' shown';
    noresults.style.display = shown ? 'none' : '';
  }

  search.addEventListener('input', apply);
  confSel.addEventListener('change', apply);
  typeSel.addEventListener('change', apply);
  onlyVulns.addEventListener('change', apply);
  expandAll.addEventListener('change', function(){
    cards.forEach(function(c){ c.open = expandAll.checked; });
  });
  reset.addEventListener('click', function(){
    search.value=''; confSel.value=''; typeSel.value='';
    onlyVulns.checked=false; expandAll.checked=false;
    sevOff = {};
    document.querySelectorAll('#sevsegs .seg').forEach(function(s){s.classList.remove('off');});
    cards.forEach(function(c){c.open=false;});
    apply();
  });

  // Sortable tables.
  document.querySelectorAll('table.sortable').forEach(function(tbl){
    var dir = {};
    tbl.querySelectorAll('th').forEach(function(th, col){
      th.addEventListener('click', function(){
        var body = tbl.tBodies[0];
        var rows = Array.prototype.slice.call(body.rows);
        var asc = dir[col] = !dir[col];
        rows.sort(function(a,b){
          var x = a.cells[col].getAttribute('data-sort');
          var y = b.cells[col].getAttribute('data-sort');
          if(x!==null && y!==null && x!=='' && y!=='' && !isNaN(x) && !isNaN(y)){
            return asc ? x-y : y-x;
          }
          x = a.cells[col].textContent.trim(); y = b.cells[col].textContent.trim();
          return asc ? x.localeCompare(y) : y.localeCompare(x);
        });
        rows.forEach(function(r){ body.appendChild(r); });
      });
    });
  });

  // Expand everything before printing so closed <details> still print.
  var wasOpen = null;
  window.addEventListener('beforeprint', function(){
    wasOpen = cards.map(function(c){return c.open;});
    cards.forEach(function(c){ c.style.display=''; c.open = true; });
  });
  window.addEventListener('afterprint', function(){
    if(wasOpen) cards.forEach(function(c,i){ c.open = wasOpen[i]; });
    apply();
  });

  apply();

  // Deep-link: open the targeted finding.
  function openHash(){
    if(location.hash){
      var el = document.querySelector(location.hash);
      if(el && el.classList.contains('finding')){ el.open = true; el.style.display=''; }
    }
  }
  window.addEventListener('hashchange', openHash);
  openHash();
})();
"""
