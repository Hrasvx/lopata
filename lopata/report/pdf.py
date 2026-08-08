"""PDF report.

Structured the way an assessment report is read rather than the way a scanner
produces output: conclusions first (score, executive summary, priorities),
then the evidence, then the raw tool output in an appendix for anyone who
wants to check the working.
"""

from __future__ import annotations

import datetime
import html
from collections import Counter, defaultdict

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (HRFlowable, PageBreak, Paragraph,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

from ..core.knowledge import GROUP_ORDER
from ..core.models import (CONFIDENCE_HEX, SCORE_AREAS, SEVERITY_HEX,
                           Confidence, FindingType, Severity)
from ..core.scoring import weakest_areas

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
              Severity.LOW, Severity.INFO]

_TYPE_ORDER = [FindingType.CONFIRMED_VULN, FindingType.POTENTIAL_VULN,
               FindingType.MISCONFIGURATION, FindingType.EXPOSURE,
               FindingType.INVENTORY, FindingType.INFORMATIONAL]

_INK = colors.HexColor("#0f172a")
_MUTED = colors.HexColor("#64748b")
_RULE = colors.HexColor("#e2e8f0")
_PANEL = colors.HexColor("#f8fafc")

_GRADE_HEX = {"A": "#15803d", "B": "#65a30d", "C": "#ca8a04",
              "D": "#ea580c", "F": "#b91c1c", "—": "#94a3b8"}


def default_report_name(target: str, ext: str = "pdf") -> str:
    host = target.replace("https://", "").replace("http://", "").strip("/")
    host = host.replace("/", "_").replace(":", "_")
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"lopata_report_{host}_{ts}.{ext.lstrip('.')}"


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("LTitle", parent=ss["Title"], fontSize=24,
                          textColor=_INK, spaceAfter=2))
    ss.add(ParagraphStyle("LH1", parent=ss["Heading1"], fontSize=16,
                          textColor=_INK, spaceBefore=16, spaceAfter=6))
    ss.add(ParagraphStyle("LH2", parent=ss["Heading2"], fontSize=13,
                          textColor=_INK, spaceBefore=12, spaceAfter=4))
    ss.add(ParagraphStyle("LH3", parent=ss["Heading3"], fontSize=10,
                          textColor=_MUTED, spaceBefore=6, spaceAfter=1))
    ss.add(ParagraphStyle("LSmall", parent=ss["Normal"], fontSize=8,
                          textColor=colors.HexColor("#475569"), leading=10.5))
    ss.add(ParagraphStyle("LMono", parent=ss["Code"], fontSize=7,
                          textColor=_INK, backColor=colors.HexColor("#f1f5f9"),
                          leading=9.5, leftIndent=4, rightIndent=4,
                          spaceBefore=2, spaceAfter=2))
    ss.add(ParagraphStyle("LBody", parent=ss["Normal"], fontSize=9.5, leading=13.5))
    ss.add(ParagraphStyle("LBullet", parent=ss["Normal"], fontSize=9,
                          leading=12.5, leftIndent=12, bulletIndent=3))
    return ss


def generate_report(ctx, path: str, meta: dict) -> None:
    doc = SimpleDocTemplate(
        path, pagesize=A4, title=f"lopata assessment — {ctx.target}",
        author="lopata", subject="Security assessment report",
        leftMargin=1.7 * cm, rightMargin=1.7 * cm,
        topMargin=1.5 * cm, bottomMargin=1.5 * cm)
    ss = _styles()
    story = []

    findings = list(ctx.findings)
    scores = ctx.scores or {}

    _cover(story, ss, ctx, findings, meta, scores)
    _executive_summary(story, ss, ctx, findings, scores)
    _score_section(story, ss, scores)
    _technology_section(story, ss, ctx)
    _attack_surface_section(story, ss, ctx)
    _priorities(story, ss, findings)
    _findings_by_severity(story, ss, findings)
    _findings_by_category(story, ss, findings)
    _details(story, ss, findings)
    _passed_checks(story, ss, ctx)
    _appendix(story, ss, ctx, meta)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(_MUTED)
    canvas.drawString(1.7 * cm, 1.0 * cm,
                      "lopata — confidential security assessment")
    canvas.drawRightString(A4[0] - 1.7 * cm, 1.0 * cm, f"page {doc.page}")
    canvas.restoreState()


# --------------------------------------------------------------------------
# Cover & summary
# --------------------------------------------------------------------------

def _cover(story, ss, ctx, findings, meta, scores) -> None:
    story.append(Paragraph("Security Assessment", ss["LTitle"]))
    story.append(Paragraph(
        f"<font color='#64748b'>{html.escape(ctx.target)}</font>", ss["LH2"]))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 10))

    overall = scores.get("overall")
    grade = scores.get("grade", "—")
    started = meta.get("started_at")
    counts = Counter(f.severity for f in findings)
    actionable = [f for f in findings
                  if f.severity >= Severity.MEDIUM
                  and f.confidence >= Confidence.MEDIUM]

    score_cell = (f"<font size=26 color='{_GRADE_HEX.get(grade, '#64748b')}'>"
                  f"<b>{overall if overall is not None else '—'}</b></font>"
                  f"<font size=11 color='#94a3b8'>/100</font><br/>"
                  f"<font size=9 color='#64748b'>grade {grade} · "
                  f"{scores.get('band', 'n/a')}</font>")

    left = [
        ["Target", ctx.target],
        ["Assessed", started.strftime("%Y-%m-%d %H:%M UTC") if started else "—"],
        ["Duration", f"{meta.get('duration_seconds', 0):.1f} s"],
        ["Checks run", f"{len(ctx.modules_run)} module(s), "
                       f"{sum(1 for t in ctx.tools.values() if t.available)} "
                       "external tool(s)"],
        ["Surface", f"{len(ctx.discovered_urls)} URL(s), "
                    f"{len(ctx.services)} open port(s), "
                    f"{len(ctx.subdomains)} subdomain(s)"],
        ["Findings", f"{len(findings)} total · {len(actionable)} actionable · "
                     f"{sum(1 for f in findings if f.confidence == Confidence.CONFIRMED)} "
                     "confirmed"],
    ]
    info = Table([[Table([[Paragraph(f"<b>{k}</b>", ss["LSmall"]),
                           Paragraph(html.escape(str(v)), ss["LSmall"])]
                          for k, v in left],
                         colWidths=[2.6 * cm, 8.4 * cm],
                         style=TableStyle([
                             ("VALIGN", (0, 0), (-1, -1), "TOP"),
                             ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                             ("LINEBELOW", (0, 0), (-1, -2), 0.3, _RULE),
                         ])),
                   Paragraph(score_cell, ss["LBody"])]],
                 colWidths=[11.2 * cm, 6.0 * cm])
    info.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (1, 0), (1, 0), _PANEL),
        ("ALIGN", (1, 0), (1, 0), "CENTER"),
        ("BOX", (1, 0), (1, 0), 0.4, _RULE),
        ("LEFTPADDING", (1, 0), (1, 0), 10),
    ]))
    story.append(info)
    story.append(Spacer(1, 10))

    bar = [[Paragraph(f"<b>{sev.label}</b>", ss["LSmall"]) for sev in _SEV_ORDER],
           [Paragraph(f"<font size=15 color='{SEVERITY_HEX[sev]}'>"
                      f"<b>{counts.get(sev, 0)}</b></font>", ss["LBody"])
            for sev in _SEV_ORDER]]
    t = Table(bar, colWidths=[3.44 * cm] * 5)
    t.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND", (0, 0), (-1, -1), _PANEL),
        ("BOX", (0, 0), (-1, -1), 0.4, _RULE),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, _RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "This report is the product of authorized security testing. Findings "
        "are graded by evidence: only items lopata reproduced itself are marked "
        "Confirmed, and severity is capped where the evidence does not support "
        "a stronger claim.", ss["LSmall"]))


def _executive_summary(story, ss, ctx, findings, scores) -> None:
    story.append(Paragraph("Executive Summary", ss["LH1"]))

    confirmed_vulns = [f for f in findings
                       if f.ftype is FindingType.CONFIRMED_VULN]
    potential = [f for f in findings if f.ftype is FindingType.POTENTIAL_VULN]
    exposures = [f for f in findings if f.ftype is FindingType.EXPOSURE]
    misconfigs = [f for f in findings
                  if f.ftype is FindingType.MISCONFIGURATION]
    top = [f for f in findings
           if f.severity >= Severity.HIGH and f.confidence >= Confidence.MEDIUM]

    overall = scores.get("overall")
    weak = weakest_areas(scores, 2)
    weak_text = ", ".join(f"{area} ({data['score']}/100)" for area, data in weak)

    if confirmed_vulns:
        verdict = (f"{len(confirmed_vulns)} vulnerability(ies) were reproduced "
                   "directly against the target and should be treated as "
                   "present, not suspected.")
    elif top:
        verdict = ("No vulnerability was reproduced, but "
                   f"{len(top)} high-severity issue(s) carry enough evidence to "
                   "warrant prompt action.")
    else:
        verdict = ("Nothing was reproduced as exploitable during this "
                   "assessment. The findings below are hardening gaps and "
                   "exposure observations.")

    story.append(Paragraph(
        f"lopata assessed <b>{html.escape(ctx.target)}</b> across "
        f"{len(ctx.modules_run)} check module(s), reaching "
        f"{len(ctx.discovered_urls)} URL(s)"
        + (f" and {len(ctx.services)} network service(s)" if ctx.services else "")
        + f". The overall security score is <b>{overall}/100</b> "
        f"(grade {scores.get('grade', '—')}, {scores.get('band', 'n/a')})"
        + (f", held down primarily by {weak_text}." if weak_text else ".")
        + f" {verdict}", ss["LBody"]))
    story.append(Spacer(1, 6))

    rows = [["", "Count", "What it means"]]
    rows.append(["Confirmed vulnerabilities", str(len(confirmed_vulns)),
                 "Reproduced by lopata during the scan; treat as present."])
    rows.append(["Potential vulnerabilities", str(len(potential)),
                 "Credible evidence, not reproduced — needs manual confirmation."])
    rows.append(["Misconfigurations", str(len(misconfigs)),
                 "Settings that weaken defences without being exploitable alone."])
    rows.append(["Security exposures", str(len(exposures)),
                 "Reachable surface that should be restricted or justified."])
    rows.append(["Checks passed", str(len(ctx.passed_checks)),
                 "Controls tested and found working — including tool checks "
                 "that returned negative."])

    table = Table([[Paragraph(f"<b>{r[0]}</b>" if i else r[0], ss["LSmall"]),
                    Paragraph(r[1], ss["LSmall"]),
                    Paragraph(r[2], ss["LSmall"])]
                   for i, r in enumerate(rows)],
                  colWidths=[5.0 * cm, 1.6 * cm, 10.6 * cm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _PANEL),
        ("GRID", (0, 0), (-1, -1), 0.3, _RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(table)

    if top:
        story.append(Spacer(1, 8))
        story.append(Paragraph("Principal risks", ss["LH2"]))
        for finding in sorted(top, key=lambda f: -f.priority)[:5]:
            story.append(Paragraph(
                f"<font color='{SEVERITY_HEX[finding.severity]}'><b>"
                f"{finding.severity.label}</b></font> — "
                f"<b>{html.escape(finding.name)}</b> "
                f"<font size=8 color='#64748b'>({finding.confidence.label} "
                f"confidence)</font><br/>{html.escape(finding.summary)}",
                ss["LBullet"], bulletText="•"))
            story.append(Spacer(1, 3))


# --------------------------------------------------------------------------
# Scores
# --------------------------------------------------------------------------

def _score_section(story, ss, scores) -> None:
    categories = scores.get("categories") or {}
    if not categories:
        return
    story.append(Paragraph("Security Score by Category", ss["LH1"]))
    story.append(Paragraph(
        "Each finding is charged against the area it belongs to. The overall "
        "score is a weighted average of the areas that were actually assessed — "
        "an area nobody tested is shown as not assessed rather than scored "
        "perfect.", ss["LSmall"]))
    story.append(Spacer(1, 6))

    ceiling = scores.get("ceiling_reason")
    if ceiling:
        story.append(Paragraph(
            f"<b>Note:</b> the overall score is capped because {html.escape(ceiling)}.",
            ss["LSmall"]))
        story.append(Spacer(1, 4))

    weights = scores.get("weights", {})
    rows = [["Category", "Score", "Grade", "", "Weight", "Findings",
             "Largest contributor"]]
    for area in SCORE_AREAS:
        data = categories.get(area, {})
        score = data.get("score")
        grade = data.get("grade", "—")
        bar_len = int(round((score or 0) / 5))
        rows.append([
            area,
            f"{score}/100" if score is not None else "—",
            grade,
            "█" * bar_len + "░" * (20 - bar_len) if score is not None else "",
            f"{int(weights.get(area, 0) * 100)}%",
            str(data.get("findings", 0)),
            data.get("top_issue", "") or "—",
        ])

    table = Table([[Paragraph(f"<b>{c}</b>", ss["LSmall"]) if i == 0
                    else Paragraph(html.escape(str(c)), ss["LSmall"])
                    for c in row] for i, row in enumerate(rows)],
                  colWidths=[3.9 * cm, 1.5 * cm, 1.2 * cm, 4.0 * cm, 1.4 * cm,
                             1.5 * cm, 3.7 * cm],
                  repeatRows=1)
    style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, _RULE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ])
    for i, area in enumerate(SCORE_AREAS, start=1):
        grade = categories.get(area, {}).get("grade", "—")
        hexcolor = colors.HexColor(_GRADE_HEX.get(grade, "#94a3b8"))
        style.add("TEXTCOLOR", (2, i), (3, i), hexcolor)
        style.add("FONT", (2, i), (2, i), "Helvetica-Bold", 8)
    table.setStyle(style)
    story.append(table)


# --------------------------------------------------------------------------
# Technology & attack surface
# --------------------------------------------------------------------------

def _technology_section(story, ss, ctx) -> None:
    if not ctx.technologies:
        return
    story.append(Paragraph("Technology Summary", ss["LH1"]))

    grouped = defaultdict(list)
    for tech in ctx.technologies.values():
        grouped[tech.category].append(tech)

    rows = [["Category", "Component", "Version", "Confidence", "Detected by"]]
    for category in sorted(grouped):
        for tech in sorted(grouped[category], key=lambda t: t.name.lower()):
            rows.append([category, tech.name, tech.version or "—",
                         tech.confidence.label,
                         ", ".join(tech.sources) or "—"])

    table = Table([[Paragraph(f"<b>{c}</b>" if i == 0 else html.escape(str(c)),
                              ss["LSmall"]) for c in row]
                   for i, row in enumerate(rows)],
                  colWidths=[3.6 * cm, 5.4 * cm, 2.6 * cm, 2.6 * cm, 3.0 * cm],
                  repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, _RULE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _PANEL]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(table)
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "Confidence reflects how the component was identified: banner-only "
        "detections are Low because banners are self-reported and often wrong; "
        "components seen by two independent methods are promoted to High.",
        ss["LSmall"]))


def _attack_surface_section(story, ss, ctx) -> None:
    if not ctx.services and not ctx.subdomains:
        return
    story.append(Paragraph("Attack Surface Summary", ss["LH1"]))

    if ctx.services:
        external = [s for s in ctx.services if not s.internal]
        internal = [s for s in ctx.services if s.internal]
        story.append(Paragraph(
            f"{len(external)} service(s) on externally routable addresses and "
            f"{len(internal)} on internal address space, grouped by function:",
            ss["LBody"]))
        story.append(Spacer(1, 4))

        grouped = defaultdict(list)
        for service in ctx.services:
            grouped[service.group].append(service)

        rows = [["Group", "Endpoints", "Service / version", "Scope"]]
        for group in GROUP_ORDER:
            services = grouped.get(group)
            if not services:
                continue
            services.sort(key=lambda s: s.port)
            rows.append([
                group,
                ", ".join(f"{s.port}/{s.proto}" for s in services),
                "; ".join(sorted({(s.banner or s.name) for s in services})),
                "external" if any(not s.internal for s in services) else "internal",
            ])

        table = Table([[Paragraph(f"<b>{c}</b>" if i == 0 else html.escape(str(c)),
                                  ss["LSmall"]) for c in row]
                       for i, row in enumerate(rows)],
                      colWidths=[4.6 * cm, 3.4 * cm, 7.2 * cm, 2.0 * cm],
                      repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _INK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, _RULE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(table)

    if ctx.subdomains:
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            f"<b>Subdomains ({len(ctx.subdomains)}):</b> "
            + html.escape(", ".join(sorted(ctx.subdomains)[:60]))
            + (" …" if len(ctx.subdomains) > 60 else ""), ss["LSmall"]))


# --------------------------------------------------------------------------
# Priorities and finding tables
# --------------------------------------------------------------------------

def _priorities(story, ss, findings) -> None:
    actionable = [f for f in findings
                  if f.severity >= Severity.LOW
                  and f.confidence >= Confidence.MEDIUM]
    if not actionable:
        return
    story.append(PageBreak())
    story.append(Paragraph("Recommended Remediation Order", ss["LH1"]))

    quick = [f for f in actionable if f.quick_win]
    if quick:
        story.append(Paragraph(
            f"<b>Quick wins ({len(quick)}):</b> these are Medium severity or "
            "above and take a configuration change rather than a code change. "
            "Doing them first buys the largest security improvement per hour "
            "spent.", ss["LBody"]))
        story.append(Spacer(1, 4))

    rows = [["#", "Finding", "Severity", "Confidence", "Effort",
             "Business impact", "Quick win"]]
    for i, finding in enumerate(sorted(actionable, key=lambda f: -f.priority)[:25],
                                start=1):
        rows.append([str(i), finding.name, finding.severity.label,
                     finding.confidence.label, finding.effort.label,
                     finding.business_impact.label,
                     "yes" if finding.quick_win else ""])

    table = Table([[Paragraph(f"<b>{c}</b>" if i == 0 else html.escape(str(c)),
                              ss["LSmall"]) for c in row]
                   for i, row in enumerate(rows)],
                  colWidths=[0.8 * cm, 6.4 * cm, 1.9 * cm, 2.1 * cm, 1.8 * cm,
                             2.6 * cm, 1.6 * cm],
                  repeatRows=1)
    style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, _RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ])
    for i, finding in enumerate(sorted(actionable, key=lambda f: -f.priority)[:25],
                                start=1):
        style.add("TEXTCOLOR", (2, i), (2, i),
                  colors.HexColor(SEVERITY_HEX[finding.severity]))
        style.add("TEXTCOLOR", (3, i), (3, i),
                  colors.HexColor(CONFIDENCE_HEX[finding.confidence]))
        if finding.quick_win:
            style.add("TEXTCOLOR", (6, i), (6, i), colors.HexColor("#15803d"))
    table.setStyle(style)
    story.append(table)


def _findings_by_severity(story, ss, findings) -> None:
    if not findings:
        return
    story.append(Paragraph("Findings by Severity", ss["LH1"]))
    counts = Counter(f.severity for f in findings)
    conf_counts = Counter(f.confidence for f in findings)

    rows = [["Severity", "Count", "Distribution"]]
    total = len(findings)
    for sev in _SEV_ORDER:
        n = counts.get(sev, 0)
        width = int(36 * n / total) if total else 0
        rows.append([sev.label, str(n), "█" * width])

    table = Table([[Paragraph(f"<b>{c}</b>" if i == 0 else html.escape(str(c)),
                              ss["LSmall"]) for c in row]
                   for i, row in enumerate(rows)],
                  colWidths=[3.0 * cm, 1.8 * cm, 12.4 * cm], repeatRows=1)
    style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _PANEL),
        ("GRID", (0, 0), (-1, -1), 0.3, _RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ])
    for i, sev in enumerate(_SEV_ORDER, start=1):
        style.add("TEXTCOLOR", (0, i), (2, i),
                  colors.HexColor(SEVERITY_HEX[sev]))
    table.setStyle(style)
    story.append(table)

    story.append(Spacer(1, 5))
    story.append(Paragraph(
        "<b>By confidence:</b> " + " · ".join(
            f"<font color='{CONFIDENCE_HEX[c]}'>{c.label} {conf_counts.get(c, 0)}"
            "</font>"
            for c in (Confidence.CONFIRMED, Confidence.HIGH, Confidence.MEDIUM,
                      Confidence.LOW, Confidence.INFORMATIONAL)),
        ss["LSmall"]))


def _findings_by_category(story, ss, findings) -> None:
    if not findings:
        return
    story.append(Paragraph("Findings by Type and Category", ss["LH1"]))

    by_type = defaultdict(list)
    for finding in findings:
        by_type[finding.ftype].append(finding)

    rows = [["Type", "Count", "Categories"]]
    for ftype in _TYPE_ORDER:
        items = by_type.get(ftype)
        if not items:
            continue
        cats = Counter(f.resolved_category() for f in items)
        rows.append([ftype.label, str(len(items)),
                     ", ".join(f"{name} ({n})" for name, n in cats.most_common())])

    table = Table([[Paragraph(f"<b>{c}</b>" if i == 0 else html.escape(str(c)),
                              ss["LSmall"]) for c in row]
                   for i, row in enumerate(rows)],
                  colWidths=[4.4 * cm, 1.6 * cm, 11.2 * cm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, _RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(table)


# --------------------------------------------------------------------------
# Detailed findings
# --------------------------------------------------------------------------

def _details(story, ss, findings) -> None:
    if not findings:
        return
    story.append(PageBreak())
    story.append(Paragraph("Detailed Findings", ss["LH1"]))
    story.append(Paragraph(
        "Findings are grouped by type: reproduced vulnerabilities first, then "
        "unconfirmed leads, then configuration and exposure observations, then "
        "inventory.", ss["LSmall"]))

    by_type = defaultdict(list)
    for finding in findings:
        by_type[finding.ftype].append(finding)

    index = 0
    for ftype in _TYPE_ORDER:
        items = by_type.get(ftype)
        if not items:
            continue
        story.append(Paragraph(f"{ftype.label} ({len(items)})", ss["LH2"]))
        for finding in sorted(items, key=lambda f: -f.priority):
            index += 1
            _one_finding(story, ss, index, finding)


def _one_finding(story, ss, index, f) -> None:
    sev_hex = SEVERITY_HEX[f.severity]
    block = [
        HRFlowable(width="100%", thickness=1.6, color=colors.HexColor(sev_hex),
                   spaceBefore=8, spaceAfter=4),
        Paragraph(
            f"<b>{index}. {html.escape(f.name)}</b>", ss["LBody"]),
        Paragraph(
            f"<font color='{sev_hex}'><b>{f.severity.label}</b></font> · "
            f"<font color='{CONFIDENCE_HEX[f.confidence]}'>{f.confidence.label} "
            f"confidence</font> · {html.escape(f.ftype.label)} · "
            f"{html.escape(f.resolved_category())} · effort: "
            f"{f.effort.label} · business impact: {f.business_impact.label}"
            + (f" · CVSS {f.cvss:.1f}" if f.cvss else ""),
            ss["LSmall"]),
    ]
    story.extend(block)

    _kv(story, ss, "Affected", _locations_text(f))
    if f.summary:
        _kv(story, ss, "Summary", f.summary)
    if f.description:
        _section(story, ss, "Technical detail", f.description)
    if f.risk:
        _section(story, ss, "Why it matters", f.risk)
    if f.impact:
        _section(story, ss, "Potential impact", f.impact)

    if f.severity_reasons:
        story.append(Paragraph("Severity rationale", ss["LH3"]))
        for reason in f.severity_reasons:
            story.append(Paragraph(html.escape(reason), ss["LBullet"],
                                   bulletText="–"))

    if f.request or f.response or f.evidence:
        story.append(Paragraph("Evidence", ss["LH3"]))
        if f.request:
            story.append(Paragraph(_mono(f.request, 600), ss["LMono"]))
        if f.response:
            story.append(Paragraph(_mono(f.response, 600), ss["LMono"]))
        if f.evidence:
            story.append(Paragraph(_mono(f.evidence, 1200), ss["LMono"]))

    if f.verified_by:
        _kv(story, ss, "Verification performed", f.verified_by)

    if f.remediation_steps:
        story.append(Paragraph("Remediation", ss["LH3"]))
        for step in f.remediation_steps:
            story.append(Paragraph(html.escape(step), ss["LBullet"],
                                   bulletText="•"))
    elif f.remediation:
        _section(story, ss, "Remediation", f.remediation)

    if f.verification:
        _section(story, ss, "How to verify the fix", f.verification)

    if f.references:
        story.append(Paragraph(
            "<b>References:</b> " + "<br/>".join(html.escape(r)
                                                 for r in f.references),
            ss["LSmall"]))
    if f.sources:
        story.append(Paragraph(
            f"<font color='#94a3b8'>Reported by: "
            f"{html.escape(', '.join(f.sources))}</font>", ss["LSmall"]))
    story.append(Spacer(1, 4))


def _locations_text(f) -> str:
    locations = f.all_locations()
    if len(locations) == 1:
        return locations[0]
    shown = locations[:12]
    text = "\n".join(shown)
    if len(locations) > len(shown):
        text += f"\n… and {len(locations) - len(shown)} more"
    return text


def _kv(story, ss, label, value) -> None:
    story.append(Paragraph(
        f"<b>{label}:</b> {html.escape(str(value)).replace(chr(10), '<br/>')}",
        ss["LSmall"]))


def _section(story, ss, label, text) -> None:
    story.append(Paragraph(label, ss["LH3"]))
    story.append(Paragraph(
        html.escape(str(text)).replace("\n", "<br/>"), ss["LBody"]))


def _mono(text, limit) -> str:
    text = str(text)
    if len(text) > limit:
        text = text[:limit - 1] + "…"
    return html.escape(text).replace("\n", "<br/>").replace(" ", "&nbsp;")


# --------------------------------------------------------------------------
# Passed checks & appendix
# --------------------------------------------------------------------------

def _passed_checks(story, ss, ctx) -> None:
    if not ctx.passed_checks:
        return
    story.append(PageBreak())
    story.append(Paragraph("Checks Passed", ss["LH1"]))
    story.append(Paragraph(
        "Controls that were tested and found working. These are listed because "
        "a negative result is a result: they are also where scanner output "
        "reporting \"NOT VULNERABLE\" ends up, instead of being converted into "
        "a finding.", ss["LSmall"]))
    story.append(Spacer(1, 5))

    rows = [["Check", "Detail", "Source"]]
    for check in ctx.passed_checks:
        rows.append([check.name, check.detail, check.source])

    table = Table([[Paragraph(f"<b>{c}</b>" if i == 0 else html.escape(str(c)),
                              ss["LSmall"]) for c in row]
                   for i, row in enumerate(rows)],
                  colWidths=[5.4 * cm, 8.8 * cm, 3.0 * cm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#15803d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, _RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(table)


def _appendix(story, ss, ctx, meta) -> None:
    story.append(PageBreak())
    story.append(Paragraph("Appendix A — Tooling", ss["LH1"]))

    rows = [["Tool", "Status", "Version / note"]]
    for name, info in sorted(ctx.tools.items()):
        rows.append([name, "used" if info.available else "skipped",
                     info.version or info.note or "—"])
    table = Table([[Paragraph(f"<b>{c}</b>" if i == 0 else html.escape(str(c)),
                              ss["LSmall"]) for c in row]
                   for i, row in enumerate(rows)],
                  colWidths=[3.6 * cm, 2.4 * cm, 11.2 * cm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, _RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(table)

    notes = meta.get("notes") or []
    if notes:
        story.append(Paragraph("Scan notes", ss["LH2"]))
        for note in notes[:40]:
            story.append(Paragraph(html.escape(str(note)), ss["LSmall"]))

    if ctx.discovered_urls:
        story.append(Paragraph("Appendix B — Discovered URLs", ss["LH1"]))
        listing = sorted(ctx.discovered_urls)
        story.append(Paragraph(
            "<br/>".join(html.escape(u) for u in listing[:250])
            + (f"<br/>… and {len(listing) - 250} more"
               if len(listing) > 250 else ""), ss["LSmall"]))

    if getattr(ctx, "spa_routes", None):
        story.append(Paragraph("Appendix C — Client-side routes", ss["LH1"]))
        story.append(Paragraph(
            "<br/>".join(html.escape(r) for r in ctx.spa_routes[:120]),
            ss["LSmall"]))

    if ctx.raw_outputs:
        story.append(PageBreak())
        story.append(Paragraph("Appendix D — Raw Scanner Output", ss["LH1"]))
        story.append(Paragraph(
            "Verbatim output from each external tool, so any interpretation "
            "made in this report can be checked against its source.",
            ss["LSmall"]))
        for tool, text in sorted(ctx.raw_outputs.items()):
            story.append(Paragraph(tool, ss["LH2"]))
            story.append(Paragraph(_mono(text, 6000), ss["LMono"]))
