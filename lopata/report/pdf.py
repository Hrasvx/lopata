from __future__ import annotations

import datetime
import html
from collections import Counter

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (HRFlowable, PageBreak, Paragraph,
                               SimpleDocTemplate, Spacer, Table, TableStyle)

from ..core.models import SEVERITY_HEX, Confidence, Severity

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
              Severity.LOW, Severity.INFO]

_SEV_WEIGHT = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 8,
               Severity.LOW: 2, Severity.INFO: 0}


def default_report_name(target: str) -> str:
    host = target.replace("https://", "").replace("http://", "").strip("/")
    host = host.replace("/", "_").replace(":", "_")
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"lopata_report_{host}_{ts}.pdf"


def _risk_score(findings) -> int:
    score = sum(_SEV_WEIGHT[f.severity] for f in findings)
    return min(100, score)


def _risk_band(score: int) -> tuple[str, colors.Color]:
    if score >= 60:
        return "CRITICAL", colors.HexColor(SEVERITY_HEX[Severity.CRITICAL])
    if score >= 35:
        return "HIGH", colors.HexColor(SEVERITY_HEX[Severity.HIGH])
    if score >= 15:
        return "MEDIUM", colors.HexColor(SEVERITY_HEX[Severity.MEDIUM])
    if score > 0:
        return "LOW", colors.HexColor(SEVERITY_HEX[Severity.LOW])
    return "MINIMAL", colors.HexColor(SEVERITY_HEX[Severity.INFO])


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("LTitle", parent=ss["Title"], fontSize=22,
                          textColor=colors.HexColor("#0f172a")))
    ss.add(ParagraphStyle("LH2", parent=ss["Heading2"], fontSize=14,
                          textColor=colors.HexColor("#0f172a"), spaceBefore=14))
    ss.add(ParagraphStyle("LSmall", parent=ss["Normal"], fontSize=8,
                          textColor=colors.HexColor("#475569")))
    ss.add(ParagraphStyle("LMono", parent=ss["Code"], fontSize=7.5,
                          textColor=colors.HexColor("#0f172a"),
                          backColor=colors.HexColor("#f1f5f9"), leading=10))
    ss.add(ParagraphStyle("LBody", parent=ss["Normal"], fontSize=9.5, leading=13))
    return ss


def generate_report(ctx, path: str, meta: dict) -> None:
    doc = SimpleDocTemplate(path, pagesize=A4, title="lopata scan report",
                            leftMargin=1.8 * cm, rightMargin=1.8 * cm,
                            topMargin=1.6 * cm, bottomMargin=1.6 * cm)
    ss = _styles()
    story = []
    findings = sorted(ctx.findings, key=lambda f: (int(f.severity),
                                                   int(f.confidence)),
                      reverse=True)

    _cover(story, ss, ctx, findings, meta)
    _summary(story, ss, findings)
    _findings_table(story, ss, findings)
    _details(story, ss, findings)
    _tools_appendix(story, ss, ctx)

    doc.build(story)


def _cover(story, ss, ctx, findings, meta) -> None:
    story.append(Paragraph("lopata", ss["LTitle"]))
    story.append(Paragraph("Web Application Security Scan Report", ss["LH2"]))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 8))

    score = _risk_score(findings)
    band, band_color = _risk_band(score)
    started = meta.get("started_at")
    finished = meta.get("finished_at")
    info = [
        ["Target", ctx.target],
        ["Scan started", started.strftime("%Y-%m-%d %H:%M UTC") if started else "—"],
        ["Duration", f"{meta.get('duration_seconds', 0):.1f} s"],
        ["Modules run", str(len(ctx.modules_run))],
        ["URLs discovered", str(len(ctx.discovered_urls))],
        ["Risk score", f"{score}/100  ({band})"],
    ]
    t = Table(info, colWidths=[4 * cm, 11 * cm])
    t.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, -1), "Helvetica", 9.5),
        ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 9.5),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#475569")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#e2e8f0")),
        ("TEXTCOLOR", (1, 5), (1, 5), band_color),
        ("FONT", (1, 5), (1, 5), "Helvetica-Bold", 9.5),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "This report is the result of authorized security testing. It is "
        "confidential and intended solely for the system owner.", ss["LSmall"]))


def _summary(story, ss, findings) -> None:
    story.append(Paragraph("Executive Summary", ss["LH2"]))
    counts = Counter(f.severity for f in findings)
    confirmed = sum(1 for f in findings if f.confidence == Confidence.CONFIRMED)
    leads = sum(1 for f in findings if f.confidence == Confidence.TENTATIVE)

    rows = [["Severity", "Count", ""]]
    total = len(findings)
    for sev in _SEV_ORDER:
        n = counts.get(sev, 0)
        bar_w = int(30 * n / total) if total else 0
        rows.append([sev.label, str(n), "█" * bar_w])
    body = [
        TableStyle([
            ("FONT", (0, 0), (-1, -1), "Helvetica", 9.5),
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9.5),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
        ])
    ]
    style = body[0]
    for i, sev in enumerate(_SEV_ORDER, start=1):
        c = colors.HexColor(SEVERITY_HEX[sev])
        style.add("TEXTCOLOR", (0, i), (0, i), c)
        style.add("TEXTCOLOR", (2, i), (2, i), c)
        style.add("FONT", (0, i), (0, i), "Helvetica-Bold", 9.5)
    t = Table(rows, colWidths=[3.5 * cm, 2 * cm, 9.5 * cm])
    t.setStyle(style)
    story.append(t)
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"<b>{total}</b> findings total — <b>{confirmed}</b> confirmed, "
        f"<b>{leads}</b> low-confidence lead(s) flagged for manual review.",
        ss["LBody"]))


def _findings_table(story, ss, findings) -> None:
    if not findings:
        return
    story.append(Paragraph("Findings Overview", ss["LH2"]))
    header = ["#", "Type", "Endpoint", "Severity", "Confidence"]
    rows = [header]
    for i, f in enumerate(findings, 1):
        rows.append([
            str(i),
            Paragraph(html.escape(f.name), ss["LSmall"]),
            Paragraph(html.escape(_trim(f.location, 60)), ss["LSmall"]),
            f.severity.label,
            f.confidence.label,
        ])
    t = Table(rows, colWidths=[0.8 * cm, 4.2 * cm, 6.5 * cm, 2 * cm, 2 * cm],
              repeatRows=1)
    style = TableStyle([
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
        ("FONT", (0, 1), (-1, -1), "Helvetica", 8.5),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f8fafc")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
    ])
    for i, f in enumerate(findings, 1):
        style.add("TEXTCOLOR", (3, i), (3, i),
                  colors.HexColor(SEVERITY_HEX[f.severity]))
        style.add("FONT", (3, i), (3, i), "Helvetica-Bold", 8.5)
    t.setStyle(style)
    story.append(t)


def _details(story, ss, findings) -> None:
    if not findings:
        return
    story.append(PageBreak())
    story.append(Paragraph("Detailed Findings", ss["LH2"]))
    for i, f in enumerate(findings, 1):
        c = colors.HexColor(SEVERITY_HEX[f.severity])
        story.append(Spacer(1, 6))
        story.append(HRFlowable(width="100%", thickness=2, color=c))
        story.append(Paragraph(
            f"<b>{i}. {html.escape(f.name)}</b> "
            f"<font color='{SEVERITY_HEX[f.severity]}'>[{f.severity.label}]</font> "
            f"<font size=8 color='#64748b'>· {f.confidence.label} · "
            f"{html.escape(f.resolved_category())}</font>",
            ss["LBody"]))
        story.append(Paragraph(f"<b>Location:</b> {html.escape(f.location)}",
                               ss["LSmall"]))
        story.append(Spacer(1, 3))
        story.append(Paragraph(html.escape(f.description), ss["LBody"]))
        if f.request:
            story.append(Spacer(1, 2))
            story.append(Paragraph("Request", ss["LSmall"]))
            story.append(Paragraph(html.escape(_trim(f.request, 400)), ss["LMono"]))
        if f.response:
            story.append(Paragraph("Response", ss["LSmall"]))
            story.append(Paragraph(html.escape(_trim(f.response, 400)), ss["LMono"]))
        if f.evidence:
            story.append(Paragraph("Evidence", ss["LSmall"]))
            story.append(Paragraph(html.escape(_trim(f.evidence, 500)), ss["LMono"]))
        story.append(Spacer(1, 3))
        story.append(Paragraph(f"<b>Remediation:</b> {html.escape(f.remediation)}",
                               ss["LBody"]))


def _tools_appendix(story, ss, ctx) -> None:
    story.append(PageBreak())
    story.append(Paragraph("External Tools Used", ss["LH2"]))
    if not ctx.tools:
        story.append(Paragraph("No external tools were invoked.", ss["LBody"]))
        return
    rows = [["Tool", "Status", "Version / Note"]]
    for name, info in sorted(ctx.tools.items()):
        status = "used" if info.available else "skipped"
        detail = info.version or info.note or ""
        rows.append([name, status, _trim(detail, 60)])
    t = Table(rows, colWidths=[4 * cm, 3 * cm, 8 * cm], repeatRows=1)
    t.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
        ("FONT", (0, 1), (-1, -1), "Helvetica", 8.5),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "lopata is for authorized security testing only. Findings marked "
        "\"Tentative\" are leads requiring manual confirmation.", ss["LSmall"]))


def _trim(text: str, n: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[:n - 1] + "…"
