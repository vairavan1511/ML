"""PDF report generation for saved analysis cases."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    ListFlowable,
    ListItem,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.config import settings

_NOT_AVAILABLE = "not available"
_LIMITATIONS = (
    "This automated analysis is informational and may be incorrect. "
    "It does not verify the sender's identity or guarantee that a message is safe."
)


def _model_metrics() -> tuple[str, str]:
    metrics_path = settings.artifacts_dir / "metrics.json"
    if not metrics_path.exists():
        return _NOT_AVAILABLE, _NOT_AVAILABLE

    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    model_name = metrics.get("best_model") or _NOT_AVAILABLE
    overall = metrics.get("test_metrics_overall")
    test_f1 = overall.get("f1") if isinstance(overall, dict) else None
    return str(model_name), str(test_f1) if test_f1 is not None else _NOT_AVAILABLE


def _text(value) -> str:
    return _NOT_AVAILABLE if value is None or value == "" else str(value)


def _forensic_summary(result: dict) -> dict:
    """Return origin, location, hops and checks from a stored analysis result."""
    forensics = result.get("forensics") or {}
    geo = result.get("geolocation") or {}
    origin = forensics.get("origin") or {}
    location = "Not available"
    if geo.get("available"):
        location = ", ".join(x for x in (geo.get("city"), geo.get("country")) if x) or "Not available"
    return {
        "origin_ip": _text(origin.get("ip")),
        "confidence": _text(origin.get("confidence")),
        "origin_reason": _text(origin.get("reason")),
        "location": location,
        "location_note": _text(geo.get("reason")),
        "hops": forensics.get("hops") or [],
        "findings": forensics.get("findings") or [],
        "is_email": result.get("channel") == "email",
    }


def _forensic_text_lines(fx: dict) -> list[str]:
    """Plain-text lines for the hashed report text."""
    if not fx["is_email"]:
        return []
    lines = [
        f"Origin IP: {fx['origin_ip']}",
        f"Origin confidence: {fx['confidence']}",
        f"Origin note: {fx['origin_reason']}",
        f"Location: {fx['location']}",
        f"Location note: {fx['location_note']}",
        "Received chain (oldest hop first):",
    ]
    if not fx["hops"]:
        lines.append("- no Received headers")
    for hop in fx["hops"]:
        lines.append(
            f"- hop {hop.get('hop')}: from {hop.get('from_host') or '-'} by {hop.get('by_host') or '-'}"
            f" ip {hop.get('ip') or '-'} time {hop.get('timestamp') or '-'}"
            f" delay {hop.get('delay_seconds') if hop.get('delay_seconds') is not None else '-'}s"
            f" note {hop.get('anomaly') or 'none'}"
        )
    lines.append("Checks:")
    if not fx["findings"]:
        lines.append("- none triggered")
    for finding in fx["findings"]:
        lines.append(f"- [{finding.get('kind')}] {finding.get('detail')} (weight {finding.get('severity')})")
    return lines


def _forensic_story(fx: dict, styles) -> list:
    """Flowables for the origin, hop table and checks sections of the PDF."""
    if not fx["is_email"]:
        return []
    cell = styles["BodyText"]
    story: list = [
        Paragraph("Origin and location", styles["Heading2"]),
        Paragraph(f"<b>Origin IP:</b> {escape(fx['origin_ip'])}", cell),
        Paragraph(f"<b>Confidence:</b> {escape(fx['confidence'])}", cell),
        Paragraph(escape(fx["origin_reason"]), cell),
        Paragraph(f"<b>Location:</b> {escape(fx['location'])}", cell),
        Paragraph(escape(fx["location_note"]), cell),
        Spacer(1, 3 * mm),
        Paragraph("Received chain (oldest hop first)", styles["Heading2"]),
    ]
    if fx["hops"]:
        rows = [[Paragraph(h, cell) for h in ("Hop", "From", "By", "IP", "Time (UTC)", "Delay", "Note")]]
        for hop in fx["hops"]:
            delay = hop.get("delay_seconds")
            rows.append([
                Paragraph(escape(str(hop.get("hop", ""))), cell),
                Paragraph(escape(hop.get("from_host") or "-"), cell),
                Paragraph(escape(hop.get("by_host") or "-"), cell),
                Paragraph(escape(hop.get("ip") or "-"), cell),
                Paragraph(escape(hop.get("timestamp") or "-"), cell),
                Paragraph("-" if delay is None else f"{delay}s", cell),
                Paragraph(escape(hop.get("anomaly") or "none"), cell),
            ])
        table = Table(rows, repeatRows=1, colWidths=[12 * mm, 34 * mm, 34 * mm, 28 * mm, 34 * mm, 14 * mm, 28 * mm])
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No Received headers in this message, so the route cannot be traced.", cell))
    story += [Spacer(1, 3 * mm), Paragraph("Checks", styles["Heading2"])]
    if fx["findings"]:
        story.append(ListFlowable(
            [ListItem(Paragraph(escape(f"[{f.get('kind')}] {f.get('detail')} (weight {f.get('severity')})"), cell))
             for f in fx["findings"]],
            bulletType="bullet", leftIndent=16,
        ))
    else:
        story.append(Paragraph("No header or sender checks were triggered.", cell))
    return story


def generate_report(case_id: str, result: dict) -> bytes:
    """Return an A4 PDF for an analysis result."""
    timestamp = datetime.now(timezone.utc).isoformat()
    model_name, test_f1 = _model_metrics()
    reasons = [_text(reason) for reason in result.get("reasons", [])] or [_NOT_AVAILABLE]
    urls = [
        _text(url.get("defanged"))
        for url in result.get("urls", [])
        if isinstance(url, dict) and url.get("defanged")
    ] or [_NOT_AVAILABLE]

    fx = _forensic_summary(result)
    report_lines = [
        f"Case ID: {case_id}",
        f"UTC timestamp: {timestamp}",
        f"Verdict: {_text(result.get('verdict'))}",
        f"Risk score: {_text(result.get('risk_score'))}",
        "Reasons:",
        *[f"- {reason}" for reason in reasons],
        "Defanged links:",
        *[f"- {url}" for url in urls],
        *_forensic_text_lines(fx),
        f"Model name: {model_name}",
        f"Test F1: {test_f1}",
        f"Limitations: {_LIMITATIONS}",
    ]
    report_text = "\n".join(report_lines)
    report_hash = sha256(report_text.encode("utf-8")).hexdigest()

    styles = getSampleStyleSheet()
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=20 * mm,
        title=f"ThreatShield report {case_id}",
    )
    story = [
        Paragraph("ThreatShield Analysis Report", styles["Title"]),
        Spacer(1, 8 * mm),
        Paragraph(f"<b>Case ID:</b> {escape(case_id)}", styles["BodyText"]),
        Paragraph(f"<b>UTC timestamp:</b> {escape(timestamp)}", styles["BodyText"]),
        Paragraph(f"<b>Verdict:</b> {escape(_text(result.get('verdict')))}", styles["BodyText"]),
        Paragraph(f"<b>Risk score:</b> {escape(_text(result.get('risk_score')))}", styles["BodyText"]),
        Spacer(1, 4 * mm),
        Paragraph("Reasons", styles["Heading2"]),
        ListFlowable(
            [ListItem(Paragraph(escape(reason), styles["BodyText"])) for reason in reasons],
            bulletType="bullet",
            leftIndent=16,
        ),
        Spacer(1, 4 * mm),
        Paragraph("Defanged links", styles["Heading2"]),
        ListFlowable(
            [ListItem(Paragraph(escape(url), styles["BodyText"])) for url in urls],
            bulletType="bullet",
            leftIndent=16,
        ),
        Spacer(1, 4 * mm),
        *_forensic_story(fx, styles),
        Spacer(1, 4 * mm),
        Paragraph(f"<b>Model name:</b> {escape(model_name)}", styles["BodyText"]),
        Paragraph(f"<b>Test F1:</b> {escape(test_f1)}", styles["BodyText"]),
        Spacer(1, 4 * mm),
        Paragraph("Limitations", styles["Heading2"]),
        Paragraph(escape(_LIMITATIONS), styles["BodyText"]),
    ]

    def draw_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.drawString(
            doc.leftMargin,
            10 * mm,
            f"Report text SHA-256: {report_hash}",
        )
        canvas.restoreState()

    document.build(story, onFirstPage=draw_footer, onLaterPages=draw_footer)
    return buffer.getvalue()
