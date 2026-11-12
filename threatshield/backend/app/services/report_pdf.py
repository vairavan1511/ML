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
from reportlab.platypus import (
    ListFlowable,
    ListItem,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
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

    report_lines = [
        f"Case ID: {case_id}",
        f"UTC timestamp: {timestamp}",
        f"Verdict: {_text(result.get('verdict'))}",
        f"Risk score: {_text(result.get('risk_score'))}",
        "Reasons:",
        *[f"- {reason}" for reason in reasons],
        "Defanged links:",
        *[f"- {url}" for url in urls],
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
