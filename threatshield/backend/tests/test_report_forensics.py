"""The PDF report must carry the origin, the Received chain and the checks."""
from __future__ import annotations

import io
import sys
from pathlib import Path

_backend = str(Path(__file__).parent.parent)
_ml = str(Path(__file__).parent.parent.parent / "ml")
for _path in (_backend, _ml):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from pdfminer.high_level import extract_text  # noqa: E402

from app.services.analyzer import analyse_email_text  # noqa: E402
from app.services.report_pdf import generate_report  # noqa: E402

SAMPLE = Path(__file__).parent.parent.parent / "samples" / "phishing_email.eml"


def _pdf_text(result: dict) -> str:
    pdf = generate_report("case-test", result)
    assert pdf.startswith(b"%PDF")
    return extract_text(io.BytesIO(pdf))


def test_email_report_has_origin_hops_and_checks():
    text = _pdf_text(analyse_email_text(SAMPLE.read_bytes()))
    assert "Origin IP: 45.76.10.25" in text
    assert "Received chain" in text
    assert "Checks" in text
    assert "SPF failed" in text


def test_location_is_not_invented_without_database():
    text = _pdf_text(analyse_email_text(SAMPLE.read_bytes()))
    assert "Location: Not available" in text


def test_report_footer_hash_is_still_present():
    text = _pdf_text(analyse_email_text(SAMPLE.read_bytes()))
    assert "Report text SHA-256:" in text
