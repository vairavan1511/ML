from __future__ import annotations

from io import BytesIO
import re
from pathlib import Path
import sys

_backend = str(Path(__file__).parent.parent)
if _backend not in sys.path:
    sys.path.insert(0, _backend)

from app.services.report_pdf import generate_report
from pdfminer.high_level import extract_text


def test_report_footer_hash_is_extractable():
    pdf = generate_report(
        "TEST123",
        {
            "verdict": "SPAM-PHISHING",
            "risk_score": 80,
            "reasons": ["test reason"],
            "urls": [],
        },
    )
    text = extract_text(BytesIO(pdf))

    assert re.search(r"SHA-256:\s*[0-9a-f]{64}\b", text)
