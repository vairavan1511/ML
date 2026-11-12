from __future__ import annotations

from pathlib import Path
import sys

from fastapi.testclient import TestClient

_backend = str(Path(__file__).parent.parent)
_ml = str(Path(__file__).parent.parent.parent / "ml")
for _path in (_backend, _ml):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from app.main import app

client = TestClient(app)
PHISHING_SAMPLE = Path(__file__).parent.parent.parent / "samples" / "phishing_email.eml"


def test_phishing_analysis_report_download():
    response = client.post(
        "/api/analyze/email",
        files={"file": ("phishing_email.eml", PHISHING_SAMPLE.read_bytes(), "message/rfc822")},
    )
    assert response.status_code == 200
    case_id = response.json()["case_id"]

    report = client.get(f"/api/report/{case_id}.pdf")
    assert report.status_code == 200
    assert report.headers["content-type"].startswith("application/pdf")
    assert report.content.startswith(b"%PDF")


def test_unknown_case_report_returns_404():
    response = client.get("/api/report/unknown-case.pdf")
    assert response.status_code == 404
