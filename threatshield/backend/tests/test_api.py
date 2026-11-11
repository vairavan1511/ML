"""
Pytest suite for ThreatShield backend.
Run from threatshield/: pytest backend/tests/ -v
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure app and ml packages are importable
import sys
_backend = str(Path(__file__).parent.parent)
_ml     = str(Path(__file__).parent.parent.parent / "ml")
for _p in (_backend, _ml):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from app.main import app

client = TestClient(app)
SAMPLES = Path(__file__).parent.parent.parent / "samples"


# ── Health & meta ─────────────────────────────────────────────────────────────

def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["model_loaded"] is True


def test_model_info():
    r = client.get("/api/model/info")
    assert r.status_code == 200
    data = r.json()
    assert "best_model" in data
    assert data["best_model"] != ""
    assert "f1" in data["test_metrics_overall"]
    assert len(data["top_spam_terms"]) > 0


# ── URL analysis ──────────────────────────────────────────────────────────────

def test_url_safe():
    r = client.post("/api/analyze/url", json={"text": "https://www.example.com/page"})
    assert r.status_code == 200
    data = r.json()
    assert data["risk"] < 60
    assert data["level"] in ("LOW", "MEDIUM")


def test_url_phishing():
    r = client.post("/api/analyze/url", json={"text": "http://sbi.secure-login.xyz/verify?redirect=http://evil.top"})
    assert r.status_code == 200
    data = r.json()
    assert data["risk"] >= 30
    assert data["defanged"].startswith("hxxp")


def test_url_ip_host():
    r = client.post("/api/analyze/url", json={"text": "http://192.168.1.1/login"})
    assert r.status_code == 200
    assert r.json()["risk"] >= 30


# ── SMS analysis ──────────────────────────────────────────────────────────────

def test_sms_otp_scam():
    text = (SAMPLES / "spam_sms.txt").read_text().strip()
    r = client.post("/api/analyze/sms", json={"text": text, "sender": "+919876543210"})
    assert r.status_code == 200
    data = r.json()
    assert data["verdict"] in ("SUSPICIOUS", "SPAM-PHISHING")
    assert data["risk_score"] >= 30
    assert len(data["reasons"]) > 0


def test_sms_safe():
    text = (SAMPLES / "safe_sms.txt").read_text().strip()
    r = client.post("/api/analyze/sms", json={"text": text})
    assert r.status_code == 200
    data = r.json()
    # Safe OTP notification — model may flag "otp" but overall score should be lower
    assert data["risk_score"] < 80   # not a definitive phishing score
    assert data["channel"] == "sms"


def test_sms_empty_rejected():
    r = client.post("/api/analyze/sms", json={"text": "   "})
    assert r.status_code == 422


# ── Email analysis ────────────────────────────────────────────────────────────

def test_email_safe():
    raw = (SAMPLES / "safe_email.eml").read_bytes()
    r = client.post("/api/analyze/email", files={"file": ("safe_email.eml", raw, "message/rfc822")})
    assert r.status_code == 200
    data = r.json()
    assert data["verdict"] == "SAFE"
    assert data["risk_score"] < 30


def test_email_phishing():
    raw = (SAMPLES / "phishing_email.eml").read_bytes()
    r = client.post("/api/analyze/email", files={"file": ("phishing_email.eml", raw, "message/rfc822")})
    assert r.status_code == 200
    data = r.json()
    assert data["verdict"] in ("SUSPICIOUS", "SPAM-PHISHING")
    assert data["risk_score"] >= 30
    assert len(data["urls"]) > 0


def test_email_raw_text():
    raw = (SAMPLES / "phishing_email.eml").read_text()
    r = client.post("/api/analyze/email", data={"text": raw})
    assert r.status_code == 200
    assert r.json()["risk_score"] >= 30


def test_email_malformed_never_crashes():
    r = client.post("/api/analyze/email", data={"text": "not an email at all <<<>>>"})
    assert r.status_code == 200   # must not 500


def test_email_bad_extension():
    r = client.post("/api/analyze/email",
                    files={"file": ("malware.exe", b"MZ\x90\x00", "application/octet-stream")})
    assert r.status_code == 400


def test_email_no_input():
    r = client.post("/api/analyze/email")
    assert r.status_code == 422
