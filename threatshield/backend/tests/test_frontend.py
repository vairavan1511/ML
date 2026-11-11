"""
Pytest suite for ThreatShield frontend.
Run from threatshield/: pytest backend/tests/ -v
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure app and ml packages are importable
import sys
_backend = str(Path(__file__).parent.parent)
_ml = str(Path(__file__).parent.parent.parent / "ml")
for _p in (_backend, _ml):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from app.main import app

client = TestClient(app)
FRONTEND = Path(__file__).parent.parent.parent / "frontend"
METRICS = Path(__file__).parent.parent.parent / "ml" / "artifacts" / "metrics.json"


def test_root_returns_html():
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
    body = r.text
    assert body.lstrip().lower().startswith("<!doctype html>") or "<html" in body[:200].lower()


def test_no_message_link_anchors():
    """The page must not render message URLs as clickable <a> tags (S3b adds Link Shield)."""
    html = client.get("/").text
    assert "<a href" not in html


def test_model_info_matches_metrics():
    r = client.get("/api/model/info")
    assert r.status_code == 200
    data = r.json()
    metrics = json.loads(METRICS.read_text())
    assert data["best_model"] == metrics["best_model"]
    assert data["test_metrics_overall"] == metrics["test_metrics_overall"]
    assert data["test_metrics_by_channel"] == metrics["test_metrics_by_channel"]
    assert data["model_comparison_on_val"] == metrics["model_comparison_on_val"]
    assert data["dataset_sizes"] == metrics["dataset_sizes"]
