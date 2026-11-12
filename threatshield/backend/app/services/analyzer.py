"""Central analysis orchestrator — loads model once, routes email/SMS."""
from __future__ import annotations

import json
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

import joblib
import sys as _sys

from app.config import settings

# ml/ must be on sys.path so joblib can unpickle the features module
_ML_DIR = str(settings.artifacts_dir.parent)
if _ML_DIR not in _sys.path:
    _sys.path.insert(0, _ML_DIR)
from app.services.urls import analyse_url
from app.services.sms import analyse_sms
from app.services.email_parser import parse_email
from app.services.scoring import score_email, score_sms
from app.services.explain import build_reasons
from app.services.highlight import get_highlights
from app.services.header_forensics import analyse_headers
from app.services.geolocate import locate_ip
import email as _email
import email.policy as _policy


@lru_cache(maxsize=1)
def _load_model():
    """Load sklearn pipeline once; cached for the process lifetime."""
    p = settings.artifacts_dir / "model.joblib"
    if not p.exists():
        raise FileNotFoundError(f"model.joblib not found at {p}")
    return joblib.load(p)


def _ml_score(text: str) -> float:
    """Return spam probability 0-1 from the sklearn pipeline."""
    try:
        pipe = _load_model()
        prob = pipe.predict_proba([text])[0][1]
        return float(prob)
    except Exception:
        return 0.0


def _url_results(links: list[dict]) -> tuple[list[dict], list[int], list[str]]:
    """Analyse all links; return (url_result_dicts, risk_scores, flat_reasons)."""
    results, scores, reasons = [], [], []
    for link in links:
        r = analyse_url(link.get("href", ""), link_text=link.get("text") or None)
        results.append(r)
        scores.append(r["risk"])
        if r["risk"] > 0:  # a benign link adds no reason (avoids "no signals" text beside warnings)
            reasons.extend(r["reasons"])
    return results, scores, reasons


def analyse_email_text(raw: str | bytes) -> dict[str, Any]:
    """Full analysis pipeline for an email (raw source or pasted text)."""
    parsed = parse_email(raw)
    body   = parsed["body_text"]
    full_text = f"{parsed['subject']} {parsed['from_']} {body}"

    ml_prob = _ml_score(full_text)
    url_results, url_scores, url_reasons = _url_results(parsed["links"])

    # Header forensics: Received chain, stated authentication, spoofing checks
    raw_bytes = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw
    msg = _email.message_from_bytes(raw_bytes, policy=_policy.compat32)
    forensics = analyse_headers(msg, body_text=body, subject=parsed["subject"])
    header_score = float(forensics["score"])
    geo = locate_ip(forensics["origin"]["ip"])

    # Attachment score: penalise executable/macro types
    att_flags = _attachment_flags(parsed["attachments"])
    att_score = min(100.0, len(att_flags) * 30)

    header_flags = [f["detail"] for f in forensics["findings"]]
    risk, verdict = score_email(ml_prob, url_scores, header_score, att_score)
    reasons = build_reasons(full_text, att_flags + header_flags, url_reasons, [], ml_prob)
    highlights = get_highlights(full_text)

    return {
        "verdict": verdict,
        "risk_score": risk,
        "reasons": reasons,
        "highlights": highlights,
        "urls": url_results,
        "ml_score": round(ml_prob, 4),
        "channel": "email",
        "forensics": forensics,
        "geolocation": geo,
        "metadata": {
            "subject": parsed["subject"],
            "from_": parsed["from_"],
            "reply_to": parsed["reply_to"],
            "attachments": parsed["attachments"],
            "auth": parsed["auth"],
            "parse_error": parsed.get("_parse_error"),
            "html_preview": parsed["html_preview"],
        },
    }


def analyse_sms_text(text: str, sender: str | None = None) -> dict[str, Any]:
    """Full analysis pipeline for an SMS."""
    ml_prob = _ml_score(text)
    sms_analysis = analyse_sms(text, sender)

    links = [{"href": u, "text": ""} for u in
             __import__("re").findall(r"https?://\S+|www\.\S+", text, __import__("re").I)]
    url_results, url_scores, url_reasons = _url_results(links)

    risk, verdict = score_sms(ml_prob, url_scores, sms_analysis["pattern_score"])
    reasons = build_reasons(
        text,
        sms_analysis["flags"],
        url_reasons,
        [],
        ml_prob,
    )
    highlights = get_highlights(text)

    return {
        "verdict": verdict,
        "risk_score": risk,
        "reasons": reasons,
        "highlights": highlights,
        "urls": url_results,
        "ml_score": round(ml_prob, 4),
        "channel": "sms",
        "metadata": {
            "sender": sender,
            "patterns": sms_analysis["patterns"],
            "sender_suspicious": sms_analysis["sender_suspicious"],
            "hidden_unicode": sms_analysis["hidden_unicode"],
        },
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

def _attachment_flags(attachments: list[dict]) -> list[str]:
    RISKY_TYPES = {
        "application/x-msdownload", "application/x-executable",
        "application/vnd.ms-excel.sheet.macroEnabled.12",
        "application/vnd.ms-word.document.macroEnabled.12",
        "application/zip", "application/x-rar-compressed",
        "application/x-7z-compressed",
    }
    RISKY_EXTS = {".exe", ".bat", ".cmd", ".vbs", ".js", ".jar",
                  ".xlsm", ".docm", ".ps1", ".scr", ".com"}
    flags = []
    for att in attachments:
        ext = Path(att.get("filename", "")).suffix.lower()
        ct  = att.get("content_type", "")
        if ext in RISKY_EXTS or ct in RISKY_TYPES:
            flags.append(f"Attachment '{att['filename']}' is a potentially dangerous file type")
    return flags
