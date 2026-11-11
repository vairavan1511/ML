"""Risk scoring: combines ML + URL + pattern/header/attachment signals."""
from __future__ import annotations

import math
from app.config import settings


def _verdict(score: int) -> str:
    if score < settings.threshold_safe:
        return "SAFE"
    if score < settings.threshold_suspicious:
        return "SUSPICIOUS"
    return "SPAM-PHISHING"


def score_email(
    ml_prob: float,
    url_scores: list[int],
    header_score: float = 0.0,
    attachment_score: float = 0.0,
) -> tuple[int, str]:
    """Return (risk_score 0-100, verdict) for an email.

    Missing signals (score=0) cause their weight to be redistributed.
    """
    signals = {
        "ml":         (ml_prob * 100,       settings.email_weight_ml),
        "url":        (_agg_url(url_scores), settings.email_weight_url),
        "header":     (header_score,         settings.email_weight_header),
        "attachment": (attachment_score,      settings.email_weight_attachment),
    }
    return _weighted(signals)


def score_sms(
    ml_prob: float,
    url_scores: list[int],
    pattern_score: float = 0.0,
) -> tuple[int, str]:
    """Return (risk_score 0-100, verdict) for an SMS."""
    signals = {
        "ml":      (ml_prob * 100,       settings.sms_weight_ml),
        "url":     (_agg_url(url_scores), settings.sms_weight_url),
        "pattern": (pattern_score,        settings.sms_weight_pattern),
    }
    return _weighted(signals)


def _agg_url(scores: list[int]) -> float:
    """Aggregate URL scores: max + small bonus for multiple risky URLs."""
    if not scores:
        return 0.0
    top = max(scores)
    bonus = min(10, sum(1 for s in scores if s >= 30) * 3)
    return min(100.0, top + bonus)


def _weighted(signals: dict[str, tuple[float, float]]) -> tuple[int, str]:
    """Renormalise weights for any zero-value signals, compute weighted sum."""
    total_weight = sum(w for _, w in signals.values())
    if total_weight == 0:
        return 0, "SAFE"
    composite = sum(v * w for v, w in signals.values()) / total_weight
    score = min(100, max(0, round(composite)))
    return score, _verdict(score)
