"""Generate top-5 plain-English reasons from model weights + triggered rules."""
from __future__ import annotations

import json
import re
from pathlib import Path

from app.config import settings

_TOP_TERMS: dict | None = None


def _load_top_terms() -> dict:
    global _TOP_TERMS
    if _TOP_TERMS is None:
        p = settings.artifacts_dir / "top_terms.json"
        _TOP_TERMS = json.loads(p.read_text()) if p.exists() else {}
    return _TOP_TERMS


def _term_reasons(text: str) -> list[tuple[str, int]]:
    """Find top-terms from LR weights that appear in the text."""
    terms = _load_top_terms()
    spam_terms = terms.get("top_spam_terms", [])
    # Whole-word match only, and skip very short terms, so "co" or "to" never match inside words.
    found = [
        t for t in spam_terms
        if len(t) >= 3 and re.search(rf"(?<!\w){re.escape(t.lower())}(?!\w)", text.lower())
    ]
    reasons = []
    for i, t in enumerate(found[:5]):
        weight = len(spam_terms) - spam_terms.index(t)   # higher rank = higher weight
        reasons.append((f"Contains a word often seen in spam: '{t}'", weight))
    return reasons


def build_reasons(
    text: str,
    rule_flags: list[str],
    url_reasons: list[str],
    attachment_flags: list[str],
    ml_prob: float,
) -> list[str]:
    """Return top-5 plain-English reasons, ranked by signal strength."""
    candidates: list[tuple[str, int]] = []

    # (a) Model-weight terms
    candidates.extend(_term_reasons(text))

    # (b) Triggered rules (SMS patterns, header anomalies)
    for i, flag in enumerate(rule_flags):
        candidates.append((flag, 100 - i * 5))   # preserve rule order as priority

    # (c) URL findings
    # URL evidence (e.g. link text that differs from the real target) outranks generic header flags
    for i, r in enumerate(url_reasons):
        candidates.append((r, 105 - i * 2))

    # (d) Attachment findings
    for i, r in enumerate(attachment_flags):
        candidates.append((r, 70 - i * 5))

    # (e) ML confidence note
    if ml_prob >= 0.85:
        candidates.append((
            f"ML model is {ml_prob*100:.0f}% confident this is spam/phishing",
            int(ml_prob * 60)
        ))
    elif ml_prob >= 0.5:
        candidates.append((
            f"ML model flags this as suspicious ({ml_prob*100:.0f}% spam probability)",
            int(ml_prob * 40)
        ))

    # Deduplicate, sort by weight descending, return top 5
    seen: set[str] = set()
    ranked: list[str] = []
    for reason, _ in sorted(candidates, key=lambda x: -x[1]):
        if reason not in seen:
            seen.add(reason)
            ranked.append(reason)
        if len(ranked) == 5:
            break

    return ranked or ["No strong spam/phishing signals detected"]
