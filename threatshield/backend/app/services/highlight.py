"""Return list of suspicious token spans to highlight in the UI."""
from __future__ import annotations

import json
import re
from pathlib import Path

from app.config import settings

_SPAM_TERMS: list[str] = []

PATTERN_WORDS = re.compile(
    r"\b(otp|kyc|upi|urgent|immediately|verify|suspend|block|expire|"
    r"confirm|alert|warning|free|prize|winner|lottery|congratulations|"
    r"loan|click here|act now|limited|offer|account|password|credential|"
    r"rs\.\d+|inr\s*\d+|\d{6})\b",
    re.I,
)

URL_RE = re.compile(r"https?://\S+|www\.\S+", re.I)


def _load_spam_terms() -> list[str]:
    global _SPAM_TERMS
    if not _SPAM_TERMS:
        p = settings.artifacts_dir / "top_terms.json"
        if p.exists():
            data = json.loads(p.read_text())
            _SPAM_TERMS = [t.lower() for t in data.get("top_spam_terms", [])]
    return _SPAM_TERMS


def get_highlights(text: str) -> list[str]:
    """Return unique suspicious tokens found in text."""
    found: set[str] = set()

    # Pattern-based keywords
    for m in PATTERN_WORDS.finditer(text):
        found.add(m.group(0))

    # Top spam terms from model
    # Whole-word matches only, and short terms are skipped, so "our" never highlights "your"
    for term in _load_spam_terms():
        if len(term) < 3:
            continue
        for m in re.finditer(rf"(?<!\w){re.escape(term)}(?!\w)", text, re.I):
            found.add(m.group(0))

    # URLs are always highlighted
    for m in URL_RE.finditer(text):
        found.add(m.group(0))

    return sorted(found, key=lambda s: text.lower().find(s.lower()))
