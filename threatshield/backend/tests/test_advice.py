from __future__ import annotations

from pathlib import Path
import sys

_backend = str(Path(__file__).parent.parent)
if _backend not in sys.path:
    sys.path.insert(0, _backend)

from app.services.advice import advice_for


def test_each_verdict_has_advice_steps():
    for verdict in ("SAFE", "SUSPICIOUS", "SPAM-PHISHING"):
        advice = advice_for(verdict)
        assert advice["title"]
        assert advice["steps"]
        assert all(advice["steps"])
