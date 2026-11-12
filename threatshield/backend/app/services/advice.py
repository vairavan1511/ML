"""Verdict-specific user guidance."""
from __future__ import annotations

from copy import deepcopy

_ADVICE = {
    "SAFE": {
        "title": "Stay alert",
        "steps": [
            "Stay alert, even when a message appears safe.",
            "Never share personal information in response to an unsolicited message.",
        ],
    },
    "SUSPICIOUS": {
        "title": "Verify before taking action",
        "steps": [
            "Do not click links in the message.",
            "Verify the request through the organisation's official app or website.",
        ],
    },
    "SPAM-PHISHING": {
        "title": "Protect your accounts and report the message",
        "steps": [
            "Do not click links or reply to the message.",
            "Never share your OTP, PIN, or CVV.",
            "Block the sender and delete the message.",
            "For financial fraud, report it at cybercrime.gov.in or call helpline 1930.",
            'For suspicious messages, use the Sanchar Saathi "Chakshu" option; verify the current process.',
        ],
    },
}


def advice_for(verdict: str) -> dict:
    key = verdict.strip().upper()
    if key not in _ADVICE:
        raise ValueError(f"Unsupported verdict: {verdict}")
    return deepcopy(_ADVICE[key])
