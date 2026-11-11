"""SMS-specific pattern analysis."""
from __future__ import annotations

import re
import unicodedata

# ── Pattern sets ──────────────────────────────────────────────────────────────
OTP_RE = re.compile(
    r"\botp\b|\bone.?time.?pass|\bverification.?code\b|\bshare.{0,20}(otp|code|pin)\b",
    re.I,
)
UPI_RE = re.compile(
    r"\bupi\b.{0,40}(collect|request|approve|pay)|"
    r"(collect|request|approve).{0,40}\bupi\b|"
    r"\bpay\b.{0,20}(rs\.?|inr|rupee)",
    re.I,
)
KYC_RE = re.compile(
    r"\bkyc\b|\bknow.?your.?customer\b|\baadhaar\b.{0,30}(link|update|verify)|"
    r"\bpan\b.{0,20}(link|update|verify)",
    re.I,
)
BANK_BLOCK_RE = re.compile(
    r"(account|card|debit|credit).{0,30}(block|suspend|freeze|deactivat)|"
    r"(block|suspend|freeze|deactivat).{0,30}(account|card)",
    re.I,
)
COURIER_RE = re.compile(
    r"(parcel|package|shipment|delivery).{0,40}(fee|charge|pay|hold|custom)|"
    r"(fee|charge|pay).{0,40}(parcel|package|delivery)",
    re.I,
)
LOTTERY_RE = re.compile(
    r"\b(won|winner|prize|lottery|lucky.?draw|reward|congratulation)\b",
    re.I,
)
ELECTRICITY_RE = re.compile(
    r"(electricity|power|electric).{0,40}(disconnect|cut|bill|due|overdue)|"
    r"(disconnect|cut).{0,40}(electricity|power|supply)",
    re.I,
)
JOB_RE = re.compile(
    r"\b(work.?from.?home|part.?time|earn.{0,10}(rs|inr|\$)|"
    r"data.?entry|hiring|job.?offer|apply.?now)\b",
    re.I,
)
LOAN_RE = re.compile(
    r"\b(instant.?loan|personal.?loan|pre.?approved|0%.?interest|"
    r"no.?document|loan.?approved)\b",
    re.I,
)
URGENCY_RE = re.compile(
    r"\b(urgent|immediately|expire|last.?chance|act.?now|"
    r"within.{0,10}(hour|min|hr)|limited.?time|today.?only)\b",
    re.I,
)
FEAR_RE = re.compile(
    r"\b(suspend|block|terminate|legal.?action|arrest|penalty|"
    r"fine|disconnected|deactivated)\b",
    re.I,
)
REWARD_RE = re.compile(
    r"\b(free|gift|bonus|cashback|refund|claim|selected|chosen)\b",
    re.I,
)

# Sender ID patterns
RANDOM_DIGITS_RE = re.compile(r"^\+?\d{7,}$")
BRAND_LOOKALIKE_RE = re.compile(
    r"(sbi|hdfc|icici|axis|paytm|amazon|google|apple|microsoft|paypal)",
    re.I,
)

# Hidden Unicode: zero-width and common homoglyphs
ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u00ad]")


def _has_hidden_unicode(text: str) -> bool:
    if ZERO_WIDTH_RE.search(text):
        return True
    # Check for Cyrillic/Greek homoglyphs mixed with Latin
    scripts = {unicodedata.name(c, "").split()[0] for c in text if c.isalpha()}
    return len(scripts) > 1 and "LATIN" in scripts


def analyse_sms(text: str, sender: str | None = None) -> dict:
    """Return pattern findings for an SMS message.

    Returns:
        {
          patterns: list of triggered pattern names,
          flags: list of plain-English descriptions,
          sender_suspicious: bool,
          hidden_unicode: bool,
          pattern_score: int 0-100
        }
    """
    flags: list[str] = []
    patterns: list[str] = []
    score = 0

    checks = [
        (OTP_RE,         "otp_sharing",    "Asks you to share an OTP or verification code", 40),
        (UPI_RE,         "upi_collect",    "Contains a UPI collect/payment request lure",   35),
        (KYC_RE,         "fake_kyc",       "Fake KYC / Aadhaar / PAN update demand",        30),
        (BANK_BLOCK_RE,  "bank_block",     "Threatens to block your bank account or card",  30),
        (COURIER_RE,     "courier_fee",    "Fake courier / customs fee demand",             25),
        (LOTTERY_RE,     "lottery",        "Lottery / prize / lucky-draw lure",             25),
        (ELECTRICITY_RE, "electricity",    "Fake electricity disconnection threat",         25),
        (JOB_RE,         "job_scam",       "Suspicious job / work-from-home offer",         20),
        (LOAN_RE,        "loan_scam",      "Instant loan / pre-approved loan scam",         20),
        (URGENCY_RE,     "urgency",        "Creates artificial urgency",                    15),
        (FEAR_RE,        "fear",           "Uses fear / threat language",                   15),
        (REWARD_RE,      "reward",         "Uses reward / free-gift language",              10),
    ]

    for pattern, name, description, weight in checks:
        if pattern.search(text):
            patterns.append(name)
            flags.append(description)
            score += weight

    # Sender ID checks
    sender_suspicious = False
    if sender:
        if RANDOM_DIGITS_RE.match(sender):
            flags.append(f"Sender ID '{sender}' is a random number (not a registered brand ID)")
            sender_suspicious = True
            score += 15
        elif BRAND_LOOKALIKE_RE.search(sender) and len(sender) > 6:
            flags.append(f"Sender ID '{sender}' mimics a known brand name")
            sender_suspicious = True
            score += 20

    # Hidden Unicode
    hidden = _has_hidden_unicode(text)
    if hidden:
        flags.append("Message contains hidden Unicode characters (zero-width or homoglyphs)")
        score += 20

    return {
        "patterns": patterns,
        "flags": flags,
        "sender_suspicious": sender_suspicious,
        "hidden_unicode": hidden,
        "pattern_score": min(score, 100),
    }
