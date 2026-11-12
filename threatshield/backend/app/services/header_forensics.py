"""Email header forensics: Received chain, stated authentication, spoofing checks.

Static analysis only. Results describe what the message itself states; SPF,
DKIM and DMARC are read from the headers and are never re-checked over DNS.
"""
from __future__ import annotations

import email.utils
import ipaddress
import re
from datetime import datetime
from email.message import Message
from typing import Any

# Clock skew tolerated between servers before a backwards timestamp is flagged.
CLOCK_SKEW_SECONDS = 300

FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
             "rediffmail.com", "live.com", "aol.com", "proton.me", "protonmail.com"}
BANK_WORDS = {"bank", "kyc", "account", "otp", "upi", "sbi", "hdfc", "icici",
              "axis", "pnb", "kotak", "blocked", "suspended", "verify"}
BRANDS = {"paypal", "amazon", "apple", "google", "microsoft", "netflix", "sbi",
          "hdfc", "icici", "axis", "paytm", "npci", "fedex", "dhl", "whatsapp"}
SUSPICIOUS_TLDS = {"top", "xyz", "tk", "ml", "ga", "cf", "gq", "pw", "click", "link", "live", "online", "site"}
BULK_MAILERS = ("phpmailer", "sendblaster", "mass mailer", "bulk mailer")

_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"})
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\[([0-9a-fA-F:.]{2,})\]")
_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)", re.I)
_DMARC_POLICY_RE = re.compile(r"\bp\s*=\s*([a-zA-Z]+)", re.I)
_EMAIL_RE = re.compile(r"[\w.+\-]+@([\w.\-]+)")


def _domain_of(address: str) -> str:
    """Return the lower-case domain of the real address, or ''.

    The address inside <...> is used when present, so a display name such as
    "support@paypal.com" <alert@evil.example> yields evil.example.
    """
    angle = re.search(r"<([^<>]+)>", address or "")
    source = angle.group(1) if angle else (address or "")
    match = _EMAIL_RE.search(source)
    return match.group(1).lower().rstrip(".") if match else ""


def _registered_label(domain: str) -> str:
    """Return the second-level label, e.g. 'sbi' for 'mail.sbi-kyc.xyz' (approximate)."""
    parts = [p for p in domain.split(".") if p]
    return parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")


def _tld(domain: str) -> str:
    parts = [p for p in domain.split(".") if p]
    return parts[-1] if parts else ""


def _public_ip(text: str) -> str | None:
    """Return the first public IP literal in text, or None."""
    candidates = _IPV4_RE.findall(text) + [m for m in _IPV6_RE.findall(text)]
    for candidate in candidates:
        try:
            addr = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if not (addr.is_private or addr.is_loopback or addr.is_reserved
                or addr.is_link_local or addr.is_multicast or addr.is_unspecified):
            return str(addr)
    return None


def parse_received_hop(raw: str) -> dict[str, Any]:
    """Parse one Received header into from/by hosts, IP, and timestamp."""
    text = re.sub(r"\s+", " ", raw).strip()
    stamp_part = text.rsplit(";", 1)[-1] if ";" in text else ""
    timestamp: datetime | None = None
    try:
        timestamp = email.utils.parsedate_to_datetime(stamp_part.strip()) if stamp_part.strip() else None
    except (TypeError, ValueError):
        timestamp = None

    lowered = text.lower()
    from_clause = text
    by_index = lowered.find(" by ")
    if by_index != -1:
        from_clause = text[:by_index]
    by_host = ""
    by_match = re.search(r"\bby\s+([\w.\-]+)", text, re.I)
    if by_match:
        by_host = by_match.group(1)

    from_host = ""
    from_match = re.search(r"\bfrom\s+([\w.\-\[\]:]+)", from_clause, re.I)
    if from_match:
        from_host = from_match.group(1).strip("[]")

    ip = None
    ip_match = _IPV6_RE.search(from_clause) or _IPV4_RE.search(from_clause)
    if ip_match:
        ip = ip_match.group(1) if ip_match.re is _IPV6_RE else ip_match.group(0)
    return {
        "from_host": from_host,
        "by_host": by_host,
        "ip": ip,
        "public_ip": _public_ip(from_clause),
        "timestamp": timestamp.isoformat() if timestamp else None,
        "_ts": timestamp,
        "raw": text[:300],
    }


def walk_received_chain(msg: Message) -> list[dict[str, Any]]:
    """Return Received hops ordered bottom-to-top (oldest hop first), with delays."""
    raw_hops = msg.get_all("Received") or []
    hops = [parse_received_hop(str(h)) for h in reversed(raw_hops)]
    previous: datetime | None = None
    for index, hop in enumerate(hops, start=1):
        hop["hop"] = index
        current = hop.pop("_ts")
        hop["delay_seconds"] = None
        hop["anomaly"] = None
        if current is not None and previous is not None:
            delta = (current - previous).total_seconds()
            hop["delay_seconds"] = int(delta)
            if delta < -CLOCK_SKEW_SECONDS:
                hop["anomaly"] = "Timestamp goes backwards compared with the previous hop"
        if current is not None:
            previous = current
    return hops


def origin_ip(hops: list[dict[str, Any]]) -> dict[str, Any]:
    """Pick the originating public IP and rate confidence in that choice."""
    public = next((h for h in hops if h.get("public_ip")), None)
    if public is None:
        return {"ip": None, "confidence": "Low",
                "reason": "No public IP address was found in the Received chain"}
    anomalies = any(h.get("anomaly") for h in hops)
    if len(hops) < 2:
        return {"ip": public["public_ip"], "confidence": "Low",
                "reason": "Only one Received hop, so the origin cannot be confirmed by a relay chain"}
    if anomalies:
        return {"ip": public["public_ip"], "confidence": "Medium",
                "reason": "The chain has timestamps that go backwards, so hop order may be unreliable"}
    return {"ip": public["public_ip"], "confidence": "High",
            "reason": "The first public hop is consistent with the chain order and timestamps. "
                      "VPN, Tor and relay use cannot be detected offline"}


def _stated_auth(msg: Message) -> dict[str, Any]:
    """Read SPF, DKIM and DMARC results as stated in the message headers."""
    stated: dict[str, Any] = {"spf": None, "dkim": None, "dmarc": None, "dmarc_policy": None,
                              "dkim_signature_present": bool(msg.get("DKIM-Signature"))}
    results_headers = " ".join(str(v) for v in (msg.get_all("Authentication-Results") or []))
    spf_header = str(msg.get("Received-SPF", "") or "")
    for name, value in _AUTH_RE.findall(results_headers):
        stated[name.lower()] = value.lower()
    if stated["spf"] is None and spf_header:
        first = spf_header.strip().split(None, 1)[0].lower().strip(" ,;")
        stated["spf"] = first or None
    policy = _DMARC_POLICY_RE.search(results_headers)
    if policy:
        stated["dmarc_policy"] = policy.group(1).lower()
    return stated


def analyse_headers(msg: Message, body_text: str = "", subject: str = "") -> dict[str, Any]:
    """Return forensic findings for a parsed email message.

    Each finding is a short plain-English reason; severity is a rough 0-100 score
    used by the scorer, not a probability.
    """
    from_header = str(msg.get("From", "") or "")
    return_path = str(msg.get("Return-Path", "") or "")
    reply_to = str(msg.get("Reply-To", "") or "")
    message_id = str(msg.get("Message-ID", "") or "")
    mailer = str(msg.get("X-Mailer", "") or msg.get("User-Agent", "") or "")

    display_name = ""
    name_match = re.match(r'\s*"?([^"<]+?)"?\s*<', from_header)
    if name_match:
        display_name = name_match.group(1).strip()

    from_domain = _domain_of(from_header)
    return_domain = _domain_of(return_path)
    reply_domain = _domain_of(reply_to)
    hops = walk_received_chain(msg)
    auth = _stated_auth(msg)

    findings: list[dict[str, Any]] = []

    def add(kind: str, detail: str, severity: int) -> None:
        findings.append({"kind": kind, "detail": detail, "severity": int(severity)})

    if auth["spf"] in {"fail", "permerror"}:
        add("auth", "SPF failed for the sending server (as stated in the message)", 40)
    elif auth["spf"] == "softfail":
        add("auth", "SPF soft-failed for the sending server (as stated in the message)", 20)
    elif auth["spf"] is None:
        add("auth", "No SPF result is present in the message", 10)

    if auth["dmarc"] in {"fail"}:
        add("auth", "DMARC failed (as stated in the message)", 35)
    elif auth["dmarc"] is None:
        add("auth", "No DMARC result is present in the message", 5)

    if auth["dkim"] in {"fail", "permerror"}:
        add("auth", "DKIM signature failed (as stated in the message)", 25)
    elif not auth["dkim_signature_present"] and auth["dkim"] in {None, "none"}:
        add("auth", "The message is not DKIM-signed", 10)

    if return_domain and from_domain and return_domain != from_domain:
        add("mismatch", f"Return-Path domain ({return_domain}) differs from the From domain ({from_domain})", 25)
    if reply_domain and from_domain and reply_domain != from_domain:
        add("mismatch", f"Reply-To domain ({reply_domain}) differs from the From domain ({from_domain})", 25)

    if display_name and from_domain:
        display_lower = display_name.lower()
        display_domains = {_domain_of(tok) or tok.strip("<>") for tok in re.findall(r"[\w.\-]+\.[a-z]{2,}", display_lower)}
        display_domains.discard("")
        for dom in display_domains:
            if dom != from_domain and not from_domain.endswith("." + dom):
                add("spoof", f"Display name shows '{dom}' but the address is {from_domain}", 35)
                break
        else:
            for brand in BRANDS:
                if brand in display_lower and brand not in from_domain:
                    add("spoof", f"Display name mentions '{brand}' but the sender domain is {from_domain}", 25)
                    break

    if from_domain:
        label = _registered_label(from_domain)
        normalised = label.translate(_HOMOGLYPHS).replace("rn", "m")
        if normalised in BRANDS and label not in BRANDS:
            add("lookalike", f"Sender domain '{from_domain}' looks like the brand '{normalised}'", 40)
        elif any(brand in label for brand in BRANDS) and _tld(from_domain) in SUSPICIOUS_TLDS:
            add("lookalike", f"Sender domain '{from_domain}' contains a brand name and uses a high-risk TLD", 30)

    if from_domain in FREE_MAIL:
        text_lower = f"{subject} {body_text}".lower()
        bank_hits = sorted(w for w in BANK_WORDS if re.search(rf"\b{w}\b", text_lower))
        if bank_hits:
            add("freemail", f"Free-mail sender ({from_domain}) with bank-style wording: {', '.join(bank_hits[:3])}", 20)

    if not message_id.strip():
        add("anomaly", "Message-ID header is missing", 10)
    if mailer and any(tag in mailer.lower() for tag in BULK_MAILERS):
        add("anomaly", f"Bulk-mailer header present ({mailer.strip()[:40]}); common in scam mail but not proof", 10)
    for hop in hops:
        if hop.get("anomaly"):
            add("anomaly", hop["anomaly"], 15)
            break

    origin = origin_ip(hops)
    score = min(100, sum(f["severity"] for f in findings))
    return {
        "hops": hops,
        "origin": origin,
        "auth": auth,
        "from_domain": from_domain,
        "return_path_domain": return_domain,
        "reply_to_domain": reply_domain,
        "findings": findings,
        "score": score,
    }
