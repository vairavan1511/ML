"""Static URL risk analyser — never fetches any URL."""
from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlparse, parse_qs

import tldextract

# ── Constants ─────────────────────────────────────────────────────────────────
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "short.io", "tiny.cc",
    "rb.gy", "clck.ru", "bl.ink", "soo.gd",
}

SUSPICIOUS_TLDS = {
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "pw", "cc",
    "click", "link", "live", "online", "site", "website", "space",
    "in", "co", "io",   # not inherently bad but common in phishing
}

HIGH_RISK_TLDS = {"top", "xyz", "tk", "ml", "ga", "cf", "gq", "pw", "click", "link"}

BRAND_WORDS = {
    "paypal", "amazon", "apple", "google", "microsoft", "netflix",
    "sbi", "hdfc", "icici", "axis", "paytm", "upi", "npci",
    "facebook", "instagram", "whatsapp", "twitter", "linkedin",
    "ebay", "walmart", "fedex", "dhl", "ups",
}

REDIRECT_PARAMS = {"url", "redirect", "next", "goto", "return", "returnurl", "redir", "target", "link"}

HOMOGLYPH_MAP = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0456": "i",
    "0": "o", "1": "l", "3": "e", "5": "s",
})

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _defang(url: str) -> str:
    """hxxp://evil[.]com"""
    return url.replace("http", "hxxp").replace(".", "[.]", 1)


def _has_homoglyphs(domain: str) -> bool:
    normalised = domain.translate(HOMOGLYPH_MAP)
    return normalised != domain


def _is_punycode(domain: str) -> bool:
    return "xn--" in domain.lower()


def analyse_url(raw: str, link_text: str | None = None) -> dict:
    """Return {display, defanged, risk, level, reasons} for one URL.
    Never fetches the URL.
    """
    reasons: list[str] = []
    risk = 0

    # Normalise scheme
    url = raw.strip()
    if not re.match(r"https?://", url, re.I):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or ""
        ext = tldextract.extract(url)
        domain = ext.domain.lower()
        suffix = ext.suffix.lower()
        subdomain = ext.subdomain.lower()
        fqdn = f"{domain}.{suffix}" if suffix else domain
    except Exception:
        return {"display": raw, "defanged": _defang(raw), "risk": 60,
                "level": "HIGH", "reasons": ["Malformed URL"]}

    # IP host
    if IP_RE.match(host):
        reasons.append("URL uses a raw IP address instead of a domain name")
        risk += 35

    # @ trick
    if "@" in (parsed.netloc or ""):
        reasons.append("URL contains '@' — real destination may be hidden after it")
        risk += 30

    # Punycode / IDN
    if _is_punycode(host):
        reasons.append("Punycode/IDN domain — may visually impersonate a trusted brand")
        risk += 25

    # Homoglyphs
    if _has_homoglyphs(domain):
        reasons.append("Domain contains look-alike characters (homoglyphs)")
        risk += 20

    # Many subdomains
    sub_parts = [s for s in subdomain.split(".") if s]
    if len(sub_parts) >= 3:
        reasons.append(f"Unusually many subdomains ({len(sub_parts)}) — common in phishing")
        risk += 15
    elif len(sub_parts) == 2:
        risk += 5

    # Suspicious / high-risk TLD
    if suffix in HIGH_RISK_TLDS:
        reasons.append(f"High-risk TLD '.{suffix}' frequently used in phishing")
        risk += 25
    elif suffix in SUSPICIOUS_TLDS:
        reasons.append(f"Suspicious TLD '.{suffix}'")
        risk += 10

    # URL shortener
    if fqdn in SHORTENERS or domain in {s.split(".")[0] for s in SHORTENERS}:
        reasons.append("URL shortener hides the real destination")
        risk += 20

    # Brand word in subdomain (not in registered domain)
    for brand in BRAND_WORDS:
        if brand in subdomain and brand not in domain:
            reasons.append(f"Brand name '{brand}' in subdomain — possible impersonation")
            risk += 25
            break
        if brand in path.lower():
            reasons.append(f"Brand name '{brand}' in URL path — possible impersonation")
            risk += 10
            break

    # Redirect parameters
    try:
        qs_keys = {k.lower() for k in parse_qs(parsed.query)}
        hit = qs_keys & REDIRECT_PARAMS
        if hit:
            reasons.append(f"Redirect parameter '{next(iter(hit))}' may chain to a malicious site")
            risk += 15
    except Exception:
        pass

    # Link-text vs real target mismatch
    if link_text:
        lt = link_text.strip().lower()
        if lt.startswith("http") and lt != url.lower():
            lt_ext = tldextract.extract(lt)
            if lt_ext.domain and lt_ext.domain != domain:
                reasons.append(
                    f"Link text shows '{link_text}' but real URL goes to '{fqdn}'"
                )
                risk += 30

    risk = min(risk, 100)
    level = "HIGH" if risk >= 60 else ("MEDIUM" if risk >= 30 else "LOW")

    return {
        "display": raw,
        "defanged": _defang(raw),
        "risk": risk,
        "level": level,
        "reasons": reasons or ["No obvious URL risk signals detected"],
    }
