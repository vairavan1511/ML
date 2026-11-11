"""Parse .eml / raw email source into a structured dict. Never crashes."""
from __future__ import annotations

import email
import email.policy
import hashlib
import html
import re
from email.message import Message
from typing import Any

LINK_RE = re.compile(r'href=["\']?(https?://[^\s"\'<>]+)', re.I)
URL_RE  = re.compile(r'https?://[^\s"\'<>]+', re.I)
TAG_RE  = re.compile(r"<[^>]+>")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strip_tags(raw_html: str) -> str:
    return TAG_RE.sub(" ", html.unescape(raw_html))


def _extract_links(html_body: str) -> list[dict[str, str]]:
    """Extract {href, text} pairs from HTML, flagging text/href mismatches."""
    links = []
    for m in re.finditer(
        r'<a[^>]+href=["\']?(https?://[^\s"\'<>]+)["\']?[^>]*>(.*?)</a>',
        html_body, re.I | re.S
    ):
        href = m.group(1).strip()
        text = TAG_RE.sub("", m.group(2)).strip()
        links.append({"href": href, "text": text})
    # Also plain URLs not in anchors
    anchor_hrefs = {l["href"] for l in links}
    for u in URL_RE.findall(html_body):
        if u not in anchor_hrefs:
            links.append({"href": u, "text": ""})
    return links


def _walk_parts(msg: Message) -> tuple[str, str, list[dict]]:
    """Return (plain_text, html_body, attachments)."""
    plain, html_body = "", ""
    attachments: list[dict] = []

    for part in msg.walk():
        ct = part.get_content_type()
        cd = part.get_content_disposition() or ""

        if "attachment" in cd or part.get_filename():
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            attachments.append({
                "filename": part.get_filename() or "unknown",
                "content_type": ct,
                "size_bytes": len(payload),
                "sha256": _sha256(payload),
            })
            continue

        if ct == "text/plain" and not plain:
            try:
                plain = part.get_payload(decode=True).decode(
                    part.get_content_charset() or "utf-8", errors="replace"
                )
            except Exception:
                pass

        if ct == "text/html" and not html_body:
            try:
                html_body = part.get_payload(decode=True).decode(
                    part.get_content_charset() or "utf-8", errors="replace"
                )
            except Exception:
                pass

    return plain, html_body, attachments


def parse_email(raw: str | bytes) -> dict[str, Any]:
    """Parse raw email source. Returns structured dict; never raises."""
    try:
        if isinstance(raw, str):
            raw = raw.encode("utf-8", errors="replace")
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)

        subject   = str(msg.get("Subject", "") or "")
        from_     = str(msg.get("From", "") or "")
        reply_to  = str(msg.get("Reply-To", "") or "")
        date      = str(msg.get("Date", "") or "")
        msg_id    = str(msg.get("Message-ID", "") or "")

        # Auth headers
        spf   = str(msg.get("Received-SPF", "") or "")
        dkim  = str(msg.get("DKIM-Signature", "") or "")
        dmarc = str(msg.get("Authentication-Results", "") or "")

        plain, html_body, attachments = _walk_parts(msg)

        # Fallback: single-part non-MIME
        if not plain and not html_body:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    plain = payload.decode(
                        msg.get_content_charset() or "utf-8", errors="replace"
                    )
            except Exception:
                plain = str(msg.get_payload() or "")

        body_text = plain or _strip_tags(html_body)
        links = _extract_links(html_body) if html_body else []
        # Also pull plain-text URLs
        for u in URL_RE.findall(plain):
            if not any(l["href"] == u for l in links):
                links.append({"href": u, "text": ""})

        return {
            "subject": subject,
            "from_": from_,
            "reply_to": reply_to,
            "date": date,
            "message_id": msg_id,
            "body_text": body_text,
            "html_body": html_body,
            "links": links,
            "attachments": attachments,
            "auth": {"spf": spf, "dkim": bool(dkim), "dmarc": dmarc},
        }
    except Exception as exc:
        return {
            "subject": "", "from_": "", "reply_to": "", "date": "",
            "message_id": "", "body_text": "", "html_body": "",
            "links": [], "attachments": [],
            "auth": {"spf": "", "dkim": False, "dmarc": ""},
            "_parse_error": str(exc),
        }
