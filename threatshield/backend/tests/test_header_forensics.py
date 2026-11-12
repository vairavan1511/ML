"""Tests for Received-chain, authentication and spoofing checks (synthetic messages only)."""
from __future__ import annotations

import sys
from email import message_from_string
from email.policy import compat32
from pathlib import Path

_backend = str(Path(__file__).parent.parent)
if _backend not in sys.path:
    sys.path.insert(0, _backend)

from app.services.header_forensics import analyse_headers, origin_ip, walk_received_chain  # noqa: E402


def _msg(headers: str, body: str = "Hello") -> object:
    raw = headers.strip("\n") + "\n\n" + body + "\n"
    return message_from_string(raw, policy=compat32)


def _kinds(result: dict) -> set[str]:
    return {f["kind"] for f in result["findings"]}


def _details(result: dict) -> str:
    return " | ".join(f["detail"] for f in result["findings"])


PHISH = """
Return-Path: <bounce@mailer-sbi-kyc.xyz>
Received: from mx.relay-two.example (mx.relay-two.example [198.18.0.20]) by mx.receiver.example with ESMTPS id 4f2; Thu, 12 Nov 2026 10:20:40 +0000
Received: from unknown (unknown [103.21.244.10]) by mx.relay-two.example with ESMTP id 9a1; Thu, 12 Nov 2026 10:20:05 +0000
Authentication-Results: mx.receiver.example; spf=fail smtp.mailfrom=mailer-sbi-kyc.xyz; dkim=none; dmarc=fail (p=REJECT) header.from=sbi-kyc.xyz
From: "SBI Support <help@sbi-kyc.xyz>"
Reply-To: collect.support@attacker-domain.top
Subject: KYC update required
Date: Thu, 12 Nov 2026 10:20:04 +0000
X-Mailer: PHPMailer 6.8
"""


def test_spoofed_message_reports_auth_mismatch_and_lookalike():
    result = analyse_headers(_msg(PHISH), body_text="Verify your KYC", subject="KYC update required")
    kinds = _kinds(result)
    assert {"auth", "mismatch", "lookalike", "anomaly"} <= kinds
    assert "SPF failed" in _details(result)
    assert "DMARC failed" in _details(result)
    assert "Reply-To domain (attacker-domain.top)" in _details(result)
    assert "Return-Path domain" in _details(result)
    assert result["score"] >= 60


def test_stated_authentication_is_read_from_headers():
    result = analyse_headers(_msg(PHISH))
    assert result["auth"]["spf"] == "fail"
    assert result["auth"]["dmarc"] == "fail"
    assert result["auth"]["dmarc_policy"] == "reject"
    assert result["auth"]["dkim"] == "none"


def test_clean_message_has_no_mismatch_findings():
    clean = """
Return-Path: <news@shop.example.com>
Received: from mail.shop.example.com (mail.shop.example.com [203.0.113.7]) by mx.receiver.example with ESMTPS id 1; Thu, 12 Nov 2026 09:00:02 +0000
Received: from relay.shop.example.com (relay.shop.example.com [198.51.100.4]) by mail.shop.example.com with ESMTP id 2; Thu, 12 Nov 2026 09:00:01 +0000
Authentication-Results: mx.receiver.example; spf=pass smtp.mailfrom=shop.example.com; dkim=pass header.d=shop.example.com; dmarc=pass header.from=shop.example.com
DKIM-Signature: v=1; a=rsa-sha256; d=shop.example.com; s=k1; h=from; bh=x; b=y
From: "Shop Example" <news@shop.example.com>
Message-ID: <abc@shop.example.com>
Subject: Your weekly update
Date: Thu, 12 Nov 2026 09:00:00 +0000
"""
    result = analyse_headers(_msg(clean), subject="Your weekly update")
    assert _kinds(result) == set()
    assert result["score"] == 0


def test_received_chain_is_ordered_oldest_first_with_delays():
    hops = walk_received_chain(_msg(PHISH))
    assert [h["hop"] for h in hops] == [1, 2]
    assert hops[0]["ip"] == "103.21.244.10"
    assert hops[1]["delay_seconds"] == 35
    assert hops[1]["anomaly"] is None


def test_backwards_timestamp_is_flagged():
    backwards = PHISH.replace("Thu, 12 Nov 2026 10:20:05 +0000", "Thu, 12 Nov 2026 10:40:05 +0000")
    hops = walk_received_chain(_msg(backwards))
    assert hops[1]["anomaly"] is not None
    assert origin_ip(hops)["confidence"] == "Medium"


def test_origin_confidence_levels():
    no_public = """
Received: from localhost (localhost [127.0.0.1]) by mx.example with ESMTP id 1; Thu, 12 Nov 2026 10:00:00 +0000
From: a@example.com
"""
    assert origin_ip(walk_received_chain(_msg(no_public)))["confidence"] == "Low"

    single = """
Received: from unknown (unknown [103.21.244.10]) by mx.example with ESMTP id 1; Thu, 12 Nov 2026 10:00:00 +0000
From: a@example.com
"""
    single_origin = origin_ip(walk_received_chain(_msg(single)))
    assert single_origin["ip"] == "103.21.244.10"
    assert single_origin["confidence"] == "Low"

    assert origin_ip(walk_received_chain(_msg(PHISH)))["confidence"] == "High"


def test_display_name_spoofing_is_detected():
    spoof = """
From: "support@paypal.com" <alert@evil-mail.example>
Message-ID: <x@evil-mail.example>
"""
    result = analyse_headers(_msg(spoof))
    assert "spoof" in _kinds(result)
    assert "paypal.com" in _details(result)


def test_free_mail_with_bank_wording_is_flagged():
    freemail = """
From: "Bank Desk" <desk.sbi.team@gmail.com>
Message-ID: <y@gmail.com>
"""
    result = analyse_headers(_msg(freemail), body_text="Your bank account is blocked. Share OTP.", subject="Account blocked")
    assert "freemail" in _kinds(result)


def test_malformed_headers_do_not_crash():
    broken = "Received: ;;;; by\nFrom: <<<>>>\nDate: not-a-date\n"
    result = analyse_headers(_msg(broken))
    assert isinstance(result["score"], int)
    assert result["origin"]["confidence"] in {"Low", "Medium", "High"}
