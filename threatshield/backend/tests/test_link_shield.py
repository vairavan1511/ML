from __future__ import annotations

from pathlib import Path
import sys

_backend = str(Path(__file__).parent.parent)
_ml = str(Path(__file__).parent.parent.parent / "ml")
for _path in (_backend, _ml):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from app.services.analyzer import analyse_email_text


def test_email_html_preview_removes_links_and_active_content():
    raw = """From: sender@example.com
Content-Type: text/html; charset=utf-8

<html><body><p onclick="alert(1)">Click <a href="https://example.com">here</a></p>
<img src="https://example.com/image.png"><svg><image xlink:href="https://example.com/icon.svg"></image></svg>
<script>alert(1)</script>
<iframe src="https://example.com"></iframe><object data="payload"></object>
<embed src="payload"><form action="https://example.com"><input></form></body></html>"""

    preview = analyse_email_text(raw)["metadata"]["html_preview"].lower()

    assert "<a " not in preview
    assert "href" not in preview
    assert "src=" not in preview
    assert "<script" not in preview
    assert "onclick" not in preview


def test_email_without_html_has_empty_preview():
    raw = "From: sender@example.com\nContent-Type: text/plain; charset=utf-8\n\nHello"

    assert analyse_email_text(raw)["metadata"]["html_preview"] == ""