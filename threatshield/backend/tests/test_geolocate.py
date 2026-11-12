"""Tests for geolocation fallbacks. No GeoLite2 file is needed or bundled."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_backend = str(Path(__file__).parent.parent)
if _backend not in sys.path:
    sys.path.insert(0, _backend)

from app.config import settings  # noqa: E402
from app.services import geolocate  # noqa: E402


@pytest.fixture(autouse=True)
def _no_database(monkeypatch):
    monkeypatch.setattr(settings, "geolite_city_path", None)
    geolocate._reader.cache_clear()


def test_missing_ip_is_reported():
    result = geolocate.locate_ip(None)
    assert result["available"] is False
    assert result["latitude"] is None


def test_invalid_ip_is_reported():
    assert geolocate.locate_ip("not-an-ip")["reason"] == "Not a valid IP address"


def test_private_address_has_no_public_location():
    result = geolocate.locate_ip("192.168.1.10")
    assert result["available"] is False
    assert "Private or reserved" in result["reason"]


def test_public_ip_without_database_says_not_installed():
    result = geolocate.locate_ip("103.21.244.10")
    assert result["available"] is False
    assert result["reason"] == geolocate.NOT_INSTALLED
    assert result["latitude"] is None and result["country"] is None


def test_configured_but_missing_file_is_not_installed(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "geolite_city_path", tmp_path / "absent.mmdb")
    geolocate._reader.cache_clear()
    assert geolocate.locate_ip("103.21.244.10")["reason"] == geolocate.NOT_INSTALLED
