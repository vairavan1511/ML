"""Offline IP geolocation using a local MaxMind GeoLite2-City database.

The database is never downloaded by the app. Set GEOLITE_CITY_PATH to a
GeoLite2-City.mmdb file you obtained from MaxMind (free account). Without it,
every lookup returns available=False with a clear message; no location is invented.
"""
from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.config import settings

logger = logging.getLogger(__name__)

NOT_INSTALLED = "GeoIP database not installed. Place GeoLite2-City.mmdb and set GEOLITE_CITY_PATH."


def _unavailable(ip: str | None, reason: str) -> dict[str, Any]:
    return {"ip": ip, "available": False, "reason": reason, "country": None,
            "city": None, "latitude": None, "longitude": None}


@lru_cache(maxsize=1)
def _reader(path_text: str) -> Any | None:
    """Open the .mmdb once. Returns None if the file or the geoip2 package is missing."""
    path = Path(path_text)
    if not path_text or not path.is_file():
        return None
    try:
        import geoip2.database  # imported lazily so the app runs without geoip2
    except ImportError:
        logger.warning("geoip2 is not installed; geolocation is disabled")
        return None
    try:
        return geoip2.database.Reader(str(path))
    except Exception as exc:  # corrupt or unreadable file
        logger.warning("Could not open GeoLite2 database: %s", type(exc).__name__)
        return None


def locate_ip(ip: str | None) -> dict[str, Any]:
    """Return a location for a public IP, or a labelled reason why none is available."""
    if not ip:
        return _unavailable(None, "No origin IP address to locate")
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return _unavailable(ip, "Not a valid IP address")
    if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
        return _unavailable(str(addr), "Private or reserved address: no public location")

    reader = _reader(str(settings.geolite_city_path or ""))
    if reader is None:
        return _unavailable(str(addr), NOT_INSTALLED)
    try:
        record = reader.city(str(addr))
    except Exception:  # address not in the database
        return _unavailable(str(addr), "Address not found in the GeoLite2 database")
    location = record.location
    return {
        "ip": str(addr),
        "available": location.latitude is not None and location.longitude is not None,
        "reason": "Approximate location from the GeoLite2 database. "
                  "City accuracy is limited, and VPNs and relays hide the true origin.",
        "country": record.country.name,
        "city": record.city.name,
        "latitude": location.latitude,
        "longitude": location.longitude,
    }
