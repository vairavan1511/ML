"""Central configuration — weights, thresholds, limits."""
from __future__ import annotations
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Artifact paths
    artifacts_dir: Path = Path(__file__).parent.parent.parent / "ml" / "artifacts"

    # Optional offline GeoIP database (MaxMind GeoLite2-City.mmdb, obtained by the user)
    geolite_city_path: Path | None = None

    # Scoring weights (must sum to 1.0 per channel)
    email_weight_ml: float = 0.55
    email_weight_url: float = 0.20
    email_weight_header: float = 0.15
    email_weight_attachment: float = 0.10

    sms_weight_ml: float = 0.60
    sms_weight_url: float = 0.25
    sms_weight_pattern: float = 0.15

    # Verdict thresholds
    threshold_safe: int = 30        # < 30  -> SAFE
    threshold_suspicious: int = 60  # < 60  -> SUSPICIOUS, >= 60 -> SPAM-PHISHING

    # API limits
    max_upload_bytes: int = 5 * 1024 * 1024   # 5 MB
    allowed_email_extensions: tuple[str, ...] = (".eml", ".msg", ".txt")

    # CORS
    cors_origins: list[str] = []      # same-origin only; override via .env


settings = Settings()
