"""Pydantic schemas for API request/response."""
from __future__ import annotations
from typing import Any
from pydantic import BaseModel


class URLResult(BaseModel):
    display: str
    defanged: str
    risk: int
    level: str          # LOW / MEDIUM / HIGH
    reasons: list[str]


class AnalysisRequest(BaseModel):
    text: str
    sender: str | None = None   # SMS sender ID


class Advice(BaseModel):
    title: str
    steps: list[str]


class HopOut(BaseModel):
    hop: int
    from_host: str
    by_host: str
    ip: str | None
    public_ip: str | None
    timestamp: str | None
    delay_seconds: int | None
    anomaly: str | None
    raw: str


class OriginOut(BaseModel):
    ip: str | None
    confidence: str     # High / Medium / Low
    reason: str


class AuthOut(BaseModel):
    spf: str | None
    dkim: str | None
    dmarc: str | None
    dmarc_policy: str | None
    dkim_signature_present: bool


class FindingOut(BaseModel):
    kind: str           # auth / mismatch / spoof / lookalike / freemail / anomaly
    detail: str
    severity: int


class ForensicsOut(BaseModel):
    hops: list[HopOut]
    origin: OriginOut
    auth: AuthOut
    from_domain: str
    return_path_domain: str
    reply_to_domain: str
    findings: list[FindingOut]
    score: int


class GeolocationOut(BaseModel):
    ip: str | None
    available: bool
    reason: str
    country: str | None
    city: str | None
    latitude: float | None
    longitude: float | None


class AnalysisResult(BaseModel):
    verdict: str                # SAFE / SUSPICIOUS / SPAM-PHISHING
    risk_score: int             # 0-100
    reasons: list[str]          # top-5 plain-English
    highlights: list[str]       # suspicious tokens
    urls: list[URLResult]
    ml_score: float
    channel: str
    metadata: dict[str, Any] = {}
    forensics: ForensicsOut | None = None
    geolocation: GeolocationOut | None = None
    case_id: str | None = None
    advice: Advice


class ModelInfo(BaseModel):
    best_model: str
    test_metrics_overall: dict[str, Any]
    test_metrics_by_channel: list[dict[str, Any]]
    model_comparison_on_val: list[dict[str, Any]]
    dataset_sizes: dict[str, Any]
    top_spam_terms: list[str]
    top_ham_terms: list[str]


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    artifacts_present: list[str]
