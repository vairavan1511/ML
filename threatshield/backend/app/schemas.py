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


class AnalysisResult(BaseModel):
    verdict: str                # SAFE / SUSPICIOUS / SPAM-PHISHING
    risk_score: int             # 0-100
    reasons: list[str]          # top-5 plain-English
    highlights: list[str]       # suspicious tokens
    urls: list[URLResult]
    ml_score: float
    channel: str
    metadata: dict[str, Any] = {}


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
