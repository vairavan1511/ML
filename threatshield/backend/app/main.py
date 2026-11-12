"""FastAPI application — routes, middleware, static serving."""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure ml/ is on sys.path so joblib can unpickle the features module
_ML_DIR = str(Path(__file__).parent.parent.parent / "ml")
if _ML_DIR not in sys.path:
    sys.path.insert(0, _ML_DIR)

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.schemas import AnalysisResult, AnalysisRequest, HealthResponse, ModelInfo, URLResult
from app.services.analyzer import analyse_email_text, analyse_sms_text, _load_model
from app.services.advice import advice_for
from app.services.cases import get as get_case, save as save_case
from app.services.report_pdf import generate_report
from app.services.urls import analyse_url

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="ThreatShield",
    description="Email & SMS spam/phishing analyser",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=getattr(settings, "cors_origins", []),
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Serve frontend
_FRONTEND = Path(__file__).parent.parent.parent / "frontend"
if _FRONTEND.exists():
    app.mount("/static", StaticFiles(directory=str(_FRONTEND)), name="static")


@app.get("/", include_in_schema=False)
async def root():
    index = _FRONTEND / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return JSONResponse({"message": "ThreatShield API — frontend not built yet"})


# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/api/health", response_model=HealthResponse, tags=["meta"])
async def health():
    """Liveness + readiness check."""
    artifacts = settings.artifacts_dir
    present = [f.name for f in artifacts.iterdir() if f.is_file()] if artifacts.exists() else []
    try:
        _load_model()
        loaded = True
    except Exception:
        loaded = False
    return HealthResponse(status="ok", model_loaded=loaded, artifacts_present=present)


# ── Model info ────────────────────────────────────────────────────────────────
@app.get("/api/model/info", response_model=ModelInfo, tags=["meta"])
async def model_info():
    """Return real metrics from artifacts/metrics.json and top_terms.json."""
    metrics_path = settings.artifacts_dir / "metrics.json"
    terms_path   = settings.artifacts_dir / "top_terms.json"
    if not metrics_path.exists():
        raise HTTPException(503, "metrics.json not found — run ml/train.py first")
    metrics = json.loads(metrics_path.read_text())
    terms   = json.loads(terms_path.read_text()) if terms_path.exists() else {}
    return ModelInfo(
        best_model=metrics.get("best_model", "unknown"),
        test_metrics_overall=metrics.get("test_metrics_overall", {}),
        test_metrics_by_channel=metrics.get("test_metrics_by_channel", []),
        model_comparison_on_val=metrics.get("model_comparison_on_val", []),
        dataset_sizes=metrics.get("dataset_sizes", {}),
        top_spam_terms=terms.get("top_spam_terms", []),
        top_ham_terms=terms.get("top_ham_terms", []),
    )


# ── Email analysis ────────────────────────────────────────────────────────────
@app.post("/api/analyze/email", response_model=AnalysisResult, tags=["analyze"])
async def analyze_email(
    file: UploadFile | None = File(default=None),
    text: str | None = Form(default=None),
):
    """Analyse an email from an uploaded .eml file or pasted raw text."""
    if file and file.filename:
        ext = Path(file.filename).suffix.lower()
        if ext not in settings.allowed_email_extensions:
            raise HTTPException(400, f"Unsupported file type '{ext}'")
        content = await file.read()
        if len(content) > settings.max_upload_bytes:
            raise HTTPException(413, "File exceeds 5 MB limit")
        raw: str | bytes = content
    elif text:
        raw = text
    else:
        raise HTTPException(422, "Provide either 'file' or 'text'")

    result = analyse_email_text(raw)
    return _to_response(result)


# ── SMS analysis ──────────────────────────────────────────────────────────────
@app.post("/api/analyze/sms", response_model=AnalysisResult, tags=["analyze"])
async def analyze_sms(body: AnalysisRequest):
    """Analyse an SMS message with optional sender ID."""
    if not body.text.strip():
        raise HTTPException(422, "text must not be empty")
    result = analyse_sms_text(body.text, body.sender)
    return _to_response(result)


# ── URL analysis ──────────────────────────────────────────────────────────────
@app.post("/api/analyze/url", response_model=URLResult, tags=["analyze"])
async def analyze_url_endpoint(body: AnalysisRequest):
    """Analyse a single URL (static analysis only — never fetched)."""
    url = body.text.strip()
    if not url:
        raise HTTPException(422, "text must not be empty")
    return analyse_url(url)


# ── Analysis report ───────────────────────────────────────────────────────────
@app.get("/api/report/{case_id}.pdf", tags=["report"])
async def analysis_report(case_id: str):
    result = get_case(case_id)
    if result is None:
        raise HTTPException(404, "Analysis case not found")
    return Response(
        content=generate_report(case_id, result),
        media_type="application/pdf",
    )


# ── Helper ────────────────────────────────────────────────────────────────────
def _to_response(result: dict) -> AnalysisResult:
    case_id = save_case(result)
    return AnalysisResult(
        verdict=result["verdict"],
        risk_score=result["risk_score"],
        reasons=result["reasons"],
        highlights=result["highlights"],
        urls=[URLResult(**u) for u in result["urls"]],
        ml_score=result["ml_score"],
        channel=result["channel"],
        metadata=result.get("metadata", {}),
        forensics=result.get("forensics"),
        geolocation=result.get("geolocation"),
        case_id=case_id,
        advice=advice_for(result["verdict"]),
    )
