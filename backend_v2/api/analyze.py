"""
api/analyze.py
--------------
/analyze  – POST  – phishing analysis
/health   – GET   – uptime check
/stats    – GET   – scan statistics
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from services.phishing_service import analyze, get_stats

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Request / Response schemas ────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    text: str
    context: Optional[str] = None   # optional caller context ("url"|"email"|"token")

    @field_validator("text")
    @classmethod
    def text_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Input text must not be empty")
        if len(v) > 10_000:
            raise ValueError("Input too long (max 10 000 characters)")
        return v


class AnalyzeResponse(BaseModel):
    input_type: str
    risk_score: int
    risk_level: str          # "safe" | "suspicious" | "phishing"
    flags: list[str]
    explanation: str
    ai_enhanced: bool
    analyzed_at: str


class StatsResponse(BaseModel):
    total_scans: int
    phishing_detected: int
    safe_count: int
    suspicious_count: int
    detection_rate_pct: float


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/analyze", response_model=AnalyzeResponse, summary="Analyse a URL, email, or token for phishing")
async def analyze_endpoint(req: AnalyzeRequest):
    """
    Accepts a URL, email body, plain text, or JWT token.
    Returns a phishing risk score (0–100) with a colour-coded level and
    detailed explanation of every flag raised.
    """
    try:
        result = analyze(req.text)
        return AnalyzeResponse(**result.to_dict())
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Analysis engine error. Please try again.")


@router.get("/health", summary="Health check")
async def health():
    """Returns 200 OK when the service is running."""
    return {"status": "ok", "service": "TokenGuardian", "version": "2.0.0"}


@router.get("/stats", response_model=StatsResponse, summary="Scan statistics")
async def stats():
    """
    Returns aggregated scan statistics.
    In demo mode these are in-memory (reset on restart).
    With Firestore they persist across restarts.
    """
    s = get_stats()
    total = s["total_scans"]
    phishing = s["phishing_detected"]
    rate = round((phishing / total * 100), 1) if total else 0.0
    return StatsResponse(
        total_scans=total,
        phishing_detected=phishing,
        safe_count=s["safe_count"],
        suspicious_count=s["suspicious_count"],
        detection_rate_pct=rate,
    )
