from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database.session import get_db
from services.phishing_service import analyze_phishing
from schemas.analysis_schema import AnalysisRequest, AnalysisResponse, AnalysisHistorySchema
from models.analysis import AnalysisHistory
from typing import List

router = APIRouter()

@router.post("/analyze", response_model=AnalysisResponse)
def analyze_content(request: AnalysisRequest, db: Session = Depends(get_db)):
    try:
        result = analyze_phishing(request.content)

        # Save to history
        history_entry = AnalysisHistory(
            content_type=request.content_type,
            content=request.content,
            score=result["score"],
            risk_level=result["risk_level"],
            explanation=result["explanation"]
        )
        db.add(history_entry)
        db.commit()

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@router.get("/history", response_model=List[AnalysisHistorySchema])
def get_analysis_history(limit: int = 5, db: Session = Depends(get_db)):
    history = db.query(AnalysisHistory).order_by(AnalysisHistory.created_at.desc()).limit(limit).all()
    return history

@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    total_scans = db.query(AnalysisHistory).count()
    phishing_detected = db.query(AnalysisHistory).filter(AnalysisHistory.score > 50).count()
    safe_count = total_scans - phishing_detected
    return {
        "total_scans": total_scans,
        "phishing_detected": phishing_detected,
        "safe_count": safe_count
    }