from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class AnalysisRequest(BaseModel):
    content: str
    content_type: Optional[str] = "message"  # 'url', 'email', 'message'

class AnalysisResponse(BaseModel):
    score: float
    explanation: str
    risk_level: str

class AnalysisHistorySchema(BaseModel):
    id: int
    content_type: str
    content: str
    score: float
    risk_level: str
    explanation: str
    created_at: datetime

    class Config:
        from_attributes = True