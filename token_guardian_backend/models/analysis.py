from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from sqlalchemy.sql import func
from database.session import Base

class AnalysisHistory(Base):
    __tablename__ = "analysis_history"

    id = Column(Integer, primary_key=True, index=True)
    content_type = Column(String, index=True)  # 'url', 'email', 'message'
    content = Column(Text)
    score = Column(Float)
    risk_level = Column(String)  # 'low', 'medium', 'high'
    explanation = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())