from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from database.session import Base

class TokenFamily(Base):
    __tablename__ = "token_families"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    jti = Column(String, unique=True, index=True, nullable=False)  # JWT ID
    is_revoked = Column(Boolean, default=False)
    issued_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)

    user = relationship("User", back_populates="tokens")
    usages = relationship("TokenUsage", back_populates="token_family", cascade="all, delete-orphan")

class TokenUsage(Base):
    __tablename__ = "token_usages"

    id = Column(Integer, primary_key=True, index=True)
    token_family_id = Column(Integer, ForeignKey("token_families.id"), nullable=False)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    used_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    risk_score = Column(Float, default=0.0)

    token_family = relationship("TokenFamily", back_populates="usages")
