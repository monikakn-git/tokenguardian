from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional

class TokenUsageSchema(BaseModel):
    id: int
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    used_at: datetime
    risk_score: float

    class Config:
        from_attributes = True

class TokenFamilySchema(BaseModel):
    id: int
    jti: str
    is_revoked: bool
    issued_at: datetime
    expires_at: datetime
    usages: List[TokenUsageSchema] = []

    class Config:
        from_attributes = True
