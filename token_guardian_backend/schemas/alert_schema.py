from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class AlertSchema(BaseModel):
    id: int
    user_id: int
    token_id: Optional[int] = None
    alert_type: str
    description: str
    created_at: datetime

    class Config:
        from_attributes = True
