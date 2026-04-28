from pydantic import BaseModel

class ScanRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    status: str
    reason: str
    risk_score: int
