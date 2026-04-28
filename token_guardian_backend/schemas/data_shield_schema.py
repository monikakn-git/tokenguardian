from pydantic import BaseModel

class ShieldRequest(BaseModel):
    input_text: str
    context_url: str

class ShieldResponse(BaseModel):
    is_blocked: bool
    detected_data_type: str | None = None
    reason: str
