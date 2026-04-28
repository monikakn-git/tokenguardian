from fastapi import APIRouter, Depends, HTTPException
from schemas.data_shield_schema import ShieldRequest, ShieldResponse
from services.data_shield_service import DataShieldService
from api.auth import get_current_user

router = APIRouter()

@router.post("/analyze", response_model=ShieldResponse)
async def analyze_data_input(request: ShieldRequest, current_user = Depends(get_current_user)):
    """
    Analyzes input text against the current context URL to determine if sensitive data
    is being entered into an unverified or potentially malicious site.
    """
    result = DataShieldService.analyze_input(request.input_text, request.context_url)
    return result
