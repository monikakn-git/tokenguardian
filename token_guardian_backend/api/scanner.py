from fastapi import APIRouter, Depends, HTTPException
from schemas.scanner_schema import ScanRequest, ScanResponse
from services.scanner_service import ScannerService
from api.auth import get_current_user

router = APIRouter()

@router.post("/scan", response_model=ScanResponse)
async def scan_url(request: ScanRequest, current_user = Depends(get_current_user)):
    """
    Scans a URL for malicious patterns and returns the security status.
    """
    if not request.url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    result = ScannerService.analyze_url(request.url)
    return result
