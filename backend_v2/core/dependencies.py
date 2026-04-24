from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError

from core.security import decode_token
from database.firestore import get_db
from services import guardian_service, honeypot_service

security = HTTPBearer()


class HoneypotInterrupt(Exception):
    """Raised when a request is intercepted by the honeypot."""
    def __init__(self, fake_data: dict):
        self.fake_data = fake_data


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host or "0.0.0.0"


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token = credentials.credentials
    current_ip = _get_client_ip(request)
    current_ua = request.headers.get("User-Agent", "unknown")
    endpoint = request.url.path

    # Decode JWT
    try:
        payload = decode_token(token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    jti = payload.get("jti")
    user_id = payload.get("sub")
    if not jti or not user_id:
        raise HTTPException(status_code=401, detail="Malformed token")

    # Run Guardian pipeline
    result = guardian_service.evaluate(jti, current_ip, current_ua)

    if result["status"] == "not_found":
        raise HTTPException(status_code=401, detail="Token not recognised")

    if result["status"] == "revoked":
        raise HTTPException(status_code=403, detail="Token has been revoked")

    if result["status"] == "honeypot":
        tf = result["token_family"]
        # Check if honeypot has expired
        if honeypot_service.is_expired(tf):
            honeypot_service.generate_threat_report(tf)
            raise HTTPException(status_code=403, detail="Session expired")
        # Serve fake data — attacker never sees a real 403
        fake = honeypot_service.generate_fake_response(tf, endpoint, request.method)
        raise HoneypotInterrupt(fake_data=fake)

    if result["status"] == "activate_honeypot":
        tf = result["token_family"]
        honeypot_service.activate(tf, current_ip, current_ua)
        fake = honeypot_service.generate_fake_response(tf, endpoint, request.method)
        raise HoneypotInterrupt(fake_data=fake)

    # Normal flow — return user_id for the endpoint to use
    return {"user_id": user_id}
