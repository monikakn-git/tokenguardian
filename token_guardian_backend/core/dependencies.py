from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from database.session import get_db
from models.user import User
from models.token import TokenFamily, TokenUsage
from core.config import settings
from services.guardian_service import evaluate_token_risk

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def get_current_user(request: Request, simulate_ip: str = None, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        jti: str = payload.get("jti")
        if username is None or jti is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception

    token_family = db.query(TokenFamily).filter(TokenFamily.jti == jti).first()
    if token_family is None:
        raise credentials_exception

    # TokenGuardian: Check risk before allowing request
    if simulate_ip:
        client_ip = simulate_ip  # Let the user act like a hacker for testing!
    else:
        client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
        
    user_agent = request.headers.get("user-agent", "unknown")

    risk_score, alerts = evaluate_token_risk(db, token_family, client_ip, user_agent)
    
    # Log usage
    usage = TokenUsage(
        token_family_id=token_family.id,
        ip_address=client_ip,
        user_agent=user_agent,
        risk_score=risk_score
    )
    db.add(usage)
    db.commit()

    if token_family.is_revoked or risk_score >= 70.0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token has been revoked due to high security risk or anomaly detected."
        )

    return user
