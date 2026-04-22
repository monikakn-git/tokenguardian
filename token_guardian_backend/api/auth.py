from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from database.session import get_db
from models.user import User
from schemas.user_schema import UserCreate, UserResponse, Token
from services.auth_service import create_user, issue_token
from core.security import verify_password, get_password_hash
from models.token import TokenUsage, TokenFamily
from core.dependencies import get_current_user
from pydantic import BaseModel

router = APIRouter()

@router.post("/register", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return create_user(db=db, user=user)

@router.post("/login", response_model=Token)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = issue_token(db=db, user=user)
    
    # Context extraction for TokenGuardian
    # Use X-Forwarded-For to allow simulating IP changes in tests
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    user_agent = request.headers.get("user-agent", "unknown")
    
    # The TokenFamily was just created in issue_token. We need to find its ID.
    from jose import jwt
    from core.config import settings
    payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    jti = payload.get("jti")
    
    from models.token import TokenFamily
    token_family = db.query(TokenFamily).filter(TokenFamily.jti == jti).first()
    
    if token_family:
        usage = TokenUsage(
            token_family_id=token_family.id,
            ip_address=client_ip,
            user_agent=user_agent,
            risk_score=0.0 # Initial login is baseline
        )
        db.add(usage)
        db.commit()

    return {"access_token": access_token, "token_type": "bearer"}

class PasswordReset(BaseModel):
    old_password: str
    new_password: str

@router.post("/reset-password")
def reset_password(data: PasswordReset, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(data.old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect old password")
    
    current_user.hashed_password = get_password_hash(data.new_password)
    db.add(current_user)
    
    # TokenGuardian: The crucial fix - Revoke all existing tokens for this user
    active_tokens = db.query(TokenFamily).filter(
        TokenFamily.user_id == current_user.id, 
        TokenFamily.is_revoked == False
    ).all()
    
    for token in active_tokens:
        token.is_revoked = True
        db.add(token)
        
    db.commit()
    return {"message": "Password reset successful. All previous sessions have been revoked."}
