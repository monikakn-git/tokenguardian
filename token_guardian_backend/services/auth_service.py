import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from models.user import User
from models.token import TokenFamily
from core.security import get_password_hash, create_access_token
from schemas.user_schema import UserCreate

def create_user(db: Session, user: UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def issue_token(db: Session, user: User) -> str:
    # Generate a unique JWT ID (jti)
    jti = str(uuid.uuid4())
    
    expires_delta = timedelta(minutes=30)
    expires_at = datetime.now(timezone.utc) + expires_delta
    
    # Store token family in DB
    db_token_family = TokenFamily(
        user_id=user.id,
        jti=jti,
        expires_at=expires_at
    )
    db.add(db_token_family)
    db.commit()
    db.refresh(db_token_family)
    
    # Create the actual JWT
    access_token = create_access_token(
        data={"sub": user.username, "jti": jti},
        expires_delta=expires_delta
    )
    return access_token
