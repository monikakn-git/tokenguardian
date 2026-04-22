from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database.session import get_db
from models.user import User
from models.alert import SecurityAlert
from core.dependencies import get_current_user
from schemas.alert_schema import AlertSchema
from typing import List

router = APIRouter()

@router.get("/me")
def read_users_me(current_user: User = Depends(get_current_user)):
    return {"id": current_user.id, "username": current_user.username}

@router.get("/alerts", response_model=List[AlertSchema])
def get_my_alerts(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    alerts = db.query(SecurityAlert).filter(SecurityAlert.user_id == current_user.id).all()
    return alerts
