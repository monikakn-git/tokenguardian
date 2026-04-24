from fastapi import APIRouter, Depends

from core.dependencies import get_current_user
from database.firestore import get_db

router = APIRouter()


@router.get("/me")
def get_me(current_user: dict = Depends(get_current_user)):
    db = get_db()
    user_id = current_user["user_id"]
    docs = db.collection("users").where("id", "==", user_id).limit(1).get()
    if not docs:
        return {"user_id": user_id}
    user = docs[0].to_dict()
    return {
        "user_id": user_id,
        "username": user.get("username"),
        "created_at": str(user.get("created_at")),
    }


@router.get("/alerts")
def get_alerts(current_user: dict = Depends(get_current_user)):
    db = get_db()
    docs = (
        db.collection("security_alerts")
        .where("user_id", "==", current_user["user_id"])
        .order_by("created_at", direction="DESCENDING")
        .limit(20)
        .get()
    )
    return {"alerts": [d.to_dict() for d in docs]}


@router.get("/honeypot-logs")
def get_honeypot_logs(current_user: dict = Depends(get_current_user)):
    db = get_db()
    docs = (
        db.collection("honeypot_logs")
        .where("user_id", "==", current_user["user_id"])
        .order_by("timestamp", direction="DESCENDING")
        .limit(50)
        .get()
    )
    return {"logs": [d.to_dict() for d in docs]}


@router.get("/threat-reports")
def get_threat_reports(current_user: dict = Depends(get_current_user)):
    db = get_db()
    docs = (
        db.collection("threat_reports")
        .where("user_id", "==", current_user["user_id"])
        .order_by("generated_at", direction="DESCENDING")
        .limit(10)
        .get()
    )
    return {"reports": [d.to_dict() for d in docs]}
