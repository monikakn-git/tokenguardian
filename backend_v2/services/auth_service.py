from datetime import datetime, timezone

from database.firestore import get_db
from core.security import hash_password, verify_password, create_access_token


def create_user(username: str, password: str) -> dict:
    db = get_db()
    # Check username taken
    existing = db.collection("users").where("username", "==", username).limit(1).get()
    if len(existing) > 0:
        return None
    doc_ref = db.collection("users").document()
    user = {
        "id": doc_ref.id,
        "username": username,
        "hashed_password": hash_password(password),
        "created_at": datetime.now(timezone.utc),
    }
    doc_ref.set(user)
    return user


def authenticate_user(username: str, password: str) -> dict | None:
    db = get_db()
    docs = db.collection("users").where("username", "==", username).limit(1).get()
    if not docs:
        return None
    user = docs[0].to_dict()
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


def issue_token(user_id: str) -> tuple[str, str]:
    """Creates token_families doc and returns (jwt, jti)."""
    db = get_db()
    token, jti = create_access_token(user_id)
    doc_ref = db.collection("token_families").document()
    doc_ref.set({
        "id": doc_ref.id,
        "user_id": user_id,
        "jti": jti,
        "mode": "active",
        "issued_at": datetime.now(timezone.utc),
        "honeypot_activated_at": None,
        "honeypot_expires_at": None,
        "attacker_ip": None,
        "attacker_ua": None,
    })
    return token, jti


def cascade_revoke(user_id: str) -> int:
    """CascadeShield: revoke ALL active/honeypot tokens for a user."""
    db = get_db()
    docs = db.collection("token_families") \
        .where("user_id", "==", user_id) \
        .where("mode", "in", ["active", "honeypot"]) \
        .get()
    batch = db.batch()
    for doc in docs:
        batch.update(doc.reference, {"mode": "revoked"})
    batch.commit()
    return len(docs)
