import os
from google.cloud import firestore
from datetime import datetime

db = None

def get_db():
    global db
    if db is None:
        db = firestore.Client(project=os.getenv("GCP_PROJECT_ID"))
    return db

async def save_scan(scan_result: dict):
    try:
        get_db().collection("scans").document(scan_result["id"]).set(scan_result)
    except Exception as e:
        print(f"Firestore save error: {e}")

async def get_scan_history(limit=50):
    try:
        docs = get_db().collection("scans").order_by("timestamp", direction=firestore.Query.DESCENDING).limit(limit).stream()
        return [doc.to_dict() for doc in docs]
    except:
        return []

async def save_user(username: str, data: dict):
    try:
        get_db().collection("users").document(username).set(data)
    except Exception as e:
        print(f"Firestore user save error: {e}")

async def get_user(username: str):
    try:
        doc = get_db().collection("users").document(username).get()
        return doc.to_dict() if doc.exists else None
    except:
        return None

async def save_security_event(event: dict):
    try:
        get_db().collection("security_events").document(event["id"]).set(event)
    except Exception as e:
        print(f"Firestore event save error: {e}")

async def get_security_events(limit=100):
    try:
        docs = get_db().collection("security_events").order_by("timestamp", direction=firestore.Query.DESCENDING).limit(limit).stream()
        return [doc.to_dict() for doc in docs]
    except:
        return []
