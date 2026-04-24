import firebase_admin
from firebase_admin import credentials, firestore

from core.config import settings

_db = None


def get_db():
    global _db
    if _db is None:
        if not firebase_admin._apps:
            cred = credentials.Certificate(settings.GOOGLE_APPLICATION_CREDENTIALS)
            firebase_admin.initialize_app(cred)
        _db = firestore.client()
    return _db
