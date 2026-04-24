from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Project
    PROJECT_NAME: str = "TokenGuardian v2"

    # JWT
    SECRET_KEY: str = "changeme-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 30

    # Gemini
    GEMINI_API_KEY: str = ""

    # Firebase
    FIREBASE_PROJECT_ID: str = ""
    # Path to the service account JSON downloaded from Firebase console
    GOOGLE_APPLICATION_CREDENTIALS: str = "serviceAccountKey.json"

    # Guardian thresholds
    RISK_THRESHOLD: float = 70.0
    HEURISTIC_IP_WEIGHT: float = 75.0
    HEURISTIC_UA_WEIGHT: float = 30.0

    # Honeypot
    HONEYPOT_DURATION_MINUTES: int = 10

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
