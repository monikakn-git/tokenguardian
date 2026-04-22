import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "TokenGuardian"
    SECRET_KEY: str = "a_very_secure_secret_key_change_in_production_123456"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    DATABASE_URL: str = "sqlite:///./sql_app.db"
    GEMINI_API_KEY: str = ""

    class Config:
        env_file = ".env"

settings = Settings()
