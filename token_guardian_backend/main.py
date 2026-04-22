from fastapi import FastAPI
from core.config import settings
from database.session import engine, Base
import models  # Important to register models
from api import auth, tokens

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title=settings.PROJECT_NAME)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(tokens.router, prefix="/api/tokens", tags=["tokens"])

@app.get("/")
def read_root():
    return {"message": "Welcome to TokenGuardian API"}
