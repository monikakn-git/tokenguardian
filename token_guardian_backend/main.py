from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.config import settings
from database.session import engine, Base
import models  # Important to register models
from api import auth, tokens, scanner, data_shield
...
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(tokens.router, prefix="/api/tokens", tags=["tokens"])
app.include_router(scanner.router, prefix="/api/scanner", tags=["scanner"])
app.include_router(data_shield.router, prefix="/api/shield", tags=["data_shield"])


@app.get("/")
def read_root():
    return {"message": "Welcome to TokenGuardian API"}
