import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.config import settings
from core.dependencies import HoneypotInterrupt
from api import auth, tokens

logging.basicConfig(level=logging.INFO)

app = FastAPI(title=settings.PROJECT_NAME, version="2.0.0")

# ── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── HONEYPOT EXCEPTION HANDLER ────────────────────────────────────────────────
# Attacker gets 200 OK with fake data — they never know they're trapped
@app.exception_handler(HoneypotInterrupt)
async def honeypot_handler(request: Request, exc: HoneypotInterrupt):
    return JSONResponse(status_code=200, content=exc.fake_data)

# ── ROUTERS ───────────────────────────────────────────────────────────────────
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(tokens.router, prefix="/api/tokens", tags=["tokens"])


@app.get("/")
def health():
    return {"status": "ok", "service": settings.PROJECT_NAME}
