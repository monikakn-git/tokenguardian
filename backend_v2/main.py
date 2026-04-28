"""
main.py  ── TokenGuardian v2 FastAPI entry-point
"""

import logging
import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from core.config import settings

# ── Conditional imports (Firestore-dependent routes) ──────────────────────────
try:
    from core.dependencies import HoneypotInterrupt
    from api import auth, tokens, demo as demo_router
    _firestore_enabled = True
except Exception as _e:
    logging.warning(f"Firestore-dependent routes disabled: {_e}")
    _firestore_enabled = False

from api import analyze as analyze_router

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="TokenGuardian 🛡️",
    description=(
        "Proactive phishing & social-engineering defence system. "
        "Analyse URLs, emails, messages, and JWT tokens for threat indicators."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
origins = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Exception handlers ────────────────────────────────────────────────────────
if _firestore_enabled:
    @app.exception_handler(HoneypotInterrupt)
    async def honeypot_handler(request: Request, exc: HoneypotInterrupt):
        """Attacker gets a convincing 200 OK with AI-generated fake data."""
        return JSONResponse(status_code=200, content=exc.fake_data)

# ── Routers ───────────────────────────────────────────────────────────────────

# Core phishing-analysis routes (always available — demo-safe)
app.include_router(analyze_router.router, tags=["Phishing Analysis"])

# Firestore-backed auth + token-theft routes (require Firebase)
if _firestore_enabled:
    app.include_router(auth.router, prefix="/api/auth", tags=["Auth"])
    app.include_router(tokens.router, prefix="/api/tokens", tags=["Token Guardian"])
    app.include_router(demo_router.router, prefix="/api/demo", tags=["Demo"])
    logger.info("Firestore routes loaded ✅")
else:
    logger.warning("Running in DEMO MODE — Firestore routes unavailable ⚠️")


# ── Static frontend (optional) ────────────────────────────────────────────────
_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_STATIC_DIR):
    app.mount("/", StaticFiles(directory=_STATIC_DIR, html=True), name="static")
    logger.info("Serving React frontend from /static ✅")


# ── Root ─────────────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
def root():
    return {
        "service": "TokenGuardian 🛡️",
        "version": "2.0.0",
        "status": "ok",
        "firestore_enabled": _firestore_enabled,
        "docs": "/docs",
    }
