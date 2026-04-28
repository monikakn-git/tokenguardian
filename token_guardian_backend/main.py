import hashlib
import os
import time
import uuid
from collections import deque, defaultdict
from datetime import datetime
from ipaddress import ip_address
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

from analyzer import analyze_content
from gemini_analyzer import gemini_analyze

load_dotenv()

app = FastAPI(title="TokenGuardian API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

scan_history = deque(maxlen=100)
stats = {"total": 0, "phishing": 0, "suspicious": 0, "safe": 0}
active_websockets = []

SESSION_COOKIE_NAME = "tg_session_id"
MAX_REQUESTS_PER_MINUTE = 40
REQUEST_WINDOW_SECONDS = 60
BLOCK_DURATION_SECONDS = 3600

blocked_ips: dict[str, float] = {}
blocked_sessions: dict[str, float] = {}
request_history: dict[str, deque[float]] = defaultdict(lambda: deque())
session_store: dict[str, dict] = {}

def normalize_ip(raw_ip: Optional[str]) -> str:
    if not raw_ip:
        return "unknown"
    raw_ip = raw_ip.split(",")[0].strip()
    try:
        return str(ip_address(raw_ip))
    except Exception:
        return raw_ip


def create_session_id(client_ip: str) -> str:
    token = f"{client_ip}-{uuid.uuid4()}-{time.time()}"
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def is_blocked(client_ip: str, session_id: Optional[str]) -> bool:
    now = time.time()
    if client_ip in blocked_ips:
        if blocked_ips[client_ip] > now:
            return True
        del blocked_ips[client_ip]
    if session_id and session_id in blocked_sessions:
        if blocked_sessions[session_id] > now:
            return True
        del blocked_sessions[session_id]
    return False


def block_client(client_ip: str, session_id: Optional[str] = None) -> None:
    expire = time.time() + BLOCK_DURATION_SECONDS
    blocked_ips[client_ip] = expire
    if session_id:
        blocked_sessions[session_id] = expire


def record_request(client_ip: str, session_id: Optional[str]) -> None:
    now = time.time()
    for key in (client_ip, session_id) if session_id else (client_ip,):
        history = request_history[key]
        history.append(now)
        while history and now - history[0] > REQUEST_WINDOW_SECONDS:
            history.popleft()
        if len(history) > MAX_REQUESTS_PER_MINUTE:
            block_client(client_ip, session_id)
            raise HTTPException(status_code=429, detail="Too many requests")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "TokenGuardian"}


async def authorize_request(request: Request, response: Response) -> str:
    client_ip = normalize_ip(request.headers.get("x-forwarded-for") or request.client.host if request.client else "unknown")
    session_id = request.cookies.get(SESSION_COOKIE_NAME) or request.headers.get("x-session-id")

    if is_blocked(client_ip, session_id):
        raise HTTPException(status_code=403, detail="Access denied")

    if not session_id or session_id not in session_store:
        session_id = create_session_id(client_ip)
        session_store[session_id] = {
            "ip": client_ip,
            "created_at": time.time(),
            "last_seen": time.time(),
        }
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=session_id,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=7 * 24 * 3600,
        )
    else:
        session_store[session_id]["last_seen"] = time.time()

    record_request(client_ip, session_id)
    return session_id

@app.post("/api/analyze")
async def analyze(request: Request, response: Response, _session_id: str = Depends(authorize_request)):
    body = await request.json()
    content = body.get("content", "").strip()
    if not content:
        return JSONResponse(status_code=400, content={"detail": "Content is required."})

    rule_result = analyze_content(content)
    gemini_result = await gemini_analyze(content, rule_result)
    final_score = gemini_result.get("final_score", rule_result["score"])

    if final_score >= 70:
        risk = "HIGH"
        stats["phishing"] += 1
    elif final_score >= 40:
        risk = "MEDIUM"
        stats["suspicious"] += 1
    else:
        risk = "LOW"
        stats["safe"] += 1
    stats["total"] += 1

    result = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "content_preview": content[:120] + ("..." if len(content) > 120 else ""),
        "score": final_score,
        "risk_level": risk,
        "verdict": gemini_result.get("explanation", rule_result["verdict"]),
        "summary": gemini_result.get("explanation", rule_result["verdict"]),
        "attack_type": gemini_result.get("attack_type", "unknown"),
        "signals": rule_result["signals"],
        "recommendations": gemini_result.get("recommendations", []),
        "indicators": gemini_result.get("indicators", []),
        "confidence": gemini_result.get("confidence", "medium"),
        "url_count": rule_result["url_count"],
    }

    scan_history.appendleft(result)

    if risk == "HIGH":
        dead_sockets = []
        for ws in active_websockets:
            try:
                await ws.send_json({"type": "alert", "data": result})
            except Exception:
                dead_sockets.append(ws)
        for ws in dead_sockets:
            if ws in active_websockets:
                active_websockets.remove(ws)

    return result

@app.get("/api/history")
async def get_history(limit: int = 5, response: Response = None, _session_id: str = Depends(authorize_request)):
    return list(scan_history)[:limit]

@app.get("/api/stats")
async def get_stats(response: Response, _session_id: str = Depends(authorize_request)):
    threat_score = round(((stats["phishing"] + stats["suspicious"]) / max(stats["total"], 1)) * 100)
    return {
        **stats,
        "threat_score": threat_score,
        "alerts": stats["phishing"],
        "recent_scans": list(scan_history)[:5],
    }

@app.get("/api/graph")
async def get_graph(response: Response, _session_id: str = Depends(authorize_request)):
    nodes = []
    links = []
    history = list(scan_history)[:20]
    for scan in history:
        nodes.append({
            "id": scan["id"],
            "label": scan["attack_type"] or 'scan',
            "score": scan["score"],
            "risk": scan["risk_level"],
            "type": "scan",
            "threat": scan["risk_level"] == 'HIGH',
        })
    for index, scan in enumerate(history[:-1]):
        links.append({"source": scan["id"], "target": history[index + 1]["id"]})
    return {"nodes": nodes, "links": links, "edges": links}

@app.websocket("/alerts/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    active_websockets.append(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        if ws in active_websockets:
            active_websockets.remove(ws)
