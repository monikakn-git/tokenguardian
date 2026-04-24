import asyncio
import json

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from services.auth_service import create_user, authenticate_user, issue_token
from services.guardian_service import evaluate, _call_gemini_risk
from core.security import anonymize_ip
from database.firestore import get_db

router = APIRouter()

# ── SIMULATE ATTACK ───────────────────────────────────────────────────────────

@router.post("/simulate-attack")
def simulate_attack():
    """
    Full scripted demo sequence:
    1. Register victim + attacker (same account, stolen token)
    2. Victim logs in from Bangalore IP
    3. Log victim's normal usage
    4. Attacker uses same token from Moscow IP → Guardian detects → Honeypot
    Returns structured event log for the 3-panel theater.
    """
    db = get_db()
    events = []

    # Step 1: Create demo user
    username = "alice_demo"
    password = "demo1234"
    existing = db.collection("users").where("username", "==", username).limit(1).get()
    if existing:
        user = existing[0].to_dict()
    else:
        user = create_user(username, password)
    events.append({"panel": "victim", "msg": f"👤 Victim '{username}' ready"})

    # Step 2: Victim logs in
    token, jti = issue_token(user["id"])
    events.append({"panel": "victim", "msg": "🔐 Victim logged in from Bangalore (122.15.x.x)"})
    events.append({"panel": "guardian", "msg": "✅ Session started — risk score: 0"})

    # Step 3: Victim makes a normal request (logs usage)
    victim_ip = "122.15.10.5"
    victim_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"
    result = evaluate(jti, victim_ip, victim_ua)
    events.append({"panel": "victim", "msg": "📧 Victim checks email — normal usage"})
    events.append({"panel": "guardian", "msg": f"✅ Guardian: {result['status']} — risk: 0"})

    # Step 4: Attacker uses stolen token from Moscow
    attacker_ip = "185.20.12.5"
    attacker_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14) Safari/17"
    events.append({"panel": "attacker", "msg": "💀 Attacker sends stolen token from Moscow"})

    result2 = evaluate(jti, attacker_ip, attacker_ua)
    events.append({"panel": "guardian", "msg": f"🚨 Guardian: {result2['status'].upper()} — honeypot activated!"})
    events.append({"panel": "attacker", "msg": "😈 Attacker receives: 200 OK (fake data)"})
    events.append({"panel": "victim", "msg": "🛡️ Alert: Suspicious access from Moscow. You're safe."})

    return {"events": events, "token": token, "jti": jti, "victim_ip": victim_ip, "attacker_ip": attacker_ip}


# ── SSE GEMINI REASONING STREAM ───────────────────────────────────────────────

@router.get("/stream-reasoning")
async def stream_reasoning(
    prev_ip: str = "122.15.10.5",
    curr_ip: str = "185.20.12.5",
    prev_ua: str = "Chrome/120 Windows",
    curr_ua: str = "Safari/17 Mac",
):
    """
    SSE endpoint — streams Gemini's reasoning word by word to the Guardian panel.
    """
    from datetime import datetime, timezone, timedelta
    import google.generativeai as genai
    from core.config import settings

    genai.configure(api_key=settings.GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-1.5-pro")

    now = datetime.now(timezone.utc)
    prev_time = now - timedelta(minutes=3)

    prompt = f"""
You are a security AI. Explain your reasoning for this session anomaly in 4-5 sentences.

Previous session: IP hash {anonymize_ip(prev_ip)}, device: {prev_ua}, time: {prev_time.isoformat()}
Current request: IP hash {anonymize_ip(curr_ip)}, device: {curr_ua}, time: {now.isoformat()}
Time delta: 3 minutes

Reason through whether this is physically possible and give a risk score 0-100 at the end.
Format: plain reasoning text, then on the last line: RISK_SCORE: <number>
"""

    async def event_generator():
        try:
            response = model.generate_content(prompt, stream=True)
            for chunk in response:
                if chunk.text:
                    data = json.dumps({"word": chunk.text})
                    yield f"data: {data}\n\n"
                    await asyncio.sleep(0.05)
            yield "data: {\"done\": true}\n\n"
        except Exception as e:
            yield f"data: {{\"error\": \"{str(e)}\"}}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")
