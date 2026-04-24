import json
import logging
from datetime import datetime, timezone, timedelta

import google.generativeai as genai

from core.config import settings
from database.firestore import get_db

logger = logging.getLogger(__name__)
_gemini = genai.GenerativeModel("gemini-1.5-pro")


# ── ACTIVATE ────────────────────────────────────────────────────────────────

def activate(token_family: dict, attacker_ip: str, attacker_ua: str):
    db = get_db()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=settings.HONEYPOT_DURATION_MINUTES)

    token_family["_ref"].update({
        "mode": "honeypot",
        "honeypot_activated_at": now,
        "honeypot_expires_at": expires,
        "attacker_ip": attacker_ip,
        "attacker_ua": attacker_ua,
    })

    db.collection("security_alerts").add({
        "user_id": token_family["user_id"],
        "token_family_id": token_family["id"],
        "alert_type": "HONEYPOT_ACTIVATED",
        "description": (
            f"Suspicious access detected from a different location/device. "
            f"A honeypot trap has been activated. The attacker is receiving "
            f"AI-generated fake data. Your real data is safe. "
            f"Please log in again to get a new secure session."
        ),
        "attacker_ip": attacker_ip,
        "created_at": now,
    })
    logger.warning(f"Honeypot activated for token_family={token_family['id']}")


# ── EXPIRY CHECK ─────────────────────────────────────────────────────────────

def is_expired(token_family: dict) -> bool:
    exp = token_family.get("honeypot_expires_at")
    if not exp:
        return False
    if hasattr(exp, "tzinfo") and exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) > exp


# ── IS REAL USER ─────────────────────────────────────────────────────────────

def is_real_user(token_family: dict, current_ip: str, current_ua: str) -> bool:
    return (
        current_ip == token_family.get("attacker_ip") is False
        and current_ua != token_family.get("attacker_ua")
    )


# ── FAKE DATA GENERATOR ───────────────────────────────────────────────────────

_FAKE_DATA_PROMPT = """
You are a security system generating FAKE but realistic-looking API response data
for a honeypot trap. An attacker has stolen a session token and is trying to access
user data. Generate plausible fake data that looks real but contains NO actual user
information.

The attacker requested: {method} {endpoint}

Previously generated fake identity for this session (maintain consistency):
{context}

Generate a realistic JSON response for this endpoint.
Rules:
- Use realistic but fictional names, emails, dates
- Match the structure a real API would return for this endpoint
- Do NOT include any markers revealing this is fake data
- Keep it concise

Return ONLY valid JSON. No explanation.
"""


def generate_fake_response(token_family: dict, endpoint: str, method: str) -> dict:
    db = get_db()
    tf_id = token_family["id"]
    cache_key = f"{tf_id}:{method}:{endpoint}"

    # Check cache first (consistency)
    cached_docs = db.collection("honeypot_cache") \
        .where("cache_key", "==", cache_key).limit(1).get()
    if cached_docs:
        cached = cached_docs[0].to_dict()
        _log_activity(db, token_family, endpoint, method, cached["cached_response"])
        return cached["cached_response"]

    # Build context from previously cached responses
    prior = db.collection("honeypot_cache") \
        .where("token_family_id", "==", tf_id).limit(5).get()
    context = "\n".join(
        f"- {d.to_dict()['endpoint']}: {json.dumps(d.to_dict()['cached_response'])[:100]}"
        for d in prior
    ) or "No prior context."

    prompt = _FAKE_DATA_PROMPT.format(method=method, endpoint=endpoint, context=context)

    try:
        resp = _gemini.generate_content(
            prompt,
            generation_config={"temperature": 0.7, "max_output_tokens": 300},
        )
        fake_data = json.loads(resp.text.strip())
    except Exception as e:
        logger.error(f"Gemini fake data failed: {e}")
        fake_data = {"message": "OK", "data": None}

    # Cache it
    db.collection("honeypot_cache").add({
        "cache_key": cache_key,
        "token_family_id": tf_id,
        "endpoint": endpoint,
        "method": method,
        "cached_response": fake_data,
        "generated_at": datetime.now(timezone.utc),
    })

    _log_activity(db, token_family, endpoint, method, fake_data)
    return fake_data


# ── ACTIVITY LOGGING ──────────────────────────────────────────────────────────

def _log_activity(db, token_family: dict, endpoint: str, method: str, fake_response: dict):
    prior_count = len(db.collection("honeypot_logs")
                       .where("token_family_id", "==", token_family["id"]).get())
    db.collection("honeypot_logs").add({
        "token_family_id": token_family["id"],
        "user_id": token_family["user_id"],
        "method": method,
        "endpoint": endpoint,
        "ip_address": token_family.get("attacker_ip"),
        "user_agent": token_family.get("attacker_ua"),
        "timestamp": datetime.now(timezone.utc),
        "fake_response_summary": str(fake_response)[:200],
        "request_number": prior_count + 1,
    })


# ── THREAT REPORT ─────────────────────────────────────────────────────────────

_THREAT_PROMPT = """
Analyze this attacker's behavior during a honeypot session and generate a threat intelligence report.

Attacker IP: {attacker_ip}
Attacker Device: {attacker_ua}
Activation time: {activated_at}
Total requests: {total_requests}

Request log:
{log_summary}

Generate a concise report covering:
1. ATTACK CLASSIFICATION (targeted exfiltration / exploratory / automated bot)
2. SOPHISTICATION LEVEL (low / medium / high) with one-sentence reasoning
3. BEHAVIORAL PATTERN (what did they target first? what were they after?)
4. TOP 2 RECOMMENDATIONS for the app owner

Keep it under 200 words. Be specific and actionable.
"""


def generate_threat_report(token_family: dict):
    db = get_db()
    logs = db.collection("honeypot_logs") \
        .where("token_family_id", "==", token_family["id"]) \
        .order_by("timestamp").get()

    log_summary = "\n".join(
        f"{l.to_dict()['timestamp']} | {l.to_dict()['method']} {l.to_dict()['endpoint']}"
        for l in logs
    ) or "No requests logged."

    prompt = _THREAT_PROMPT.format(
        attacker_ip=token_family.get("attacker_ip", "unknown"),
        attacker_ua=token_family.get("attacker_ua", "unknown"),
        activated_at=token_family.get("honeypot_activated_at", "unknown"),
        total_requests=len(logs),
        log_summary=log_summary,
    )

    try:
        resp = _gemini.generate_content(prompt, generation_config={"temperature": 0.3})
        report_text = resp.text
    except Exception as e:
        logger.error(f"Gemini threat report failed: {e}")
        report_text = "Threat report generation failed. Review honeypot_logs manually."

    db.collection("threat_reports").add({
        "token_family_id": token_family["id"],
        "user_id": token_family["user_id"],
        "report": report_text,
        "generated_at": datetime.now(timezone.utc),
        "total_attacker_requests": len(logs),
    })

    # Finally revoke the token
    token_family["_ref"].update({"mode": "revoked"})
    logger.warning(f"Honeypot expired → threat report generated → token revoked: {token_family['id']}")
