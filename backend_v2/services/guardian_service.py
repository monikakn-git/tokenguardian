import logging
from datetime import datetime, timezone

import google.generativeai as genai

from core.config import settings
from core.security import anonymize_ip
from database.firestore import get_db

logger = logging.getLogger(__name__)

genai.configure(api_key=settings.GEMINI_API_KEY)
_gemini = genai.GenerativeModel("gemini-1.5-pro")

# ── GEMINI RISK SCORING PROMPT ──────────────────────────────────────────────

_RISK_PROMPT = """
You are a security system evaluating whether an OAuth session token has been stolen.

HISTORICAL SESSION (verified facts from database):
- Anonymized IP hash: {prev_ip}
- Device (User-Agent): {prev_ua}
- Last seen: {prev_time}

CURRENT REQUEST:
- Anonymized IP hash: {curr_ip}
- Device (User-Agent): {curr_ua}
- Time: {curr_time}
- Seconds since last request: {delta_seconds}

The IP hashes are different if the values differ. You cannot determine exact location,
but you can reason about whether the same person is likely making this request based on
device consistency, timing plausibility, and pattern coherence.

Return ONLY a single integer between 0 and 100 representing theft risk.
0 = definitely legitimate. 100 = definitely stolen.
No explanation. No text. Just the number.
"""


def _call_gemini_risk(prev_ip, prev_ua, prev_time, curr_ip, curr_ua, curr_time) -> float:
    delta = (curr_time - prev_time).total_seconds()
    prompt = _RISK_PROMPT.format(
        prev_ip=anonymize_ip(prev_ip),
        prev_ua=prev_ua,
        curr_ip=anonymize_ip(curr_ip),
        curr_ua=curr_ua,
        prev_time=prev_time.isoformat(),
        curr_time=curr_time.isoformat(),
        delta_seconds=int(delta),
    )
    try:
        resp = _gemini.generate_content(
            prompt,
            generation_config={"temperature": 0, "max_output_tokens": 10},
        )
        return min(100.0, max(0.0, float(resp.text.strip())))
    except Exception as e:
        logger.error(f"Gemini risk scoring failed: {e}")
        return None  # signals fallback to heuristic


def _heuristic_score(prev_ip: str, prev_ua: str, curr_ip: str, curr_ua: str) -> float:
    score = 0.0
    if anonymize_ip(prev_ip) != anonymize_ip(curr_ip):
        score += settings.HEURISTIC_IP_WEIGHT
    if prev_ua.strip().lower() != curr_ua.strip().lower():
        score += settings.HEURISTIC_UA_WEIGHT
    return min(score, 100.0)


def _log_usage(db, token_family_id: str, user_id: str, ip: str, ua: str, risk: float):
    db.collection("token_usages").add({
        "token_family_id": token_family_id,
        "user_id": user_id,
        "ip_address": ip,
        "user_agent": ua,
        "risk_score": risk,
        "used_at": datetime.now(timezone.utc),
    })


def evaluate(jti: str, current_ip: str, current_ua: str) -> dict:
    """
    4-layer pipeline.
    Returns:
      {"status": "allow"}
      {"status": "honeypot", "token_family": <doc_dict>}
      {"status": "revoked"}
      {"status": "not_found"}
    """
    db = get_db()

    # ── LAYER 0: Token lookup ────────────────────────────────────────────────
    docs = db.collection("token_families").where("jti", "==", jti).limit(1).get()
    if not docs:
        return {"status": "not_found"}

    tf_doc = docs[0]
    tf = tf_doc.to_dict()
    tf["_ref"] = tf_doc.reference

    if tf["mode"] == "revoked":
        return {"status": "revoked"}

    # ── LAYER 1: Already in honeypot? ────────────────────────────────────────
    if tf["mode"] == "honeypot":
        return {"status": "honeypot", "token_family": tf}

    # ── LAYER 2: Heuristic fast-path ─────────────────────────────────────────
    usages = (
        db.collection("token_usages")
        .where("token_family_id", "==", tf["id"])
        .order_by("used_at", direction="DESCENDING")
        .limit(1)
        .get()
    )

    if not usages:
        # First ever request — log and allow
        _log_usage(db, tf["id"], tf["user_id"], current_ip, current_ua, 0.0)
        return {"status": "allow"}

    last = usages[0].to_dict()
    h_score = _heuristic_score(last["ip_address"], last["user_agent"], current_ip, current_ua)

    if h_score == 0.0:
        # Fast-path: nothing changed, skip Gemini
        _log_usage(db, tf["id"], tf["user_id"], current_ip, current_ua, 0.0)
        return {"status": "allow"}

    # ── LAYER 3: Gemini contextual reasoning ─────────────────────────────────
    g_score = _call_gemini_risk(
        last["ip_address"], last["user_agent"], last["used_at"],
        current_ip, current_ua, datetime.now(timezone.utc),
    )
    final_score = max(h_score, g_score) if g_score is not None else h_score

    logger.info(f"Risk eval jti={jti[:8]} h={h_score} g={g_score} final={final_score}")

    # ── LAYER 4: Autonomous response ─────────────────────────────────────────
    _log_usage(db, tf["id"], tf["user_id"], current_ip, current_ua, final_score)

    if final_score >= settings.RISK_THRESHOLD:
        return {"status": "activate_honeypot", "token_family": tf, "risk_score": final_score}

    return {"status": "allow"}
