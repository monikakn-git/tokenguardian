"""
phishing_service.py
-------------------
Proactive phishing & social-engineering analysis service.

Architecture (4 layers):
  1. Rule-based heuristic engine (always runs — demo-safe, no API keys needed)
  2. Gemini AI enrichment  (runs when GEMINI_API_KEY is set)
  3. Score aggregation + normalisation
  4. Stats persistence (in-memory + optional Firestore)
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# In-memory stats  (reset on restart; Firestore persistence is optional)
# ──────────────────────────────────────────────────────────────────────────────
_stats: dict = {
    "total_scans": 0,
    "phishing_detected": 0,
    "safe_count": 0,
    "suspicious_count": 0,
}

# ──────────────────────────────────────────────────────────────────────────────
# Heuristic rule tables
# ──────────────────────────────────────────────────────────────────────────────

# Urgency / pressure keywords
_URGENCY_PATTERNS = [
    r"\bact\s+now\b",
    r"\bimmediately\b",
    r"\burgent\b",
    r"\blast\s+chance\b",
    r"\bexpires?\s+(today|tonight|now|in\s+\d+\s+hour)\b",
    r"\byour\s+account\s+(will\s+be\s+)?suspended\b",
    r"\bverify\s+within\s+\d+\s+hour",
    r"\baction\s+required\b",
    r"\bdeadline\b",
    r"\blimited\s+time\b",
    r"\bfinal\s+notice\b",
    r"\b(suspend|terminat|delet|clos)\w+\s+your\s+account\b",
]

# Credential-harvesting phrases
_CREDENTIAL_PATTERNS = [
    r"\benter\s+your\s+password\b",
    r"\bconfirm\s+your\s+(credit\s+card|card\s+number|ssn|social\s+security)\b",
    r"\bprovide\s+your\s+(account\s+)?credentials\b",
    r"\bupdate\s+your\s+(billing|payment)\s+info(rmation)?\b",
    r"\bverify\s+your\s+(identity|account|email|details)\b",
    r"\bclick\s+(here|below)\s+to\s+(confirm|verify|update|activate)\b",
    r"\bsign\s+in\s+to\s+(confirm|verify)\b",
    r"\bopen\s+attachment\b",
    r"\bdownload\s+the\s+file\b",
    r"\byour\s+(otp|one.time\s+password|pin)\s+is\b",
    r"\bnever\s+share\s+your\s+otp\b",   # itself harmless but common in phishing payloads
]

# Known suspicious URL tokens
_SUSPICIOUS_URL_PATTERNS = [
    r"@",                          # user-info in URL
    r"//[^/]+//",                  # double-slash
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",   # raw IP host
    r"[a-z0-9\-]+\.(xyz|tk|ml|cf|ga|pw|top|gq|ru|cn|su)(/|$)",  # high-abuse TLDs
    r"bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly",    # URL shorteners
    r"secure[-_]?login",
    r"account[-_]?verify",
    r"update[-_]?billing",
    r"paypal\.com\..*\.com",       # brand in subdomain of different domain
    r"amazon\.com\..*\.com",
    r"google\.com\..*\.com",
    r"microsoft\.com\..*\.com",
    r"apple\.com\..*\.com",
    r"login[-_.]?(page|portal|secure)",
    r"confirm[-_.]?(account|email|identity)",
]

# Lookalike / typosquat domain patterns  (scored separately)
_BRAND_MISSPELLINGS = {
    "paypa1": "paypal",
    "paypai": "paypal",
    "amaz0n": "amazon",
    "micosoft": "microsoft",
    "micros0ft": "microsoft",
    "g00gle": "google",
    "g0ogle": "google",
    "app1e": "apple",
    "faceb00k": "facebook",
    "netfl1x": "netflix",
    "linkedln": "linkedin",
    "arnazon": "amazon",
    "yah00": "yahoo",
    "wellsfarg0": "wellsfargo",
    "bankofamerica-": "bankofamerica",
}


# ──────────────────────────────────────────────────────────────────────────────
# Analysis result dataclass
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class PhishingAnalysis:
    input_text: str
    input_type: str          # "url" | "email" | "text" | "token"
    risk_score: int          # 0-100
    risk_level: str          # "safe" | "suspicious" | "phishing"
    flags: list[str] = field(default_factory=list)
    explanation: str = ""
    ai_enhanced: bool = False
    analyzed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "input_text": self.input_text,
            "input_type": self.input_type,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "flags": self.flags,
            "explanation": self.explanation,
            "ai_enhanced": self.ai_enhanced,
            "analyzed_at": self.analyzed_at,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Helper utilities
# ──────────────────────────────────────────────────────────────────────────────

def _detect_input_type(text: str) -> str:
    text = text.strip()
    if re.match(r"^https?://", text, re.I):
        return "url"
    if re.search(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text):
        return "email"
    if re.match(r"^[A-Za-z0-9\-_\.]+\.[A-Za-z0-9\-_\.]+\.[A-Za-z0-9\-_\.]+$", text):
        return "token"
    return "text"


def _risk_level(score: int) -> str:
    if score < 35:
        return "safe"
    if score < 65:
        return "suspicious"
    return "phishing"


# ──────────────────────────────────────────────────────────────────────────────
# Layer 1: Heuristic engine
# ──────────────────────────────────────────────────────────────────────────────

def _heuristic_analyze(text: str, input_type: str) -> tuple[int, list[str]]:
    """Return (raw_score, flags).  raw_score is *unbounded* — caller clamps to 100."""
    score = 0
    flags: list[str] = []
    lower = text.lower()

    # ── URL-specific checks ──────────────────────────────────────────────────
    if input_type == "url":
        try:
            parsed = urlparse(text)
            host = parsed.hostname or ""

            # Raw IP address host
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                score += 40
                flags.append("🚨 URL uses a raw IP address — common phishing tactic")

            # HTTP (not HTTPS) for a login-looking path
            if parsed.scheme == "http" and any(
                kw in (parsed.path + parsed.query).lower()
                for kw in ["login", "secure", "account", "verify", "update"]
            ):
                score += 25
                flags.append("⚠️ Insecure HTTP used for a login/verification page")

            # Suspicious TLD
            tld_match = re.search(r"\.(xyz|tk|ml|cf|ga|pw|top|gq|su)$", host)
            if tld_match:
                score += 30
                flags.append(f"⚠️ High-risk top-level domain: .{tld_match.group(1)}")

            # URL shortener
            for shortener in ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"]:
                if shortener in host:
                    score += 20
                    flags.append(f"⚠️ URL shortener detected ({shortener}) — destination hidden")

            # @ in URL
            if "@" in text:
                score += 35
                flags.append("🚨 @ symbol in URL can be used to disguise the true destination")

            # Double slash after host
            if re.search(r"https?://[^/]+//", text):
                score += 20
                flags.append("⚠️ Unusual double-slash in URL path")

            # Brand in subdomain (e.g., paypal.com.evil.com)
            brand_subdomain = re.search(
                r"(paypal|amazon|google|microsoft|apple|facebook|netflix|linkedin)\.[a-z]+\.[a-z]+\.[a-z]+",
                host,
            )
            if brand_subdomain:
                score += 50
                flags.append(
                    f"🚨 Brand name '{brand_subdomain.group(1)}' appears in subdomain — classic phishing domain trick"
                )

            # Lookalike / typosquat
            for misspell, brand in _BRAND_MISSPELLINGS.items():
                if misspell in host:
                    score += 55
                    flags.append(f"🚨 Lookalike domain detected: '{misspell}' impersonating '{brand}'")

            # Many subdomains
            subdomains = host.split(".")
            if len(subdomains) > 4:
                score += 15
                flags.append(f"⚠️ Unusually deep subdomain structure ({len(subdomains)} levels)")

            # Port in URL
            if parsed.port and parsed.port not in (80, 443):
                score += 20
                flags.append(f"⚠️ Non-standard port {parsed.port} — rare for legitimate sites")

        except Exception:
            pass

        # Regex patterns on full URL
        for pattern in _SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, text, re.I):
                score += 10   # additive

    # ── Token checks ─────────────────────────────────────────────────────────
    if input_type == "token":
        # JWT-like: 3 base64 segments
        parts = text.split(".")
        if len(parts) == 3:
            import base64, json as _json
            try:
                # Decode header
                padded = parts[0] + "=" * (-len(parts[0]) % 4)
                header = _json.loads(base64.urlsafe_b64decode(padded))
                if header.get("alg", "").upper() == "NONE":
                    score += 70
                    flags.append('🚨 JWT uses "none" algorithm — token is unsigned and trivially forgeable')
                # Check for very long expiry
                padded2 = parts[1] + "=" * (-len(parts[1]) % 4)
                payload = _json.loads(base64.urlsafe_b64decode(padded2))
                exp = payload.get("exp")
                iat = payload.get("iat")
                if exp and iat and (exp - iat) > 86400 * 365:
                    score += 30
                    flags.append("⚠️ JWT expires more than 1 year from issuance — overly permissive")
                if not exp:
                    score += 40
                    flags.append("🚨 JWT has no expiry claim (exp) — token never expires")
                # Admin-looking claims
                for claim in ["admin", "role", "is_staff", "is_superuser", "sudo"]:
                    if claim in str(payload).lower():
                        score += 20
                        flags.append(f"⚠️ JWT payload contains elevated-privilege claim: '{claim}'")
            except Exception:
                score += 10
                flags.append("⚠️ Could not fully decode token structure")
        else:
            score += 5
            flags.append("ℹ️ Token does not appear to be a standard JWT")

    # ── Text/email checks ─────────────────────────────────────────────────────
    urgency_hits = []
    for pat in _URGENCY_PATTERNS:
        m = re.search(pat, lower)
        if m:
            urgency_hits.append(m.group())

    if urgency_hits:
        score += min(10 * len(urgency_hits), 40)
        flags.append(
            f"🚨 Urgency/pressure language detected: {', '.join(f'\"{h}\"' for h in urgency_hits[:3])}"
        )

    cred_hits = []
    for pat in _CREDENTIAL_PATTERNS:
        m = re.search(pat, lower)
        if m:
            cred_hits.append(m.group())

    if cred_hits:
        score += min(15 * len(cred_hits), 50)
        flags.append(
            f"🚨 Credential-harvesting phrases detected: {', '.join(f'\"{h}\"' for h in cred_hits[:3])}"
        )

    # Suspicious links within email body
    urls_in_text = re.findall(r"https?://[^\s\"'<>]+", text, re.I)
    for url in urls_in_text:
        sub_score, sub_flags = _heuristic_analyze(url, "url")
        if sub_score > 20:
            score += sub_score // 2
            flags.extend([f"(in embedded link) {f}" for f in sub_flags[:2]])

    return score, flags


# ──────────────────────────────────────────────────────────────────────────────
# Layer 2: Gemini AI enrichment
# ──────────────────────────────────────────────────────────────────────────────

_GEMINI_PROMPT = """
You are a cybersecurity expert specialising in phishing and social-engineering attacks.

Analyse the following {input_type} for phishing / social-engineering indicators.

INPUT:
\"\"\"
{text}
\"\"\"

Preliminary heuristic score: {heuristic_score}/100
Heuristic flags already identified:
{flags}

Your task:
1. Validate or challenge the heuristic flags.
2. Identify any ADDITIONAL threats the rule engine may have missed.
3. Provide a concise FINAL_SCORE between 0 and 100.
4. Write a plain-English explanation (3-5 sentences) suitable for a non-technical user.

Response format (JSON, no markdown fences):
{{
  "final_score": <integer 0-100>,
  "additional_flags": [<string>, ...],
  "explanation": "<plain-english explanation>"
}}
"""


def _gemini_enrich(text: str, input_type: str, heuristic_score: int, flags: list[str]) -> Optional[dict]:
    """Call Gemini API. Returns dict or None on failure."""
    try:
        from core.config import settings
        if not settings.GEMINI_API_KEY:
            return None

        import google.generativeai as genai
        genai.configure(api_key=settings.GEMINI_API_KEY)
        model = genai.GenerativeModel("gemini-1.5-flash")

        prompt = _GEMINI_PROMPT.format(
            input_type=input_type,
            text=text[:2000],   # trim to avoid token overflow
            heuristic_score=heuristic_score,
            flags="\n".join(f"- {f}" for f in flags) or "None",
        )

        resp = model.generate_content(
            prompt,
            generation_config={"temperature": 0.1, "max_output_tokens": 512},
        )
        import json
        raw = resp.text.strip()
        # Strip markdown fences if present
        raw = re.sub(r"^```json\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
        return json.loads(raw)
    except Exception as e:
        logger.warning(f"Gemini phishing enrichment failed: {e}")
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Layer 3: Build human-readable explanation (heuristic-only fallback)
# ──────────────────────────────────────────────────────────────────────────────

def _build_explanation(risk_level: str, flags: list[str], input_type: str, score: int) -> str:
    if risk_level == "safe":
        return (
            f"This {input_type} appears safe. No significant phishing indicators were detected. "
            "Always stay vigilant — no automated system is 100% accurate."
        )

    intro = {
        "suspicious": f"This {input_type} shows some warning signs (risk score {score}/100). "
                       "Treat it with caution.",
        "phishing":   f"⚠️ HIGH RISK — This {input_type} shows strong phishing indicators "
                       f"(risk score {score}/100). Do NOT click links or provide credentials.",
    }[risk_level]

    flag_summary = " | ".join(flags[:4])  # first 4 flags in one line
    advice = {
        "url":    "Do not visit this URL. If it claims to be from a trusted service, navigate directly to that service's official website.",
        "email":  "Do not reply to this email, click any links, or open attachments. Report it as phishing.",
        "text":   "Do not follow instructions in this message. Contact the sender through a verified channel to confirm.",
        "token":  "Do not use or distribute this token. Tokens with these properties may be forged or malicious.",
    }.get(input_type, "Exercise extreme caution with this content.")

    return f"{intro} Key issues: {flag_summary}. {advice}"


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def analyze(text: str) -> PhishingAnalysis:
    """Full analysis pipeline. Always returns a PhishingAnalysis."""
    text = text.strip()
    input_type = _detect_input_type(text)

    # Layer 1: heuristics
    raw_score, flags = _heuristic_analyze(text, input_type)
    heuristic_score = min(int(raw_score), 100)

    # Layer 2: Gemini (optional)
    ai_enhanced = False
    gemini_result = _gemini_enrich(text, input_type, heuristic_score, flags)
    if gemini_result:
        ai_enhanced = True
        final_score = min(int(gemini_result.get("final_score", heuristic_score)), 100)
        additional = gemini_result.get("additional_flags", [])
        flags = flags + [f"🤖 AI: {f}" for f in additional]
        explanation = gemini_result.get("explanation", "")
    else:
        final_score = heuristic_score
        explanation = ""

    risk_level = _risk_level(final_score)

    if not explanation:
        explanation = _build_explanation(risk_level, flags, input_type, final_score)

    # Layer 3: persist stats
    _update_stats(risk_level)

    # Optionally persist to Firestore (fire-and-forget; fail silently)
    _persist_to_firestore(text, input_type, final_score, risk_level, flags, explanation)

    return PhishingAnalysis(
        input_text=text,
        input_type=input_type,
        risk_score=final_score,
        risk_level=risk_level,
        flags=flags,
        explanation=explanation,
        ai_enhanced=ai_enhanced,
    )


def get_stats() -> dict:
    return dict(_stats)


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _update_stats(risk_level: str):
    _stats["total_scans"] += 1
    if risk_level == "phishing":
        _stats["phishing_detected"] += 1
    elif risk_level == "suspicious":
        _stats["suspicious_count"] += 1
    else:
        _stats["safe_count"] += 1


def _persist_to_firestore(text, input_type, score, risk_level, flags, explanation):
    try:
        from database.firestore import get_db
        db = get_db()
        db.collection("phishing_scans").add({
            "input_preview": text[:200],
            "input_type": input_type,
            "risk_score": score,
            "risk_level": risk_level,
            "flags": flags,
            "explanation": explanation,
            "scanned_at": datetime.now(timezone.utc),
        })
    except Exception:
        pass   # Firestore not configured → silent no-op
