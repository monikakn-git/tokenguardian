import re
import google.generativeai as genai
from core.config import settings
import logging

logger = logging.getLogger(__name__)

if settings.GEMINI_API_KEY:
    genai.configure(api_key=settings.GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-1.5-pro')
else:
    model = None

def analyze_phishing(content: str) -> dict:
    """
    Analyze content for phishing risk.
    Returns: {"score": float, "explanation": str, "risk_level": str}
    """
    score = 0.0
    explanations = []

    # Rule-based heuristics
    # 1. Suspicious URL patterns
    url_pattern = r'https?://[^\s]+'
    urls = re.findall(url_pattern, content)
    for url in urls:
        if any(susp in url.lower() for susp in ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'short']):
            score += 30
            explanations.append(f"Shortened URL detected: {url}")
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):  # IP addresses
            score += 20
            explanations.append(f"IP address in URL: {url}")
        # Lookalike domains (simple check)
        if 'google' in url.lower() and 'googIe' in url:  # homoglyph
            score += 40
            explanations.append(f"Potential lookalike domain: {url}")

    # 2. Urgency keywords
    urgency_words = ['urgent', 'immediate', 'action required', 'act now', 'limited time', 'expires soon']
    for word in urgency_words:
        if word in content.lower():
            score += 15
            explanations.append(f"Urgency keyword detected: '{word}'")

    # 3. Credential-harvesting phrases
    cred_phrases = ['verify your account', 'login here', 'reset password', 'confirm identity', 'update payment info']
    for phrase in cred_phrases:
        if phrase in content.lower():
            score += 25
            explanations.append(f"Credential-harvesting phrase: '{phrase}'")

    # 4. Email-specific checks if it looks like an email
    if '@' in content and ('subject:' in content.lower() or 'from:' in content.lower()):
        score += 10
        explanations.append("Email format detected - increased scrutiny")

    # AI-enhanced analysis if model available
    if model:
        try:
            prompt = f"""
            Analyze the following text for phishing indicators. Provide a risk score from 0-100 and a brief explanation.
            Text: {content[:1000]}  # Limit to 1000 chars

            Response format: SCORE: <number>
            EXPLANATION: <brief text>
            """
            response = model.generate_content(prompt)
            ai_text = response.text.strip()
            # Parse response
            score_match = re.search(r'SCORE:\s*(\d+)', ai_text, re.IGNORECASE)
            if score_match:
                ai_score = float(score_match.group(1))
                score = max(score, ai_score)  # Take higher
                exp_match = re.search(r'EXPLANATION:\s*(.+)', ai_text, re.IGNORECASE)
                if exp_match:
                    explanations.append(f"AI Analysis: {exp_match.group(1)}")
        except Exception as e:
            logger.error(f"Gemini API Error: {e}")

    # Cap score at 100
    score = min(score, 100.0)

    # Determine risk level
    if score >= 70:
        risk_level = "high"
    elif score >= 40:
        risk_level = "medium"
    else:
        risk_level = "low"

    explanation = "; ".join(explanations) if explanations else "No suspicious indicators detected."

    return {
        "score": round(score, 1),
        "explanation": explanation,
        "risk_level": risk_level
    }