import google.generativeai as genai
from sqlalchemy.orm import Session
from models.token import TokenFamily, TokenUsage
from models.alert import SecurityAlert
from core.config import settings
import logging

logger = logging.getLogger(__name__)

if settings.GEMINI_API_KEY:
    genai.configure(api_key=settings.GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-1.5-pro')
else:
    model = None

def evaluate_token_risk(db: Session, token_family: TokenFamily, current_ip: str, current_ua: str) -> float:
    risk_score = 0.0
    alerts = []

    # 1. Base check: Is it already revoked?
    if token_family.is_revoked:
        risk_score = 100.0
        alerts.append("Usage of a revoked token detected.")
        return risk_score, alerts

    # Get previous usages
    previous_usages = db.query(TokenUsage).filter(
        TokenUsage.token_family_id == token_family.id
    ).order_by(TokenUsage.used_at.desc()).all()

    if not previous_usages:
        return risk_score, alerts # First use, baseline

    last_usage = previous_usages[0]

    # 2. Heuristics Check: Device/IP Mismatch
    if last_usage.ip_address != current_ip:
        risk_score += 75.0  # Increased to 75 for Hackathon demo (instant block)
        alerts.append(f"IP address changed from {last_usage.ip_address} to {current_ip}.")
    
    if last_usage.user_agent != current_ua:
        risk_score += 30.0
        alerts.append("User-Agent changed significantly.")

    # 3. AI Check (Google Tech Advantage)
    if model and risk_score > 0:
        try:
            # We use Gemini to evaluate if the context switch is reasonable or "impossible travel"
            prompt = f"""
            Analyze the following token usage context for potential theft or 'impossible travel':
            Previous IP: {last_usage.ip_address}
            Previous User-Agent: {last_usage.user_agent}
            Previous Time: {last_usage.used_at}

            Current IP: {current_ip}
            Current User-Agent: {current_ua}
            
            Based on this, return a risk score from 0 to 100 where 100 is definite theft.
            Only return the number, nothing else.
            """
            response = model.generate_content(prompt)
            ai_score = float(response.text.strip())
            risk_score = max(risk_score, ai_score) # Take the higher risk
            if ai_score >= 80:
                alerts.append("Gemini AI flagged this as high risk (Impossible Travel or Stolen Token).")
        except Exception as e:
            logger.error(f"Gemini API Error: {e}")

    # If risk is extremely high, we automatically revoke the token (Proactive Defense)
    if risk_score >= 70.0:
        token_family.is_revoked = True
        db.add(token_family)

        # Generate a Security Alert
        for alert_desc in alerts:
            alert = SecurityAlert(
                user_id=token_family.user_id,
                token_id=token_family.id,
                alert_type="HIGH_RISK_USAGE",
                description=alert_desc
            )
            db.add(alert)
        
        db.commit()

    return risk_score, alerts
