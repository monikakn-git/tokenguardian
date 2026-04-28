import re
import math
from urllib.parse import urlparse

PHISHING_KEYWORDS = [
    "verify", "suspended", "urgent", "account", "password", "confirm",
    "update", "bank", "paypal", "login", "credential", "expire", "locked",
    "secure", "alert", "immediately", "click here", "limited time", "winner",
    "congratulations", "free", "prize", "claim", "act now"
]

SUSPICIOUS_TLDS = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.click']
LOOKALIKE_BRANDS = ['paypa1', 'g00gle', 'amaz0n', 'faceb00k', 'micros0ft', 'app1e', 'netfl1x']


def analyze_content(text: str) -> dict:
    score = 0
    signals = []

    # URL analysis
    urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text)
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        if not url.startswith('https://'):
            score += 20
            signals.append("Uses HTTP (not HTTPS) — insecure connection")

        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 35
                signals.append(f"Suspicious TLD ({tld}) commonly used in phishing")

        for brand in LOOKALIKE_BRANDS:
            if brand in domain:
                score += 45
                signals.append(f"Lookalike domain detected: '{brand}' mimics a trusted brand")

        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            score += 30
            signals.append("URL uses raw IP address instead of domain name")

        if len(domain) > 40:
            score += 15
            signals.append("Unusually long domain name — common obfuscation tactic")

        if domain.count('-') > 3:
            score += 20
            signals.append("Excessive hyphens in domain — phishing indicator")

        if domain.count('.') > 4:
            score += 25
            signals.append("Multiple subdomains — common in phishing redirects")

        if 'bit.ly' in domain or 'tinyurl' in domain or 'goo.gl' in domain:
            score += 25
            signals.append("URL shortener detected — hides final destination")

    # Keyword analysis
    text_lower = text.lower()
    matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in text_lower]
    if len(matched_keywords) >= 3:
        score += min(len(matched_keywords) * 8, 40)
        signals.append(f"High-urgency phishing language detected: {', '.join(matched_keywords[:5])}")
    elif len(matched_keywords) >= 1:
        score += len(matched_keywords) * 5
        signals.append(f"Suspicious keywords found: {', '.join(matched_keywords)}")

    # Urgency pattern detection
    urgency_patterns = [
        r'\b(24|48)\s*hours?\b', r'\bimmediately\b', r'\bact now\b',
        r'\bexpires?\s*(in|today|soon)\b', r'\blimited time\b'
    ]
    urgency_count = sum(1 for p in urgency_patterns if re.search(p, text_lower))
    if urgency_count >= 2:
        score += 25
        signals.append("Multiple urgency triggers — classic social engineering tactic")

    # No signals = safe
    if not signals:
        signals.append("No phishing indicators detected — content appears safe")

    score = min(score, 100)

    if score >= 70:
        risk_level = "HIGH"
        verdict = "⚠️ Likely Phishing — Do not click or respond"
    elif score >= 40:
        risk_level = "MEDIUM"
        verdict = "🔶 Suspicious — Proceed with caution"
    else:
        risk_level = "LOW"
        verdict = "✅ Safe — No significant threats detected"

    return {
        "score": score,
        "risk_level": risk_level,
        "verdict": verdict,
        "signals": signals,
        "url_count": len(urls)
    }
