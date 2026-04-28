import re
from urllib.parse import urlparse

class ScannerService:
    SUSPICIOUS_DOMAINS = [
        "evil.com",
        "phishing-site.net",
        "free-money.org",
        "secure-login-update.com",
        "verify-account-now.top"
    ]

    @staticmethod
    def analyze_url(url: str):
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                # Try adding http if missing to see if it parses
                if not url.startswith(('http://', 'https://')):
                    parsed = urlparse('http://' + url)
                
            domain = parsed.netloc.lower()
            
            # 1. Check against blacklist
            if any(suspicious in domain for suspicious in ScannerService.SUSPICIOUS_DOMAINS):
                return {
                    "status": "malicious",
                    "reason": "Known malicious domain detected.",
                    "risk_score": 95
                }

            # 2. Check for IP address as domain
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if re.match(ip_pattern, domain):
                return {
                    "status": "malicious",
                    "reason": "URL uses an IP address instead of a domain name, often used in phishing.",
                    "risk_score": 85
                }

            # 3. Check for suspicious keywords in domain
            suspicious_keywords = ["login", "verify", "update", "bank", "secure", "account"]
            if any(keyword in domain for keyword in suspicious_keywords) and domain not in ["google.com", "microsoft.com", "apple.com"]:
                return {
                    "status": "suspicious",
                    "reason": "Domain contains security-related keywords commonly used in phishing.",
                    "risk_score": 60
                }

            return {
                "status": "safe",
                "reason": "No immediate threats detected.",
                "risk_score": 5
            }

        except Exception as e:
            return {
                "status": "error",
                "reason": f"Invalid URL format: {str(e)}",
                "risk_score": 0
            }
