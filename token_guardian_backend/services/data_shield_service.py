import re
from urllib.parse import urlparse

class DataShieldService:
    VERIFIED_DOMAINS = [
        "chase.com",
        "bankofamerica.com",
        "paypal.com",
        "wellsfargo.com",
        "citi.com",
        "stripe.com",
        "google.com"
    ]

    # Simple regex for finding 13-19 digit credit cards (ignoring spaces/dashes for logic check)
    CC_PATTERN = r'\b(?:\d[ -]*?){13,16}\b'
    
    # Simple SSN regex (XXX-XX-XXXX or XXXXXXXXX)
    SSN_PATTERN = r'\b\d{3}[-]?\d{2}[-]?\d{4}\b'

    @staticmethod
    def is_verified_domain(url: str) -> bool:
        if not url:
            return False
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
                
            # Check if domain ends with any verified domain (handles subdomains like login.chase.com)
            for verified in DataShieldService.VERIFIED_DOMAINS:
                if domain == verified or domain.endswith('.' + verified):
                    return True
            return False
        except:
            return False

    @staticmethod
    def analyze_input(input_text: str, context_url: str):
        if not input_text:
            return {
                "is_blocked": False,
                "detected_data_type": None,
                "reason": "Empty input."
            }

        detected_type = None

        # Clean text for CC check
        clean_text = re.sub(r'[\s-]', '', input_text)
        
        if re.search(r'\b\d{13,19}\b', clean_text): # Simplistic CC check after stripping chars
             detected_type = "Credit Card Number"
        elif re.search(DataShieldService.SSN_PATTERN, input_text):
            detected_type = "Social Security Number"
            
        if not detected_type:
            return {
                "is_blocked": False,
                "detected_data_type": None,
                "reason": "No sensitive data detected."
            }
            
        # Sensitive data found, verify context
        if DataShieldService.is_verified_domain(context_url):
            return {
                "is_blocked": False,
                "detected_data_type": detected_type,
                "reason": f"{detected_type} detected, but context ({context_url}) is a verified secure domain."
            }
        else:
            return {
                "is_blocked": True,
                "detected_data_type": detected_type,
                "reason": f"BLOCKED: Attempted to enter {detected_type} on an unverified or potentially malicious domain."
            }
