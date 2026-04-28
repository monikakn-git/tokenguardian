import google.generativeai as genai
import os
import json

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

async def gemini_analyze(text: str, rule_based_result: dict) -> dict:
    if not GEMINI_API_KEY:
        return {
            "gemini_score": rule_based_result["score"],
            "final_score": rule_based_result["score"],
            "confidence": "low",
            "attack_type": "unknown",
            "explanation": "Rule-based scoring applied for this request.",
            "recommendations": ["Treat with caution", "Do not click suspicious links"],
            "indicators": rule_based_result["signals"],
        }

    model = genai.GenerativeModel('gemini-1.5-pro')
    prompt = f"""
You are a cybersecurity expert specializing in phishing and social engineering detection.

Analyze this content and return ONLY a valid JSON object (no markdown, no explanation):

Content to analyze:
{text}

Rule-based pre-analysis found:
- Score: {rule_based_result['score']}/100
- Signals: {rule_based_result['signals']}

Return this exact JSON structure:
{{
  "gemini_score": <integer 0-100>,
  "confidence": <"high"|"medium"|"low">,
  "attack_type": <"phishing"|"social_engineering"|"credential_harvesting"|"malware_distribution"|"safe"|"suspicious">,
  "explanation": "<2-3 sentence human-readable explanation>",
  "recommendations": ["<action 1>", "<action 2>", "<action 3>"],
  "indicators": ["<specific indicator 1>", "<specific indicator 2>"]
}}
"""
    try:
        response = model.generate_content(prompt)
        result_text = response.text.strip()
        parsed = json.loads(result_text)

        final_score = int(rule_based_result['score'] * 0.4 + parsed['gemini_score'] * 0.6)
        parsed['final_score'] = min(final_score, 100)
        return parsed
    except Exception as e:
        return {
            "gemini_score": rule_based_result['score'],
            "final_score": rule_based_result['score'],
            "confidence": "low",
            "attack_type": "unknown",
            "explanation": "Gemini analysis unavailable. Using rule-based score.",
            "recommendations": ["Treat with caution", "Do not click suspicious links"],
            "indicators": rule_based_result['signals'],
        }
