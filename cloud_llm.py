"""Optional Gemini explanation adapter for Sentinel.

The API key is read only from GEMINI_API_KEY and is never printed or persisted.
"""

import os
import requests


def explain_alert(alert):
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return None

    model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    prompt = (
        "You are Sentinel, a defensive SOC assistant. Analyze only this alert. "
        "Return a short classification, confidence, explanation, and safe next steps. "
        "Do not recommend automatic blocking or destructive actions. Alert: "
        + repr(alert)
    )
    response = requests.post(
        url,
        params={"key": api_key},
        json={"contents": [{"parts": [{"text": prompt}]}]},
        timeout=30,
    )
    response.raise_for_status()
    data = response.json()
    return data["candidates"][0]["content"]["parts"][0]["text"]
