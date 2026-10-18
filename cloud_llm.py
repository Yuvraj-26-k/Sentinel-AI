"""Optional Gemini adapter for Sentinel.

The API key is read only from GEMINI_API_KEY and is never printed or persisted.
"""

import os
import requests


def _generate(prompt):
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return None
    model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    response = requests.post(
        url,
        params={"key": api_key},
        json={"contents": [{"parts": [{"text": prompt}]}]},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["candidates"][0]["content"]["parts"][0]["text"]


def explain_alert(alert):
    return _generate(
        "You are Sentinel, a defensive SOC assistant. Analyze only this alert. "
        "Return a short classification, confidence, explanation, and safe next steps. "
        "Do not recommend automatic blocking or destructive actions. Alert: "
        + repr(alert)
    )


def chat(message, context=""):
    return _generate(
        "You are Sentinel, a concise defensive cybersecurity assistant. "
        "Answer the user's question using only the supplied local context. "
        "Never execute commands, expose secrets, or recommend automatic blocking. "
        f"\nLocal context: {context}\nUser: {message}"
    )
