"""Optional Gemini adapter for Sentinel.

The API key is read only from GEMINI_API_KEY and is never printed or persisted.
"""

import os
import json
import requests

from evidence_validator import EVIDENCE_FIELDS, INVESTIGATION_STEPS


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
    evidence_fields = sorted(field for field in EVIDENCE_FIELDS if field in alert)
    step_ids = sorted(INVESTIGATION_STEPS)
    response = _generate(
        "You are a defensive security analyst. Select only telemetry evidence fields "
        "that are present in the supplied alert, and choose investigation step IDs "
        "from the supplied allow-list. Do not write prose, infer intent, claim a "
        "compromise, or recommend response actions. Return one JSON object with "
        '"evidence": [{"field": field_name, "value": exact_value_from_alert}], '
        'and "investigation_steps": [allowed_step_id]. '
        f"\nAllowed fields: {evidence_fields}\nAllowed steps: {step_ids}"
        f"\nAlert: {json.dumps(alert, sort_keys=True)}"
    )
    return json.loads(response) if response else None


def chat(message, context=""):
    return _generate(
        "You are Sentinel, a concise defensive cybersecurity assistant. "
        "Answer the user's question using only the supplied local context. "
        "Never execute commands, expose secrets, or recommend automatic blocking. "
        f"\nLocal context: {context}\nUser: {message}"
    )
