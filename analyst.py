import argparse
import json
import os
import re
import requests
from pathlib import Path
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text, create_engine, inspect, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from detection import ANOMALY_THRESHOLD, ANOMALY_Z, Baseline, IsolationForestScorer

# --- evidence_validator.py ---
EVIDENCE_FIELDS = {
    "source",
    "destination",
    "events",
    "unique_ports",
    "destination_port",
    "protocol",
    "source_platform",
    "source_type",
    "source_event",
    "event_timestamp",
    "rate",
    "destination_diversity",
    "mean_interarrival_seconds",
    "interarrival_std_seconds",
    "active_span_seconds",
    "rule_signals",
    "window_seconds",
    "port_scan_threshold",
    "fast_probe_min_events",
    "fast_probe_rate_threshold",
    "ml_anomaly_score",
    "ml_model",
    "ml_is_anomaly",
    "historical_baseline_samples",
    "statistical_anomaly_score",
}

INVESTIGATION_STEPS = {
    "correlate_network": "Correlate the source and destination with firewall, Zeek, or Suricata records.",
    "review_host": "Review endpoint process and authentication telemetry for the same time window.",
    "verify_owner": "Verify the source and destination ownership and whether the activity was authorized.",
    "preserve_evidence": "Preserve the relevant logs and timestamps before changing system state.",
}


def validate_analysis(alert, proposal):
    """Return only evidence-backed observations and approved investigation steps."""
    if not isinstance(proposal, dict):
        return {"observations": [], "investigation_steps": []}
    observations = []
    seen = set()
    evidence = proposal.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = []
    for reference in evidence:
        if not isinstance(reference, dict):
            continue
        field = reference.get("field")
        if (
            not isinstance(field, str)
            or field not in EVIDENCE_FIELDS
            or field in seen
            or field not in alert
            or alert[field] is None
            or reference.get("value") != alert[field]
        ):
            continue
        seen.add(field)
        observations.append({"field": field, "value": alert[field]})
    steps = []
    proposed_steps = proposal.get("investigation_steps", [])
    if not isinstance(proposed_steps, list):
        proposed_steps = []
    for step_id in proposed_steps:
        if (
            isinstance(step_id, str)
            and step_id in INVESTIGATION_STEPS
            and step_id not in steps
        ):
            steps.append(step_id)
    return {
        "observations": observations,
        "investigation_steps": [INVESTIGATION_STEPS[step] for step in steps],
    }

# --- security_analyst.py ---
def local_analysis(alert):
    rule_signals = alert.get("rule_signals") or []
    if not rule_signals and alert.get("event") == "possible_port_scan":
        rule_signals = ["unique_ports_threshold"]

    evidence_fields = [
        "source",
        "destination",
        "events",
        "unique_ports",
        "destination_port",
        "protocol",
        "source_platform",
        "source_type",
        "event_timestamp",
        "rate",
        "destination_diversity",
        "mean_interarrival_seconds",
        "interarrival_std_seconds",
        "active_span_seconds",
        "rule_signals",
        "window_seconds",
        "port_scan_threshold",
        "fast_probe_min_events",
        "fast_probe_rate_threshold",
        "ml_anomaly_score",
        "ml_model",
        "ml_is_anomaly",
        "historical_baseline_samples",
        "statistical_anomaly_score",
    ]
    evidence = [
        {"field": field, "value": alert[field]}
        for field in evidence_fields
        if field in EVIDENCE_FIELDS and alert.get(field) is not None
    ]
    steps = ["correlate_network", "review_host", "verify_owner"]
    if alert.get("event") == "possible_port_scan":
        steps.append("preserve_evidence")
    verified = validate_analysis(
        alert,
        {"evidence": evidence, "investigation_steps": steps},
    )
    rationale = []
    if "unique_ports_threshold" in rule_signals:
        rationale.append(
            f"{alert.get('unique_ports')} unique destination ports met the "
            f"configured {alert.get('port_scan_threshold', 15)}-port scan threshold "
            f"within {alert.get('window_seconds', 60)} seconds."
        )
    if "high_volume_fast_probing" in rule_signals:
        rationale.append(
            f"The event volume met the {alert.get('fast_probe_min_events', 15)}-event "
            f"threshold and its port rate met {alert.get('fast_probe_rate_threshold', 1.0)} "
            "unique ports per second."
        )
    if "historical_statistical_deviation" in rule_signals:
        rationale.append(
            "The activity differs from this source's learned statistical baseline."
        )
    if alert.get("ml_is_anomaly") is True:
        rationale.append(
            "The Isolation Forest flagged this behavior against "
            f"{alert.get('historical_baseline_samples')} prior normal windows "
            f"(raw anomaly score {alert.get('ml_anomaly_score')})."
        )
    if not rationale:
        rationale.append(
            "The event was retained for review based on the alert's recorded telemetry."
        )
    return {
        "classification": alert.get("event", "network_activity"),
        "assessment": "Suspicious activity requiring review; this alert is not proof of compromise.",
        "rationale": rationale,
        "evidence": verified["observations"],
        "investigation_steps": verified["investigation_steps"],
        "automatic_response": "disabled",
    }


def verified_ai_analysis(alert, proposal):
    if proposal is None:
        return None
    result = validate_analysis(alert, proposal)
    if not result["observations"] and not result["investigation_steps"]:
        return None
    return result


def format_analysis(analysis):
    lines = [
        f"Assessment: {analysis['assessment']}",
        f"Classification: {analysis['classification']}",
    ]
    lines.append("Why it matters:")
    lines.extend(f"- {reason}" for reason in analysis["rationale"])
    lines.append("Verified evidence:")
    for item in analysis["evidence"]:
        lines.append(f"- {item['field']}: {item['value']}")
    lines.append("Investigation steps:")
    lines.extend(f"- {step}" for step in analysis["investigation_steps"])
    lines.append("Automatic response: disabled")
    return "\n".join(lines)

# --- cloud_llm.py ---
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


def web_research(query):
    """Ask Gemini to search the web and return its answer with URL citations."""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "online research requires GEMINI_API_KEY; no question was sent"
        )
    query = query.strip()
    if not query or len(query) > 4000:
        raise ValueError("online research questions must contain 1 to 4000 characters")

    model = os.getenv("GEMINI_WEB_MODEL", "gemini-3.8-flash")
    response = requests.post(
        "https://generativelanguage.googleapis.com/v1beta/interactions",
        headers={"x-goog-api-key": api_key},
        json={
            "model": model,
            "input": (
                "Answer the user's question using Google Search results. "
                "Distinguish sourced facts from uncertainty, mention when evidence "
                "is conflicting or insufficient, and never claim guaranteed accuracy.\n\n"
                f"Question: {query}"
            ),
            "tools": [{"type": "google_search"}],
        },
        timeout=45,
    )
    response.raise_for_status()
    payload = response.json()
    answer_parts = []
    sources = []
    seen_urls = set()
    for step in payload.get("steps", []):
        if not isinstance(step, dict) or step.get("type") != "model_output":
            continue
        for block in step.get("content", []):
            if not isinstance(block, dict) or block.get("type") != "text":
                continue
            text = block.get("text")
            if isinstance(text, str) and text.strip():
                answer_parts.append(text.strip())
            for annotation in block.get("annotations", []):
                if not isinstance(annotation, dict):
                    continue
                url = annotation.get("url")
                if (
                    annotation.get("type") == "url_citation"
                    and isinstance(url, str)
                    and url.startswith("https://")
                    and url not in seen_urls
                ):
                    seen_urls.add(url)
                    title = annotation.get("title")
                    sources.append(
                        {"title": title if isinstance(title, str) else url, "url": url}
                    )
    answer = "\n\n".join(answer_parts)
    if not answer:
        raise RuntimeError("online research returned no answer text")
    return {"answer": answer, "sources": sources}


# --- rag_agent.py ---
#!/usr/bin/env python3
"""Local RAG + agentic security analyst for the Nmap detector.

No cloud model or credentials are required. Retrieval is transparent keyword
scoring, and the agent only recommends actions. It never blocks hosts.
"""


TOKEN_RE = re.compile(r"[a-z0-9_]+")


DEFAULT_GUIDANCE = """
# Port Scan Triage
A scan is more credible when multiple signals agree: unique destination ports, probe rate, repeated activity, or a baseline anomaly. Confirm the source is not an approved scanner; correlate firewall events with Zeek or Suricata; review exposed services; preserve timestamps; never automatically block based on one alert. Firewall-only logs may miss slow or distributed scans.
"""

class KnowledgeBase:
    def __init__(self, directory):
        self.documents = [("built-in-port-scan-triage", DEFAULT_GUIDANCE)]
        for path in sorted(Path(directory).glob("*.md")) if Path(directory).exists() else []:
            text = path.read_text(encoding="utf-8")
            self.documents.append((path.name, text))

    def search(self, query, limit=3):
        wanted = set(TOKEN_RE.findall(query.lower()))
        ranked = []
        for name, text in self.documents:
            words = TOKEN_RE.findall(text.lower())
            score = sum(words.count(token) for token in wanted)
            if score:
                ranked.append((score, name, text))
        ranked.sort(reverse=True)
        return ranked[:limit]


class SecurityAgent:
    def __init__(self, knowledge_dir, model_file):
        self.kb = KnowledgeBase(knowledge_dir)
        self.baseline = Baseline(model_file)
        self.ml_scorer = IsolationForestScorer(
            self.baseline.data.get("ml_samples", {})
        )

    def analyze(
        self,
        source,
        events,
        unique_ports,
        duration_seconds,
        unique_destinations=1,
        mean_interarrival=0.0,
        interarrival_std=0.0,
    ):
        duration = max(duration_seconds, 1)
        rate = unique_ports / duration
        features = (events, unique_ports, rate)
        statistical_score = self.baseline.anomaly_score(source, features)
        ml_features = {
            "events": float(events),
            "unique_ports": float(unique_ports),
            "ports_per_second": rate,
            "unique_destinations": float(unique_destinations),
            "destinations_per_second": unique_destinations / duration,
            "mean_interarrival_seconds": mean_interarrival,
            "interarrival_std_seconds": interarrival_std,
            "active_span_seconds": duration_seconds,
        }
        ml_result = self.ml_scorer.score(source, ml_features)
        signals = []
        if unique_ports >= 15:
            signals.append("many unique destination ports")
        if rate >= 1:
            signals.append("fast probing rate")
        if statistical_score is not None and statistical_score >= ANOMALY_Z:
            signals.append("historical statistical baseline deviation is high")
        if ml_result and ml_result["decision_function"] < ANOMALY_THRESHOLD:
            signals.append("Isolation Forest identifies unusual behavior")
        confidence = "high" if len(signals) >= 2 else "medium" if signals else "low"
        query = "port scan response " + " ".join(signals)
        evidence = [
            {"document": name, "score": score_value, "excerpt": text[:500]}
            for score_value, name, text in self.kb.search(query)
        ]
        return {
            "agent": "SentinelAI",
            "source": source,
            "classification": "possible_port_scan" if signals else "no strong signal",
            "confidence": confidence,
            "signals": signals,
            "ml_anomaly_score": ml_result["score"] if ml_result else None,
            "ml_model": ml_result["model"] if ml_result else None,
            "ml_training_samples": ml_result["training_samples"] if ml_result else 0,
            "historical_statistical_score": statistical_score,
            "behavior_features": ml_features,
            "recommendation": "review and correlate with Zeek/Suricata; do not auto-block",
            "retrieved_evidence": evidence,
        }


def analyst_main(argv=None):
    parser = argparse.ArgumentParser(description="Local RAG and agentic scan analyst")
    parser.add_argument("--query", help="Search the local security knowledge base")
    parser.add_argument("--source", default="192.0.2.10")
    parser.add_argument("--events", type=int, default=15)
    parser.add_argument("--unique-ports", type=int, default=15)
    parser.add_argument("--duration", type=float, default=10)
    parser.add_argument("--unique-destinations", type=int, default=1)
    parser.add_argument("--mean-interarrival", type=float, default=0)
    parser.add_argument("--interarrival-std", type=float, default=0)
    parser.add_argument("--knowledge-dir", default="knowledge")
    parser.add_argument("--model-file", default="~/.nmap_ai_baseline.json")
    args = parser.parse_args(argv)
    agent = SecurityAgent(args.knowledge_dir, str(Path(args.model_file).expanduser()))
    if args.query:
        result = [
            {"document": name, "score": score, "excerpt": text[:700]}
            for score, name, text in agent.kb.search(args.query)
        ]
    else:
        result = agent.analyze(
            args.source,
            args.events,
            args.unique_ports,
            args.duration,
            args.unique_destinations,
            args.mean_interarrival,
            args.interarrival_std,
        )
    print(json.dumps(result, indent=2))

# --- alert_store.py ---
class Base(DeclarativeBase):
    pass


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    source_ip: Mapped[str] = mapped_column(String(128), default="unknown")
    destination_ip: Mapped[str] = mapped_column(String(128), default="unknown")
    event_type: Mapped[str] = mapped_column(String(128), default="security_alert")
    unique_ports: Mapped[int] = mapped_column(Integer, default=0)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    incident_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    deduplication_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    anomaly_score: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    confidence: Mapped[str] = mapped_column(String(32), default="medium")
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open")


class AlertStore:
    def __init__(self, path="~/.sentinel.db"):
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{path}")
        Base.metadata.create_all(self.engine)
        columns = {column["name"] for column in inspect(self.engine).get_columns("alerts")}
        migrations = {
            "incident_id": "ALTER TABLE alerts ADD COLUMN incident_id VARCHAR(36)",
            "deduplication_key": "ALTER TABLE alerts ADD COLUMN deduplication_key VARCHAR(64)",
            "severity": "ALTER TABLE alerts ADD COLUMN severity VARCHAR(16) NOT NULL DEFAULT 'medium'",
        }
        with self.engine.begin() as connection:
            for column, statement in migrations.items():
                if column not in columns:
                    connection.exec_driver_sql(statement)

    def add(self, event):
        with Session(self.engine) as session:
            deduplication_key = event.get("deduplication_key")
            if deduplication_key and session.scalar(
                select(Alert.id).where(Alert.deduplication_key == deduplication_key)
            ):
                return None
            alert = Alert(
                source_ip=event.get("source", "unknown"),
                destination_ip=event.get("destination", "unknown"),
                event_type=event.get("event", "security_alert"),
                unique_ports=int(event.get("unique_ports", 0)),
                event_count=int(event.get("events", 0)),
                incident_id=event.get("incident_id"),
                deduplication_key=deduplication_key,
                anomaly_score=event.get("anomaly_score"),
                severity=event.get("severity", "medium"),
                confidence=event.get("confidence", "medium"),
                explanation=event.get("recommendation"),
            )
            session.add(alert)
            session.commit()
            return alert.id

    def recent(self, limit=10):
        with Session(self.engine) as session:
            rows = session.scalars(select(Alert).order_by(Alert.id.desc()).limit(limit)).all()
            return [
                {
                    "id": row.id,
                    "time": row.timestamp.isoformat(),
                    "source": row.source_ip,
                    "event": row.event_type,
                    "ports": row.unique_ports,
                    "status": row.status,
                    "severity": row.severity,
                    "incident_id": row.incident_id,
                    "confidence": row.confidence,
                }
                for row in rows
            ]
