#!/usr/bin/env python3
"""Local RAG + agentic security analyst for the Nmap detector.

No cloud model or credentials are required. Retrieval is transparent keyword
scoring, and the agent only recommends actions. It never blocks hosts.
"""

import argparse
import json
import re
from pathlib import Path
from smart_detector import ANOMALY_Z, Baseline

TOKEN_RE = re.compile(r"[a-z0-9_]+")


class KnowledgeBase:
    def __init__(self, directory):
        self.documents = []
        for path in sorted(Path(directory).glob("*.md")):
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

    def analyze(self, source, events, unique_ports, duration_seconds):
        rate = unique_ports / max(duration_seconds, 1)
        features = (events, unique_ports, rate)
        score = self.baseline.anomaly_score(source, features)
        signals = []
        if unique_ports >= 15:
            signals.append("many unique destination ports")
        if rate >= 1:
            signals.append("fast probing rate")
        if score is not None and score >= ANOMALY_Z:
            signals.append("machine-learning anomaly score is high")
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
            "ml_anomaly_score": score,
            "recommendation": "review and correlate with Zeek/Suricata; do not auto-block",
            "retrieved_evidence": evidence,
        }


def main():
    parser = argparse.ArgumentParser(description="Local RAG and agentic scan analyst")
    parser.add_argument("--query", help="Search the local security knowledge base")
    parser.add_argument("--source", default="192.0.2.10")
    parser.add_argument("--events", type=int, default=15)
    parser.add_argument("--unique-ports", type=int, default=15)
    parser.add_argument("--duration", type=float, default=10)
    parser.add_argument("--knowledge-dir", default="knowledge")
    parser.add_argument("--model-file", default="~/.nmap_ai_baseline.json")
    args = parser.parse_args()
    agent = SecurityAgent(args.knowledge_dir, str(Path(args.model_file).expanduser()))
    if args.query:
        result = [
            {"document": name, "score": score, "excerpt": text[:700]}
            for score, name, text in agent.kb.search(args.query)
        ]
    else:
        result = agent.analyze(args.source, args.events, args.unique_ports, args.duration)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
