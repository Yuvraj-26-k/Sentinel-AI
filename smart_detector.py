#!/usr/bin/env python3
"""Self-learning defensive port-scan detector.

Learns normal per-source activity with a persistent mean/variance baseline.
It reports anomalies but never changes firewall rules automatically.
"""

import argparse
import json
import math
import os
import time
from collections import defaultdict, deque
from datetime import datetime

import ingestion
from scan_detector import ScanDetector, ScanThresholds
from telemetry_store import TelemetryStore
from ml_model import (
    ANOMALY_THRESHOLD,
    FEATURE_NAMES,
    IsolationForestScorer,
    MAXIMUM_TRAINING_SAMPLES,
    window_features,
)
import ufw_adapter

DEFAULT_MODEL = os.path.expanduser("~/.nmap_ai_baseline.json")
DEFAULT_ALERTS = os.path.expanduser("~/.sentinel_alerts.jsonl")
WINDOW_SECONDS = 60
MIN_SAMPLES = 20
ANOMALY_Z = 4.0
PORT_THRESHOLD = 15
MAX_TRACKED_SOURCES = 2048

FEATURES = ("events", "unique_ports", "ports_per_second")
events = defaultdict(deque)
last_alert = {}


class Baseline:
    def __init__(self, path):
        self.path = path
        self.data = {}
        try:
            with open(path, "r", encoding="utf-8") as handle:
                self.data = json.load(handle)
        except (FileNotFoundError, json.JSONDecodeError):
            self.data = {}
        if not isinstance(self.data, dict):
            self.data = {}
        self.data.setdefault("ml_samples", {})
        self.data.setdefault("ml_last_sample", {})
        self.data.setdefault("last_seen", {})
        if not isinstance(self.data["ml_samples"], dict):
            self.data["ml_samples"] = {}
        if not isinstance(self.data["ml_last_sample"], dict):
            self.data["ml_last_sample"] = {}
        if not isinstance(self.data["last_seen"], dict):
            self.data["last_seen"] = {}
        for source, samples in list(self.data["ml_samples"].items()):
            if not isinstance(samples, list):
                self.data["ml_samples"].pop(source)
                continue
            valid = []
            for row in samples:
                if isinstance(row, list) and len(row) == len(FEATURE_NAMES):
                    try:
                        valid.append([float(value) for value in row])
                    except (TypeError, ValueError):
                        continue
            self.data["ml_samples"][source] = valid[-MAXIMUM_TRAINING_SAMPLES:]
        for source in self._tracked_sources():
            self.data["last_seen"].setdefault(
                source, float(self.data["ml_last_sample"].get(source, 0))
            )
        self._evict_sources()
        self.ml_scorer = IsolationForestScorer(self.data["ml_samples"])

    def _tracked_sources(self):
        reserved = {"ml_samples", "ml_last_sample", "last_seen"}
        return {
            key
            for key, value in self.data.items()
            if key not in reserved and isinstance(value, dict)
        } | set(self.data["ml_samples"]) | set(self.data["ml_last_sample"]) | set(
            self.data["last_seen"]
        )

    def _evict_sources(self):
        tracked = self._tracked_sources()
        while len(tracked) > MAX_TRACKED_SOURCES:
            oldest = min(
                tracked,
                key=lambda source: float(self.data["last_seen"].get(source, 0)),
            )
            self.data.pop(oldest, None)
            self.data["ml_samples"].pop(oldest, None)
            self.data["ml_last_sample"].pop(oldest, None)
            self.data["last_seen"].pop(oldest, None)
            if hasattr(self, "ml_scorer"):
                self.ml_scorer.invalidate(oldest)
            tracked.remove(oldest)

    def touch(self, source, now=None):
        self.data["last_seen"][source] = float(now if now is not None else time.time())
        self._evict_sources()

    def record_ml_sample(self, source, features, now, interval_seconds=10):
        self.touch(source, now)
        last_sample = self.data["ml_last_sample"].get(source, 0)
        if now - last_sample < interval_seconds:
            return False
        values = [float(features[name]) for name in FEATURE_NAMES]
        samples = self.data["ml_samples"].setdefault(source, [])
        samples.append(values)
        del samples[:-MAXIMUM_TRAINING_SAMPLES]
        self.data["ml_last_sample"][source] = now
        self.ml_scorer.invalidate(source)
        return True

    def update(self, source, values, now=None):
        self.touch(source, now)
        item = self.data.setdefault(source, {"count": 0, "mean": {}, "m2": {}})
        item["count"] += 1
        count = item["count"]
        for name, value in zip(FEATURES, values):
            old_mean = item["mean"].get(name, 0.0)
            delta = value - old_mean
            item["mean"][name] = old_mean + delta / count
            item["m2"][name] = item["m2"].get(name, 0.0) + delta * (value - item["mean"][name])

    def anomaly_score(self, source, values):
        item = self.data.get(source)
        if not item or item["count"] < MIN_SAMPLES:
            return None
        scores = []
        for name, value in zip(FEATURES, values):
            variance = item["m2"].get(name, 0.0) / max(item["count"] - 1, 1)
            standard_deviation = max(math.sqrt(variance), 0.1)
            scores.append(abs(value - item["mean"].get(name, 0.0)) / standard_deviation)
        return max(scores)

    def save(self):
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        temporary = f"{self.path}.tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(self.data, handle, indent=2)
        os.replace(temporary, self.path)


def report(
    source,
    destination,
    ports,
    values,
    score,
    learning,
    alert_file,
    normalized_event=None,
    metrics=None,
    ml_result=None,
    rule_signals=None,
    statistical_score=None,
):
    if rule_signals:
        mode = "rule_alert"
    elif learning:
        mode = "learning"
    elif score is not None:
        mode = f"anomaly_score={score:.2f}"
    elif ml_result:
        mode = f"ml_anomaly_score={ml_result['score']:.4f}"
    else:
        mode = "anomaly"
    event = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "source": source,
        "destination": destination,
        "event": "possible_port_scan",
        "unique_ports": len(ports),
        "events": values[0],
        "mode": mode,
        "anomaly_score": round(score, 2) if score is not None else None,
        "confidence": "high" if len(ports) >= PORT_THRESHOLD else "medium",
        "recommendation": "review and correlate; automatic blocking is disabled",
        "rule_signals": rule_signals or [],
        "window_seconds": WINDOW_SECONDS,
        "port_scan_threshold": PORT_THRESHOLD,
        "fast_probe_min_events": PORT_THRESHOLD,
        "fast_probe_rate_threshold": 1.0,
        "statistical_anomaly_score": (
            round(statistical_score, 2) if statistical_score is not None else None
        ),
        "ml_anomaly_score": ml_result["score"] if ml_result else None,
        "ml_model": ml_result["model"] if ml_result else None,
        "ml_is_anomaly": ml_result["is_anomaly"] if ml_result else None,
        "historical_baseline_samples": (
            ml_result["training_samples"] if ml_result else 0
        ),
    }
    if metrics:
        event["rate"] = round(metrics["ports_per_second"], 4)
        event["destination_diversity"] = int(metrics["unique_destinations"])
        event["mean_interarrival_seconds"] = round(
            metrics["mean_interarrival_seconds"], 4
        )
        event["interarrival_std_seconds"] = round(
            metrics["interarrival_std_seconds"], 4
        )
        event["active_span_seconds"] = round(metrics["active_span_seconds"], 4)
    if normalized_event:
        event["source_type"] = normalized_event.get("sensor")
        event["source_platform"] = normalized_event.get("platform")
        event["protocol"] = normalized_event.get("protocol")
        event["action"] = normalized_event.get("action")
        event["destination_port"] = normalized_event.get("destination_port")
        event["source_event"] = normalized_event.get("event")
        event["event_timestamp"] = normalized_event.get("timestamp")
    parent = os.path.dirname(alert_file)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(alert_file, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")
    print(
        f"[ALERT] Possible scan | source={source} | unique_ports={len(ports)} | "
        f"events={len(ports)} | {mode} | time={event['time']}",
        flush=True,
    )


def process_event(normalized_event, baseline, alert_file):
    if not normalized_event or normalized_event.get("destination_port") is None:
        return
    source = normalized_event.get("source")
    destination = normalized_event.get("destination")
    if not source or source == "unknown":
        return
    port = normalized_event["destination_port"]
    now = time.time()
    events[source].append((now, port, destination))
    while events[source] and now - events[source][0][0] > WINDOW_SECONDS:
        events[source].popleft()

    ports = {item[1] for item in events[source]}
    metrics = window_features(events[source], WINDOW_SECONDS)
    values = (
        len(events[source]),
        len(ports),
        len(ports) / WINDOW_SECONDS,
    )
    statistical_score = baseline.anomaly_score(source, values)
    ml_result = baseline.ml_scorer.score(source, metrics)
    rule_signals = []
    if len(ports) >= PORT_THRESHOLD:
        rule_signals.append("unique_ports_threshold")
    if (
        len(events[source]) >= PORT_THRESHOLD
        and metrics["ports_per_second"] >= 1.0
    ):
        rule_signals.append("high_volume_fast_probing")
    ml_anomaly = bool(
        ml_result and ml_result["decision_function"] < ANOMALY_THRESHOLD
    )
    suspicious = (
        bool(rule_signals)
        or ml_anomaly
        or (statistical_score is not None and statistical_score >= ANOMALY_Z)
    )
    if statistical_score is not None and statistical_score >= ANOMALY_Z:
        rule_signals.append("historical_statistical_deviation")

    if suspicious:
        report(
            source,
            destination,
            ports,
            values,
            statistical_score,
            statistical_score is None and not ml_result,
            alert_file,
            normalized_event,
            metrics,
            ml_result,
            rule_signals,
            statistical_score,
        )
    elif len(events[source]) >= 3:
        baseline.update(source, values)
        if baseline.record_ml_sample(source, metrics, now):
            baseline.save()


def process_line(line, baseline, alert_file):
    normalized_event = ufw_adapter.parse_line(line)
    if normalized_event is not None:
        process_event(normalized_event, baseline, alert_file)


def follow_file(path, baseline, alert_file, source="ufw"):
    ingestion.follow_file(
        path,
        source,
        baseline,
        alert_file,
        lambda event: process_event(event, baseline, alert_file),
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cross-platform Sentinel network event detector")
    parser.add_argument(
        "--source",
        choices=ingestion.SOURCES,
        default="auto",
        help="Native platform source or supported log format (default: auto)",
    )
    parser.add_argument("--log-file", help="Log path for file-based sources")
    parser.add_argument("--model-file", default=DEFAULT_MODEL)
    parser.add_argument("--alert-file", default=DEFAULT_ALERTS)
    parser.add_argument(
        "--database-file",
        default=os.path.expanduser("~/.sentinel.db"),
        help="SQLite event and incident store",
    )
    parser.add_argument("--scan-window-seconds", type=int, default=60)
    parser.add_argument("--vertical-ports", type=int, default=15)
    parser.add_argument("--horizontal-window-seconds", type=int, default=60)
    parser.add_argument("--horizontal-hosts", type=int, default=10)
    parser.add_argument("--horizontal-min-events", type=int, default=10)
    parser.add_argument("--horizontal-max-ports", type=int, default=5)
    parser.add_argument("--slow-window-seconds", type=int, default=900)
    parser.add_argument("--slow-ports", type=int, default=10)
    parser.add_argument("--syn-ports", type=int, default=10)
    parser.add_argument("--failure-events", type=int, default=10)
    parser.add_argument("--incident-merge-seconds", type=int, default=900)
    args = parser.parse_args()
    source = ingestion.resolve_source(args.source)
    try:
        thresholds = ScanThresholds(
            scan_window_seconds=args.scan_window_seconds,
            vertical_ports=args.vertical_ports,
            horizontal_window_seconds=args.horizontal_window_seconds,
            horizontal_hosts=args.horizontal_hosts,
            horizontal_min_events=args.horizontal_min_events,
            horizontal_max_ports=args.horizontal_max_ports,
            slow_window_seconds=args.slow_window_seconds,
            slow_ports=args.slow_ports,
            syn_ports=args.syn_ports,
            failure_events=args.failure_events,
            incident_merge_seconds=args.incident_merge_seconds,
        )
    except ValueError as error:
        parser.error(str(error))
    store = TelemetryStore(args.database_file)
    baseline = Baseline(args.model_file)
    detector = ScanDetector(
        store,
        args.alert_file,
        thresholds=thresholds,
        baseline=baseline,
    )
    store.update_health(source, "starting")
    print(
        f"Starting {source} ingestion. SQLite events/incidents: {store.path}. "
        f"Learning baseline at {args.model_file}."
    )

    def process_and_track(event):
        try:
            detector.process_event(event)
            store.update_health(source, "healthy")
        except Exception as error:
            store.update_health(source, "error", type(error).__name__)
            raise

    try:
        ingestion.follow_source(
            source,
            args.log_file,
            baseline,
            args.alert_file,
            process_and_track,
        )
    except KeyboardInterrupt:
        baseline.save()
        store.update_health(source, "stopped")
        print("\nStopped safely.")
    except (OSError, RuntimeError, ValueError) as error:
        store.update_health(source, "error", type(error).__name__)
        parser.exit(1, f"Sentinel ingestion failed: {error}\n")
