import argparse
import hashlib
import json
import math
import os
import time
from collections import deque
from collections import defaultdict
from datetime import datetime, timezone

from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from types import SimpleNamespace

from telemetry import (
    SOURCES,
    TelemetryStore,
    follow_source,
    resolve_source,
    ufw_adapter,
)

# --- ml_model.py ---
FEATURE_NAMES = (
    "events",
    "unique_ports",
    "ports_per_second",
    "unique_destinations",
    "destinations_per_second",
    "mean_interarrival_seconds",
    "interarrival_std_seconds",
    "active_span_seconds",
)
MINIMUM_TRAINING_SAMPLES = 30
MAXIMUM_TRAINING_SAMPLES = 512
ANOMALY_THRESHOLD = 0.0


def window_features(window, duration_seconds=60):
    """Build stable numeric features from (time, port, destination) events."""
    if not window:
        return {name: 0.0 for name in FEATURE_NAMES}
    timestamps = [item[0] for item in window]
    ports = {item[1] for item in window}
    destinations = {item[2] for item in window}
    span = max(timestamps[-1] - timestamps[0], 0.0)
    elapsed = max(min(duration_seconds, span), 1.0)
    intervals = [
        max(timestamps[index] - timestamps[index - 1], 0.0)
        for index in range(1, len(timestamps))
    ]
    mean_interval = sum(intervals) / len(intervals) if intervals else 0.0
    variance = (
        sum((value - mean_interval) ** 2 for value in intervals) / len(intervals)
        if intervals
        else 0.0
    )
    return {
        "events": float(len(window)),
        "unique_ports": float(len(ports)),
        "ports_per_second": len(ports) / elapsed,
        "unique_destinations": float(len(destinations)),
        "destinations_per_second": len(destinations) / elapsed,
        "mean_interarrival_seconds": mean_interval,
        "interarrival_std_seconds": variance**0.5,
        "active_span_seconds": span,
    }


class IsolationForestScorer:
    def __init__(self, sample_store, minimum_samples=MINIMUM_TRAINING_SAMPLES):
        self.sample_store = sample_store
        self.minimum_samples = minimum_samples
        self._models = {}

    def invalidate(self, source):
        self._models.pop(source, None)

    def score(self, source, features):
        rows = self.sample_store.get(source, [])
        if len(rows) < self.minimum_samples:
            return None
        model = self._models.get(source)
        if model is None or model[0] != len(rows):
            estimator = make_pipeline(
                StandardScaler(),
                IsolationForest(
                    n_estimators=100,
                    contamination="auto",
                    random_state=42,
                    n_jobs=1,
                ),
            )
            estimator.fit(rows)
            model = (len(rows), estimator)
            self._models[source] = model
        vector = [features[name] for name in FEATURE_NAMES]
        decision = float(model[1].decision_function([vector])[0])
        return {
            "score": round(max(0.0, -decision), 6),
            "decision_function": round(decision, 6),
            "is_anomaly": decision < ANOMALY_THRESHOLD,
            "training_samples": len(rows),
            "model": "isolation_forest",
        }

# --- scan_detector.py ---
RULE_VERSION = "sentinel-rules-v2"
MODEL_VERSION = "isolation-forest-v1"
FAILURE_STATES = {
    "blocked",
    "block",
    "deny",
    "denied",
    "drop",
    "dropped",
    "reject",
    "rejected",
    "failed",
    "s0",
    "rej",
    "rsto",
    "rstr",
    "sh",
    "shr",
    "oth",
}


class ScanThresholds:
    def __init__(
        self,
        scan_window_seconds=60,
        vertical_ports=15,
        horizontal_window_seconds=60,
        horizontal_hosts=10,
        horizontal_min_events=10,
        horizontal_max_ports=5,
        slow_window_seconds=900,
        slow_ports=10,
        syn_ports=10,
        failure_events=10,
        incident_merge_seconds=900,
        max_history_events=20000,
        clock_skew_tolerance_seconds=300,
    ):
        positive = {
            "scan_window_seconds": scan_window_seconds,
            "vertical_ports": vertical_ports,
            "horizontal_window_seconds": horizontal_window_seconds,
            "horizontal_hosts": horizontal_hosts,
            "horizontal_min_events": horizontal_min_events,
            "slow_window_seconds": slow_window_seconds,
            "slow_ports": slow_ports,
            "syn_ports": syn_ports,
            "failure_events": failure_events,
            "incident_merge_seconds": incident_merge_seconds,
            "max_history_events": max_history_events,
            "clock_skew_tolerance_seconds": clock_skew_tolerance_seconds,
        }
        for name, value in positive.items():
            if not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if not 1 <= horizontal_max_ports <= 65535:
            raise ValueError("horizontal_max_ports must be between 1 and 65535")
        self.__dict__.update(positive)
        self.horizontal_max_ports = horizontal_max_ports
        self.max_window_seconds = max(scan_window_seconds, slow_window_seconds)


def _parse_time(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _event_failure(event):
    action = str(event.get("action") or "").lower()
    raw = event.get("raw") or {}
    state = str(raw.get("conn_state") or "").lower() if isinstance(raw, dict) else ""
    return action in FAILURE_STATES or state in FAILURE_STATES


def _event_syn(event):
    flags = event.get("tcp_flags") or []
    if any(str(flag).upper() in {"S", "SYN"} for flag in flags):
        return True
    raw = event.get("raw") or {}
    if isinstance(raw, dict):
        history = str(raw.get("history") or "").upper()
        tcp = raw.get("tcp") or {}
        if not isinstance(tcp, dict):
            tcp = {}
        raw_flags = str(tcp.get("tcp_flags") or tcp.get("flags") or "").upper()
        return "S" in history or "S" in raw_flags
    return False


class ScanDetector:
    def __init__(
        self,
        store,
        alert_file=None,
        thresholds=None,
        baseline=None,
    ):
        self.store = store
        self.alert_file = alert_file
        self.thresholds = thresholds or ScanThresholds()
        self.baseline = baseline
        self.history = deque(maxlen=self.thresholds.max_history_events)
        self.last_event_at = None
        self._recover()

    def _recover(self):
        if not self.store:
            return
        cutoff = datetime.now(timezone.utc).timestamp() - self.thresholds.max_window_seconds
        for event in self.store.recent_events(limit=self.thresholds.max_history_events):
            timestamp = _parse_time(event.get("effective_event_timestamp") or event.get("timestamp"))
            if timestamp is not None and timestamp >= cutoff:
                self.history.append((timestamp, event))

    def process_event(self, event):
        if not isinstance(event, dict):
            return None
        event_timestamp = event.get("timestamp")
        ingestion_timestamp = event.get("ingestion_timestamp") or datetime.now(
            timezone.utc
        ).isoformat(timespec="seconds")
        ingestion_epoch = _parse_time(ingestion_timestamp) or datetime.now(
            timezone.utc
        ).timestamp()
        source_epoch = _parse_time(event_timestamp)
        if source_epoch is None:
            source_epoch = ingestion_epoch
            if event_timestamp is not None:
                event["source_event_timestamp"] = event_timestamp
            event["timestamp"] = ingestion_timestamp
            event["timestamp_quality"] = "ingestion_fallback"
        skew = source_epoch - ingestion_epoch
        event["source_clock_skew_seconds"] = round(skew, 3)
        if skew > self.thresholds.clock_skew_tolerance_seconds:
            source_epoch = ingestion_epoch
            event["timestamp_quality"] = "future_clock_clamped"
        elif abs(skew) > self.thresholds.clock_skew_tolerance_seconds:
            event["timestamp_quality"] = "clock_skew"
        event["effective_event_timestamp"] = datetime.fromtimestamp(
            source_epoch, timezone.utc
        ).isoformat(timespec="seconds")
        event["ingestion_timestamp"] = ingestion_timestamp

        dedupe_key = event.get("deduplication_key")
        if self.store and dedupe_key and self.store.has_event(dedupe_key):
            return {"duplicate": True, "incident": None}

        wall_now = datetime.now(timezone.utc).timestamp()
        while self.history and wall_now - self.history[0][0] > self.thresholds.max_window_seconds:
            self.history.popleft()
        if source_epoch >= wall_now - self.thresholds.max_window_seconds:
            self.history.append((source_epoch, event))

        decision = self._detect(event, source_epoch, wall_now)
        event["rule_version"] = RULE_VERSION
        event["model_version"] = (
            decision.get("model_version") if decision else None
        )
        event["supporting_evidence"] = (
            decision["evidence"]
            if decision
            else {"rule_signals": [], "detection": "no_rule_match"}
        )
        event["incident_id"] = None
        event["severity"] = decision["severity"] if decision else "info"
        event["confidence"] = decision["confidence"] if decision else "low"
        record = self.store.record(
            event,
            decision,
            merge_seconds=self.thresholds.incident_merge_seconds,
        ) if self.store else {"duplicate": False, "incident": None}
        if record["duplicate"]:
            return record
        if decision and self.alert_file:
            self._write_alert(event, decision, record.get("incident"))
        self.last_event_at = ingestion_timestamp
        return {
            "duplicate": False,
            "incident": record.get("incident"),
            "detection": decision,
        }

    def _detect(self, event, timestamp, now):
        source = event.get("source")
        destination = event.get("destination")
        port = event.get("destination_port")
        if not source or source == "unknown" or not destination or destination == "unknown":
            return None
        if port is None:
            return None

        source_window = self._matching(
            lambda candidate: candidate.get("source") == source,
            now - self.thresholds.horizontal_window_seconds,
        )
        target_window = self._matching(
            lambda candidate: candidate.get("source") == source
            and candidate.get("destination") == destination,
            now - self.thresholds.scan_window_seconds,
        )
        target_slow = self._matching(
            lambda candidate: candidate.get("source") == source
            and candidate.get("destination") == destination,
            now - self.thresholds.slow_window_seconds,
        )
        target_ports = {candidate.get("destination_port") for _, candidate in target_window}
        slow_ports = {candidate.get("destination_port") for _, candidate in target_slow}
        failed = [candidate for _, candidate in target_window if _event_failure(candidate)]
        syn_events = [candidate for _, candidate in target_window if _event_syn(candidate)]
        rule_signals = []
        classification = None
        evidence_window = target_window

        if len(syn_events) >= self.thresholds.failure_events and len(target_ports) >= self.thresholds.syn_ports:
            classification = "possible SYN port scan"
            rule_signals.append("tcp_syn_port_diversity")
        elif len(failed) >= self.thresholds.failure_events and len(target_ports) >= 5:
            classification = "possible connection-failure scan"
            rule_signals.append("connection_failure_sweep")
        elif len(target_ports) >= self.thresholds.vertical_ports:
            classification = "possible vertical port scan"
            rule_signals.append("vertical_port_diversity")
        elif (
            len(slow_ports) >= self.thresholds.slow_ports
            and len(slow_ports) < self.thresholds.vertical_ports
            and target_slow
            and target_slow[-1][0] - target_slow[0][0] > self.thresholds.scan_window_seconds
        ):
            classification = "possible slow vertical port scan"
            rule_signals.append("slow_vertical_port_diversity")
            evidence_window = target_slow

        if classification is None:
            destinations = {
                candidate.get("destination")
                for _, candidate in source_window
                if candidate.get("destination") not in (None, "unknown")
            }
            source_ports = {
                candidate.get("destination_port")
                for _, candidate in source_window
                if candidate.get("destination_port") is not None
            }
            if (
                len(source_window) >= self.thresholds.horizontal_min_events
                and len(destinations) >= self.thresholds.horizontal_hosts
                and len(source_ports) <= self.thresholds.horizontal_max_ports
            ):
                classification = "possible horizontal port scan"
                rule_signals.append("horizontal_host_diversity")
                evidence_window = source_window

        ml_result = None
        statistical_score = None
        if self.baseline and source_window:
            self.baseline.touch(source, now)
            ml_features = window_features(
                [
                    (event_time, row["destination_port"], row["destination"])
                    for event_time, row in source_window
                ],
                self.thresholds.horizontal_window_seconds,
            )
            values = (
                len(source_window),
                len({row["destination_port"] for _, row in source_window}),
                ml_features["ports_per_second"],
            )
            statistical_score = self.baseline.anomaly_score(source, values)
            ml_result = self.baseline.ml_scorer.score(source, ml_features)
            if (
                classification is None
                and ml_result
                and ml_result["decision_function"] < ANOMALY_THRESHOLD
            ):
                classification = "possible anomalous network activity"
                rule_signals.append("isolation_forest_anomaly")
                evidence_window = source_window
            elif (
                classification is None
                and statistical_score is not None
                and statistical_score >= 4.0
            ):
                classification = "possible anomalous network activity"
                rule_signals.append("historical_statistical_deviation")
                evidence_window = source_window

        if classification is None:
            if self.baseline and len(source_window) >= 3:
                values = (
                    len(source_window),
                    len({row["destination_port"] for _, row in source_window}),
                    len({row["destination_port"] for _, row in source_window})
                    / max(self.thresholds.horizontal_window_seconds, 1),
                )
                self.baseline.update(source, values, now)
                features = window_features(
                    [
                        (event_time, row["destination_port"], row["destination"])
                        for event_time, row in source_window
                    ],
                    self.thresholds.horizontal_window_seconds,
                )
                if self.baseline.record_ml_sample(source, features, now):
                    self.baseline.save()
            return None

        selected_ports = {
            row.get("destination_port")
            for _, row in evidence_window
            if row.get("destination_port") is not None
        }
        selected_destinations = {
            row.get("destination")
            for _, row in evidence_window
            if row.get("destination") not in (None, "unknown")
        }
        evidence = {
            "rule_version": RULE_VERSION,
            "model_version": ml_result.get("model") if ml_result else None,
            "rule_signals": rule_signals,
            "supporting_event_count": len(evidence_window),
            "unique_destination_ports": sorted(selected_ports),
            "unique_destination_hosts": sorted(selected_destinations),
            "syn_event_count": sum(1 for _, row in evidence_window if _event_syn(row)),
            "failure_event_count": sum(
                1 for _, row in evidence_window if _event_failure(row)
            ),
            "window_start": datetime.fromtimestamp(
                evidence_window[0][0], timezone.utc
            ).isoformat(timespec="seconds"),
            "window_end": datetime.fromtimestamp(
                evidence_window[-1][0], timezone.utc
            ).isoformat(timespec="seconds"),
            "statistical_anomaly_score": statistical_score,
            "ml_anomaly_score": ml_result.get("score") if ml_result else None,
            "ml_training_samples": ml_result.get("training_samples") if ml_result else 0,
        }
        severity = "high" if classification in {
            "possible SYN port scan",
            "possible vertical port scan",
            "possible connection-failure scan",
        } else "medium"
        confidence = "high" if len(rule_signals) > 1 or len(selected_ports) >= 20 else "medium"
        incident_target = (
            "*" if classification == "possible horizontal port scan" else destination
        )
        incident_identity = "|".join((classification, source, incident_target))
        deduplication_key = hashlib.sha256(incident_identity.encode()).hexdigest()
        return {
            "classification": classification,
            "destination": None if incident_target == "*" else incident_target,
            "destination_port": port,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence,
            "rule_version": RULE_VERSION,
            "model_version": MODEL_VERSION if ml_result else None,
            "deduplication_key": deduplication_key,
        }

    def _matching(self, predicate, since):
        return sorted(
            (
                (timestamp, event)
                for timestamp, event in self.history
                if timestamp >= since and predicate(event)
            ),
            key=lambda item: item[0],
        )

    def _write_alert(self, event, detection, incident):
        output = dict(event)
        output.update(
            {
                "event": detection["classification"],
                "incident_id": incident["incident_id"] if incident else None,
                "incident_event_count": incident["event_count"] if incident else 1,
                "severity": detection["severity"],
                "confidence": detection["confidence"],
                "deduplication_key": event.get("deduplication_key"),
                "rule_version": detection["rule_version"],
                "model_version": detection.get("model_version"),
                "supporting_evidence": detection["evidence"],
                "recommendation": (
                    "Review the supporting telemetry and correlate with host and "
                    "network records. Automatic response is disabled."
                ),
            }
        )
        parent = os.path.dirname(self.alert_file)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(self.alert_file, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(output, sort_keys=True, default=str) + "\n")
        print(
            f"[{detection['severity'].upper()}] {detection['classification']} | "
            f"source={event.get('source')} | destination={event.get('destination')} | "
            f"incident={output['incident_id']} | observations={output['incident_event_count']}",
            flush=True,
        )

# --- smart_detector.py ---
#!/usr/bin/env python3
"""Self-learning defensive port-scan detector.

Learns normal per-source activity with a persistent mean/variance baseline.
It reports anomalies but never changes firewall rules automatically.
"""



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


def detector_main(argv=None):
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
    args = parser.parse_args(argv)
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

ingestion = SimpleNamespace(SOURCES=SOURCES, follow_source=follow_source, resolve_source=resolve_source)
