"""Configurable, bounded-memory scan and connection-failure detector."""

import hashlib
import json
import os
from collections import deque
from datetime import datetime, timezone

from ml_model import ANOMALY_THRESHOLD, window_features

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
