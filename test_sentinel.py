import io
import json
import random
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.routing import APIRoute

import telemetry
import telemetry as ingestion
import telemetry as macos_adapter
import telemetry as ufw_adapter
import telemetry as windows_firewall_adapter
import telemetry as zeek_adapter
import telemetry as suricata_adapter
import detection
import detection as smart_detector
import analyst

from telemetry import TelemetryStore, normalize_event, parse_event_xml
from detection import (
    Baseline,
    FEATURE_NAMES,
    IsolationForestScorer,
    ScanDetector,
    ScanThresholds,
    window_features,
)
from analyst import (
    AlertStore,
    SecurityAgent,
    local_analysis,
    validate_analysis,
    verified_ai_analysis,
)
from sentinel import Sentinel, create_app

# --- test_api.py ---
class ApiTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = TelemetryStore(str(Path(self.directory.name, "api.db")))
        self.store.update_health("test_sensor", "healthy")
        detector = ScanDetector(
            self.store,
            thresholds=ScanThresholds(vertical_ports=2),
        )
        for port in (80, 443):
            detector.process_event(
                normalize_event(
                    "192.0.2.1",
                    "198.51.100.1",
                    port,
                    protocol="TCP",
                    platform="test",
                    sensor="test_sensor",
                    event_id=f"api-{port}",
                )
            )
        app = create_app(self.store)
        self.endpoints = {
            route.path: route.endpoint
            for route in app.routes
            if isinstance(route, APIRoute)
        }

    def tearDown(self):
        self.directory.cleanup()

    def test_health_events_incidents_and_terminal_root(self):
        health = self.endpoints["/api/health"]()
        self.assertEqual(health["stored_events"], 2)
        self.assertEqual(health["open_incidents"], 1)
        self.assertEqual(health["sources"][0]["status"], "healthy")

        events = self.endpoints["/api/events"](limit=10, since=None)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[-1]["ingestion_timestamp"] is not None, True)

        incidents = self.endpoints["/api/incidents"](limit=100, status=None)
        self.assertEqual(incidents[0]["classification"], "possible vertical port scan")
        detail = self.endpoints["/api/incidents/{incident_id}"](
            incidents[0]["incident_id"]
        )
        self.assertEqual(len(detail["timeline"]), 1)
        self.assertIn("supporting_event_count", detail["evidence"])

        root = self.endpoints["/"]()
        self.assertEqual(root["interface"], "terminal")
        self.assertEqual(root["health"], "/api/health")

    def test_unknown_incident_returns_404_and_routes_are_read_only(self):
        with self.assertRaises(HTTPException) as error:
            self.endpoints["/api/incidents/{incident_id}"]("not-found")
        self.assertEqual(error.exception.status_code, 404)
        app = create_app(self.store)
        methods = {
            method
            for route in app.routes
            if isinstance(route, APIRoute)
            for method in route.methods
        }
        self.assertEqual(methods, {"GET"})
        self.assertNotIn("/docs", {route.path for route in app.routes})

# --- test_event_adapters.py ---
class EventAdapterTests(unittest.TestCase):
    def setUp(self):
        smart_detector.last_alert.clear()
        smart_detector.events.clear()

    def test_ufw_event_uses_common_schema(self):
        event = ufw_adapter.parse_line(
            "[UFW BLOCK] IN=eth0 SRC=192.0.2.1 DST=198.51.100.2 "
            "PROTO=TCP DPT=443"
        )
        self.assertEqual(event["schema_version"], 1)
        self.assertEqual(event["sensor"], "ufw")
        self.assertEqual(event["source"], "192.0.2.1")
        self.assertEqual(event["destination_port"], 443)
        self.assertEqual(event["action"], "block")

    def test_windows_firewall_w3c_header_and_record(self):
        adapter = windows_firewall_adapter.WindowsFirewallAdapter()
        ingestion._prime_parser(
            io.StringIO(
                "#Version: 1.5\n"
                "#Fields: date time action protocol src-ip dst-ip src-port dst-port\n"
            ),
            adapter.parse_line,
            "windows-firewall",
        )
        event = adapter.parse_line(
            "2026-10-19 08:00:00 DROP TCP 192.0.2.3 198.51.100.4 50123 22"
        )
        self.assertEqual(event["sensor"], "windows_firewall")
        self.assertEqual(event["source"], "192.0.2.3")
        self.assertEqual(event["destination_port"], 22)
        self.assertEqual(event["timestamp"], "2026-10-19T08:00:00Z")

    def test_windows_wfp_event_xml(self):
        xml = """<Event><System><EventID>5157</EventID>
        <TimeCreated SystemTime="2026-10-19T08:00:00.000Z" /></System><EventData>
        <Data Name="Application">app.exe</Data>
        <Data Name="SourceAddress">192.0.2.5</Data>
        <Data Name="DestAddress">198.51.100.6</Data>
        <Data Name="DestPort">443</Data><Data Name="Protocol">6</Data>
        </EventData></Event>"""
        event = windows_firewall_adapter.parse_wfp_event_xml(xml)
        self.assertEqual(event["sensor"], "windows_filtering_platform")
        self.assertEqual(event["action"], "blocked")
        self.assertEqual(event["destination_port"], 443)
        self.assertEqual(event["application"], "app.exe")
        self.assertEqual(event["timestamp"], "2026-10-19T08:00:00.000Z")

    def test_sysmon_network_event_xml(self):
        xml = """<Event><System><EventID>3</EventID>
        <TimeCreated SystemTime="2026-10-19T08:01:00.000Z" /></System><EventData>
        <Data Name="SourceIp">192.0.2.7</Data>
        <Data Name="DestinationIp">198.51.100.8</Data>
        <Data Name="DestinationPort">8080</Data>
        <Data Name="Protocol">tcp</Data></EventData></Event>"""
        event = parse_event_xml(xml)
        self.assertEqual(event["sensor"], "sysmon")
        self.assertEqual(event["event_id"], "3")
        self.assertEqual(event["destination_port"], 8080)
        self.assertEqual(event["timestamp"], "2026-10-19T08:01:00.000Z")

    def test_macos_unified_log_with_endpoint_message(self):
        event = macos_adapter.parse_log_entry(
            json.dumps(
                {
                    "timestamp": "2026-10-19T08:00:00Z",
                    "process": "socketfilterfw",
                    "eventMessage": "deny 192.0.2.9:50100 -> 198.51.100.10:443",
                }
            )
        )
        self.assertEqual(event["sensor"], "unified_log")
        self.assertEqual(event["source"], "192.0.2.9")
        self.assertEqual(event["destination_port"], 443)
        self.assertEqual(event["action"], "blocked")

    def test_macos_json_stream_handles_pretty_printed_records(self):
        entries = list(
            macos_adapter.iter_log_entries(
                io.StringIO(
                    '{\n  "eventMessage": "first"\n}\n'
                    '{\n  "eventMessage": "second"\n}\n'
                )
            )
        )
        self.assertEqual([entry["eventMessage"] for entry in entries], ["first", "second"])

    def test_suricata_eve_alert(self):
        event = suricata_adapter.parse_suricata_line(
            json.dumps(
                {
                    "timestamp": "2026-10-19T08:00:00Z",
                    "event_type": "alert",
                    "src_ip": "192.0.2.11",
                    "dest_ip": "198.51.100.12",
                    "dest_port": 443,
                    "proto": "TCP",
                    "alert": {"signature": "test signature", "signature_id": 42},
                }
            )
        )
        self.assertEqual(event["sensor"], "suricata")
        self.assertEqual(event["signature_id"], 42)
        self.assertEqual(event["destination_port"], 443)

    def test_zeek_connection_tsv(self):
        adapter = zeek_adapter.ZeekAdapter()
        ingestion._prime_parser(
            io.StringIO(
                "#separator \\x09\n"
                "#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\tconn_state\n"
            ),
            adapter.parse_line,
            "zeek",
        )
        event = adapter.parse_line(
            "1792396800.0\t192.0.2.13\t198.51.100.14\t53\tudp\tSF"
        )
        self.assertEqual(event["sensor"], "zeek")
        self.assertEqual(event["source"], "192.0.2.13")
        self.assertEqual(event["destination_port"], 53)
        self.assertEqual(event["action"], "SF")

    def test_normalized_events_feed_the_existing_detector(self):
        with tempfile.TemporaryDirectory() as directory:
            alert_file = Path(directory, "alerts.jsonl")
            baseline = smart_detector.Baseline(str(Path(directory, "baseline.json")))
            for port in range(1, smart_detector.PORT_THRESHOLD + 1):
                event = {
                    "source": "192.0.2.20",
                    "destination": "198.51.100.20",
                    "destination_port": port,
                    "sensor": "suricata",
                    "platform": "network",
                    "protocol": "TCP",
                    "action": None,
                    "event": "suricata_flow",
                    "timestamp": "2026-10-19T08:00:00Z",
                }
                smart_detector.process_event(event, baseline, str(alert_file))
            alert = json.loads(alert_file.read_text(encoding="utf-8"))
        self.assertEqual(alert["source_type"], "suricata")
        self.assertEqual(alert["destination_port"], smart_detector.PORT_THRESHOLD)
        self.assertEqual(alert["unique_ports"], smart_detector.PORT_THRESHOLD)
        self.assertEqual(alert["event_timestamp"], "2026-10-19T08:00:00Z")

# --- test_incident_pipeline.py ---
def event(source, destination, port, event_id, timestamp=None, **fields):
    return normalize_event(
        source,
        destination,
        port,
        protocol=fields.pop("protocol", "TCP"),
        action=fields.pop("action", None),
        event="connection",
        timestamp=timestamp,
        platform="test",
        sensor="test_sensor",
        event_id=event_id,
        raw=fields.pop("raw", {}),
    ) | fields


class ScanDetectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = TelemetryStore(str(Path(self.directory.name, "telemetry.db")))
        self.thresholds = ScanThresholds(
            vertical_ports=4,
            horizontal_hosts=5,
            horizontal_min_events=5,
            horizontal_max_ports=2,
            slow_ports=3,
            syn_ports=4,
            failure_events=4,
        )
        self.detector = ScanDetector(self.store, thresholds=self.thresholds)

    def tearDown(self):
        self.directory.cleanup()

    def test_vertical_scans_are_grouped_per_source_and_destination(self):
        for index, host in enumerate(
            ("198.51.100.1", "198.51.100.2", "198.51.100.3")
        ):
            self.assertIsNone(
                self.detector.process_event(event("192.0.2.1", host, 443, f"h{index}"))[
                    "detection"
                ]
            )
        results = [
            self.detector.process_event(
                event("192.0.2.1", "198.51.100.4", port, f"v{port}")
            )
            for port in range(20, 24)
        ]
        self.assertEqual(
            results[-1]["detection"]["classification"],
            "possible vertical port scan",
        )
        incidents = self.store.list_incidents()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["destination_ip"], "198.51.100.4")
        self.assertEqual(incidents[0]["severity"], "high")

    def test_horizontal_scans_detect_many_hosts_on_few_ports(self):
        results = []
        for index in range(5):
            results.append(
                self.detector.process_event(
                    event(
                        "192.0.2.2",
                        f"198.51.100.{index + 1}",
                        22,
                        f"horizontal-{index}",
                    )
                )
            )
        self.assertEqual(
            results[-1]["detection"]["classification"],
            "possible horizontal port scan",
        )
        incident = self.store.list_incidents()[0]
        self.assertIsNone(incident["destination_ip"])
        self.assertEqual(incident["evidence"]["unique_destination_hosts"], [
            "198.51.100.1",
            "198.51.100.2",
            "198.51.100.3",
            "198.51.100.4",
            "198.51.100.5",
        ])

    def test_syn_scans_and_connection_failures_need_telemetry_support(self):
        syn_results = []
        for port in range(30, 34):
            syn_results.append(
                self.detector.process_event(
                    event(
                        "192.0.2.3",
                        "198.51.100.30",
                        port,
                        f"syn-{port}",
                        tcp_flags=["SYN"],
                    )
                )
            )
        self.assertEqual(
            syn_results[-1]["detection"]["classification"],
            "possible SYN port scan",
        )

        failure_results = []
        for port in range(40, 45):
            failure_results.append(
                self.detector.process_event(
                    event(
                        "192.0.2.4",
                        "198.51.100.40",
                        port,
                        f"fail-{port}",
                        action="rejected",
                    )
                )
            )
        self.assertEqual(
            failure_results[-1]["detection"]["classification"],
            "possible connection-failure scan",
        )

    def test_slow_scans_use_longer_window_and_are_named_as_possible(self):
        now = datetime.now(timezone.utc)
        results = []
        for index in range(3):
            stamp = (now - timedelta(seconds=120 - index * 40)).isoformat()
            results.append(
                self.detector.process_event(
                    event(
                        "192.0.2.5",
                        "198.51.100.50",
                        1000 + index,
                        f"slow-{index}",
                        timestamp=stamp,
                    )
                )
            )
        self.assertEqual(
            results[-1]["detection"]["classification"],
            "possible slow vertical port scan",
        )

    def test_repeated_observations_update_one_incident_and_duplicates_are_dropped(self):
        results = []
        for port in range(1, 6):
            results.append(
                self.detector.process_event(
                    event("192.0.2.6", "198.51.100.60", port, f"incident-{port}")
                )
            )
        incident_id = results[3]["incident"]["incident_id"]
        self.assertEqual(results[-1]["incident"]["incident_id"], incident_id)
        duplicate = self.detector.process_event(
            event("192.0.2.6", "198.51.100.60", 5, "incident-5")
        )
        self.assertTrue(duplicate["duplicate"])
        incident = self.store.get_incident(incident_id)
        self.assertEqual(incident["event_count"], 2)
        self.assertEqual(len(incident["timeline"]), 2)
        self.assertIsNotNone(incident["timeline"][0]["ingestion_timestamp"])
        self.assertIsNotNone(incident["timeline"][0]["timestamp"])

    def test_restart_recovers_recent_window_and_memory_is_bounded(self):
        for port in range(1, 4):
            self.detector.process_event(
                event("192.0.2.7", "198.51.100.70", port, f"restart-{port}")
            )
        restarted = ScanDetector(
            self.store,
            thresholds=self.thresholds,
        )
        result = restarted.process_event(
            event("192.0.2.7", "198.51.100.70", 4, "restart-4")
        )
        self.assertEqual(
            result["detection"]["classification"],
            "possible vertical port scan",
        )
        tiny = ScanDetector(
            self.store,
            thresholds=ScanThresholds(max_history_events=2),
        )
        self.assertLessEqual(len(tiny.history), 2)

    def test_future_source_clock_is_clamped_for_detection_but_recorded(self):
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        result = self.detector.process_event(
            event("192.0.2.8", "198.51.100.80", 80, "clock", timestamp=future)
        )
        saved = self.store.recent_events(limit=1)[0]
        self.assertEqual(saved["timestamp_quality"], "future_clock_clamped")
        self.assertLessEqual(
            datetime.fromisoformat(saved["effective_event_timestamp"]).timestamp(),
            datetime.now(timezone.utc).timestamp(),
        )
        self.assertIsNone(result["detection"])

    def test_threshold_validation_rejects_invalid_settings(self):
        with self.assertRaises(ValueError):
            ScanThresholds(vertical_ports=0)
        with self.assertRaises(ValueError):
            ScanThresholds(horizontal_max_ports=0)


class RotatingFileTests(unittest.TestCase):
    def test_file_follower_reads_events_after_log_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "firewall.log")
            path.write_text("initial ignored line\n", encoding="utf-8")
            seen = []

            def handle(event):
                seen.append(event["destination_port"])
                if len(seen) == 2:
                    raise StopIteration

            calls = 0

            def sleep(_seconds):
                nonlocal calls
                calls += 1
                if calls == 1:
                    with path.open("a", encoding="utf-8") as stream:
                        stream.write(
                            "[UFW BLOCK] SRC=192.0.2.9 DST=198.51.100.9 DPT=80\n"
                        )
                elif calls == 2:
                    archived = Path(directory, "firewall.log.1")
                    path.rename(archived)
                    replacement = Path(directory, "replacement.log")
                    replacement.write_text(
                        "[UFW BLOCK] SRC=192.0.2.9 DST=198.51.100.9 DPT=443\n",
                        encoding="utf-8",
                    )
                    replacement.rename(path)
                elif calls == 3:
                    with path.open("a", encoding="utf-8") as stream:
                        stream.write("unused trailing line\n")

            with patch.object(ingestion.time, "sleep", side_effect=sleep):
                with self.assertRaises(StopIteration):
                    ingestion.follow_file(
                        str(path),
                        "ufw",
                        type("BaselineStub", (), {"save": lambda _self: None})(),
                        None,
                        handle,
                    )
            self.assertEqual(seen, [80, 443])

# --- test_ml_analyst.py ---
class BehavioralModelTests(unittest.TestCase):
    def test_window_features_include_timing_and_destination_diversity(self):
        features = window_features(
            [
                (10.0, 22, "198.51.100.1"),
                (12.0, 80, "198.51.100.1"),
                (16.0, 443, "198.51.100.2"),
            ]
        )
        self.assertEqual(features["events"], 3)
        self.assertEqual(features["unique_ports"], 3)
        self.assertEqual(features["unique_destinations"], 2)
        self.assertAlmostEqual(features["mean_interarrival_seconds"], 3.0)
        self.assertAlmostEqual(features["interarrival_std_seconds"], 1.0)
        self.assertAlmostEqual(features["ports_per_second"], 0.5)

    def test_isolation_forest_trains_on_history_and_scores_behavior(self):
        randomizer = random.Random(7)
        normal_rows = [
            [
                randomizer.gauss(5, 1),
                randomizer.gauss(3, 1),
                randomizer.gauss(0.08, 0.02),
                randomizer.gauss(2, 1),
                randomizer.gauss(0.03, 0.01),
                randomizer.gauss(5, 2),
                randomizer.gauss(1, 0.3),
                randomizer.gauss(35, 8),
            ]
            for _ in range(100)
        ]
        scorer = IsolationForestScorer({"192.0.2.1": normal_rows})
        normal = dict(zip(FEATURE_NAMES, normal_rows[0]))
        unusual = {
            "events": 40.0,
            "unique_ports": 35.0,
            "ports_per_second": 2.0,
            "unique_destinations": 25.0,
            "destinations_per_second": 1.5,
            "mean_interarrival_seconds": 0.05,
            "interarrival_std_seconds": 0.01,
            "active_span_seconds": 1.0,
        }
        normal_result = scorer.score("192.0.2.1", normal)
        anomaly_result = scorer.score("192.0.2.1", unusual)
        self.assertFalse(normal_result["is_anomaly"])
        self.assertTrue(anomaly_result["is_anomaly"])
        self.assertEqual(anomaly_result["model"], "isolation_forest")
        self.assertEqual(anomaly_result["training_samples"], 100)

    def test_insufficient_history_does_not_claim_anomaly_score(self):
        scorer = IsolationForestScorer(
            {"192.0.2.2": [[0.0] * len(FEATURE_NAMES)] * 29}
        )
        self.assertIsNone(
            scorer.score("192.0.2.2", dict.fromkeys(FEATURE_NAMES, 1.0))
        )

    def test_baseline_persists_capped_samples_and_sampling_cadence(self):
        with tempfile.TemporaryDirectory() as directory:
            model_path = Path(directory, "model.json")
            baseline = Baseline(str(model_path))
            features = dict.fromkeys(FEATURE_NAMES, 1.0)
            self.assertTrue(baseline.record_ml_sample("192.0.2.3", features, 100))
            self.assertFalse(baseline.record_ml_sample("192.0.2.3", features, 105))
            self.assertTrue(baseline.record_ml_sample("192.0.2.3", features, 110))
            baseline.save()
            loaded = Baseline(str(model_path))
        self.assertEqual(len(loaded.data["ml_samples"]["192.0.2.3"]), 2)
        self.assertEqual(loaded.data["ml_last_sample"]["192.0.2.3"], 110)

    def test_baseline_evicts_inactive_sources_with_a_bounded_source_cap(self):
        import detection as smart_detector

        previous_cap = smart_detector.MAX_TRACKED_SOURCES
        smart_detector.MAX_TRACKED_SOURCES = 2
        with tempfile.TemporaryDirectory() as directory:
            try:
                baseline = Baseline(str(Path(directory, "model.json")))
                baseline.touch("first", 1)
                baseline.touch("second", 2)
                baseline.touch("third", 3)
            finally:
                smart_detector.MAX_TRACKED_SOURCES = previous_cap
        self.assertNotIn("first", baseline.data["last_seen"])
        self.assertEqual(set(baseline.data["last_seen"]), {"second", "third"})

    def test_rag_analyst_uses_trained_isolation_forest(self):
        randomizer = random.Random(7)
        rows = [
            [
                randomizer.gauss(5, 1),
                randomizer.gauss(3, 1),
                randomizer.gauss(0.08, 0.02),
                randomizer.gauss(2, 1),
                randomizer.gauss(0.03, 0.01),
                randomizer.gauss(5, 2),
                randomizer.gauss(1, 0.3),
                randomizer.gauss(35, 8),
            ]
            for _ in range(100)
        ]
        with tempfile.TemporaryDirectory() as directory:
            baseline_path = Path(directory, "model.json")
            baseline_path.write_text(
                json.dumps({"ml_samples": {"192.0.2.4": rows}, "ml_last_sample": {}}),
                encoding="utf-8",
            )
            agent = SecurityAgent("knowledge", str(baseline_path))
            result = agent.analyze(
                "192.0.2.4",
                40,
                35,
                1,
                unique_destinations=25,
                mean_interarrival=0.05,
                interarrival_std=0.01,
            )
        self.assertEqual(result["ml_model"], "isolation_forest")
        self.assertEqual(result["ml_training_samples"], 100)
        self.assertIn("Isolation Forest identifies unusual behavior", result["signals"])


class EvidenceAnalystTests(unittest.TestCase):
    def setUp(self):
        self.alert = {
            "event": "possible_port_scan",
            "source": "192.0.2.10",
            "destination": "198.51.100.10",
            "events": 20,
            "unique_ports": 18,
            "destination_port": 8443,
            "source_type": "suricata",
            "source_platform": "network",
            "rate": 1.8,
            "destination_diversity": 2,
            "rule_signals": ["unique_ports_threshold"],
            "window_seconds": 60,
            "port_scan_threshold": 15,
            "ml_model": "isolation_forest",
            "ml_anomaly_score": 0.12,
            "ml_is_anomaly": True,
            "historical_baseline_samples": 30,
        }

    def test_validator_rejects_unobserved_values_and_unapproved_steps(self):
        result = validate_analysis(
            self.alert,
            {
                "evidence": [
                    {"field": "source", "value": "203.0.113.99"},
                    {"field": "events", "value": 20},
                    {"field": ["password"], "value": "compromised"},
                ],
                "investigation_steps": ["verify_owner", "disable_firewall"],
            },
        )
        self.assertEqual(
            result["observations"], [{"field": "events", "value": 20}]
        )
        self.assertEqual(len(result["investigation_steps"]), 1)
        self.assertEqual(
            validate_analysis(self.alert, {"evidence": None, "investigation_steps": None}),
            {"observations": [], "investigation_steps": []},
        )

    def test_ai_analysis_renders_only_validated_telemetry_and_steps(self):
        result = verified_ai_analysis(
            self.alert,
            {
                "evidence": [
                    {"field": "unique_ports", "value": 18},
                    {"field": "classification", "value": "confirmed breach"},
                ],
                "investigation_steps": ["correlate_network", "auto_block"],
                "summary": "The source exfiltrated data.",
            },
        )
        self.assertEqual(result["observations"], [{"field": "unique_ports", "value": 18}])
        self.assertEqual(len(result["investigation_steps"]), 1)
        self.assertNotIn("summary", result)

    def test_local_analysis_uses_recorded_evidence_and_safe_steps(self):
        result = local_analysis(self.alert)
        fields = {item["field"] for item in result["evidence"]}
        self.assertIn("unique_ports", fields)
        self.assertIn("source_type", fields)
        self.assertEqual(result["automatic_response"], "disabled")
        self.assertTrue(result["investigation_steps"])
        self.assertTrue(any("Isolation Forest flagged" in item for item in result["rationale"]))

# --- test_sentinel_ui.py ---
class SentinelUiTests(unittest.TestCase):
    def test_alert_store_migrates_existing_database_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory, "sentinel.db")
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    """
                    CREATE TABLE alerts (
                        id INTEGER PRIMARY KEY,
                        timestamp DATETIME,
                        source_ip VARCHAR(128),
                        destination_ip VARCHAR(128),
                        event_type VARCHAR(128),
                        unique_ports INTEGER,
                        event_count INTEGER,
                        anomaly_score VARCHAR(64),
                        confidence VARCHAR(32),
                        explanation TEXT,
                        status VARCHAR(32)
                    )
                    """
                )
                connection.commit()
            finally:
                connection.close()
            store = AlertStore(str(database))
            alert = {
                "source": "192.0.2.1",
                "destination": "198.51.100.1",
                "event": "possible vertical port scan",
                "events": 15,
                "unique_ports": 15,
                "incident_id": "incident-1",
                "deduplication_key": "event-1",
                "severity": "high",
                "confidence": "high",
            }
            self.assertEqual(store.add(alert), 1)
            self.assertIsNone(store.add(alert))
            recent = store.recent(1)[0]
            self.assertEqual(recent["incident_id"], "incident-1")
            self.assertEqual(recent["severity"], "high")
            store.engine.dispose()

    def test_terminal_alert_renders_incident_and_severity(self):
        rendered = Sentinel.render(
            {
                "event": "possible horizontal port scan",
                "source": "192.0.2.2",
                "destination": "198.51.100.2",
                "destination_port": 22,
                "events": 10,
                "unique_ports": 1,
                "severity": "medium",
                "confidence": "medium",
                "incident_id": "incident-2",
                "timestamp": "2026-10-19T08:00:00Z",
            }
        )
        self.assertIn("possible horizontal port scan", rendered)
        self.assertIn("incident-2", rendered)
        self.assertIn("Automatic response: OFF", rendered)

# --- test_smart_detector.py ---
class SmartDetectorTests(unittest.TestCase):
    def setUp(self):
        smart_detector.last_alert.clear()
        smart_detector.events.clear()

    def test_report_persists_complete_event_counts_and_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            alert_file = Path(directory, "alerts.jsonl")
            smart_detector.report(
                "192.0.2.10",
                "198.51.100.20",
                {22, 80, 443},
                (7, 3, 0.05),
                4.26,
                False,
                str(alert_file),
            )
            event = json.loads(alert_file.read_text(encoding="utf-8"))

        self.assertEqual(event["destination"], "198.51.100.20")
        self.assertEqual(event["events"], 7)
        self.assertEqual(event["unique_ports"], 3)
        self.assertEqual(event["anomaly_score"], 4.26)
        self.assertEqual(event["confidence"], "medium")

    def test_learning_alert_has_no_fake_anomaly_score(self):
        with tempfile.TemporaryDirectory() as directory:
            alert_file = Path(directory, "alerts.jsonl")
            smart_detector.report(
                "192.0.2.11",
                "198.51.100.21",
                set(range(1, 16)),
                (20, 15, 0.25),
                None,
                True,
                str(alert_file),
            )
            event = json.loads(alert_file.read_text(encoding="utf-8"))

        self.assertIsNone(event["anomaly_score"])
        self.assertEqual(event["confidence"], "high")
        self.assertEqual(event["mode"], "learning")

    def test_parsed_firewall_lines_create_a_complete_alert(self):
        with tempfile.TemporaryDirectory() as directory:
            alert_file = Path(directory, "alerts.jsonl")
            for port in range(1, smart_detector.PORT_THRESHOLD + 1):
                smart_detector.process_line(
                    f"[UFW BLOCK] SRC=192.0.2.99 DST=198.51.100.99 DPT={port}",
                    smart_detector.Baseline(str(Path(directory, "baseline.json"))),
                    str(alert_file),
                )
            event = json.loads(alert_file.read_text(encoding="utf-8"))

        self.assertEqual(event["source"], "192.0.2.99")
        self.assertEqual(event["destination"], "198.51.100.99")
        self.assertEqual(event["events"], smart_detector.PORT_THRESHOLD)
        self.assertEqual(event["unique_ports"], smart_detector.PORT_THRESHOLD)
        self.assertIsNone(event["anomaly_score"])
