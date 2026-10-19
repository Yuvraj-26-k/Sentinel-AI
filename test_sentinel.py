import io
import json
import random
import sqlite3
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

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
    KnowledgeBase,
    LocalSecurityAgent,
    SecurityAgent,
    classify_intent,
    local_analysis,
    validate_analysis,
    verified_ai_analysis,
)
from sentinel import (
    Sentinel,
    _monitor_source,
    _prepare_linux_ufw,
    _prompt_input,
    analyze_log_file,
    collect_main as sentinel_module_collect_main,
    collect_evidence,
    hash_file,
    hash_main as sentinel_module_hash_main,
    logs_main as sentinel_module_logs_main,
    main as sentinel_main,
    password_main as sentinel_module_password_main,
)

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

    def test_ufw_default_log_uses_available_kernel_or_system_log(self):
        with patch(
            "telemetry.os.path.isfile",
            side_effect=lambda path: path == "/var/log/kern.log",
        ):
            self.assertEqual(
                telemetry.default_log_file("ufw"),
                "/var/log/kern.log",
            )

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

    def test_nlp_intent_router_handles_synonyms_and_inflections(self):
        self.assertEqual(classify_intent("what can Sentinel do for me?"), "features")
        self.assertEqual(classify_intent("why did this alert trigger?"), "explain")
        self.assertEqual(classify_intent("help me inspect these logs"), "logs")
        self.assertEqual(classify_intent("nmap scans across many ports"), "scan_guidance")
        self.assertEqual(classify_intent("show recent incidents"), "status")
        self.assertEqual(classify_intent("unrelated question about ocean tides"), "unknown")

    def test_local_rag_retrieves_normalized_nmap_guidance(self):
        knowledge = KnowledgeBase("knowledge")
        results = knowledge.search("How do Nmap SYN scans find open ports?")
        self.assertTrue(results)
        self.assertEqual(results[0][1], "nmap-scan-interpretation")
        self.assertIn("Authorized scans", results[0][2])

    def test_local_agent_keeps_retrieved_guidance_separate_from_alert_evidence(self):
        agent = LocalSecurityAgent()
        result = agent.analyze_alert(self.alert)
        self.assertEqual(result["analysis"]["classification"], "possible_port_scan")
        self.assertTrue(result["analysis"]["evidence"])
        self.assertTrue(result["retrieved_guidance"])
        self.assertIn("document", result["retrieved_guidance"][0])

# --- test_sentinel_ui.py ---
class SentinelUiTests(unittest.TestCase):
    def test_interactive_prompt_animates_and_colors_prompt_and_typed_input(self):
        class TTYBuffer(io.StringIO):
            def isatty(self):
                return True

        stdout = TTYBuffer()
        with (
            patch("sentinel.sys.stdout", stdout),
            patch("sentinel.time.sleep") as sleep,
            patch("builtins.input", return_value="status") as read_input,
            patch.dict("os.environ", {}, clear=True),
        ):
            answer = _prompt_input()
        self.assertEqual(answer, "status")
        self.assertEqual(sleep.call_count, 3)
        self.assertIn("\033[96m", stdout.getvalue())
        self.assertIn("\033[92m", read_input.call_args.args[0])
        self.assertEqual(
            read_input.call_args.args[0],
            "\033[95m>\033[0m \033[96m\033[0m\033[92m",
        )

    def test_noninteractive_or_no_color_prompt_has_no_ansi_sequences(self):
        with patch("sentinel.sys.stdout", io.StringIO()):
            with patch("builtins.input", return_value="status") as read_input:
                self.assertEqual(_prompt_input(), "status")
        self.assertEqual(read_input.call_args.args, ("> ",))

        class TTYBuffer(io.StringIO):
            def isatty(self):
                return True

        stdout = TTYBuffer()
        with (
            patch("sentinel.sys.stdout", stdout),
            patch("sentinel.time.sleep"),
            patch("builtins.input", return_value="status") as read_input,
            patch.dict("os.environ", {"NO_COLOR": "1"}),
        ):
            self.assertEqual(_prompt_input(), "status")
        self.assertNotIn("\033[", stdout.getvalue())
        self.assertNotIn("\033[", read_input.call_args.args[0])

    def test_online_setup_explains_google_gemini_auth_and_chatgpt_limitation(self):
        with patch.dict("os.environ", {}, clear=True), patch(
            "sys.stdout", new_callable=io.StringIO
        ) as stdout:
            Sentinel._show_online_setup()
        output = stdout.getvalue()
        self.assertIn("Gemini chat needs GEMINI_API_KEY", output)
        self.assertIn("browser-based Google OAuth", output)
        self.assertIn("GEMINI_OAUTH_CLIENT_FILE", output)

    def test_hashing_streams_file_and_writes_exclusive_digest_report(self):
        import hashlib

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "evidence.bin")
            content = b"private evidence" * 100000
            source.write_bytes(content)
            report_path = Path(directory, "digest.txt")

            report = hash_file(source)

            self.assertIn("Algorithm: SHA-256", report)
            self.assertIn(hashlib.sha256(content).hexdigest(), report)
            self.assertNotIn("private evidence", report)
            with patch("sys.stdout", new_callable=io.StringIO) as stdout:
                self.assertEqual(
                    sentinel_module_hash_main(
                        [str(source), "--algorithm", "sha512", "--output", str(report_path)]
                    ),
                    0,
                )
            self.assertEqual(report_path.read_text(encoding="utf-8"), stdout.getvalue())
            existing_report = report_path.read_text(encoding="utf-8")

            with redirect_stderr(io.StringIO()) as stderr:
                with self.assertRaises(SystemExit) as raised:
                    sentinel_module_hash_main(
                        [str(source), "--output", str(report_path)]
                    )
            self.assertEqual(raised.exception.code, 1)
            self.assertIn("cannot create report", stderr.getvalue())
            self.assertEqual(report_path.read_text(encoding="utf-8"), existing_report)

            with redirect_stderr(io.StringIO()) as stderr:
                with self.assertRaises(SystemExit) as raised:
                    sentinel_module_hash_main(
                        [str(source), "--output", str(source)]
                    )
            self.assertEqual(raised.exception.code, 1)
            self.assertIn("refusing to write report over input file", stderr.getvalue())
            self.assertEqual(source.read_bytes(), content)

    def test_password_generator_only_reveals_secret_to_interactive_terminal(self):
        class TTYBuffer(io.StringIO):
            def isatty(self):
                return True

        with patch("sys.stdout", new_callable=io.StringIO) as stdout:
            with patch("sentinel.secrets.choice") as choose:
                with self.assertRaises(SystemExit) as raised:
                    sentinel_module_password_main(["generate", "--length", "12"])
            self.assertEqual(raised.exception.code, 1)
            choose.assert_not_called()
            self.assertNotIn("Generated password", stdout.getvalue())

        stdout = TTYBuffer()
        with (
            patch("sentinel.sys.stdout", stdout),
            patch("sentinel.secrets.choice", return_value="x") as choose,
        ):
            self.assertEqual(
                sentinel_module_password_main(["generate", "--length", "12"]),
                0,
            )
        self.assertEqual(choose.call_count, 12)
        self.assertEqual(stdout.getvalue().count("x" * 12), 1)
        self.assertIn("shown once; not saved", stdout.getvalue())

        with self.assertRaises(SystemExit):
            with (
                patch("sentinel.sys.stdout", TTYBuffer()),
                patch("sentinel.secrets.choice") as choose,
            ):
                sentinel_module_password_main(["generate", "--length", "257"])
        choose.assert_not_called()

    def test_password_checker_hides_input_and_reports_only_heuristic_checks(self):
        class TTYBuffer(io.StringIO):
            def isatty(self):
                return True

        stdout = TTYBuffer()
        with (
            patch("sentinel.sys.stdout", stdout),
            patch("sentinel.sys.stdin.isatty", return_value=True),
            patch("sentinel.getpass.getpass", return_value="Secret123!"),
        ):
            self.assertEqual(sentinel_module_password_main(["check"]), 0)
        self.assertIn("heuristic (not an entropy estimate)", stdout.getvalue())
        self.assertIn("minimum length: pass", stdout.getvalue())
        self.assertNotIn("Secret123!", stdout.getvalue())

        weak_stdout = TTYBuffer()
        with (
            patch("sentinel.sys.stdout", weak_stdout),
            patch("sentinel.sys.stdin.isatty", return_value=True),
            patch("sentinel.getpass.getpass", return_value="weak"),
        ):
            self.assertEqual(sentinel_module_password_main(["check"]), 1)
        self.assertIn("minimum length: fail", weak_stdout.getvalue())

    def test_logs_command_reports_file_metrics_and_validated_indicators(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "sample.log")
            text = (
                "INFO ERROR WARNING\n"
                "INFOFUL warning\n"
                "admin@example.com 999.1.2.3 192.0.2.1 2001:db8::1\n"
            )
            source.write_bytes(text.encode("utf-8"))

            report = analyze_log_file(source)

            self.assertIn(f"Bytes: {len(text.encode('utf-8'))}", report)
            self.assertIn(f"Lines: {len(text.splitlines())}", report)
            self.assertIn(f"Words: {len(text.split())}", report)
            self.assertIn(f"Characters: {len(text)}", report)
            self.assertIn("INFO substring occurrences (case-sensitive): 2", report)
            self.assertIn("WARNING substring occurrences (case-sensitive): 1", report)
            self.assertIn("ERROR substring occurrences (case-sensitive): 1", report)
            self.assertIn("admin@example.com", report)
            self.assertIn("192.0.2.1", report)
            self.assertIn("2001:db8::1", report)
            self.assertNotIn("999.1.2.3", report)

    def test_logs_command_saves_report_and_refuses_to_overwrite_input(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "sample.log")
            output = Path(directory, "report.txt")
            source.write_text("ERROR 192.0.2.1\n", encoding="utf-8")
            with patch("sys.stdout", new_callable=io.StringIO) as stdout:
                self.assertEqual(
                    sentinel_module_logs_main(
                        [str(source), "--output", str(output)]
                    ),
                    0,
                )
            self.assertEqual(output.read_text(encoding="utf-8"), stdout.getvalue())

            with redirect_stderr(io.StringIO()) as stderr:
                with self.assertRaises(SystemExit) as raised:
                    sentinel_module_logs_main(
                        [str(source), "--output", str(source)]
                    )
            self.assertEqual(raised.exception.code, 1)
            self.assertIn("refusing to overwrite input file", stderr.getvalue())
            self.assertIn("ERROR", source.read_text(encoding="utf-8"))

    def test_logs_command_rejects_non_regular_input(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(OSError):
                analyze_log_file(directory)

    def test_evidence_collection_is_shallow_filtered_and_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "z.log").write_bytes(b"log")
            (root / "a.txt").write_bytes(b"text")
            (root / "ignored.TXT").write_bytes(b"upper-case extension")
            (root / "ignored.csv").write_bytes(b"unsupported")
            nested = root / "nested"
            nested.mkdir()
            (nested / "nested.pdf").write_bytes(b"not scanned")

            report, errors = collect_evidence(root)

            self.assertEqual(errors, [])
            self.assertIn("Matching files: 2", report)
            self.assertIn("Extensions: .log=1, .txt=1", report)
            self.assertLess(report.index("a.txt"), report.index("z.log"))
            self.assertNotIn("ignored.TXT", report)
            self.assertNotIn("nested.pdf", report)
            self.assertIn(f"{(root / 'a.txt').resolve()}", report)

    def test_evidence_collection_reports_directory_and_output_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory, "missing")
            report, errors = collect_evidence(missing)
            self.assertEqual(len(errors), 1)
            self.assertIn("Errors: 1", report)
            self.assertIn("Collection errors:", report)

            source = Path(directory, "sample.log")
            source.write_text("evidence", encoding="utf-8")
            with redirect_stderr(io.StringIO()) as stderr:
                with self.assertRaises(SystemExit) as raised:
                    sentinel_module_collect_main(
                        [
                            directory,
                            "--output",
                            str(Path(directory, "absent", "report.txt")),
                        ]
                    )
            self.assertEqual(raised.exception.code, 1)
            self.assertIn("cannot write report", stderr.getvalue())

            with redirect_stderr(io.StringIO()) as stderr:
                with self.assertRaises(SystemExit) as raised:
                    sentinel_module_collect_main(
                        [directory, "--output", str(source)]
                    )
            self.assertEqual(raised.exception.code, 1)
            self.assertIn("refusing to overwrite matching evidence file", stderr.getvalue())
            self.assertEqual(source.read_text(encoding="utf-8"), "evidence")

    def test_cli_dispatches_standalone_commands_without_starting_console(self):
        with (
            patch.object(sys, "argv", ["sentinel", "logs", "example.log"]),
            patch("sentinel.logs_main", return_value=7) as logs,
        ):
            self.assertEqual(sentinel_main(), 7)
        logs.assert_called_once_with(["example.log"])

        with (
            patch.object(sys, "argv", ["sentinel", "collect", "evidence"]),
            patch("sentinel.collect_main", return_value=3) as collect,
        ):
            self.assertEqual(sentinel_main(), 3)
        collect.assert_called_once_with(["evidence"])

        with (
            patch.object(sys, "argv", ["sentinel", "hash", "evidence.bin"]),
            patch("sentinel.hash_main", return_value=4) as hash_command,
        ):
            self.assertEqual(sentinel_main(), 4)
        hash_command.assert_called_once_with(["evidence.bin"])

        with (
            patch.object(sys, "argv", ["sentinel", "password", "generate"]),
            patch("sentinel.password_main", return_value=5) as password_command,
        ):
            self.assertEqual(sentinel_main(), 5)
        password_command.assert_called_once_with(["generate"])

    def test_interactive_assistant_routes_tools_and_natural_questions(self):
        with tempfile.TemporaryDirectory() as directory:
            terminal = Sentinel(
                str(Path(directory, "alerts.jsonl")),
                str(Path(directory, "alerts.db")),
            )
            try:
                with patch("sentinel.logs_main") as logs:
                    self.assertTrue(terminal.answer('analyze logs "C:\\Case Files\\App.log"'))
                logs.assert_called_once_with(["C:\\Case Files\\App.log"])

                with patch("sentinel.collect_main") as collect:
                    self.assertTrue(terminal.answer('collect evidence "Evidence Folder"'))
                collect.assert_called_once_with(["Evidence Folder"])

                with patch("sys.stdout", new_callable=io.StringIO) as stdout:
                    self.assertTrue(terminal.answer("how does scan detection work?"))
                self.assertIn("recorded network telemetry", stdout.getvalue())
                self.assertIn("not general AI knowledge", stdout.getvalue())

                with (
                    patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}),
                    patch(
                        "sentinel.chat_with_gemini",
                        return_value="Sure, I can explain that.",
                    ) as chat,
                    patch("builtins.input", return_value="yes"),
                    patch("sentinel.Sentinel._offer_save_report"),
                    patch("sys.stdout", new_callable=io.StringIO),
                ):
                    self.assertTrue(
                        terminal.answer("Can you help me understand how the ML works?")
                    )
                chat.assert_called_once()

                with patch("sys.stdout", new_callable=io.StringIO) as stdout:
                    self.assertTrue(terminal.answer("help"))
                self.assertIn("password generate", stdout.getvalue())
                self.assertIn("hash FILE", stdout.getvalue())
                self.assertIn("SENTINEL COMMAND CENTER", stdout.getvalue())
                self.assertIn("investigation", stdout.getvalue())

                with patch.object(terminal, "_explain_latest") as explain:
                    self.assertTrue(terminal.answer("analyze"))
                    self.assertTrue(terminal.answer("analyze alert"))
                self.assertEqual(explain.call_count, 2)

                with patch("sentinel.analyst_main") as analyst_command:
                    self.assertTrue(terminal.answer("analyze --source 192.0.2.1"))
                analyst_command.assert_called_once_with(["--source", "192.0.2.1"])
            finally:
                if terminal.store:
                    terminal.store.engine.dispose()

    def test_natural_language_question_uses_local_rag_before_online_search(self):
        with tempfile.TemporaryDirectory() as directory:
            terminal = Sentinel(
                str(Path(directory, "alerts.jsonl")),
                str(Path(directory, "alerts.db")),
            )
            try:
                with (
                    patch("sentinel.web_research") as research,
                    patch("sentinel.Sentinel._offer_save_report"),
                    patch("sys.stdout", new_callable=io.StringIO),
                ):
                    self.assertTrue(terminal.answer("How do Nmap SYN scans work?"))
                research.assert_not_called()
                self.assertIn(
                    "nmap-scan-interpretation", terminal.latest_report
                )
                self.assertIn(
                    "guidance, not alert evidence", terminal.latest_report
                )
                with patch("sys.stdout", new_callable=io.StringIO):
                    self.assertTrue(terminal.answer("analyze what is an Nmap scan"))
                self.assertIn("nmap-scan-interpretation", terminal.latest_report)
            finally:
                if terminal.store:
                    terminal.store.engine.dispose()

    def test_online_research_requires_consent_and_offers_cited_report(self):
        with tempfile.TemporaryDirectory() as directory:
            terminal = Sentinel(
                str(Path(directory, "alerts.jsonl")),
                str(Path(directory, "alerts.db")),
            )
            try:
                with (
                    patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}),
                    patch(
                        "sentinel.web_research",
                        return_value={
                            "answer": "A sourced answer.",
                            "sources": [
                                {"title": "Primary source", "url": "https://example.org"}
                            ],
                        },
                    ) as research,
                    patch("builtins.input", side_effect=("yes", "n")),
                    patch("sys.stdout", new_callable=io.StringIO) as stdout,
                ):
                    self.assertTrue(
                        terminal.answer("What is today's Gemini API pricing?")
                    )
                research.assert_called_once_with("What is today's Gemini API pricing?")
                self.assertIn("https://example.org", terminal.latest_report)
                self.assertIn("may be incomplete or incorrect", stdout.getvalue())
            finally:
                if terminal.store:
                    terminal.store.engine.dispose()

    def test_ordinary_natural_question_uses_conversational_gemini(self):
        query = "Explain DNSSEC"
        with tempfile.TemporaryDirectory() as directory:
            terminal = Sentinel(
                str(Path(directory, "alerts.jsonl")),
                str(Path(directory, "alerts.db")),
            )
            try:
                with (
                    patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}),
                    patch(
                        "sentinel.chat_with_gemini",
                        return_value="DNSSEC protects DNS records.",
                    ) as chat,
                    patch("builtins.input", return_value="yes"),
                    patch("sentinel.Sentinel._offer_save_report"),
                    patch("sys.stdout", new_callable=io.StringIO),
                ):
                    self.assertTrue(terminal.answer(query))
                chat.assert_called_once()
                self.assertEqual(chat.call_args.args[0], query)
                self.assertIn("DNSSEC protects DNS records.", terminal.latest_report)
            finally:
                if terminal.store:
                    terminal.store.engine.dispose()

    def test_current_information_search_uses_oauth_without_gemini_api_key(self):
        query = "What is the latest Python release?"
        with tempfile.TemporaryDirectory() as directory:
            terminal = Sentinel(
                str(Path(directory, "alerts.jsonl")),
                str(Path(directory, "alerts.db")),
            )
            try:
                with (
                    patch.dict("os.environ", {}, clear=True),
                    patch(
                        "sentinel.web_research",
                        return_value={"answer": "A current release.", "sources": []},
                    ) as research,
                    patch("builtins.input", side_effect=("yes", "no")),
                    patch("sentinel.Sentinel._offer_save_report"),
                    patch("sys.stdout", new_callable=io.StringIO),
                ):
                    self.assertTrue(terminal.answer(query))
                research.assert_called_once_with(query)
                self.assertIn("A current release.", terminal.latest_report)
            finally:
                if terminal.store:
                    terminal.store.engine.dispose()

    def test_natural_language_with_command_keywords_still_uses_conversation(self):
        query = "Can you help me understand how the anomaly model works?"
        with tempfile.TemporaryDirectory() as directory:
            terminal = Sentinel(
                str(Path(directory, "alerts.jsonl")),
                str(Path(directory, "alerts.db")),
            )
            try:
                with (
                    patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}),
                    patch(
                        "sentinel.chat_with_gemini",
                        return_value="The model learns patterns from telemetry.",
                    ) as chat,
                    patch("builtins.input", return_value="yes"),
                    patch("sentinel.Sentinel._offer_save_report"),
                    patch("sys.stdout", new_callable=io.StringIO),
                ):
                    self.assertTrue(terminal.answer(query))
                chat.assert_called_once()
                self.assertEqual(chat.call_args.args[0], query)
            finally:
                if terminal.store:
                    terminal.store.engine.dispose()

    def test_google_command_searches_the_supplied_question(self):
        query = "Explain DNSSEC"
        with tempfile.TemporaryDirectory() as directory:
            terminal = Sentinel(
                str(Path(directory, "alerts.jsonl")),
                str(Path(directory, "alerts.db")),
            )
            try:
                with (
                    patch.dict("os.environ", {}, clear=True),
                    patch(
                        "sentinel.web_research",
                        return_value={
                            "answer": "DNSSEC authenticates DNS data.",
                            "sources": [],
                        },
                    ) as research,
                    patch("builtins.input", side_effect=("yes", "no")),
                    patch("sentinel.Sentinel._offer_save_report"),
                    patch("sys.stdout", new_callable=io.StringIO),
                ):
                    self.assertTrue(terminal.answer(f"google {query}"))
                research.assert_called_once_with(query)
                self.assertIn("DNSSEC authenticates DNS data.", terminal.latest_report)
            finally:
                if terminal.store:
                    terminal.store.engine.dispose()

    def test_online_research_is_not_sent_without_consent(self):
        with tempfile.TemporaryDirectory() as directory:
            terminal = Sentinel(
                str(Path(directory, "alerts.jsonl")),
                str(Path(directory, "alerts.db")),
            )
            try:
                with (
                    patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}),
                    patch("sentinel.web_research") as research,
                    patch("builtins.input", return_value="no"),
                    patch("sys.stdout", new_callable=io.StringIO) as stdout,
                ):
                    self.assertTrue(terminal.answer("Search for a security topic"))
                research.assert_not_called()
                self.assertIn("cancelled; nothing was sent", stdout.getvalue())
            finally:
                if terminal.store:
                    terminal.store.engine.dispose()

    def test_conversational_question_uses_recent_history_after_consent(self):
        with tempfile.TemporaryDirectory() as directory:
            terminal = Sentinel(
                str(Path(directory, "alerts.jsonl")),
                str(Path(directory, "alerts.db")),
            )
            terminal.chat_history.extend(
                [
                    {"role": "user", "text": "Earlier question"},
                    {"role": "assistant", "text": "Earlier answer"},
                ]
            )
            try:
                with (
                    patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}),
                    patch(
                        "sentinel.chat_with_gemini",
                        return_value="A conversational response.",
                    ) as chat,
                    patch("builtins.input", return_value="yes"),
                    patch("sentinel.Sentinel._offer_save_report"),
                    patch("sys.stdout", new_callable=io.StringIO),
                ):
                    self.assertTrue(
                        terminal.answer("What is a SYN scan?")
                    )
                chat.assert_called_once()
                self.assertEqual(chat.call_args.args[0], "What is a SYN scan?")
                self.assertIn(
                    {"role": "user", "text": "Earlier question"},
                    chat.call_args.kwargs["history"],
                )
                self.assertIn("A conversational response.", terminal.latest_report)
                self.assertEqual(len(terminal.chat_history), 4)
            finally:
                if terminal.store:
                    terminal.store.engine.dispose()

    def test_conversational_llm_is_not_called_without_turn_consent(self):
        with tempfile.TemporaryDirectory() as directory:
            terminal = Sentinel(
                str(Path(directory, "alerts.jsonl")),
                str(Path(directory, "alerts.db")),
            )
            try:
                with (
                    patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}),
                    patch("sentinel.chat_with_gemini") as chat,
                    patch("builtins.input", return_value="no"),
                    patch("sys.stdout", new_callable=io.StringIO) as stdout,
                ):
                    self.assertTrue(terminal.answer("How does the TCP handshake work?"))
                chat.assert_not_called()
                self.assertFalse(terminal.chat_history)
                self.assertIn("cancelled; nothing was sent", stdout.getvalue())
            finally:
                if terminal.store:
                    terminal.store.engine.dispose()

    def test_menu_shows_numbered_actions_without_feature_or_report_panels(self):
        with tempfile.TemporaryDirectory() as directory:
            terminal = Sentinel(
                str(Path(directory, "alerts.jsonl")),
                str(Path(directory, "alerts.db")),
            )
            terminal.latest_report = "Example saved-safe report"
            output = io.StringIO()
            try:
                with patch("sys.stdout", output):
                    self.assertTrue(terminal.answer("menu"))
                rendered = output.getvalue()
                self.assertIn("SENTINEL OPTIONS", rendered)
                self.assertIn("1  Status", rendered)
                self.assertIn("2  Recent alerts", rendered)
                self.assertIn("3  Explain latest alert", rendered)
                self.assertIn("4  Search Google", rendered)
                self.assertIn("7  Analyze a log file", rendered)
                self.assertIn("8  Collect evidence files", rendered)
                self.assertIn("9  Hash a file", rendered)
                self.assertIn("10  Generate a password", rendered)
                self.assertIn("11  Check password composition", rendered)
                self.assertIn("12  Quit", rendered)
                self.assertNotIn("FEATURES", rendered)
                self.assertNotIn("LATEST REPORT", rendered)
                self.assertNotIn("Example saved-safe report", rendered)
            finally:
                if terminal.store:
                    terminal.store.engine.dispose()

    def test_numbered_menu_routes_report_help_explain_and_quit(self):
        with tempfile.TemporaryDirectory() as directory:
            terminal = Sentinel(
                str(Path(directory, "alerts.jsonl")),
                str(Path(directory, "alerts.db")),
            )
            try:
                with (
                    patch.object(terminal, "_show_report") as report,
                    patch.object(terminal, "_show_help") as help_menu,
                    patch.object(terminal, "_explain_latest") as explain,
                ):
                    self.assertTrue(terminal.answer("5"))
                    self.assertTrue(terminal.answer("6"))
                    self.assertTrue(terminal.answer("3"))
                    self.assertFalse(terminal.answer("12"))
                report.assert_called_once_with()
                help_menu.assert_called_once_with()
                explain.assert_called_once_with()
            finally:
                if terminal.store:
                    terminal.store.engine.dispose()

    def test_numbered_file_tools_prompt_for_path_and_use_existing_handlers(self):
        cases = (
            ("7", "logs_main", "sample.log", ["sample.log"]),
            ("8", "collect_main", "evidence", ["evidence"]),
            ("9", "hash_main", "capture.pcap", ["capture.pcap"]),
        )
        for choice, handler_name, value, expected_args in cases:
            with self.subTest(choice=choice), tempfile.TemporaryDirectory() as directory:
                terminal = Sentinel(
                    str(Path(directory, "alerts.jsonl")),
                    str(Path(directory, "alerts.db")),
                )
                try:
                    with (
                        patch(f"sentinel.{handler_name}") as handler,
                        patch("builtins.input", return_value=value),
                        patch.object(terminal, "_offer_save_report"),
                    ):
                        self.assertTrue(terminal.answer(choice))
                    handler.assert_called_once_with(expected_args)
                finally:
                    if terminal.store:
                        terminal.store.engine.dispose()

    def test_numbered_password_tools_route_to_existing_secure_handler(self):
        with tempfile.TemporaryDirectory() as directory:
            terminal = Sentinel(
                str(Path(directory, "alerts.jsonl")),
                str(Path(directory, "alerts.db")),
            )
            try:
                with (
                    patch("sentinel.password_main") as password_handler,
                    patch("builtins.input", return_value="32"),
                ):
                    self.assertTrue(terminal.answer("10"))
                    password_handler.assert_called_once_with(
                        ["generate", "--length", "32"]
                    )
                    password_handler.reset_mock()
                    self.assertTrue(terminal.answer("11"))
                    password_handler.assert_called_once_with(["check"])
            finally:
                if terminal.store:
                    terminal.store.engine.dispose()

    def test_numbered_google_option_prompts_for_question(self):
        with tempfile.TemporaryDirectory() as directory:
            terminal = Sentinel(
                str(Path(directory, "alerts.jsonl")),
                str(Path(directory, "alerts.db")),
            )
            try:
                with (
                    patch("builtins.input", return_value="Explain DNSSEC"),
                    patch.object(terminal, "_online_lookup") as online_lookup,
                ):
                    self.assertTrue(terminal.answer("4"))
                online_lookup.assert_called_once_with("Explain DNSSEC")
            finally:
                if terminal.store:
                    terminal.store.engine.dispose()

    def test_report_save_requires_yes_and_uses_create_only_file(self):
        with tempfile.TemporaryDirectory() as directory:
            terminal = Sentinel(
                str(Path(directory, "alerts.jsonl")),
                str(Path(directory, "alerts.db")),
            )
            try:
                terminal.latest_report = "Non-secret report text"
                with (
                    patch("sentinel.Path.home", return_value=Path(directory)),
                    patch("builtins.input", return_value="yes"),
                    patch("sys.stdout", new_callable=io.StringIO) as stdout,
                ):
                    terminal._offer_save_report()
                saved_reports = list((Path(directory) / ".sentinel" / "reports").glob("*.txt"))
                self.assertEqual(len(saved_reports), 1)
                self.assertEqual(
                    saved_reports[0].read_text(encoding="utf-8"),
                    "Non-secret report text\n",
                )
                self.assertIn("Report saved:", stdout.getvalue())
            finally:
                if terminal.store:
                    terminal.store.engine.dispose()

    def test_terminal_command_starts_and_stops_monitor_automatically(self):
        from unittest.mock import Mock
        import threading

        process = Mock()
        process.poll.return_value = None
        process.stdout = io.StringIO()
        terminal = Mock()
        terminal.stop = threading.Event()
        startup_events = []

        def launch_monitor(*args, **kwargs):
            startup_events.append("monitor")
            return process

        def show_loading(*args, **kwargs):
            startup_events.append("loading")

        with (
            patch("sentinel.subprocess.Popen", side_effect=launch_monitor) as launch,
            patch("sentinel.Sentinel", return_value=terminal),
            patch("sentinel.banner"),
            patch("sentinel.scan_animation"),
            patch("sentinel.loading", side_effect=show_loading),
            patch("builtins.input", side_effect=EOFError),
            patch.object(sys, "argv", ["sentinel", "--source", "ufw"]),
        ):
            sentinel_main()

        command = launch.call_args.args[0]
        self.assertEqual(
            command[:5], [sys.executable, "-u", "-m", "sentinel", "monitor"]
        )
        self.assertIn("--source", command)
        self.assertEqual(startup_events[-1], "monitor")
        self.assertGreater(startup_events.count("loading"), 0)
        process.terminate.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=5)

    def test_monitor_startup_failure_is_not_reported_as_online(self):
        from unittest.mock import Mock
        import threading

        process = Mock()
        process.poll.return_value = 1
        process.stdout = io.StringIO("Sentinel ingestion failed: missing log\n")
        terminal = Mock()
        terminal.stop = threading.Event()
        with (
            patch("sentinel._monitor_source", return_value="suricata"),
            patch("sentinel._prepare_linux_ufw", return_value=True),
            patch("sentinel.subprocess.Popen", return_value=process),
            patch("sentinel.Sentinel", return_value=terminal),
            patch("sentinel.banner"),
            patch("sentinel.scan_animation"),
            patch("sentinel.loading"),
            patch("builtins.input", side_effect=EOFError),
            patch("sys.stdout", new_callable=io.StringIO) as stdout,
            patch.object(sys, "argv", ["sentinel"]),
        ):
            sentinel_main()
        self.assertIn("exited during startup", stdout.getvalue())
        self.assertIn("console remains available", stdout.getvalue())
        self.assertNotIn("Sentinel is online", stdout.getvalue())

    def test_no_monitor_option_skips_background_monitor(self):
        from unittest.mock import Mock
        import threading

        terminal = Mock()
        terminal.stop = threading.Event()
        with (
            patch("sentinel.subprocess.Popen") as launch,
            patch("sentinel.Sentinel", return_value=terminal),
            patch("sentinel.banner"),
            patch("sentinel.scan_animation"),
            patch("sentinel.loading"),
            patch("builtins.input", side_effect=EOFError),
            patch.object(sys, "argv", ["sentinel", "--no-monitor"]),
        ):
            sentinel_main()

        launch.assert_not_called()

    def test_cli_help_is_a_colored_ready_command_reference(self):
        with (
            patch("sys.stdout", new_callable=io.StringIO) as stdout,
            patch.object(sys, "argv", ["sentinel", "--help"]),
            patch("sentinel.subprocess.Popen") as launch,
        ):
            self.assertEqual(sentinel_main(), 0)
        self.assertIn("SENTINEL SECURITY MONITOR", stdout.getvalue())
        self.assertIn("sentinel monitor --help", stdout.getvalue())
        self.assertIn("does not enable the firewall", stdout.getvalue())
        launch.assert_not_called()

    def test_no_animation_option_disables_startup_progress_effects(self):
        import threading
        from unittest.mock import Mock

        terminal = Mock()
        terminal.stop = threading.Event()
        with (
            patch("sentinel.subprocess.Popen") as launch,
            patch("sentinel.Sentinel", return_value=terminal),
            patch("sentinel.banner"),
            patch("sentinel.scan_animation") as animation,
            patch("sentinel.loading") as loading,
            patch("builtins.input", side_effect=EOFError),
            patch.object(sys, "argv", ["sentinel", "--no-monitor", "--no-animation"]),
        ):
            sentinel_main()

        launch.assert_not_called()
        animation.assert_called_once_with(enabled=False)
        self.assertTrue(loading.called)
        self.assertTrue(all(call.kwargs["enabled"] is False for call in loading.call_args_list))

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
        self.assertIn("MEDIUM SEVERITY", rendered)
        self.assertIn("incident-2", rendered)
        self.assertIn("Automatic response: OFF", rendered)

    def test_detector_initializes_telemetry_store_without_name_error(self):
        from unittest.mock import Mock

        store = Mock()
        store.path = "events.db"
        baseline = Mock()
        with (
            patch("detection.TelemetryStore", return_value=store) as create_store,
            patch("detection.Baseline", return_value=baseline),
            patch("detection.ScanDetector"),
            patch("detection.ingestion.follow_source", side_effect=KeyboardInterrupt),
            patch("sys.stdout", new_callable=io.StringIO),
        ):
            detection.detector_main(
                ["--source", "suricata", "--database-file", "events.db"]
            )
        create_store.assert_called_once_with("events.db")
        store.update_health.assert_any_call("suricata", "starting")
        store.update_health.assert_any_call("suricata", "stopped")
        baseline.save.assert_called_once_with()

    def test_monitor_source_defaults_to_ufw_only_on_linux(self):
        with patch("sentinel.sys.platform", "linux"):
            self.assertEqual(_monitor_source([]), "ufw")
            self.assertEqual(_monitor_source(["--source", "suricata"]), "suricata")
            self.assertEqual(_monitor_source(["--source=zeek"]), "zeek")

    def test_ufw_setup_decline_never_runs_system_commands(self):
        from unittest.mock import Mock

        with (
            patch("sentinel.sys.platform", "linux"),
            patch("sentinel.sys.stdin.isatty", return_value=True),
            patch("sentinel.shutil.which", side_effect=lambda name: {
                "ufw": None,
                "apt-get": "/usr/bin/apt-get",
            }.get(name)),
        ):
            run = Mock()
            self.assertFalse(_prepare_linux_ufw("ufw", input_fn=lambda _: "n", run=run))
        run.assert_not_called()

    def test_ufw_install_and_logging_each_require_consent(self):
        from types import SimpleNamespace

        which_results = {
            "ufw": iter((None, "/usr/sbin/ufw")),
            "apt-get": iter(("/usr/bin/apt-get",)),
        }
        commands = []

        def which(name):
            result = which_results.get(name)
            return next(result) if result else None

        def run(command, **kwargs):
            commands.append(command)
            if command[-2:] == ["status", "verbose"]:
                return SimpleNamespace(
                    returncode=0,
                    stdout="Logging: off",
                    stderr="",
                )
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with (
            patch("sentinel.sys.platform", "linux"),
            patch("sentinel.sys.stdin.isatty", return_value=True),
            patch("sentinel.shutil.which", side_effect=which),
            patch("sentinel.Path.exists", return_value=True),
        ):
            answers = iter(("yes", "yes"))
            self.assertTrue(
                _prepare_linux_ufw("ufw", input_fn=lambda _: next(answers), run=run)
            )
        self.assertEqual(
            commands,
            [
                ["sudo", "apt-get", "install", "-y", "ufw"],
                ["/usr/sbin/ufw", "status", "verbose"],
                ["sudo", "/usr/sbin/ufw", "logging", "on"],
            ],
        )

    def test_ufw_enabled_without_any_log_file_stays_in_console_mode(self):
        from unittest.mock import Mock
        from types import SimpleNamespace

        run = Mock(
            return_value=SimpleNamespace(
                returncode=0,
                stdout="Logging: on",
                stderr="",
            )
        )
        with (
            patch("sentinel.sys.platform", "linux"),
            patch("sentinel.sys.stdin.isatty", return_value=True),
            patch("sentinel.shutil.which", side_effect=lambda name: {
                "ufw": "/usr/sbin/ufw",
            }.get(name)),
            patch("sentinel.default_log_file", return_value="/var/log/ufw.log"),
            patch("sentinel.Path.exists", return_value=False),
            patch("sys.stderr", new_callable=io.StringIO) as stderr,
        ):
            self.assertFalse(_prepare_linux_ufw("ufw", run=run))
        run.assert_called_once()
        self.assertIn("no log file is available", stderr.getvalue())

    def test_google_search_grounding_parses_answer_and_https_citations(self):
        response = unittest.mock.Mock()
        response.json.return_value = {
            "steps": [
                {
                    "type": "model_output",
                    "content": [
                        {
                            "type": "text",
                            "text": "Grounded answer.",
                            "annotations": [
                                {
                                    "type": "url_citation",
                                    "title": "Official source",
                                    "url": "https://example.org/docs",
                                },
                                {
                                    "type": "url_citation",
                                    "title": "Unsafe source",
                                    "url": "http://example.org/",
                                },
                            ],
                        }
                    ],
                }
            ]
        }
        credentials = unittest.mock.Mock(token="oauth-access-token")
        with (
            patch.dict("os.environ", {}, clear=True),
            patch(
                "analyst._google_oauth_credentials",
                return_value=(credentials, "sentinel-test-project"),
            ),
            patch("analyst.requests.post", return_value=response) as post,
        ):
            result = analyst.web_research("How does feature X work?")
        self.assertEqual(result["answer"], "Grounded answer.")
        self.assertEqual(
            result["sources"],
            [{"title": "Official source", "url": "https://example.org/docs"}],
        )
        post.assert_called_once()
        self.assertEqual(
            post.call_args.kwargs["json"]["tools"],
            [{"type": "google_search"}],
        )
        self.assertEqual(
            post.call_args.kwargs["headers"],
            {
                "Authorization": "Bearer oauth-access-token",
                "x-goog-user-project": "sentinel-test-project",
            },
        )

    def test_google_search_grounding_uses_browser_oauth_flow(self):
        flow = unittest.mock.Mock()
        credentials = unittest.mock.Mock(token="oauth-access-token")
        flow.run_local_server.return_value = credentials
        with patch(
            "google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file",
            return_value=flow,
        ) as create_flow:
            self.assertIs(
                analyst._start_google_oauth_flow(Path("client.json")),
                credentials,
            )
        create_flow.assert_called_once_with(
            "client.json", analyst.GOOGLE_OAUTH_SCOPES
        )
        flow.run_local_server.assert_called_once_with(port=0, open_browser=True)

    def test_google_oauth_credentials_cache_browser_login_for_later_searches(self):
        class Credentials:
            valid = True
            refresh_token = "refresh-token"
            token = "access-token"

            def to_json(self):
                return '{"refresh_token":"refresh-token"}'

        with tempfile.TemporaryDirectory() as directory:
            client_path = Path(directory, "client.json")
            token_path = Path(directory, "oauth", "token.json")
            client_path.write_text(
                json.dumps(
                    {
                        "project_id": "sentinel-test-project",
                        "installed": {
                            "client_id": "desktop-client",
                            "client_secret": "not-a-real-secret",
                        },
                    }
                ),
                encoding="utf-8",
            )
            with (
                patch.dict(
                    "os.environ",
                    {
                        "GEMINI_OAUTH_CLIENT_FILE": str(client_path),
                        "GEMINI_OAUTH_TOKEN_FILE": str(token_path),
                    },
                ),
                patch(
                    "analyst._start_google_oauth_flow",
                    return_value=Credentials(),
                ) as start_flow,
            ):
                credentials, project_id = analyst._google_oauth_credentials()

            start_flow.assert_called_once_with(client_path)
            self.assertEqual(credentials.token, "access-token")
            self.assertEqual(project_id, "sentinel-test-project")
            self.assertTrue(token_path.is_file())
            self.assertEqual(
                json.loads(token_path.read_text(encoding="utf-8")),
                {"refresh_token": "refresh-token"},
            )
            if sys.platform != "win32":
                self.assertEqual(token_path.stat().st_mode & 0o777, 0o600)

    def test_google_search_grounding_requires_oauth_before_request(self):
        with (
            patch.dict("os.environ", {}, clear=True),
            patch(
                "analyst._google_oauth_credentials",
                side_effect=RuntimeError("Google OAuth client file is missing"),
            ),
            patch("analyst.requests.post") as post,
        ):
            with self.assertRaisesRegex(RuntimeError, "OAuth client file"):
                analyst.web_research("test")
        post.assert_not_called()

    def test_gemini_chat_prompt_includes_only_bounded_history_and_guidance(self):
        with patch("analyst._generate", return_value="Hello!") as generate:
            answer = analyst.chat(
                "Follow-up",
                context="[guide]\nSafe guidance",
                history=[
                    {"role": "user", "text": "First question"},
                    {"role": "assistant", "text": "First reply"},
                    {"role": "system", "text": "must be ignored"},
                ],
            )
        prompt = generate.call_args.args[0]
        self.assertEqual(answer, "Hello!")
        self.assertIn("First question", prompt)
        self.assertIn("First reply", prompt)
        self.assertIn("Safe guidance", prompt)
        self.assertIn("Follow-up", prompt)
        self.assertNotIn("must be ignored", prompt)

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
