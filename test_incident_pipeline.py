"""Tests for configurable detection, incident aggregation, and telemetry recovery."""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import ingestion
from event_schema import normalize_event
from scan_detector import ScanDetector, ScanThresholds
from telemetry_store import TelemetryStore


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


if __name__ == "__main__":
    unittest.main()
