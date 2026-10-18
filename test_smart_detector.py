"""Regression tests for Sentinel's local detector event schema."""

import json
import tempfile
import unittest
from pathlib import Path

import smart_detector


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


if __name__ == "__main__":
    unittest.main()
