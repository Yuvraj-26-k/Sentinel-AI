"""Tests for behavioral ML scoring and evidence-bound alert analysis."""

import json
import tempfile
import random
import unittest
from pathlib import Path

from evidence_validator import validate_analysis
from ml_model import FEATURE_NAMES, IsolationForestScorer, window_features
from rag_agent import SecurityAgent
from security_analyst import local_analysis, verified_ai_analysis
from smart_detector import Baseline


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
        import smart_detector

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


if __name__ == "__main__":
    unittest.main()
