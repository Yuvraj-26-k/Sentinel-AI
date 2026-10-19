"""Tests for incident-aware persistence and terminal alert rendering."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from alert_store import AlertStore
from sentinel import Sentinel


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


if __name__ == "__main__":
    unittest.main()
