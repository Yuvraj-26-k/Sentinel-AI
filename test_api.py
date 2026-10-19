"""Tests for the local Sentinel read-only API."""

import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException
from fastapi.routing import APIRoute

from api import create_app
from event_schema import normalize_event
from scan_detector import ScanDetector, ScanThresholds
from telemetry_store import TelemetryStore


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


if __name__ == "__main__":
    unittest.main()
