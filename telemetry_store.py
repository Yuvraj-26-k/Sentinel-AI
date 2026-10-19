"""Durable SQLite event and incident store for Sentinel."""

import hashlib
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone


class TelemetryStore:
    def __init__(self, path):
        self.path = os.path.abspath(os.path.expanduser(path))
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS telemetry_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    deduplication_key TEXT NOT NULL UNIQUE,
                    event_timestamp TEXT NOT NULL,
                    ingestion_timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    destination_port INTEGER,
                    protocol TEXT,
                    original_source TEXT,
                    source_event_id TEXT,
                    rule_version TEXT,
                    model_version TEXT,
                    severity TEXT,
                    incident_id TEXT,
                    event_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS telemetry_events_time_idx
                    ON telemetry_events(event_timestamp);
                CREATE INDEX IF NOT EXISTS telemetry_events_source_idx
                    ON telemetry_events(source_ip, event_timestamp);
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    deduplication_key TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    event_count INTEGER NOT NULL DEFAULT 0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    evidence_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS incidents_updated_idx
                    ON incidents(last_seen);
                CREATE TABLE IF NOT EXISTS ingestion_health (
                    source TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    last_event_at TEXT,
                    last_error TEXT,
                    updated_at TEXT NOT NULL
                );
                """
            )

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _encode(value):
        return json.dumps(value, sort_keys=True, default=str)

    def has_event(self, deduplication_key):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM telemetry_events WHERE deduplication_key = ?",
                (deduplication_key,),
            ).fetchone()
            return row is not None

    def record(self, event, detection=None, merge_seconds=900):
        ingestion_timestamp = event.get("ingestion_timestamp") or datetime.now(
            timezone.utc
        ).isoformat(timespec="seconds")
        event_timestamp = (
            event.get("effective_event_timestamp")
            or event.get("timestamp")
            or ingestion_timestamp
        )
        deduplication_key = event.get("deduplication_key")
        if not deduplication_key:
            identity = {
                key: event.get(key)
                for key in (
                    "source",
                    "destination",
                    "destination_port",
                    "protocol",
                    "event",
                    "event_id",
                    "timestamp",
                    "raw",
                )
            }
            deduplication_key = hashlib.sha256(self._encode(identity).encode()).hexdigest()

        incident = None
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM telemetry_events WHERE deduplication_key = ?",
                (deduplication_key,),
            ).fetchone():
                return {"duplicate": True, "incident": None}

            if detection:
                incident_key = detection["deduplication_key"]
                previous = connection.execute(
                    """
                    SELECT * FROM incidents
                    WHERE deduplication_key = ? AND status = 'open'
                    ORDER BY last_seen DESC LIMIT 1
                    """,
                    (incident_key,),
                ).fetchone()
                if previous and abs(
                    _seconds_between(event_timestamp, previous["last_seen"])
                ) <= merge_seconds:
                    incident_id = previous["incident_id"]
                    evidence = json.loads(previous["evidence_json"])
                    _merge_evidence(evidence, detection["evidence"])
                    connection.execute(
                        """
                        UPDATE incidents
                        SET event_count = event_count + 1, last_seen = ?,
                            severity = ?, confidence = ?, evidence_json = ?
                        WHERE incident_id = ?
                        """,
                        (
                            _later_timestamp(event_timestamp, previous["last_seen"]),
                            detection["severity"],
                            detection["confidence"],
                            self._encode(evidence),
                            incident_id,
                        ),
                    )
                else:
                    incident_id = str(uuid.uuid4())
                    evidence = detection["evidence"]
                    connection.execute(
                        """
                        INSERT INTO incidents (
                            incident_id, deduplication_key, classification,
                            source_ip, destination_ip, destination_port,
                            severity, confidence, status, event_count,
                            first_seen, last_seen, evidence_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', 1, ?, ?, ?)
                        """,
                        (
                            incident_id,
                            incident_key,
                            detection["classification"],
                            event.get("source", "unknown"),
                            detection.get("destination"),
                            detection.get("destination_port"),
                            detection["severity"],
                            detection["confidence"],
                            event_timestamp,
                            event_timestamp,
                            self._encode(evidence),
                        ),
                    )
                event["incident_id"] = incident_id
                incident = self._get_incident(connection, incident_id)

            connection.execute(
                """
                INSERT INTO telemetry_events (
                    deduplication_key, event_timestamp, ingestion_timestamp,
                    source_ip, destination_ip, destination_port, protocol,
                    original_source, source_event_id, rule_version, model_version,
                    severity, incident_id, event_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    deduplication_key,
                    event_timestamp,
                    ingestion_timestamp,
                    event.get("source", "unknown"),
                    event.get("destination", "unknown"),
                    event.get("destination_port"),
                    event.get("protocol"),
                    event.get("original_source") or event.get("sensor"),
                    event.get("event_id"),
                    event.get("rule_version")
                    or (detection.get("rule_version") if detection else "sentinel-rules-v2"),
                    event.get("model_version")
                    or (detection.get("model_version") if detection else None),
                    detection.get("severity") if detection else "info",
                    event.get("incident_id"),
                    self._encode(event),
                ),
            )
            event["telemetry_id"] = connection.execute(
                "SELECT id FROM telemetry_events WHERE deduplication_key = ?",
                (deduplication_key,),
            ).fetchone()["id"]
            connection.execute(
                "UPDATE telemetry_events SET event_json = ? WHERE deduplication_key = ?",
                (self._encode(event), deduplication_key),
            )
            return {"duplicate": False, "incident": dict(incident) if incident else None}

    @staticmethod
    def _get_incident(connection, incident_id):
        return connection.execute(
            "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()

    def recent_events(self, limit=500, since=None):
        limit = max(1, min(int(limit), 20000))
        query = "SELECT event_json FROM telemetry_events"
        parameters = []
        if since:
            query += " WHERE event_timestamp >= ?"
            parameters.append(since)
        query += " ORDER BY id DESC LIMIT ?"
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [json.loads(row["event_json"]) for row in reversed(rows)]

    def events_after(self, event_id=0, limit=100):
        limit = max(1, min(int(limit), 1000))
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, event_json FROM telemetry_events
                WHERE id > ? ORDER BY id LIMIT ?
                """,
                (max(0, int(event_id)), limit),
            ).fetchall()
        return [
            {"id": row["id"], "event": json.loads(row["event_json"])}
            for row in rows
        ]

    def list_incidents(self, limit=100, status=None):
        limit = max(1, min(int(limit), 1000))
        query = "SELECT * FROM incidents"
        parameters = []
        if status:
            query += " WHERE status = ?"
            parameters.append(status)
        query += " ORDER BY last_seen DESC LIMIT ?"
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [_incident_dict(row) for row in rows]

    def get_incident(self, incident_id):
        with self._connect() as connection:
            incident = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if not incident:
                return None
            event_rows = connection.execute(
                """
                SELECT event_json FROM telemetry_events
                WHERE incident_id = ? ORDER BY id LIMIT 1000
                """,
                (incident_id,),
            ).fetchall()
        result = _incident_dict(incident)
        result["timeline"] = [json.loads(row["event_json"]) for row in event_rows]
        return result

    def update_health(self, source, status, error=None):
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO ingestion_health (source, status, last_event_at, last_error, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET
                    status = excluded.status,
                    last_event_at = COALESCE(excluded.last_event_at, ingestion_health.last_event_at),
                    last_error = excluded.last_error,
                    updated_at = excluded.updated_at
                """,
                (source, status, now if status == "healthy" else None, error, now),
            )

    def health(self):
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT source, status, last_event_at, last_error, updated_at FROM ingestion_health"
            ).fetchall()
            event_count = connection.execute(
                "SELECT COUNT(*) AS count FROM telemetry_events"
            ).fetchone()["count"]
            incident_count = connection.execute(
                "SELECT COUNT(*) AS count FROM incidents WHERE status = 'open'"
            ).fetchone()["count"]
        return {
            "sources": [dict(row) for row in rows],
            "stored_events": event_count,
            "open_incidents": incident_count,
        }


def _merge_evidence(existing, new):
    for key, value in new.items():
        if isinstance(value, list):
            values = existing.setdefault(key, [])
            for item in value:
                if item not in values:
                    values.append(item)
        else:
            existing[key] = value


def _seconds_between(left, right):
    try:
        first = datetime.fromisoformat(left.replace("Z", "+00:00"))
        second = datetime.fromisoformat(right.replace("Z", "+00:00"))
        return (first - second).total_seconds()
    except (AttributeError, TypeError, ValueError):
        return 0.0


def _later_timestamp(left, right):
    first = _seconds_between(left, right)
    return left if first >= 0 else right


def _incident_dict(row):
    result = dict(row)
    result["evidence"] = json.loads(result.pop("evidence_json"))
    return result
