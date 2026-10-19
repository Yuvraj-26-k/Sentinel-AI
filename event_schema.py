"""Common event shape used by all Sentinel ingestion adapters."""

import hashlib
import json
from datetime import datetime, timezone


def normalize_event(
    source,
    destination,
    destination_port=None,
    *,
    protocol=None,
    action=None,
    event="network_connection",
    timestamp=None,
    platform="unknown",
    sensor="unknown",
    event_id=None,
    raw=None,
):
    try:
        port = int(destination_port) if destination_port not in (None, "", "-") else None
    except (TypeError, ValueError):
        return None
    if port is not None and not 0 <= port <= 65535:
        return None

    event_timestamp = timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds")
    if event_id is not None:
        identity = {"sensor": sensor, "event_id": event_id}
    else:
        identity = {
            "sensor": sensor,
            "source": source or "unknown",
            "destination": destination or "unknown",
            "destination_port": port,
            "protocol": protocol or None,
            "action": action or None,
            "event": event or "network_connection",
            "timestamp": event_timestamp if timestamp else None,
            "raw": raw,
        }
    deduplication_key = hashlib.sha256(
        json.dumps(identity, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": 1,
        "timestamp": event_timestamp,
        "ingestion_timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "platform": platform,
        "sensor": sensor,
        "original_source": sensor,
        "event_id": str(event_id) if event_id is not None else None,
        "deduplication_key": deduplication_key,
        "source": source or "unknown",
        "destination": destination or "unknown",
        "destination_port": port,
        "protocol": protocol or None,
        "action": action or None,
        "event": event or "network_connection",
        "raw": raw,
    }
