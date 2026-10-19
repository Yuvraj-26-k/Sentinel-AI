"""Normalize Suricata EVE JSON network events."""

import json

from event_schema import normalize_event


def parse_line(line):
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(record, dict):
        return None
    event_type = record.get("event_type")
    if event_type not in {"alert", "flow", "netflow", "http", "tls", "dns"}:
        return None
    source = record.get("src_ip")
    destination = record.get("dest_ip")
    if not source or not destination:
        return None
    alert = record.get("alert") or {}
    event = normalize_event(
        source,
        destination,
        record.get("dest_port"),
        protocol=record.get("proto"),
        action="alert" if event_type == "alert" else None,
        event=f"suricata_{event_type}",
        timestamp=record.get("timestamp"),
        platform="network",
        sensor="suricata",
        event_id=":".join(
            str(part)
            for part in (
                event_type,
                record.get("flow_id"),
                record.get("timestamp"),
                (record.get("alert") or {}).get("signature_id"),
                record.get("tx_id"),
            )
            if part is not None
        ),
        raw=record,
    )
    if event is not None and alert:
        event["signature"] = alert.get("signature")
        event["signature_id"] = alert.get("signature_id")
    if event is not None:
        tcp = record.get("tcp") or {}
        flags = tcp.get("tcp_flags") or tcp.get("flags")
        if isinstance(flags, str) and "S" in flags:
            event["tcp_flags"] = ["SYN"]
    return event
