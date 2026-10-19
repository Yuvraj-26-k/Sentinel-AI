"""Normalize macOS unified-log and application-firewall telemetry."""

import json
import re

from event_schema import normalize_event

IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
ENDPOINT_PATTERN = re.compile(
    rf"(?P<src>{IPV4}|[0-9a-fA-F:]+)[: ](?P<src_port>\d+)\s*(?:->|to)\s*"
    rf"(?P<dst>{IPV4}|[0-9a-fA-F:]+)[: ](?P<dst_port>\d+)",
    re.IGNORECASE,
)
FIELD_PATTERN = re.compile(
    rf"\b(?:src|source)=(?P<src>{IPV4}|[0-9a-fA-F:]+).*?"
    rf"\b(?:dst|destination)=(?P<dst>{IPV4}|[0-9a-fA-F:]+).*?"
    rf"\b(?:dport|destination_port|dst_port)=(?P<port>\d+)",
    re.IGNORECASE,
)


class JsonLogDecoder:
    def __init__(self):
        self.decoder = json.JSONDecoder()
        self.buffer = ""

    def feed(self, chunk):
        self.buffer += chunk
        records = []
        while self.buffer.strip():
            self.buffer = self.buffer.lstrip()
            try:
                record, end = self.decoder.raw_decode(self.buffer)
            except json.JSONDecodeError:
                break
            if isinstance(record, dict):
                records.append(record)
            elif isinstance(record, list):
                records.extend(item for item in record if isinstance(item, dict))
            self.buffer = self.buffer[end:]
        return records


def iter_log_entries(stream):
    decoder = JsonLogDecoder()
    for chunk in stream:
        yield from decoder.feed(chunk)


def parse_log_entry(entry):
    if isinstance(entry, str):
        try:
            entry = json.loads(entry)
        except json.JSONDecodeError:
            entry = {"eventMessage": entry}
    if not isinstance(entry, dict):
        return None

    message = str(entry.get("eventMessage") or entry.get("message") or "")
    source = entry.get("source_ip") or entry.get("src_ip") or entry.get("source")
    destination = (
        entry.get("destination_ip")
        or entry.get("dest_ip")
        or entry.get("destination")
    )
    port = (
        entry.get("destination_port")
        or entry.get("dest_port")
        or entry.get("dport")
    )
    match = FIELD_PATTERN.search(message) or ENDPOINT_PATTERN.search(message)
    if match:
        source = source or match.group("src")
        destination = destination or match.group("dst")
        port = port or match.groupdict().get("port") or match.groupdict().get("dst_port")
    if not source or not destination or not port:
        return None

    action = "blocked" if re.search(r"\b(deny|denied|block|blocked)\b", message, re.I) else None
    event = normalize_event(
        source,
        destination,
        port,
        protocol=entry.get("protocol"),
        action=action,
        event="macos_firewall_connection",
        timestamp=entry.get("timestamp"),
        platform="macos",
        sensor="unified_log",
        event_id=entry.get("event_id") or entry.get("eventID"),
        raw=entry,
    )
    if event is not None:
        event["process"] = entry.get("process")
        event["subsystem"] = entry.get("subsystem")
    return event
