"""Normalize Zeek connection logs in TSV or JSON format."""

import json
from datetime import datetime, timezone

from event_schema import normalize_event


def _timestamp(value):
    try:
        return datetime.fromtimestamp(float(value), timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError, OSError):
        return value


class ZeekAdapter:
    def __init__(self):
        self.fields = []
        self.separator = "\t"

    def parse_line(self, line):
        line = line.rstrip("\r\n")
        if not line:
            return None
        if line.startswith("#separator "):
            value = line.split(" ", 1)[1]
            self.separator = value.encode("utf-8").decode("unicode_escape")
            return None
        if line.startswith("#fields"):
            self.fields = line.split(self.separator)[1:]
            return None
        if line.startswith("#"):
            return None
        if line.startswith("{"):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                return None
        else:
            if not self.fields:
                return None
            values = line.split(self.separator)
            if len(values) != len(self.fields):
                return None
            record = dict(zip(self.fields, values))

        source = record.get("id.orig_h") or record.get("src")
        destination = record.get("id.resp_h") or record.get("dst")
        port = record.get("id.resp_p") or record.get("dest_port")
        if not source or not destination or not port or port == "-":
            return None
        event = normalize_event(
            source,
            destination,
            port,
            protocol=record.get("proto"),
            action=record.get("conn_state"),
            event="zeek_connection",
            timestamp=_timestamp(record.get("ts")),
            platform="network",
            sensor="zeek",
            event_id=record.get("uid"),
            raw=record,
        )
        if event is not None:
            event["service"] = record.get("service")
            history = record.get("history")
            if isinstance(history, str) and "S" in history:
                event["tcp_flags"] = ["SYN"]
        return event
