"""Normalize Linux UFW/kernel firewall log entries."""

import re

from event_schema import normalize_event

FIELD_PATTERN = re.compile(r"\b(?P<key>SRC|DST|DPT|PROTO)=(?P<value>\S+)")
ACTION_PATTERN = re.compile(r"\[UFW (?P<action>BLOCK|ALLOW|REJECT)\]")
TCP_FLAGS_PATTERN = re.compile(r"\bSYN=(?P<syn>[01])\b", re.IGNORECASE)


def parse_line(line):
    fields = {match.group("key"): match.group("value") for match in FIELD_PATTERN.finditer(line)}
    if not all(name in fields for name in ("SRC", "DST", "DPT")):
        return None
    action = ACTION_PATTERN.search(line)
    event = normalize_event(
        fields["SRC"],
        fields["DST"],
        fields["DPT"],
        protocol=fields.get("PROTO"),
        action=action.group("action").lower() if action else None,
        event="firewall_connection",
        platform="linux",
        sensor="ufw",
        raw=line.rstrip("\r\n"),
    )
    flags = TCP_FLAGS_PATTERN.search(line)
    if event is not None and flags and flags.group("syn") == "1":
        event["tcp_flags"] = ["SYN"]
    return event
