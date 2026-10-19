"""Normalize Windows Firewall W3C and Windows Filtering Platform event XML."""

import xml.etree.ElementTree as ET

from event_schema import normalize_event


class WindowsFirewallAdapter:
    def __init__(self):
        self.fields = []

    def parse_line(self, line):
        line = line.strip()
        if not line:
            return None
        if line.startswith("#Fields:"):
            self.fields = line.split()[1:]
            return None
        if line.startswith("#") or not self.fields:
            return None

        values = line.split()
        if len(values) != len(self.fields):
            return None
        record = dict(zip(self.fields, values))
        source = record.get("src-ip") or record.get("source-address")
        destination = record.get("dst-ip") or record.get("destination-address")
        port = record.get("dst-port") or record.get("destination-port")
        if not source or not destination or not port or port == "-":
            return None
        timestamp = None
        if record.get("date") and record.get("time"):
            timestamp = f"{record['date']}T{record['time']}Z"
        return normalize_event(
            source,
            destination,
            port,
            protocol=record.get("protocol"),
            action=record.get("action"),
            event="firewall_connection",
            timestamp=timestamp,
            platform="windows",
            sensor="windows_firewall",
            raw=record,
        )


def parse_wfp_event_xml(xml_text):
    root = ET.fromstring(xml_text)
    values = {}
    for item in root.findall(".//{*}EventData/{*}Data"):
        name = item.attrib.get("Name")
        if name:
            values[name] = item.text or ""
    event_id = root.findtext(".//{*}System/{*}EventID") or "unknown"
    source = values.get("SourceAddress") or values.get("SourceIp")
    destination = values.get("DestAddress") or values.get("DestinationAddress")
    port = values.get("DestPort") or values.get("DestinationPort")
    time_created = root.find(".//{*}System/{*}TimeCreated")
    action = "blocked" if event_id in {"5152", "5157"} else "allowed"
    event = normalize_event(
        source,
        destination,
        port,
        protocol=values.get("Protocol"),
        action=action,
        event=f"windows_wfp_event_{event_id}",
        timestamp=time_created.attrib.get("SystemTime") if time_created is not None else None,
        platform="windows",
        sensor="windows_filtering_platform",
        event_id=root.findtext(".//{*}System/{*}EventRecordID"),
        raw=values,
    )
    if event is not None:
        event["event_id"] = event_id
        event["application"] = values.get("Application")
        event["direction"] = values.get("Direction")
    return event


def parse_windows_firewall_xml(xml_text):
    """Accept WFP XML or XML-serialized Windows Firewall event records."""
    return parse_wfp_event_xml(xml_text)
