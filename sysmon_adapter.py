"""Normalize Windows Sysmon XML events for Sentinel.

Sysmon installation and event collection are Windows-specific. This adapter
accepts exported Event XML so the core remains portable and testable.
"""

import xml.etree.ElementTree as ET


def parse_event_xml(xml_text):
    root = ET.fromstring(xml_text)
    values = {}
    for item in root.findall(".//{*}EventData/{*}Data"):
        name = item.attrib.get("Name")
        if name:
            values[name] = item.text or ""
    event_id = root.findtext(".//{*}System/{*}EventID") or "unknown"
    return {
        "source": values.get("SourceIp", values.get("SourceIpAddress", "unknown")),
        "destination": values.get("DestinationIp", values.get("DestinationIpAddress", "unknown")),
        "event": f"sysmon_event_{event_id}",
        "unique_ports": 1 if values.get("DestinationPort") else 0,
        "events": 1,
        "recommendation": "Correlate this Sysmon event with network telemetry before responding.",
        "sysmon": values,
    }
