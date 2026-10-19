"""Normalize Windows Sysmon network events for Sentinel."""

import xml.etree.ElementTree as ET

from event_schema import normalize_event


def parse_event_xml(xml_text):
    root = ET.fromstring(xml_text)
    values = {}
    for item in root.findall(".//{*}EventData/{*}Data"):
        name = item.attrib.get("Name")
        if name:
            values[name] = item.text or ""
    event_id = root.findtext(".//{*}System/{*}EventID") or "unknown"
    time_created = root.find(".//{*}System/{*}TimeCreated")
    event = normalize_event(
        values.get("SourceIp") or values.get("SourceIpAddress"),
        values.get("DestinationIp") or values.get("DestinationIpAddress"),
        values.get("DestinationPort"),
        protocol=values.get("Protocol"),
        event=f"sysmon_event_{event_id}",
        timestamp=time_created.attrib.get("SystemTime") if time_created is not None else None,
        platform="windows",
        sensor="sysmon",
        event_id=root.findtext(".//{*}System/{*}EventRecordID"),
        raw=values,
    )
    if event is not None:
        event["event_id"] = event_id
        event["unique_ports"] = 1 if event["destination_port"] is not None else 0
        event["events"] = 1
        event["recommendation"] = (
            "Correlate this Sysmon event with network telemetry before responding."
        )
        event["sysmon"] = values
    return event
