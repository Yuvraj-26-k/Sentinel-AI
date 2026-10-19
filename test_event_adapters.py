"""Tests for normalizing supported native event formats."""

import io
import json
import tempfile
import unittest
from pathlib import Path

import ingestion
import macos_adapter
import smart_detector
import suricata_adapter
import ufw_adapter
import windows_firewall_adapter
import zeek_adapter
from sysmon_adapter import parse_event_xml


class EventAdapterTests(unittest.TestCase):
    def setUp(self):
        smart_detector.last_alert.clear()
        smart_detector.events.clear()

    def test_ufw_event_uses_common_schema(self):
        event = ufw_adapter.parse_line(
            "[UFW BLOCK] IN=eth0 SRC=192.0.2.1 DST=198.51.100.2 "
            "PROTO=TCP DPT=443"
        )
        self.assertEqual(event["schema_version"], 1)
        self.assertEqual(event["sensor"], "ufw")
        self.assertEqual(event["source"], "192.0.2.1")
        self.assertEqual(event["destination_port"], 443)
        self.assertEqual(event["action"], "block")

    def test_windows_firewall_w3c_header_and_record(self):
        adapter = windows_firewall_adapter.WindowsFirewallAdapter()
        ingestion._prime_parser(
            io.StringIO(
                "#Version: 1.5\n"
                "#Fields: date time action protocol src-ip dst-ip src-port dst-port\n"
            ),
            adapter.parse_line,
            "windows-firewall",
        )
        event = adapter.parse_line(
            "2026-10-19 08:00:00 DROP TCP 192.0.2.3 198.51.100.4 50123 22"
        )
        self.assertEqual(event["sensor"], "windows_firewall")
        self.assertEqual(event["source"], "192.0.2.3")
        self.assertEqual(event["destination_port"], 22)
        self.assertEqual(event["timestamp"], "2026-10-19T08:00:00Z")

    def test_windows_wfp_event_xml(self):
        xml = """<Event><System><EventID>5157</EventID>
        <TimeCreated SystemTime="2026-10-19T08:00:00.000Z" /></System><EventData>
        <Data Name="Application">app.exe</Data>
        <Data Name="SourceAddress">192.0.2.5</Data>
        <Data Name="DestAddress">198.51.100.6</Data>
        <Data Name="DestPort">443</Data><Data Name="Protocol">6</Data>
        </EventData></Event>"""
        event = windows_firewall_adapter.parse_wfp_event_xml(xml)
        self.assertEqual(event["sensor"], "windows_filtering_platform")
        self.assertEqual(event["action"], "blocked")
        self.assertEqual(event["destination_port"], 443)
        self.assertEqual(event["application"], "app.exe")
        self.assertEqual(event["timestamp"], "2026-10-19T08:00:00.000Z")

    def test_sysmon_network_event_xml(self):
        xml = """<Event><System><EventID>3</EventID>
        <TimeCreated SystemTime="2026-10-19T08:01:00.000Z" /></System><EventData>
        <Data Name="SourceIp">192.0.2.7</Data>
        <Data Name="DestinationIp">198.51.100.8</Data>
        <Data Name="DestinationPort">8080</Data>
        <Data Name="Protocol">tcp</Data></EventData></Event>"""
        event = parse_event_xml(xml)
        self.assertEqual(event["sensor"], "sysmon")
        self.assertEqual(event["event_id"], "3")
        self.assertEqual(event["destination_port"], 8080)
        self.assertEqual(event["timestamp"], "2026-10-19T08:01:00.000Z")

    def test_macos_unified_log_with_endpoint_message(self):
        event = macos_adapter.parse_log_entry(
            json.dumps(
                {
                    "timestamp": "2026-10-19T08:00:00Z",
                    "process": "socketfilterfw",
                    "eventMessage": "deny 192.0.2.9:50100 -> 198.51.100.10:443",
                }
            )
        )
        self.assertEqual(event["sensor"], "unified_log")
        self.assertEqual(event["source"], "192.0.2.9")
        self.assertEqual(event["destination_port"], 443)
        self.assertEqual(event["action"], "blocked")

    def test_macos_json_stream_handles_pretty_printed_records(self):
        entries = list(
            macos_adapter.iter_log_entries(
                io.StringIO(
                    '{\n  "eventMessage": "first"\n}\n'
                    '{\n  "eventMessage": "second"\n}\n'
                )
            )
        )
        self.assertEqual([entry["eventMessage"] for entry in entries], ["first", "second"])

    def test_suricata_eve_alert(self):
        event = suricata_adapter.parse_line(
            json.dumps(
                {
                    "timestamp": "2026-10-19T08:00:00Z",
                    "event_type": "alert",
                    "src_ip": "192.0.2.11",
                    "dest_ip": "198.51.100.12",
                    "dest_port": 443,
                    "proto": "TCP",
                    "alert": {"signature": "test signature", "signature_id": 42},
                }
            )
        )
        self.assertEqual(event["sensor"], "suricata")
        self.assertEqual(event["signature_id"], 42)
        self.assertEqual(event["destination_port"], 443)

    def test_zeek_connection_tsv(self):
        adapter = zeek_adapter.ZeekAdapter()
        ingestion._prime_parser(
            io.StringIO(
                "#separator \\x09\n"
                "#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\tconn_state\n"
            ),
            adapter.parse_line,
            "zeek",
        )
        event = adapter.parse_line(
            "1792396800.0\t192.0.2.13\t198.51.100.14\t53\tudp\tSF"
        )
        self.assertEqual(event["sensor"], "zeek")
        self.assertEqual(event["source"], "192.0.2.13")
        self.assertEqual(event["destination_port"], 53)
        self.assertEqual(event["action"], "SF")

    def test_normalized_events_feed_the_existing_detector(self):
        with tempfile.TemporaryDirectory() as directory:
            alert_file = Path(directory, "alerts.jsonl")
            baseline = smart_detector.Baseline(str(Path(directory, "baseline.json")))
            for port in range(1, smart_detector.PORT_THRESHOLD + 1):
                event = {
                    "source": "192.0.2.20",
                    "destination": "198.51.100.20",
                    "destination_port": port,
                    "sensor": "suricata",
                    "platform": "network",
                    "protocol": "TCP",
                    "action": None,
                    "event": "suricata_flow",
                    "timestamp": "2026-10-19T08:00:00Z",
                }
                smart_detector.process_event(event, baseline, str(alert_file))
            alert = json.loads(alert_file.read_text(encoding="utf-8"))
        self.assertEqual(alert["source_type"], "suricata")
        self.assertEqual(alert["destination_port"], smart_detector.PORT_THRESHOLD)
        self.assertEqual(alert["unique_ports"], smart_detector.PORT_THRESHOLD)
        self.assertEqual(alert["event_timestamp"], "2026-10-19T08:00:00Z")


if __name__ == "__main__":
    unittest.main()
