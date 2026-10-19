import base64
import hashlib
import json
import os
import re
import selectors
import sqlite3
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from datetime import datetime, timezone
from types import SimpleNamespace

# --- event_schema.py ---
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

# --- ufw_adapter.py ---
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

# --- windows_firewall_adapter.py ---
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

# --- sysmon_adapter.py ---
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

# --- macos_adapter.py ---
IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
ENDPOINT_PATTERN = re.compile(
    rf"(?P<src>{IPV4}|[0-9a-fA-F:]+)[: ](?P<src_port>\d+)\s*(?:->|to)\s*"
    rf"(?P<dst>{IPV4}|[0-9a-fA-F:]+)[: ](?P<dst_port>\d+)",
    re.IGNORECASE,
)
MACOS_FIELD_PATTERN = re.compile(
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
    match = MACOS_FIELD_PATTERN.search(message) or ENDPOINT_PATTERN.search(message)
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

# --- suricata_adapter.py ---
def parse_suricata_line(line):
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

# --- zeek_adapter.py ---
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

# --- ingestion.py ---
SOURCES = (
    "auto",
    "ufw",
    "windows-firewall",
    "windows-native",
    "macos-unified",
    "suricata",
    "zeek",
)


def resolve_source(source):
    if source != "auto":
        return source
    if sys.platform == "win32":
        return "windows-native"
    if sys.platform == "darwin":
        return "macos-unified"
    return "ufw"


def default_log_file(source):
    if source == "ufw":
        return "/var/log/ufw.log"
    if source == "windows-firewall":
        root = os.environ.get("SystemRoot", r"C:\Windows")
        return os.path.join(root, "System32", "LogFiles", "Firewall", "pfirewall.log")
    if source == "suricata":
        return "/var/log/suricata/eve.json"
    if source == "zeek":
        return "/usr/local/zeek/logs/current/conn.log"
    return None


def _line_parser(source):
    if source == "ufw":
        return ufw_adapter.parse_line
    if source == "windows-firewall":
        adapter = windows_firewall_adapter.WindowsFirewallAdapter()
        return adapter.parse_line
    if source == "suricata":
        return suricata_adapter.parse_line
    if source == "zeek":
        adapter = zeek_adapter.ZeekAdapter()
        return adapter.parse_line
    if source == "macos-unified":
        return macos_adapter.parse_log_entry
    raise ValueError(f"Source does not use a line-based log file: {source}")


def _prime_parser(logfile, parser, source):
    if source == "zeek":
        for line in logfile:
            if line.startswith("#separator ") or line.startswith("#fields"):
                parser(line)
            if line.startswith("#fields"):
                return
    elif source == "windows-firewall":
        for line in logfile:
            if line.startswith("#Fields:"):
                parser(line)
                return


def follow_file(path, source, baseline, alert_file, process_event):
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Log file not found: {path}. Select a supported source with --source "
            "or provide its path with --log-file."
        )
    print(f"Following {source} events from {path}.", flush=True)
    parser = _line_parser(source)
    malformed = 0
    last_warning = 0.0

    def consume(line, current_parser):
        nonlocal malformed, last_warning
        try:
            event = current_parser(line)
        except (ValueError, TypeError, json.JSONDecodeError, ET.ParseError, UnicodeError) as error:
            malformed += 1
            now = time.monotonic()
            if now - last_warning >= 30:
                print(
                    f"Skipped malformed {source} record "
                    f"({type(error).__name__}); malformed_count={malformed}.",
                    flush=True,
                )
                last_warning = now
            return
        if event is not None:
            process_event(event)

    logfile = _open_following_file(path)
    _prime_parser(logfile, parser, source)
    logfile.seek(0, 2)
    identity = _file_identity(os.fstat(logfile.fileno()))
    try:
        while True:
            try:
                current_stat = os.stat(path)
            except FileNotFoundError:
                current_stat = None
            if current_stat is not None:
                current_identity = _file_identity(current_stat)
                if current_identity != identity:
                    for line in logfile:
                        consume(line, parser)
                    logfile.close()
                    logfile = _open_following_file(path)
                    parser = _line_parser(source)
                    _prime_parser(logfile, parser, source)
                    logfile.seek(0)
                    identity = _file_identity(os.fstat(logfile.fileno()))
                elif current_stat.st_size < logfile.tell():
                    logfile.seek(0)
                    parser = _line_parser(source)
                    _prime_parser(logfile, parser, source)
                    identity = current_identity
            line = logfile.readline()
            if not line:
                baseline.save()
                time.sleep(0.5)
                continue
            consume(line, parser)
    finally:
        logfile.close()


def _file_identity(file_stat):
    return file_stat.st_dev, file_stat.st_ino


def _open_following_file(path):
    if os.name != "nt":
        return open(path, "r", encoding="utf-8", errors="replace")

    import ctypes
    import msvcrt

    create_file = ctypes.windll.kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    create_file.restype = ctypes.c_void_p
    handle = create_file(
        path,
        0x80000000,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x00000080,
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY)
    return os.fdopen(descriptor, "r", encoding="utf-8", errors="replace")


def follow_macos_unified(baseline, alert_file, process_event):
    predicate = (
        'process == "socketfilterfw" OR subsystem == "com.apple.alf" '
        'OR subsystem == "com.apple.network"'
    )
    command = ["log", "stream", "--style", "json", "--predicate", predicate]
    print("Following macOS unified firewall and network logs.", flush=True)
    with subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    ) as process:
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        decoder = macos_adapter.JsonLogDecoder()
        last_saved = time.monotonic()
        while process.poll() is None:
            for _key, _mask in selector.select(timeout=1):
                chunk = process.stdout.readline()
                if not chunk:
                    break
                for entry in decoder.feed(chunk):
                    event = macos_adapter.parse_log_entry(entry)
                    if event is not None:
                        process_event(event)
            if time.monotonic() - last_saved >= 5:
                baseline.save()
                last_saved = time.monotonic()
        selector.close()
        return_code = process.wait()
    if return_code:
        raise RuntimeError(f"macOS unified-log stream exited with status {return_code}.")


_WINDOWS_POLL_SCRIPT = r"""
$channels = @(
    @{ Key = 'security'; Name = 'Security'; Ids = 'EventID=5156 or EventID=5157'; Optional = $false },
    @{ Key = 'sysmon'; Name = 'Microsoft-Windows-Sysmon/Operational'; Ids = 'EventID=3'; Optional = $true }
)
$records = @{}
$available = @{}
foreach ($channel in $channels) {
    try {
        $null = Get-WinEvent -ListLog $channel.Name -ErrorAction Stop
        $available[$channel.Key] = $true
        try {
            $latest = Get-WinEvent -LogName $channel.Name -MaxEvents 1 -ErrorAction Stop
            $records[$channel.Key] = [long]$latest.RecordId
        } catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
                $records[$channel.Key] = 0
            } else {
                throw
            }
        }
        [Console]::WriteLine("WATERMARK|{0}|{1}", $channel.Key, $records[$channel.Key])
    } catch {
        if (-not $channel.Optional) {
            [Console]::Error.WriteLine("Cannot read Windows Security events: {0}", $_.Exception.Message)
            exit 2
        }
        $available[$channel.Key] = $false
        $records[$channel.Key] = 0
        [Console]::Error.WriteLine("Sysmon event channel unavailable; continuing with WFP events.")
        [Console]::WriteLine("WATERMARK|{0}|0", $channel.Key)
    }
}
[Console]::Out.Flush()
while ($true) {
    foreach ($channel in $channels) {
        if (-not $available[$channel.Key]) { continue }
        $xpath = "*[System[({0}) and EventRecordID > {1}]]" -f $channel.Ids, $records[$channel.Key]
        try {
            $found = @(Get-WinEvent -LogName $channel.Name -FilterXPath $xpath -ErrorAction Stop |
                Sort-Object RecordId | Select-Object -First 200)
            foreach ($item in $found) {
                $records[$channel.Key] = [long]$item.RecordId
                $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($item.ToXml()))
                [Console]::WriteLine("EVENT|{0}|{1}|{2}", $channel.Key, $item.RecordId, $encoded)
            }
        } catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
                continue
            } elseif (-not $channel.Optional) {
                [Console]::Error.WriteLine("Windows Security event polling failed: {0}", $_.Exception.Message)
                exit 3
            } else {
                [Console]::Error.WriteLine("Sysmon event polling failed; continuing with WFP events: {0}", $_.Exception.Message)
                $available[$channel.Key] = $false
            }
        }
    }
    [Console]::Out.Flush()
    Start-Sleep -Seconds 1
}
"""


def follow_windows_native(baseline, alert_file, process_event):
    if os.name != "nt":
        raise RuntimeError("The windows-native source is available only on Windows.")
    command = [
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        _WINDOWS_POLL_SCRIPT,
    ]
    print(
        "Following Windows Filtering Platform Security events and Sysmon network "
        "events. Security log access and WFP auditing must be enabled.",
        flush=True,
    )
    with subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    ) as process:
        for line in process.stdout:
            parts = line.rstrip("\r\n").split("|")
            if len(parts) != 4 or parts[0] != "EVENT":
                continue
            xml_text = base64.b64decode(parts[3]).decode("utf-8")
            event = (
                parse_event_xml(xml_text)
                if parts[1] == "sysmon"
                else windows_firewall_adapter.parse_wfp_event_xml(xml_text)
            )
            if event is not None:
                process_event(event)
        return_code = process.wait()
    if return_code:
        raise RuntimeError(f"Windows event polling exited with status {return_code}.")


def follow_source(source, path, baseline, alert_file, process_event):
    source = resolve_source(source)
    if source == "windows-native":
        follow_windows_native(baseline, alert_file, process_event)
    elif source == "macos-unified" and path is None:
        follow_macos_unified(baseline, alert_file, process_event)
    else:
        if source == "macos-unified":
            raise ValueError("The macos-unified source is a native stream; omit --log-file.")
        if path is None:
            path = default_log_file(source)
        if path is None:
            raise ValueError(f"No default log file is configured for source: {source}")
        follow_file(path, source, baseline, alert_file, process_event)

# --- telemetry_store.py ---
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

# Adapter namespaces keep the source dispatch readable without separate files.
ufw_adapter = SimpleNamespace(parse_line=parse_line)
windows_firewall_adapter = SimpleNamespace(
    WindowsFirewallAdapter=WindowsFirewallAdapter,
    parse_wfp_event_xml=parse_wfp_event_xml,
    parse_windows_firewall_xml=parse_windows_firewall_xml,
)
sysmon_adapter = SimpleNamespace(parse_event_xml=parse_event_xml)
macos_adapter = SimpleNamespace(
    JsonLogDecoder=JsonLogDecoder, parse_log_entry=parse_log_entry,
    iter_log_entries=iter_log_entries,
)
suricata_adapter = SimpleNamespace(parse_line=parse_suricata_line)
zeek_adapter = SimpleNamespace(ZeekAdapter=ZeekAdapter)
