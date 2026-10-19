"""Select and run platform or file-based event ingestion adapters."""

import base64
import json
import os
import selectors
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

import macos_adapter
import suricata_adapter
import ufw_adapter
import windows_firewall_adapter
import zeek_adapter
from sysmon_adapter import parse_event_xml


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
