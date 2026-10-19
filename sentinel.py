import argparse
import ipaddress
import json
import os
import re
import stat
import sys
import subprocess
import threading
import time
from collections import deque
from pathlib import Path
from analyst import (
    AlertStore,
    analyst_main,
    chat as chat_with_gemini,
    explain_alert as explain_with_gemini,
    format_analysis,
    local_analysis,
    verified_ai_analysis,
)
from detection import detector_main

EVIDENCE_EXTENSIONS = {".txt", ".log", ".pdf", ".docx", ".exe", ".bat", ".ps1"}
EMAIL_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
    r"(?![A-Za-z0-9-])"
)
IP_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9_.:])"
    r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
    r"(?![A-Za-z0-9_.:])"
    r"|(?<![A-Za-z0-9_.:])"
    r"(?:[0-9A-Fa-f]*:[0-9A-Fa-f:.]*[0-9A-Fa-f]|::)"
    r"(?![A-Za-z0-9_.:])"
)


def analyze_log_file(path):
    """Return a deterministic, file-level text analysis report."""
    path = Path(path).expanduser()
    try:
        with path.open("rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise OSError("not a regular file")
            raw = handle.read()
    except OSError as error:
        raise OSError(f"cannot read {path}: {error}") from error

    text = raw.decode("utf-8", errors="replace")
    emails = sorted(set(EMAIL_CANDIDATE_RE.findall(text)))
    addresses = set()
    for candidate in IP_CANDIDATE_RE.findall(text):
        try:
            addresses.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue
    addresses = sorted(addresses)

    lines = [
        f"Log analysis: {os.path.abspath(path)}",
        f"Bytes: {len(raw)}",
        f"Lines: {len(text.splitlines())}",
        f"Words: {len(text.split())}",
        f"Characters: {len(text)}",
        f"INFO substring occurrences (case-sensitive): {text.count('INFO')}",
        f"WARNING substring occurrences (case-sensitive): {text.count('WARNING')}",
        f"ERROR substring occurrences (case-sensitive): {text.count('ERROR')}",
        f"Unique email candidates: {len(emails)}",
    ]
    lines.extend(f"  {email}" for email in emails)
    lines.append(f"Unique validated IP addresses: {len(addresses)}")
    lines.extend(f"  {address}" for address in addresses)
    return "\n".join(lines)


def collect_evidence(directory):
    """Return a deterministic report and any directory-entry errors."""
    directory = Path(directory).expanduser()
    absolute_directory = Path(os.path.abspath(directory))
    records = []
    errors = []
    try:
        with os.scandir(directory) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                entry_path = Path(entry.path)
                if entry_path.suffix not in EVIDENCE_EXTENSIONS:
                    continue
                try:
                    absolute_path = Path(os.path.abspath(entry_path))
                    metadata = entry.stat(follow_symlinks=False)
                    if not stat.S_ISREG(metadata.st_mode):
                        continue
                    records.append(
                        (entry.name, entry_path.suffix, metadata.st_size, str(absolute_path))
                    )
                except OSError as error:
                    errors.append(
                        f"{absolute_path}: {type(error).__name__}: {error}"
                    )
    except OSError as error:
        errors.append(
            f"{absolute_directory}: {type(error).__name__}: {error}"
        )

    lines = [
        f"Evidence collection: {absolute_directory}",
        f"Matching files: {len(records)}",
        f"Errors: {len(errors)}",
    ]
    extension_counts = {}
    for _, extension, _, _ in records:
        extension_counts[extension] = extension_counts.get(extension, 0) + 1
    if extension_counts:
        lines.append(
            "Extensions: "
            + ", ".join(
                f"{extension}={extension_counts[extension]}"
                for extension in sorted(extension_counts)
            )
        )
    if records:
        lines.append("Files:")
        lines.extend(
            f"- {name} | {extension} | {size} bytes | {absolute_path}"
            for name, extension, size, absolute_path in records
        )
    else:
        lines.append("No matching files.")
    if errors:
        lines.append("Collection errors:")
        lines.extend(f"- {error}" for error in errors)
    return "\n".join(lines), errors


def _resolved_path(path):
    try:
        return Path(path).expanduser().resolve()
    except (OSError, RuntimeError) as error:
        raise OSError(f"cannot resolve path {path}: {error}") from error


def _write_report(report, output_path, protected_paths=()):
    output = Path(output_path).expanduser()
    try:
        resolved_output = _resolved_path(output)
        resolved_protected = [_resolved_path(path) for path in protected_paths]
    except OSError as error:
        return str(error)
    if resolved_output in resolved_protected:
        return f"refusing to overwrite input file: {resolved_output}"
    try:
        output.write_text(report + "\n", encoding="utf-8")
    except OSError as error:
        return f"cannot write report {output}: {error}"
    return None


def logs_main(argv=None):
    parser = argparse.ArgumentParser(
        prog="sentinel logs",
        description="Analyze coarse statistics and indicators in one local text log.",
    )
    parser.add_argument("file", help="path to the log file")
    parser.add_argument("--output", help="also save the report to this path")
    args = parser.parse_args(argv)
    try:
        report = analyze_log_file(args.file)
    except OSError as error:
        parser.exit(1, f"sentinel logs: {error}\n")
    if args.output:
        error = _write_report(report, args.output, protected_paths=(args.file,))
        if error:
            parser.exit(1, f"sentinel logs: {error}\n")
    print(report)
    return 0


def collect_main(argv=None):
    parser = argparse.ArgumentParser(
        prog="sentinel collect",
        description="List matching evidence-file metadata in one directory.",
    )
    parser.add_argument("directory", help="directory to scan (non-recursively)")
    parser.add_argument("--output", help="also save the report to this path")
    args = parser.parse_args(argv)
    if args.output:
        output = Path(args.output).expanduser()
        directory = Path(args.directory).expanduser()
        try:
            resolved_output = _resolved_path(output)
            resolved_directory = _resolved_path(directory)
        except OSError as error:
            parser.exit(1, f"sentinel collect: {error}\n")
        if resolved_output.parent == resolved_directory and resolved_output.suffix in EVIDENCE_EXTENSIONS:
            try:
                output_stat = output.stat()
            except FileNotFoundError:
                output_stat = None
            except OSError as error:
                parser.exit(1, f"sentinel collect: cannot inspect report path {output}: {error}\n")
            if output_stat and stat.S_ISREG(output_stat.st_mode):
                parser.exit(
                    1,
                    f"sentinel collect: refusing to overwrite matching evidence file: {output}\n",
                )
    report, errors = collect_evidence(args.directory)
    if args.output:
        error = _write_report(report, args.output)
        if error:
            parser.exit(1, f"sentinel collect: {error}\n")
    print(report)
    return 1 if errors else 0


# --- sentinel.py ---
#!/usr/bin/env python3
"""Interactive terminal assistant for SentinelAI alerts."""


COLOR_ENABLED = sys.stdout.isatty() and "NO_COLOR" not in os.environ
RESET = "\033[0m" if COLOR_ENABLED else ""
CYAN = "\033[96m" if COLOR_ENABLED else ""
BLUE = "\033[94m" if COLOR_ENABLED else ""
GREEN = "\033[92m" if COLOR_ENABLED else ""
RED = "\033[91m" if COLOR_ENABLED else ""
YELLOW = "\033[93m" if COLOR_ENABLED else ""
MAGENTA = "\033[95m" if COLOR_ENABLED else ""
DIM = "\033[2m" if COLOR_ENABLED else ""


def banner():
    if not sys.stdout.isatty():
        return
    logo = (
        "  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗",
        "  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║",
        "  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║",
        "  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ╚═╝",
        "  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗██╗",
        "  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝",
    )
    colors = (CYAN, BLUE, MAGENTA, BLUE, CYAN, MAGENTA)
    print()
    for color, line in zip(colors, logo):
        print(f"{color}{line}{RESET}")
    print(
        f"  {GREEN}AI-ASSISTED SECURITY MONITOR{RESET}  "
        f"{DIM}LOCAL-FIRST · CROSS-PLATFORM · RESPONSE OFF{RESET}"
    )
    print(f"  {BLUE}{'─' * 64}{RESET}")


def loading(message="Initializing security modules"):
    if not sys.stdout.isatty():
        return
    for frame in "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏":
        print(f"\r{CYAN}{frame}{RESET} {message}...", end="", flush=True)
        time.sleep(0.04)
    print(f"\r{GREEN}✔{RESET} {message} ready.{' ' * 10}")


def scan_animation():
    if not sys.stdout.isatty():
        return
    width = 24
    for frame in range(width * 2):
        position = frame if frame < width else width * 2 - frame
        bar = "─" * position + "●" + "─" * (width - position)
        print(f"\r{CYAN}[{bar}]{RESET} {DIM}warming up telemetry{RESET}", end="", flush=True)
        time.sleep(0.025)
    print(f"\r{GREEN}[{'─' * (width + 1)}]{RESET} {GREEN}telemetry ready{RESET}")


class Sentinel:
    def __init__(self, alert_file, database_file="~/.sentinel.db"):
        self.alert_file = alert_file
        self.store = AlertStore(database_file) if AlertStore else None
        self.alerts = deque(maxlen=50)
        self.stop = threading.Event()
        self.position = 0

    def load_existing(self):
        try:
            with open(self.alert_file, "r", encoding="utf-8") as handle:
                for line in handle:
                    self._add(line)
                self.position = handle.tell()
        except FileNotFoundError:
            pass

    def _add(self, line):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return
        if self.store:
            stored_id = self.store.add(event)
            if event.get("deduplication_key") and stored_id is None:
                return
        self.alerts.append(event)
        print("\n" + self.render(event) + "\nsentinel> ", end="", flush=True)

    def watch(self):
        while not self.stop.is_set():
            try:
                with open(self.alert_file, "r", encoding="utf-8") as handle:
                    handle.seek(self.position)
                    for line in handle:
                        self._add(line)
                    self.position = handle.tell()
            except FileNotFoundError:
                pass
            time.sleep(0.5)

    @staticmethod
    def render(event):
        severity = str(event.get("severity", "medium")).upper()
        severity_color = RED if severity == "HIGH" else YELLOW if severity == "MEDIUM" else CYAN
        destination = event.get("destination", "unknown")
        destination_port = event.get("destination_port")
        endpoint = f"{destination}:{destination_port}" if destination_port else destination
        return (
            f"{MAGENTA}╭─ SENTINEL INCIDENT{RESET} "
            f"{severity_color}[{severity}]{RESET}\n"
            f"{MAGENTA}│{RESET} {event.get('event', 'network activity')}\n"
            f"{MAGENTA}│{RESET} {event.get('source', 'unknown')} → {endpoint}\n"
            f"{MAGENTA}│{RESET} {event.get('events', 0)} observations · "
            f"{event.get('unique_ports', 0)} ports · "
            f"{event.get('confidence', 'medium')} confidence\n"
            f"{MAGENTA}│{RESET} {event.get('time', event.get('timestamp', 'unknown'))}\n"
            f"{MAGENTA}│{RESET} Incident: {event.get('incident_id', 'not persisted')}\n"
            f"{MAGENTA}╰─{RESET} {GREEN}Automatic response: OFF{RESET}"
        )

    def answer(self, command):
        command = command.lower().strip()
        if command in {"quit", "exit", "q"}:
            return False
        if command in {"help", "?"}:
            print(f"{CYAN}Commands{RESET}: {YELLOW}status{RESET}, {YELLOW}alerts{RESET}, {YELLOW}recent{RESET}, {YELLOW}what happened{RESET}, {YELLOW}explain{RESET}, {YELLOW}help{RESET}, {YELLOW}quit{RESET}")
        elif command in {"status", "what happened", "what happened?", "recent", "alerts"}:
            stored = self.store.recent(5) if self.store else []
            if not self.alerts and not stored:
                print("Sentinel: No scan alerts recorded yet.")
            else:
                print(f"Sentinel: {len(stored) or len(self.alerts)} alert(s) recorded.")
                rows = stored or list(self.alerts)[-5:]
                for event in rows:
                    incident_id = event.get("incident_id") or "no incident"
                    severity = event.get("severity", "medium")
                    print(
                        f"- {event.get('time')} | {severity} | "
                        f"{event.get('source')} | {event.get('event')} | "
                        f"{incident_id}"
                    )
        elif command == "explain":
            if self.alerts:
                event = self.alerts[-1]
                analysis = local_analysis(event)
                print("Sentinel evidence-bound analysis:\n" + format_analysis(analysis))
                try:
                    proposal = explain_with_gemini(event) if explain_with_gemini else None
                    ai_analysis = verified_ai_analysis(event, proposal)
                except Exception as error:
                    ai_analysis = None
                    print(
                        f"Gemini unavailable ({type(error).__name__}); "
                        "using local evidence only."
                    )
                if ai_analysis:
                    print("AI-selected verified evidence:")
                    for item in ai_analysis["observations"]:
                        print(f"- {item['field']}: {item['value']}")
                    if ai_analysis["investigation_steps"]:
                        print("AI-selected approved investigation steps:")
                        for step in ai_analysis["investigation_steps"]:
                            print(f"- {step}")
                print(self.render(event))
            else:
                print("Sentinel: There is no alert to explain.")
        else:
            context = "No alert yet." if not self.alerts else repr(self.alerts[-1])
            try:
                answer = chat_with_gemini(command, context) if chat_with_gemini else None
            except Exception as error:
                answer = f"Cloud assistant unavailable ({type(error).__name__})."
            if answer:
                print(f"{CYAN}Sentinel Gemini{RESET}: {answer}")
            elif any(word in command for word in {"safe", "security", "status", "happening", "alert"}):
                print(f"{GREEN}Sentinel{RESET}: I am monitoring the alert stream. Automatic blocking is disabled. Type {YELLOW}'alerts'{RESET} or {YELLOW}'explain'{RESET} for details.")
            else:
                print(f"{GREEN}Sentinel{RESET}: Ask me about alerts, scans, safety, status, or type {YELLOW}'help'{RESET}.")
        return True


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "monitor":
        detector_main(sys.argv[2:])
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "analyze":
        analyst_main(sys.argv[2:])
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "logs":
        return logs_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "collect":
        return collect_main(sys.argv[2:])
    parser = argparse.ArgumentParser(description="Sentinel terminal security monitor")
    parser.add_argument("--alert-file", default=os.path.expanduser("~/.sentinel_alerts.jsonl"))
    parser.add_argument("--database-file", default=os.path.expanduser("~/.sentinel.db"))
    parser.add_argument(
        "--no-monitor",
        action="store_true",
        help="Open the alert console without starting an event monitor",
    )
    args, monitor_options = parser.parse_known_args()
    if args.no_monitor and monitor_options:
        parser.error("--no-monitor cannot be combined with monitor options")

    monitor = None
    if not args.no_monitor:
        monitor = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "sentinel",
                "monitor",
                "--alert-file",
                args.alert_file,
                "--database-file",
                args.database_file,
                *monitor_options,
            ]
        )
    sentinel = Sentinel(os.path.expanduser(args.alert_file), args.database_file)
    try:
        sentinel.load_existing()
        watcher = threading.Thread(target=sentinel.watch, daemon=True)
        watcher.start()
        banner()
        scan_animation()
        loading("Loading ML and alert engine")
        loading("Connecting local alert database")
        if monitor:
            loading("Starting platform event monitor")
        print(f"{GREEN}Sentinel is online{RESET}. Type {YELLOW}'help'{RESET} for commands.")
        while sentinel.answer(input("sentinel> ")):
            pass
    except (KeyboardInterrupt, EOFError):
        print("\nSentinel stopped.")
    finally:
        sentinel.stop.set()
        if monitor:
            if monitor.poll() is None:
                monitor.terminate()
            try:
                monitor.wait(timeout=5)
            except subprocess.TimeoutExpired:
                monitor.kill()
                monitor.wait()

if __name__ == "__main__":
    main()
