import argparse
import contextlib
import getpass
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import string
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from analyst import (
    AlertStore,
    LocalSecurityAgent,
    analyst_main,
    chat as chat_with_gemini,
    classify_intent,
    explain_alert as explain_with_gemini,
    format_analysis,
    verified_ai_analysis,
    web_research,
)
from detection import detector_main
from telemetry import default_log_file

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
HASH_ALGORITHMS = ("sha224", "sha256", "sha384", "sha512")
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 256
PASSWORD_ALPHABET = string.ascii_letters + string.digits + string.punctuation


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


def hash_file(path, algorithm="sha256"):
    """Hash a regular file in chunks without exposing its contents."""
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError(f"unsupported hash algorithm: {algorithm}")
    source = Path(path).expanduser()
    try:
        with source.open("rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise OSError("not a regular file")
            digest = hashlib.new(algorithm)
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise OSError(f"cannot hash {source}: {error}") from error
    return (
        f"File: {_resolved_path(source)}\n"
        f"Algorithm: {algorithm.upper().replace('SHA', 'SHA-')}\n"
        f"Digest: {digest.hexdigest()}"
    )


def _write_report_exclusive(report, output_path, protected_paths=()):
    output = Path(output_path).expanduser()
    try:
        resolved_output = _resolved_path(output)
        resolved_protected = [_resolved_path(path) for path in protected_paths]
    except OSError as error:
        return str(error)
    if resolved_output in resolved_protected:
        return f"refusing to write report over input file: {resolved_output}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(output, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(report + "\n")
    except OSError as error:
        return f"cannot create report {output}: {error}"
    return None


def hash_main(argv=None):
    parser = argparse.ArgumentParser(
        prog="sentinel hash",
        description="Print a SHA-2 digest for a local file without printing its contents.",
    )
    parser.add_argument("file", help="file to hash")
    parser.add_argument(
        "--algorithm",
        choices=HASH_ALGORITHMS,
        default="sha256",
        help="SHA-2 algorithm (default: sha256)",
    )
    parser.add_argument("--output", help="create a digest report without overwriting")
    args = parser.parse_args(argv)
    try:
        report = hash_file(args.file, args.algorithm)
    except (OSError, ValueError) as error:
        parser.exit(1, f"sentinel hash: {error}\n")
    if args.output:
        error = _write_report_exclusive(
            report, args.output, protected_paths=(args.file,)
        )
        if error:
            parser.exit(1, f"sentinel hash: {error}\n")
    print(report)
    return 0


def _password_strength(password):
    """Return heuristic composition checks, not a measure of entropy."""
    checks = (
        len(password) >= PASSWORD_MIN_LENGTH,
        any(char.islower() for char in password),
        any(char.isupper() for char in password),
        any(char.isdigit() for char in password),
        any(not char.isalnum() for char in password),
    )
    return checks


def password_main(argv=None):
    parser = argparse.ArgumentParser(
        prog="sentinel password",
        description="Generate a one-time password or check a hidden password heuristically.",
    )
    subparsers = parser.add_subparsers(dest="action", required=True)
    generate_parser = subparsers.add_parser("generate", help="generate a secret password")
    generate_parser.add_argument(
        "--length",
        type=int,
        default=20,
        help=f"length from {PASSWORD_MIN_LENGTH} to {PASSWORD_MAX_LENGTH} (default: 20)",
    )
    subparsers.add_parser("check", help="check password composition without echoing input")
    args = parser.parse_args(argv)

    if not sys.stdout.isatty():
        parser.exit(
            1,
            "sentinel password: password actions require an interactive terminal; "
            "generated secrets are never written to redirected output\n",
        )
    if args.action == "generate":
        if not PASSWORD_MIN_LENGTH <= args.length <= PASSWORD_MAX_LENGTH:
            parser.error(
                f"--length must be between {PASSWORD_MIN_LENGTH} and {PASSWORD_MAX_LENGTH}"
            )
        password = "".join(
            secrets.choice(PASSWORD_ALPHABET) for _ in range(args.length)
        )
        print("Generated password (shown once; not saved):")
        print(password)
        return 0

    if not sys.stdin.isatty():
        parser.exit(1, "sentinel password: password check requires an interactive terminal\n")
    password = getpass.getpass("Password (input hidden): ")
    checks = _password_strength(password)
    labels = ("minimum length", "lowercase", "uppercase", "digit", "symbol")
    print("Password composition heuristic (not an entropy estimate):")
    for label, passed in zip(labels, checks):
        print(f"- {label}: {'pass' if passed else 'fail'}")
    return 0 if all(checks) else 1


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


def loading(message="Initializing security modules", enabled=True):
    if not enabled or not sys.stdout.isatty():
        return
    for frame in "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏":
        print(f"\r{CYAN}{frame}{RESET} {message}...", end="", flush=True)
        time.sleep(0.04)
    print(f"\r{GREEN}✔{RESET} {message} ready.{' ' * 10}")


def scan_animation(enabled=True):
    if not enabled or not sys.stdout.isatty():
        return
    width = 24
    for frame in range(width * 2):
        position = frame if frame < width else width * 2 - frame
        bar = "─" * position + "●" + "─" * (width - position)
        print(f"\r{CYAN}[{bar}]{RESET} {DIM}warming up telemetry{RESET}", end="", flush=True)
        time.sleep(0.025)
    print(f"\r{GREEN}[{'─' * (width + 1)}]{RESET} {GREEN}telemetry ready{RESET}")


def _prompt_input(prompt="", input_fn=None, animate=True):
    input_fn = input if input_fn is None else input_fn
    interactive = sys.stdout.isatty()
    use_color = interactive and "NO_COLOR" not in os.environ
    if interactive and animate:
        for frame in ("◐", "◓", "◑"):
            animation = f"\033[96m{frame}\033[0m" if use_color else frame
            print(f"\r{animation} Preparing prompt...", end="", flush=True)
            time.sleep(0.035)
        clear_line = "\r\033[2K" if use_color else "\r" + " " * 24 + "\r"
        print(clear_line, end="", flush=True)
    if use_color:
        reset = "\033[0m"
        prompt_color = "\033[95m"
        value = input_fn(
            f"{prompt_color}>{reset} "
            f"\033[96m{prompt}{reset}\033[92m"
        )
        print(reset, end="", flush=True)
        return value
    return input_fn(f"> {prompt}" if prompt else "> ")


def _monitor_source(arguments):
    source = "auto"
    index = 0
    while index < len(arguments):
        if arguments[index] == "--source" and index + 1 < len(arguments):
            source = arguments[index + 1]
            index += 1
        elif arguments[index].startswith("--source="):
            source = arguments[index].split("=", 1)[1]
        index += 1
    if source == "auto" and sys.platform == "linux":
        return "ufw"
    return source


def _monitor_log_file(arguments):
    for index, argument in enumerate(arguments):
        if argument == "--log-file" and index + 1 < len(arguments):
            return arguments[index + 1]
        if argument.startswith("--log-file="):
            return argument.split("=", 1)[1]
    return None


def _prepare_linux_ufw(source, input_fn=None, run=None, log_file=None):
    if sys.platform != "linux" or source != "ufw":
        return True
    input_fn = (
        (lambda prompt: _prompt_input(prompt, animate=False))
        if input_fn is None
        else input_fn
    )
    run = subprocess.run if run is None else run
    if not sys.stdin.isatty():
        print(
            f"{YELLOW}Live monitor not started:{RESET} UFW requires an interactive "
            "install/setup confirmation. Install UFW, then run Sentinel again, "
            "or select an available source with --source.",
            file=sys.stderr,
        )
        return False

    ufw = shutil.which("ufw")
    if not ufw:
        package_managers = (
            ("apt-get", ["apt-get", "install", "-y", "ufw"]),
            ("dnf", ["dnf", "install", "-y", "ufw"]),
            ("yum", ["yum", "install", "-y", "ufw"]),
            ("pacman", ["pacman", "-S", "--noconfirm", "ufw"]),
            ("zypper", ["zypper", "--non-interactive", "install", "ufw"]),
        )
        package_manager = next(
            (
                (name, command)
                for name, command in package_managers
                if shutil.which(name)
            ),
            None,
        )
        if not package_manager:
            print(
                f"{YELLOW}Live monitor not started:{RESET} UFW is missing and no "
                "supported package manager was found. Install UFW yourself or "
                "select an available source with --source.",
                file=sys.stderr,
            )
            return False
        manager_name, install_command = package_manager
        answer = input_fn(
            f"UFW is not installed. Install it using {manager_name} with sudo? [y/N] "
        ).strip().lower()
        if answer not in {"y", "yes"}:
            print(
                f"{YELLOW}Live monitor not started:{RESET} UFW was not installed. "
                "Choose another available source with --source.",
                file=sys.stderr,
            )
            return False
        try:
            result = run(["sudo", *install_command], check=False)
        except OSError as error:
            print(f"{RED}UFW installation failed:{RESET} {error}", file=sys.stderr)
            return False
        if result.returncode:
            print(
                f"{RED}UFW installation failed:{RESET} package manager exited "
                f"with status {result.returncode}.",
                file=sys.stderr,
            )
            return False
        ufw = shutil.which("ufw")
        if not ufw:
            print(
                f"{RED}UFW installation did not provide an `ufw` command.{RESET}",
                file=sys.stderr,
            )
            return False

    try:
        status = run(
            [ufw, "status", "verbose"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        print(f"{RED}Could not inspect UFW logging:{RESET} {error}", file=sys.stderr)
        return False
    status_text = f"{status.stdout or ''}\n{status.stderr or ''}"
    logging_enabled = re.search(r"(?im)^\s*logging:\s*on\b", status_text)
    if not logging_enabled:
        answer = input_fn(
            "UFW logging is off or its status is unavailable. Enable UFW logging "
            "with sudo? This does not enable the firewall. [y/N] "
        ).strip().lower()
        if answer not in {"y", "yes"}:
            print(
                f"{YELLOW}Live monitor not started:{RESET} UFW logging was not "
                "enabled. Choose another available source with --source.",
                file=sys.stderr,
            )
            return False
    log_path = Path(log_file).expanduser() if log_file else Path(
        default_log_file("ufw")
    )
    if not logging_enabled:
        try:
            result = run(["sudo", ufw, "logging", "on"], check=False)
        except OSError as error:
            print(f"{RED}Could not enable UFW logging:{RESET} {error}", file=sys.stderr)
            return False
        if result.returncode:
            print(
                f"{RED}Could not enable UFW logging:{RESET} command exited with "
                f"status {result.returncode}.",
                file=sys.stderr,
            )
            return False
    if not log_path.exists():
        print(
            f"{YELLOW}Live monitor not started:{RESET} UFW logging is enabled, "
            f"but no log file is available at {log_path}. Configure rsyslog or "
            "provide a readable UFW log with --log-file; the console will remain "
            "available without live ingestion.",
            file=sys.stderr,
        )
        return False
    return True


def _relay_monitor_output(process, stop_event):
    if process.stdout is not None:
        for line in process.stdout:
            message = line.rstrip()
            if not message:
                continue
            color = RED if "failed" in message.lower() or "error" in message.lower() else DIM
            print(f"{color}{message}{RESET}", flush=True)
    return_code = process.poll()
    if not stop_event.is_set() and return_code:
        print(
            f"{RED}Live monitor exited with status {return_code}.{RESET} "
            "Use 'help' to see source options.",
            flush=True,
        )


def _show_cli_help():
    print(
        f"\n{BLUE}╭─ SENTINEL SECURITY MONITOR {'─' * 34}{RESET}\n"
        f"{BLUE}│{RESET} {CYAN}sentinel{RESET}                         "
        "Start monitor and interactive console\n"
        f"{BLUE}│{RESET} {CYAN}sentinel --no-monitor{RESET}             "
        "Open console without live ingestion\n"
        f"{BLUE}│{RESET} {CYAN}sentinel --source SOURCE{RESET}           "
        "Choose ufw, windows-firewall, macos-unified, suricata, or zeek\n"
        f"{BLUE}│{RESET} {CYAN}google QUESTION{RESET}                   "
        "Search Google with a natural-language question\n"
        f"{BLUE}│{RESET} {CYAN}sentinel monitor --help{RESET}            "
        "Show detector thresholds and log options\n"
        f"{BLUE}│{RESET} {CYAN}sentinel logs PATH{RESET}                  "
        "Analyze a local text log\n"
        f"{BLUE}│{RESET} {CYAN}sentinel collect DIRECTORY{RESET}          "
        "Inventory local evidence files\n"
        f"{BLUE}│{RESET} {CYAN}sentinel hash FILE{RESET}                  "
        "Stream a SHA-2 file digest\n"
        f"{BLUE}│{RESET} {CYAN}sentinel password generate|check{RESET}    "
        "Use local password utilities\n"
        f"{BLUE}│{RESET} {CYAN}menu / report{RESET}                     "
        "Show numbered actions or the latest report\n"
        f"{BLUE}│{RESET} {CYAN}--no-animation{RESET}                      "
        "Disable startup animation\n"
        f"{BLUE}╰{'─' * 61}{RESET}\n"
        f"{DIM}Linux start: ./sentinel. Sentinel does not enable the firewall. "
        "Ask a question or use 'google QUESTION'; Sentinel asks "
        "before each Google Search.{RESET}\n"
        f"{DIM}Search results can be wrong or incomplete; Sentinel does not "
        "guarantee factual accuracy.{RESET}"
    )


class Sentinel:
    def __init__(self, alert_file, database_file="~/.sentinel.db"):
        self.alert_file = alert_file
        self.store = AlertStore(database_file) if AlertStore else None
        self.alerts = deque(maxlen=50)
        self.stop = threading.Event()
        self.position = 0
        self.latest_report = ""
        self.agent = LocalSecurityAgent()
        self.chat_history = deque(maxlen=16)

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
        classification = str(event.get("event", "network activity"))
        destination = event.get("destination", "unknown")
        destination_port = event.get("destination_port")
        endpoint = f"{destination}:{destination_port}" if destination_port else destination
        return (
            f"{MAGENTA}╭─ SENTINEL INCIDENT{RESET} "
            f"{severity_color}◆ {severity} SEVERITY ◆{RESET}\n"
            f"{MAGENTA}│{RESET} {severity_color}{classification}{RESET}\n"
            f"{MAGENTA}│{RESET} {event.get('source', 'unknown')} → {endpoint}\n"
            f"{MAGENTA}│{RESET} {event.get('events', 0)} observations · "
            f"{event.get('unique_ports', 0)} ports · "
            f"{event.get('confidence', 'medium')} confidence\n"
            f"{MAGENTA}│{RESET} {event.get('time', event.get('timestamp', 'unknown'))}\n"
            f"{MAGENTA}│{RESET} Incident: {event.get('incident_id', 'not persisted')}\n"
            f"{MAGENTA}╰─{RESET} {GREEN}Automatic response: OFF{RESET}"
        )

    def answer(self, command):
        command = command.strip()
        normalized = command.lower()
        if normalized == "7" or normalized in {"quit", "exit", "q"}:
            return False
        menu_commands = {
            "1": "status",
            "2": "alerts",
            "3": "explain",
            "5": "report",
            "6": "help",
        }
        if normalized == "4":
            try:
                query = _prompt_input("Google question: ").strip()
            except (EOFError, KeyboardInterrupt):
                query = ""
            if query:
                self._online_lookup(query)
            else:
                print("Google search cancelled; no question was sent.")
            return True
        command = menu_commands.get(normalized, command)
        normalized = command.lower()
        try:
            lexer = shlex.shlex(command, posix=True)
            lexer.whitespace_split = True
            lexer.escape = ""
            tokens = list(lexer)
        except ValueError as error:
            if command.split(maxsplit=1)[0].lower() in {
                "logs", "collect", "hash", "password", "analyze",
            }:
                print(
                    f"Sentinel: Could not parse command ({error}). "
                    "Use 'help' for examples."
                )
                return True
            tokens = command.split()
        lowered_tokens = [token.lower() for token in tokens]
        intent = classify_intent(command)
        if tokens and lowered_tokens[0] in {"logs", "collect", "hash", "password"}:
            command_handlers = {
                "logs": logs_main,
                "collect": collect_main,
                "hash": hash_main,
                "password": password_main,
            }
            handler_args = tokens[1:]
            if lowered_tokens[0] == "collect" and handler_args:
                if handler_args[0].lower() == "evidence":
                    handler_args = handler_args[1:]
            if lowered_tokens[0] == "password":
                self._run_cli_handler(
                    command_handlers[lowered_tokens[0]], handler_args
                )
            else:
                self._run_report_command(
                    command_handlers[lowered_tokens[0]], handler_args
                )
        elif lowered_tokens and lowered_tokens[0] == "google":
            query = " ".join(tokens[1:]).strip()
            if query:
                self._online_lookup(query)
            else:
                print("Sentinel: Use 'google QUESTION' to search Google.")
        elif lowered_tokens[:2] == ["analyze", "logs"]:
            self._run_report_command(logs_main, tokens[2:])
        elif lowered_tokens[:2] == ["analyze", "evidence"]:
            self._run_report_command(collect_main, tokens[2:])
        elif lowered_tokens and lowered_tokens[0] == "analyze":
            if len(tokens) > 1 and tokens[1].startswith("--"):
                self._run_cli_handler(analyst_main, tokens[1:])
            elif intent == "explain" and len(tokens) > 1 and "alert" in lowered_tokens:
                self._explain_latest()
            elif len(tokens) > 1 and lowered_tokens[1] != "alert":
                query = " ".join(tokens[1:])
                if not self._show_rag_answer(query):
                    self._online_lookup(query)
            else:
                self._explain_latest()
        elif normalized in {"explain", "analysis", "analyze alert", "alert analysis"}:
            self._explain_latest()
        elif normalized in {"help", "?", "commands"}:
            self._show_help()
        elif normalized in {"features", "feature", "menu", "home"}:
            self._show_menu()
        elif normalized in {"report", "reports", "show report"}:
            self._show_report()
        elif normalized in {
            "status", "what happened", "what happened?", "recent", "alerts",
        }:
            self._clear_screen()
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
        else:
            self._conversational_answer(command)
        return True

    @staticmethod
    def _requests_current_web(query):
        normalized = query.lower()
        return any(
            phrase in normalized
            for phrase in (
                "search ", "search the web", "search online", "look online", "look up online",
                "on the internet", "latest ", "current ", "today's ", "today ",
                "right now", "up to date", "recent news",
            )
        )

    def _conversational_answer(self, query):
        retrieved = self.agent.answer(query)["documents"]
        use_web_search = self._requests_current_web(query)
        local_context = "\n\n".join(
            f"[{item['document']}]\n{item['excerpt']}"
            for item in retrieved
        )
        if not os.getenv("GEMINI_API_KEY"):
            if (
                classify_intent(query) == "scan_guidance"
                or "scan detection" in query.lower()
            ):
                self._show_scan_guidance()
                self._show_analysis_scope()
            if retrieved:
                self._show_rag_answer(query)
            else:
                self._show_online_setup()
            return
        if use_web_search:
            consent_text = (
                "Send this question and up to 4 recent chat turns to Gemini "
                "for Google Search? The request is sent externally; no alerts "
                "or log contents are attached. [y/N] "
            )
        else:
            consent_text = (
                "Send this message, up to 8 recent chat turns, and relevant "
                "local guidance to Gemini? The message is sent externally; "
                "no alerts or log contents are attached. [y/N] "
            )
        try:
            consent = _prompt_input(consent_text).strip().lower()
        except (EOFError, KeyboardInterrupt):
            consent = ""
        if consent not in {"y", "yes"}:
            print("Chat request cancelled; nothing was sent.")
            return

        if use_web_search:
            history_context = "\n".join(
                f"{turn['role']}: {turn['text']}"
                for turn in list(self.chat_history)[-8:]
            )
            research_query = (
                f"Recent conversation:\n{history_context}\n\nQuestion:\n{query}"
                if history_context
                else query
            )
            try:
                result = web_research(research_query)
            except Exception as error:
                print(f"{RED}Online research failed:{RESET} {error}")
                return
            answer = result["answer"]
            if result["sources"]:
                answer += "\n\nSources:\n" + "\n".join(
                    f"- {source['title']}: {source['url']}"
                    for source in result["sources"]
                )
            answer += (
                "\n\nWeb-grounded results may be incomplete or incorrect; "
                "verify important claims."
            )
        else:
            try:
                answer = chat_with_gemini(
                    query,
                    context=local_context,
                    history=list(self.chat_history),
                )
            except Exception as error:
                print(f"{RED}Sentinel AI request failed:{RESET} {error}")
                return
            if not answer:
                self._show_online_setup()
                return

        self.chat_history.append({"role": "user", "text": query})
        self.chat_history.append({"role": "assistant", "text": answer})
        self.latest_report = f"Sentinel AI:\n{answer}"
        self._clear_screen()
        print(f"{CYAN}Sentinel AI{RESET}: {answer}")
        self._offer_save_report()

    def _show_rag_answer(self, query):
        rag_result = self.agent.answer(query)
        if not rag_result["documents"]:
            return False
        lines = [
            "Local knowledge-base retrieval (guidance, not alert evidence):"
        ]
        lines.extend(
            f"- {document['document']} (match {document['score']}): "
            f"{document['excerpt']}"
            for document in rag_result["documents"]
        )
        self.latest_report = "\n".join(lines)
        self._show_report()
        self._offer_save_report()
        return True

    def _online_lookup(self, query):
        if not os.getenv("GEMINI_API_KEY"):
            self._show_online_setup()
            return
        try:
            consent = _prompt_input(
                "Send this question to Gemini with Google Search? "
                "The question is sent externally; no alert or log data is attached. [y/N] "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            consent = ""
        if consent not in {"y", "yes"}:
            print("Online lookup cancelled; the question was not sent.")
            return
        try:
            result = web_research(query)
        except Exception as error:
            print(f"{RED}Online research failed:{RESET} {error}")
            return
        lines = [
            "Online research (may be incomplete or incorrect; verify important claims):",
            result["answer"],
        ]
        if result["sources"]:
            lines.append("Sources:")
            lines.extend(
                f"- {source['title']}: {source['url']}"
                for source in result["sources"]
            )
        else:
            lines.append(
                "No source citations were returned; treat this answer as unverified."
            )
        self.latest_report = "\n".join(lines)
        self._show_report()
        self._offer_save_report()

    @staticmethod
    def _run_cli_handler(handler, args):
        try:
            handler(args)
        except SystemExit:
            pass

    def _run_report_command(self, handler, args):
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                handler(args)
        except SystemExit:
            pass
        report = output.getvalue().strip()
        if not report:
            return
        self.latest_report = report
        print(report)
        if not any(argument == "--output" or argument.startswith("--output=") for argument in args):
            self._offer_save_report()

    def _offer_save_report(self):
        if not self.latest_report:
            return
        reports_directory = Path.home() / ".sentinel" / "reports"
        filename = f"report-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}.txt"
        destination = reports_directory / filename
        try:
            answer = _prompt_input(
                f"Save this report to {destination}? [y/N] "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer not in {"y", "yes"}:
            print("Report not saved.")
            return
        try:
            reports_directory.mkdir(parents=True, exist_ok=True)
            with destination.open("x", encoding="utf-8") as report_file:
                report_file.write(self.latest_report)
                report_file.write("\n")
        except OSError as error:
            print(f"{RED}Could not save report:{RESET} {error}")
            return
        print(f"{GREEN}Report saved:{RESET} {destination}")

    def _show_report(self):
        self._clear_screen()
        if self.latest_report:
            print(f"{MAGENTA}╭─ LATEST REPORT {'─' * 48}{RESET}")
            print(self.latest_report)
            print(f"{MAGENTA}╰{'─' * 62}{RESET}")
        else:
            print("No report generated yet. Run logs, collect, hash, or online research.")

    @staticmethod
    def _clear_screen():
        if sys.stdout.isatty():
            print("\033[2J\033[H", end="")

    def _show_menu(self):
        options = (
            ("1", "Status"),
            ("2", "Recent alerts"),
            ("3", "Explain latest alert"),
            ("4", "Search Google"),
            ("5", "Latest report"),
            ("6", "Help"),
            ("7", "Quit"),
        )
        print(f"\n{BLUE}╭─ SENTINEL OPTIONS {'─' * 42}{RESET}")
        for number, label in options:
            print(f"{BLUE}│{RESET} {CYAN}{number}{RESET}  {label}")
        print(
            f"{BLUE}╰{'─' * 61}{RESET}\n"
            f"{DIM}Choose a number or type a question / command.{RESET}"
        )

    @staticmethod
    def _show_online_setup():
        if os.getenv("GEMINI_API_KEY"):
            print("Online research is unavailable because no compatible web-search response was returned.")
        else:
            print(
                "Conversational AI and Google Search need a Gemini API key. "
                "Sign in to Google AI Studio with a Google account, create a "
                "Gemini API key, then set GEMINI_API_KEY in this terminal before "
                "starting Sentinel. Sentinel uses Gemini API authorization; "
                "ChatGPT login is not supported."
            )

    def _show_help(self):
        rows = (
            ("status", "Show recorded incident and alert status"),
            ("menu", "Show numbered actions"),
            ("report", "Show the latest non-secret report"),
            ("ask a question", "Search Google with citations after external-sharing consent"),
            ("google QUESTION", "Search Google and show cited sources after consent"),
            ("alerts / recent", "Show evidence and recommended investigation steps"),
            ("explain", "Highlight the latest alert and explain recorded evidence"),
            ("logs PATH", "Summarize one local text log"),
            ("collect DIRECTORY", "Inventory evidence files in one directory"),
            ("hash FILE", "Calculate a SHA-2 digest without printing file contents"),
            ("password generate", "Generate a one-time, securely random password"),
            ("password check", "Check password composition without echoing it"),
            ("help", "Show these commands"),
            ("quit", "Stop Sentinel and its monitor"),
        )
        print(f"\n{BLUE}╭─ SENTINEL COMMAND CENTER {'─' * 35}{RESET}")
        for command, description in rows:
            print(f"{BLUE}│{RESET} {CYAN}{command:<22}{RESET} {description}")
        print(
            f"{BLUE}╰{'─' * 61}{RESET}\n"
            f"{DIM}Examples: logs /var/log/auth.log | collect ~/evidence | "
            f"hash capture.pcap | explain{RESET}\n"
            f"{DIM}Monitoring rules and sources: sentinel --help{RESET}"
        )

    def _show_scan_guidance(self):
        recent_count = len(self.store.recent(5)) if self.store else len(self.alerts)
        print(
            f"Sentinel: live monitoring is handled by the configured event source; "
            f"{recent_count} recent alert(s) are available. Detection uses recorded "
            "network telemetry and configured scan thresholds, not general AI knowledge. "
            "Use 'status' or 'explain', or start with 'sentinel --help' and "
            "'python -m sentinel monitor --help' to configure a scan."
        )

    @staticmethod
    def _show_analysis_scope():
        print(
            "Sentinel: the local ML model performs behavioral anomaly scoring on "
            "network-event features after sufficient normal history; it is not a "
            "general-purpose language model or a source of general knowledge. "
            "Use 'explain' for evidence-bound alert analysis."
        )

    def _explain_latest(self):
        if not self.alerts:
            print("Sentinel: There is no alert to explain.")
            return
        event = self.alerts[-1]
        agent_result = self.agent.analyze_alert(event)
        analysis = agent_result["analysis"]
        print("Sentinel evidence-bound analysis:\n" + format_analysis(analysis))
        if agent_result["retrieved_guidance"]:
            print("Retrieved local guidance (not incident evidence):")
            for guidance in agent_result["retrieved_guidance"]:
                print(f"- {guidance['document']}: {guidance['excerpt']}")
        ai_analysis = None
        if explain_with_gemini and os.getenv("GEMINI_API_KEY"):
            try:
                consent = _prompt_input(
                    "Send this alert's telemetry fields to Gemini for evidence selection? [y/N] "
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                consent = ""
            if consent in {"y", "yes"}:
                try:
                    proposal = explain_with_gemini(event)
                    ai_analysis = verified_ai_analysis(event, proposal)
                except Exception as error:
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
        report_lines = [
            "Sentinel evidence-bound analysis:",
            format_analysis(analysis),
        ]
        if agent_result["retrieved_guidance"]:
            report_lines.append("Retrieved local guidance (not incident evidence):")
            report_lines.extend(
                f"- {item['document']}: {item['excerpt']}"
                for item in agent_result["retrieved_guidance"]
            )
        report_lines.append(self.render(event))
        report = "\n".join(report_lines)
        print(self.render(event))
        self.latest_report = report
        self._offer_save_report()


def main():
    if len(sys.argv) > 1 and sys.argv[1] in {"help", "-h", "--help"}:
        _show_cli_help()
        return 0
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
    if len(sys.argv) > 1 and sys.argv[1] == "hash":
        return hash_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "password":
        return password_main(sys.argv[2:])
    parser = argparse.ArgumentParser(description="Sentinel terminal security monitor")
    parser.add_argument("--alert-file", default=os.path.expanduser("~/.sentinel_alerts.jsonl"))
    parser.add_argument("--database-file", default=os.path.expanduser("~/.sentinel.db"))
    parser.add_argument(
        "--no-monitor",
        action="store_true",
        help="Open the alert console without starting an event monitor",
    )
    parser.add_argument(
        "--no-animation",
        action="store_true",
        help="Skip startup progress animations",
    )
    args, monitor_options = parser.parse_known_args()
    if args.no_monitor and monitor_options:
        parser.error("--no-monitor cannot be combined with monitor options")

    monitor = None
    monitor_thread = None
    monitor_ready = not args.no_monitor
    if not args.no_monitor:
        requested_source = _monitor_source(monitor_options)
        monitor_ready = _prepare_linux_ufw(
            requested_source,
            log_file=_monitor_log_file(monitor_options),
        )
    sentinel = Sentinel(os.path.expanduser(args.alert_file), args.database_file)
    try:
        sentinel.load_existing()
        watcher = threading.Thread(target=sentinel.watch, daemon=True)
        watcher.start()
        banner()
        scan_animation(enabled=not args.no_animation)
        loading("Loading ML and alert engine", enabled=not args.no_animation)
        loading("Connecting local alert database", enabled=not args.no_animation)
        if monitor_ready:
            loading("Starting platform event monitor", enabled=not args.no_animation)
        sentinel._show_menu()

        if monitor_ready:
            try:
                monitor = subprocess.Popen(
                    [
                        sys.executable,
                        "-u",
                        "-m",
                        "sentinel",
                        "monitor",
                        "--alert-file",
                        args.alert_file,
                        "--database-file",
                        args.database_file,
                        *monitor_options,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                )
            except OSError as error:
                monitor_ready = False
                print(
                    f"{RED}Could not start the Sentinel monitor:{RESET} {error}",
                    file=sys.stderr,
                )
        if monitor and monitor.poll() is not None:
            _relay_monitor_output(monitor, sentinel.stop)
            monitor_ready = False
            print(
                f"{RED}The live monitor exited during startup; the console "
                "remains available without live ingestion.{RESET}"
            )
        elif not monitor_ready and not args.no_monitor:
            print(
                f"{YELLOW}Console-only mode:{RESET} no live event source was started."
            )
        if monitor_ready:
            state = "Sentinel is online"
        else:
            state = "Sentinel console is ready"
        print(f"{GREEN}{state}{RESET}. Type {YELLOW}'help'{RESET} for commands.")
        print(
            f"{DIM}Chat naturally with Gemini after confirming. Ask for latest "
            "information or use 'google QUESTION' for Google Search; Sentinel "
            f"will ask first. Type 'help' for commands.{RESET}"
        )
        if monitor and monitor_ready:
            monitor_thread = threading.Thread(
                target=_relay_monitor_output,
                args=(monitor, sentinel.stop),
                daemon=True,
            )
            monitor_thread.start()
        while sentinel.answer(_prompt_input()):
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
            if monitor_thread:
                monitor_thread.join(timeout=1)

if __name__ == "__main__":
    main()
