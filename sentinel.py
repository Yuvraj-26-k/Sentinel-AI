#!/usr/bin/env python3
"""Interactive terminal assistant for SentinelAI alerts."""

import argparse
import json
import os
import sys
import threading
import time
from collections import deque

try:
    from alert_store import AlertStore
except ImportError:
    AlertStore = None

try:
    from cloud_llm import chat as chat_with_gemini
except ImportError:
    chat_with_gemini = None

try:
    from cloud_llm import explain_alert as explain_with_gemini
except ImportError:
    explain_with_gemini = None

from security_analyst import format_analysis, local_analysis, verified_ai_analysis

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
    parser = argparse.ArgumentParser(description="Sentinel interactive security chatbot")
    parser.add_argument("--alert-file", default=os.path.expanduser("~/.sentinel_alerts.jsonl"))
    parser.add_argument("--database-file", default=os.path.expanduser("~/.sentinel.db"))
    args = parser.parse_args()
    sentinel = Sentinel(os.path.expanduser(args.alert_file), args.database_file)
    sentinel.load_existing()
    watcher = threading.Thread(target=sentinel.watch, daemon=True)
    watcher.start()
    banner()
    loading("Loading ML and alert engine")
    loading("Connecting local alert database")
    loading("Starting live event watcher")
    print(f"{GREEN}Sentinel is online{RESET}. Type {YELLOW}'help'{RESET} for commands.")
    if COLOR_ENABLED:
        print(
            f"{DIM}Local read-only alert API: "
            f"http://127.0.0.1:{os.environ.get('SENTINEL_API_PORT', '8000')}/api/health{RESET}"
        )
    try:
        while sentinel.answer(input("sentinel> ")):
            pass
    except (KeyboardInterrupt, EOFError):
        print("\nSentinel stopped.")
    finally:
        sentinel.stop.set()


if __name__ == "__main__":
    main()
