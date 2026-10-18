#!/usr/bin/env python3
"""Interactive terminal assistant for SentinelAI alerts."""

import argparse
import json
import os
import threading
import time
from collections import deque

try:
    from cloud_llm import explain_alert as explain_with_gemini
except ImportError:
    explain_with_gemini = None


class Sentinel:
    def __init__(self, alert_file):
        self.alert_file = alert_file
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
        return (
            "╔══════════════════════════════════════╗\n"
            "║ 🚨 SENTINEL SECURITY ALERT           ║\n"
            "╠══════════════════════════════════════╣\n"
            f"║ Source: {event.get('source', 'unknown'):<26}║\n"
            f"║ Event: {event.get('event', 'unknown'):<27}║\n"
            f"║ Ports: {str(event.get('unique_ports', '?')):<27}║\n"
            f"║ Time: {event.get('time', 'unknown'):<28}║\n"
            "║ Automatic blocking: OFF              ║\n"
            "╚══════════════════════════════════════╝"
        )

    def answer(self, command):
        command = command.lower().strip()
        if command in {"quit", "exit", "q"}:
            return False
        if command in {"help", "?"}:
            print("Commands: status, alerts, recent, what happened, help, quit")
        elif command in {"status", "what happened", "what happened?", "recent", "alerts"}:
            if not self.alerts:
                print("Sentinel: No scan alerts recorded yet.")
            else:
                print(f"Sentinel: {len(self.alerts)} alert(s) recorded.")
                for event in list(self.alerts)[-5:]:
                    print(f"- {event.get('time')} | {event.get('source')} | {event.get('event')}")
        elif command == "explain":
            if self.alerts:
                event = self.alerts[-1]
                try:
                    cloud_answer = explain_with_gemini(event) if explain_with_gemini else None
                except Exception as error:
                    cloud_answer = f"Gemini unavailable ({type(error).__name__}); using local explanation."
                if cloud_answer:
                    print("Sentinel Gemini analysis:\n" + cloud_answer)
                else:
                    print("Sentinel local analysis: Multiple ports were probed. Review the source and correlate with Zeek or Suricata. Automatic blocking is disabled.")
                print(self.render(event))
            else:
                print("Sentinel: There is no alert to explain.")
        else:
            print("Sentinel: I do not know that command. Type 'help'.")
        return True


def main():
    parser = argparse.ArgumentParser(description="Sentinel interactive security chatbot")
    parser.add_argument("--alert-file", default=os.path.expanduser("~/.sentinel_alerts.jsonl"))
    args = parser.parse_args()
    sentinel = Sentinel(os.path.expanduser(args.alert_file))
    sentinel.load_existing()
    watcher = threading.Thread(target=sentinel.watch, daemon=True)
    watcher.start()
    print("Sentinel is online. Type 'help' for commands.")
    try:
        while sentinel.answer(input("sentinel> ")):
            pass
    except (KeyboardInterrupt, EOFError):
        print("\nSentinel stopped.")
    finally:
        sentinel.stop.set()


if __name__ == "__main__":
    main()
