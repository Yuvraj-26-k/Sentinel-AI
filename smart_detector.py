#!/usr/bin/env python3
"""Self-learning defensive port-scan detector.

Learns normal per-source activity with a persistent mean/variance baseline.
It reports anomalies but never changes firewall rules automatically.
"""

import argparse
import json
import math
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime

DEFAULT_LOG = "/var/log/ufw.log"
DEFAULT_MODEL = os.path.expanduser("~/.nmap_ai_baseline.json")
WINDOW_SECONDS = 60
MIN_SAMPLES = 20
ANOMALY_Z = 4.0
PORT_THRESHOLD = 15

PATTERN = re.compile(
    r"SRC=(?P<src>\S+).*?DST=(?P<dst>\S+).*?DPT=(?P<dpt>\d+)"
)
FEATURES = ("events", "unique_ports", "ports_per_second")
events = defaultdict(deque)
last_alert = {}


class Baseline:
    def __init__(self, path):
        self.path = path
        self.data = {}
        try:
            with open(path, "r", encoding="utf-8") as handle:
                self.data = json.load(handle)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def update(self, source, values):
        item = self.data.setdefault(source, {"count": 0, "mean": {}, "m2": {}})
        item["count"] += 1
        count = item["count"]
        for name, value in zip(FEATURES, values):
            old_mean = item["mean"].get(name, 0.0)
            delta = value - old_mean
            item["mean"][name] = old_mean + delta / count
            item["m2"][name] = item["m2"].get(name, 0.0) + delta * (value - item["mean"][name])

    def anomaly_score(self, source, values):
        item = self.data.get(source)
        if not item or item["count"] < MIN_SAMPLES:
            return None
        scores = []
        for name, value in zip(FEATURES, values):
            variance = item["m2"].get(name, 0.0) / max(item["count"] - 1, 1)
            standard_deviation = max(math.sqrt(variance), 0.1)
            scores.append(abs(value - item["mean"].get(name, 0.0)) / standard_deviation)
        return max(scores)

    def save(self):
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        temporary = f"{self.path}.tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(self.data, handle, indent=2)
        os.replace(temporary, self.path)


def report(source, ports, values, score, learning):
    now = time.time()
    if now - last_alert.get(source, 0) < 300:
        return
    last_alert[source] = now
    mode = "learning" if learning else f"anomaly_score={score:.2f}"
    print(
        f"[ALERT] Possible scan | source={source} | unique_ports={len(ports)} | "
        f"events={len(ports)} | {mode} | time={datetime.now().isoformat(timespec='seconds')}",
        flush=True,
    )


def process_line(line, baseline):
    match = PATTERN.search(line)
    if not match:
        return
    source = match.group("src")
    port = int(match.group("dpt"))
    now = time.time()
    events[source].append((now, port))
    while events[source] and now - events[source][0][0] > WINDOW_SECONDS:
        events[source].popleft()

    ports = {item[1] for item in events[source]}
    values = (len(events[source]), len(ports), len(ports) / WINDOW_SECONDS)
    score = baseline.anomaly_score(source, values)
    suspicious = len(ports) >= PORT_THRESHOLD or (score is not None and score >= ANOMALY_Z)

    if suspicious:
        report(source, ports, values, score or 0.0, score is None)
    elif len(events[source]) >= 3:
        baseline.update(source, values)


def follow_file(path, baseline):
    if not os.path.exists(path):
        print(
            f"Log file not found: {path}\n"
            "Enable UFW logging with: sudo ufw logging on\n"
            "Or use --log-file /path/to/firewall.log",
            flush=True,
        )
        return
    with open(path, "r", encoding="utf-8", errors="ignore") as logfile:
        logfile.seek(0, 2)
        while True:
            line = logfile.readline()
            if not line:
                baseline.save()
                time.sleep(0.5)
                continue
            process_line(line, baseline)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Self-learning Nmap scan detector")
    parser.add_argument("--log-file", default=DEFAULT_LOG)
    parser.add_argument("--model-file", default=DEFAULT_MODEL)
    args = parser.parse_args()
    print(f"Monitoring {args.log_file}. Learning baseline at {args.model_file}.")
    try:
        follow_file(args.log_file, Baseline(args.model_file))
    except KeyboardInterrupt:
        print("\nStopped safely.")
