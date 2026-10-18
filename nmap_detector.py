#!/usr/bin/env python3
"""Basic defensive detector for possible Nmap-style port scans.

Reads UFW firewall logs and alerts when one source probes many ports
within a rolling time window. Use only on systems you own or administer.
"""

import argparse
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime

LOG_FILE = "/var/log/ufw.log"
WINDOW_SECONDS = 60
PORT_THRESHOLD = 15
ALERT_COOLDOWN = 300

events = defaultdict(deque)
last_alert = {}

PATTERN = re.compile(
    r"SRC=(?P<src>\S+).*?DST=(?P<dst>\S+).*?DPT=(?P<dpt>\d+)"
)


def alert(source_ip, ports, event_count):
    now = time.time()
    if now - last_alert.get(source_ip, 0) < ALERT_COOLDOWN:
        return

    last_alert[source_ip] = now
    print(
        f"[ALERT] Possible Nmap scan | source={source_ip} | "
        f"unique_ports={len(ports)} | events={event_count} | "
        f"time={datetime.now().isoformat(timespec='seconds')}",
        flush=True,
    )


def process_line(line):
    match = PATTERN.search(line)
    if not match or not match.group("dpt"):
        return

    source_ip = match.group("src")
    destination_port = int(match.group("dpt"))
    now = time.time()
    events[source_ip].append((now, destination_port))

    while events[source_ip] and now - events[source_ip][0][0] > WINDOW_SECONDS:
        events[source_ip].popleft()

    ports = {port for _, port in events[source_ip]}
    if len(ports) >= PORT_THRESHOLD:
        alert(source_ip, ports, len(events[source_ip]))


def follow_file(path):
    if not os.path.exists(path):
        print(
            f"Log file not found: {path}\n"
            "Enable UFW logging with: sudo ufw logging on\n"
            "Then restart this detector. You can also provide another log "
            "file with: python3 nmap_detector.py --log-file /path/to/log",
            flush=True,
        )
        return

    with open(path, "r", encoding="utf-8", errors="ignore") as logfile:
        logfile.seek(0, 2)
        while True:
            line = logfile.readline()
            if not line:
                time.sleep(0.5)
                continue
            process_line(line)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect possible Nmap scans in firewall logs")
    parser.add_argument("--log-file", default=LOG_FILE, help=f"Log file to monitor (default: {LOG_FILE})")
    args = parser.parse_args()

    print(f"Monitoring {args.log_file}. Press Ctrl-C to stop.")
    try:
        follow_file(args.log_file)
    except KeyboardInterrupt:
        print("\nStopped.")
