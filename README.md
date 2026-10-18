# Sentinel-AI

Sentinel-AI is a **defensive, local-first port-scan monitoring prototype**. It reads firewall-style log lines, detects one source probing many destination ports within a rolling window, stores alerts locally, and provides a terminal console for reviewing them.

It is not an intrusion-prevention system, a packet capture engine, or a general-purpose AI. It **does not block IPs, change firewall rules after setup, execute response actions, or guarantee that an event is malicious**.

## What Sentinel actually does

1. `smart_detector.py` reads a log file that contains `SRC=`, `DST=`, and `DPT=` fields, such as UFW firewall logs.
2. It keeps a rolling 60-second window per source IP.
3. It alerts when a source reaches 15 unique destination ports, or when a trained per-source statistical baseline finds an unusual event/port/rate combination.
4. It writes JSON Lines alerts to `~/.sentinel_alerts.jsonl` by default. Each alert includes source, destination, event count, unique-port count, confidence, and anomaly metadata when available.
5. `sentinel.py` shows new alerts in a terminal and can persist them to a local SQLite database through SQLAlchemy.
6. `rag_agent.py` performs transparent local keyword retrieval from reviewed Markdown files in `knowledge/` and returns a recommendation. It does not call external tools or block hosts.

## Requirements

- Python 3.10 or newer
- Linux with UFW logging for the default live-monitoring path
- Permission to read the chosen log file
- Internet access only for the one-time Python dependency install or optional Gemini explanation feature

The scan detector itself uses the Python standard library. The interactive console's SQLite alert history uses SQLAlchemy, installed from `requirements.txt`.

## Install

```bash
cd /path/to/Sentinel-AI
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

Do not run the console as root. Only use elevated privileges when your operating system requires them to enable or read a protected firewall log.

## Quick start on Linux with UFW

Enable UFW logging once if you administer this host:

```bash
sudo ufw logging on
```

Start the detector in one terminal:

```bash
cd /path/to/Sentinel-AI
sudo .venv/bin/python smart_detector.py \
  --log-file /var/log/ufw.log \
  --alert-file "$HOME/.sentinel_alerts.jsonl" \
  --model-file "$HOME/.nmap_ai_baseline.json"
```

Start the console in a second terminal:

```bash
cd /path/to/Sentinel-AI
.venv/bin/python sentinel.py --alert-file "$HOME/.sentinel_alerts.jsonl"
```

Use `help`, `status`, `alerts`, `recent`, `explain`, or `quit` in the console.

### One-command launcher

```bash
./sentinel
```

The launcher creates `.venv` when missing, installs dependencies, attempts `sudo ufw logging on`, starts `smart_detector.py`, then opens the terminal console. It does not automatically block a source. To monitor another compatible log file, set:

```bash
export SENTINEL_LOG_FILE=/path/to/firewall.log
export SENTINEL_ALERT_FILE="$HOME/.sentinel_alerts.jsonl"
export SENTINEL_MODEL_FILE="$HOME/.nmap_ai_baseline.json"
./sentinel
```

## Use another compatible log source

The current detector requires lines containing all three fields below in any order:

```text
SRC=<source-ip> ... DST=<destination-ip> ... DPT=<destination-port>
```

Example:

```bash
.venv/bin/python smart_detector.py --log-file /path/to/compatible.log
```

If a source does not emit these fields, Sentinel will not parse it. UFW is the default supported live source. Packet-level sources such as Zeek or Suricata require a dedicated adapter before their native logs can be monitored directly.

## Detection and baseline behavior

- Rolling window: 60 seconds
- Port-scan threshold: 15 unique destination ports
- Baseline features: number of events, number of unique ports, and unique ports per second
- Baseline learning: a source needs at least 20 normal samples before statistical anomaly scoring is available
- Alert cooldown: 300 seconds per source

Suspicious windows are not added to the baseline. Delete the model file to reset learned values. A high score is a signal for review, not proof of an attack.

## Local analyst and knowledge retrieval

Analyze supplied scan features:

```bash
.venv/bin/python rag_agent.py --source 192.0.2.10 --events 20 --unique-ports 18 --duration 10
```

Search the local guidance:

```bash
.venv/bin/python rag_agent.py --query "port scan response"
```

`rag_agent.py` combines fixed thresholds, the saved baseline, and keyword-matched excerpts from `knowledge/*.md`. Its output is an explainable JSON recommendation, not autonomous action.

## Optional Gemini explanation

The `explain` console command can request a cloud explanation only when you intentionally configure `GEMINI_API_KEY`:

```bash
export GEMINI_API_KEY="your_private_key"
export GEMINI_MODEL="gemini-2.0-flash"
.venv/bin/python sentinel.py
```

Without a key, Sentinel uses its local explanation. Never commit an API key. Supplying a key means the selected alert context is sent to that provider.

## Windows and macOS

- **Windows:** `sentinel.ps1` creates a virtual environment, installs Python dependencies, optionally runs the included Sysmon installer, and watches `firewall.log` in the project folder by default. Set `SENTINEL_LOG_FILE` to a compatible Windows Firewall or converted log file. Sysmon XML normalization is provided by `sysmon_adapter.py`, but it is not automatically wired into the live detector.
- **macOS:** use a compatible log file with `SENTINEL_LOG_FILE`. UFW is not the default macOS firewall, so `/var/log/ufw.log` will normally not exist.

## Safe authorized test

Only from a system you own or are explicitly authorized to test:

```bash
nmap -sS -p 1-100 <authorized-test-host>
```

Review the resulting alert and corroborate it with host, firewall, and network telemetry before any response decision.

## Validate changes

```bash
.venv/bin/python -m unittest -v test_smart_detector.py
```

The tests cover alert schema fidelity and a full parsed-log-to-alert path. They do not validate a real firewall, packet capture, or production incident response workflow.
