# Sentinel-AI

Sentinel-AI is a **defensive, local-first network event monitoring prototype**. Platform and sensor adapters normalize native firewall and connection telemetry into one event schema. The existing detector uses those events to detect one source probing many destination ports within a rolling window, stores alerts locally, and provides a terminal console for reviewing them.

It is not an intrusion-prevention system, a packet capture engine, or a general-purpose AI. It **does not block IPs, change firewall rules after setup, execute response actions, or guarantee that an event is malicious**.

## What Sentinel actually does

1. `smart_detector.py` ingests normalized events from a platform-native stream or a supported log file.
2. It keeps a rolling 60-second window per source IP and applies explicit scan rules.
3. A locally trained Isolation Forest scores event volume, port and destination diversity, rates, inter-arrival timing, and active span after sufficient normal history is collected.
4. It writes JSON Lines alerts to `~/.sentinel_alerts.jsonl` by default. Alerts include rule signals, ML/statistical scores, source telemetry, and behavioral evidence when available.
5. `sentinel.py` shows new alerts in a terminal, persists them locally through SQLAlchemy, and provides evidence-bound investigation guidance.
6. `rag_agent.py` performs transparent local retrieval from reviewed Markdown guidance; retrieval is separate from the trained anomaly model and does not treat documents as telemetry evidence.

## Requirements

- Python 3.10 or newer
- Linux, Windows, or macOS; UFW is the default Linux source
- Permission to read the selected event log or native event stream
- Internet access only for the one-time Python dependency install or optional Gemini explanation feature

The detector uses scikit-learn for its local Isolation Forest. The interactive console's SQLite alert history uses SQLAlchemy; both are installed from `requirements.txt`.

## Install

```bash
cd /path/to/Sentinel-AI
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

Do not run the console as root. Only use elevated privileges when your operating system requires them to enable or read a protected firewall log.

## Quick start

The automatic source is platform-specific: Linux follows UFW, Windows reads Windows Filtering Platform events and available Sysmon network events, and macOS follows unified firewall/network logs. Use `--source` to select another adapter.

### Linux with UFW

Enable UFW logging once if you administer this host:

```bash
sudo ufw logging on
```

Start the detector in one terminal:

```bash
cd /path/to/Sentinel-AI
sudo .venv/bin/python smart_detector.py \
  --source ufw \
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

The launcher creates `.venv` when missing, installs dependencies, attempts to enable UFW logging on Linux, starts `smart_detector.py` with the platform's automatic source, then opens the terminal console. It does not automatically block a source. Set `SENTINEL_SOURCE` to choose an adapter and `SENTINEL_LOG_FILE` for a file-based source:

```bash
export SENTINEL_LOG_FILE=/path/to/firewall.log
export SENTINEL_SOURCE=windows-firewall
export SENTINEL_ALERT_FILE="$HOME/.sentinel_alerts.jsonl"
export SENTINEL_MODEL_FILE="$HOME/.nmap_ai_baseline.json"
./sentinel
```

## Supported ingestion sources

Every adapter emits the same event fields: timestamp, platform, sensor, source, destination, destination port, protocol, action, event type, and the original record. Events without a usable destination port are ignored by the port-scan detector.

- **Linux:** UFW/kernel firewall logs (`ufw`, default); supports `SRC=`, `DST=`, `DPT=`, `PROTO=`, and UFW actions.
- **Windows:** native Windows Filtering Platform Security events 5156/5157 plus Sysmon network-connect event 3 (`windows-native`, default); Windows Firewall W3C logs are available with `windows-firewall`. Enable WFP connection auditing and grant access to the Security log. Sysmon is optional; unavailable Sysmon telemetry is reported and does not disable WFP collection.
- **macOS:** native unified logs for `socketfilterfw`, `com.apple.alf`, and `com.apple.network` (`macos-unified`, default). Only records with parseable source/destination addresses and destination ports enter the port-scan detector; unified messages that omit endpoints cannot contribute.
- **Network sensors:** Suricata EVE JSON (`suricata`) and Zeek `conn.log` TSV/JSON (`zeek`).

Follow a Suricata EVE JSON file:

```sh
.venv/bin/python smart_detector.py --source suricata --log-file /var/log/suricata/eve.json
```

Follow a Zeek connection log:

```sh
.venv/bin/python smart_detector.py --source zeek --log-file /usr/local/zeek/logs/current/conn.log
```

Follow Windows Firewall W3C output (use `SENTINEL_SOURCE=windows-firewall` and optionally set `SENTINEL_LOG_FILE`; default path is the Windows Firewall log directory). For native defaults, run `python smart_detector.py --source auto`. File-based sources begin at the end of their log and process newly appended records.

## Detection and baseline behavior

- Rolling window: 60 seconds
- Deterministic rules: 15 unique destination ports, or 15 or more events with at least 1 unique destination port per active second; the rolling window is 60 seconds
- Isolation Forest features: event count, unique ports, port rate, unique destinations, destination rate, mean and standard deviation of inter-arrival time, and active span
- ML training: 30 normal feature samples per source are required; Sentinel records at most one sample per source every 10 seconds and excludes rule- or model-suspicious windows
- Model persistence: bounded recent samples and the existing statistical baseline are stored in the JSON model file; model fitting is local and reproducible
- ML score: raw Isolation Forest decision distance, not a probability or a trained malicious/benign classifier; negative decision-function values are flagged
- Incident merge interval: 900 seconds by default, independently configurable

Suspicious windows are not added to either baseline. Training is unsupervised and learns observed normal behavior; it does not establish malicious intent. Delete the model file to reset the learned history. A high score is a signal for review, not proof of an attack.

### Scan detection thresholds

The CLI accepts `--scan-window-seconds`, `--vertical-ports`, `--horizontal-window-seconds`, `--horizontal-hosts`, `--horizontal-min-events`, `--horizontal-max-ports`, `--slow-window-seconds`, `--slow-ports`, `--syn-ports`, `--failure-events`, and `--incident-merge-seconds`. All thresholds must be positive integers. Defaults detect vertical scans per source-and-destination pair, horizontal scans by one source across many hosts on a few ports, slow vertical scans across 15 minutes, and SYN/failure sweeps only when the adapter supplies relevant flags or connection outcomes. A generic log record yields a **possible** scan classification, never a claim that a scan or compromise is confirmed.

Each distinct observation is retained and associated with an open incident. Repeated observations update incident counts and evidence instead of being hidden by an alert cooldown. Events are deduplicated on stable sensor event identifiers when available, otherwise on a canonical event fingerprint.

## Durable telemetry API

The SQLite database at `~/.sentinel.db` stores normalized events, incident timelines, and ingestion health; recent events are replayed on startup to warm bounded in-memory detection windows. Event timestamps are kept separately from ingestion timestamps. Implausibly future source clocks are clamped for detection while the original timestamp and clock skew remain in telemetry. File-based sources detect truncation and rotation; malformed records are skipped without terminating ingestion. Source clock skew and fallback timestamp quality are recorded on each event.

Sentinel remains a terminal-first application; the optional API has no hosted dashboard or interactive API docs. The one-command launcher starts the read-only API bound to loopback at port `8000` by default. Override with `SENTINEL_API_PORT`. To run it separately:

```sh
.venv/bin/python -m uvicorn api:app --host 127.0.0.1 --port 8000
```

Read-only endpoints:

- `GET /api/health` — stored-event and open-incident counts plus source health
- `GET /api/events?limit=100` — recent event telemetry
- `GET /api/incidents?limit=100` — incident history
- `GET /api/incidents/{incident_id}` — incident evidence and event timeline
- `GET /api/stream` — server-sent event stream for new telemetry

The API intentionally binds to `127.0.0.1`; do not expose it publicly without adding authentication and transport security.

## Local analyst and knowledge retrieval

Analyze supplied scan features:

```bash
.venv/bin/python rag_agent.py --source 192.0.2.10 --events 20 --unique-ports 18 --duration 10
```

Search the local guidance:

```bash
.venv/bin/python rag_agent.py --query "port scan response"
```

`rag_agent.py` combines fixed rules, available per-source Isolation Forest and statistical scores, and keyword-matched excerpts from `knowledge/*.md`. Its output is an explainable JSON recommendation, not autonomous action.

## Optional Gemini explanation

The `explain` console command always provides a local evidence summary and safe investigation steps. If you intentionally configure `GEMINI_API_KEY`, Gemini may select telemetry fields and approved investigation steps, but Sentinel discards free-form claims and validates every selected field/value against the alert before displaying it:

```bash
export GEMINI_API_KEY="your_private_key"
export GEMINI_MODEL="gemini-2.0-flash"
.venv/bin/python sentinel.py
```

Without a key, Sentinel uses its local evidence-bound explanation. Never commit an API key. Supplying a key sends the selected alert context to that provider; AI output is not trusted as telemetry or as a response action.

## Safe authorized test

Only from a system you own or are explicitly authorized to test:

```bash
nmap -sS -p 1-100 <authorized-test-host>
```

Review the resulting alert and corroborate it with host, firewall, and network telemetry before any response decision.

## Validate changes

```bash
.venv/bin/python -m unittest -v test_smart_detector.py
.venv/bin/python -m unittest -v test_event_adapters.py
.venv/bin/python -m unittest -v test_ml_analyst.py
.venv/bin/python -m unittest -v test_incident_pipeline.py test_api.py
.venv/bin/python -m unittest -v test_sentinel_ui.py
```

These tests cover adapter normalization, ML scoring, evidence validation, and alert paths. They do not validate operating-system audit policy, permissions, real firewall behavior, packet capture, or production incident response workflows.
