# Sentinel-AI

**Local-first network security monitoring in your terminal.** Sentinel-AI
normalizes firewall and network-sensor logs, detects possible scans, scores
unusual behavior, and keeps an evidence-backed incident history. It runs on
Linux, Windows, and macOS, with optional Suricata and Zeek input.

Sentinel is a defensive monitoring tool—not an intrusion-prevention system. It
does not block traffic, change firewall rules, or claim that an alert proves
an attack.

## Features

- **One event format:** UFW, Windows Filtering Platform and Firewall, Sysmon,
  macOS unified logs, Suricata EVE JSON, and Zeek connection logs.
- **Useful scan rules:** configurable vertical, horizontal, slow, SYN, and
  connection-failure detection when the source provides the necessary signals.
- **Local anomaly scoring:** an Isolation Forest scores event volume, port and
  destination diversity, rate, timing, and active duration after it has enough
  normal history. Scores are not probabilities or proof of malicious activity.
- **Incident history:** SQLite storage, duplicate-event handling, incident
  aggregation, event timelines, source health, and restart recovery.
- **Evidence-grounded analysis:** local triage guidance and optional Gemini
  analysis can only surface alert evidence and approved investigation steps.
- **Animated terminal experience:** colored startup banner, scanning progress
  animation, live incident output, and interactive alert commands. Animation
  and colors are disabled in non-interactive output; `NO_COLOR` disables color.
- **Optional local API:** read-only JSON endpoints and a live SSE stream,
  bound to loopback. There is no web dashboard.

## Requirements

- Python 3.10 or newer
- Internet access for the initial dependency installation
- Permission to read the selected firewall or sensor log
- Optional: `GEMINI_API_KEY` for cloud-assisted explanations

## Installation

Clone the repository and enter its directory:

```sh
git clone https://github.com/Yuvraj-26-k/Sentinel-AI.git
cd Sentinel-AI
```

Create a virtual environment and install dependencies. Use the commands for
your operating system.

### Linux

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

For the default UFW source, enable firewall logging once:

```sh
sudo ufw logging on
```

Make sure your account can read `/var/log/ufw.log`. For example, on systems
with ACL support, grant your account read access rather than running the whole
application as root:

```sh
sudo setfacl -m "u:$USER:r" /var/log/ufw.log
```

### macOS

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The default source streams macOS unified logs with the built-in `log` utility.
Some records omit network endpoints; those records cannot be used for port
scan detection.

### Windows PowerShell

Install Python 3.10 or newer, then run:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The default source reads Windows Filtering Platform Security events. To
collect connection events, enable the Windows audit subcategory from an
elevated PowerShell prompt:

```powershell
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

The account running Sentinel also needs permission to read the Security event
log. Sysmon network-connect events are included when Sysmon is already
installed and accessible; Sysmon is optional.

## Run Sentinel

Start the detector in one terminal:

```sh
python sentinel.py monitor
```

Open a second terminal in the repository directory, activate the same virtual
environment, and start the interactive alert console:

```sh
python sentinel.py
```

The monitor uses the platform's default source: UFW on Linux, Windows Filtering
Platform on Windows, and unified logs on macOS. The console follows the alert
file and accepts these commands:

| Command | What it does |
| --- | --- |
| `status` | Show recent alerts |
| `alerts` / `recent` | List recent incidents |
| `explain` | Show evidence and safe investigation steps |
| `help` | Show commands |
| `quit` | Exit the console |

Stop the monitor with `Ctrl+C`; the baseline and source status are saved.
Animation is shown only in a terminal and can be disabled by redirecting
output. Set `NO_COLOR=1` to disable colors.

### Select a source

Pass a source to the monitor. File-based sources start at the current end of
the file and follow new records:

```sh
python sentinel.py monitor --source ufw
python sentinel.py monitor --source windows-firewall --log-file "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
python sentinel.py monitor --source suricata --log-file /var/log/suricata/eve.json
python sentinel.py monitor --source zeek --log-file /usr/local/zeek/logs/current/conn.log
```

Supported sources are `auto`, `ufw`, `windows-firewall`, `windows-native`,
`macos-unified`, `suricata`, and `zeek`. UFW is the default Linux source;
Windows Firewall W3C files and the native Windows event stream are separate
options. Suricata consumes EVE JSON and Zeek consumes `conn.log` TSV.

Additional thresholds can be configured, for example:

```sh
python sentinel.py monitor --source auto --scan-window-seconds 60 --vertical-ports 15 --horizontal-hosts 10 --slow-window-seconds 900
```

See `python sentinel.py monitor --help` for all thresholds and data-file
options. Events without a destination port are retained where supported but
cannot contribute to port-scan detection.

### Optional local API

Run the read-only API in another terminal if local tools need access to
telemetry:

```sh
python -m uvicorn sentinel:app --host 127.0.0.1 --port 8000
```

Available endpoints:

- `GET /api/health`
- `GET /api/events?limit=100`
- `GET /api/incidents?limit=100`
- `GET /api/incidents/{incident_id}`
- `GET /api/stream` (Server-Sent Events)

The API binds to loopback and has no interactive documentation or web UI. Do
not expose it publicly without adding authentication and transport security.

### Optional local analysis and Gemini

Run a local example analysis or search the built-in triage guidance:

```sh
python sentinel.py analyze --source 192.0.2.10 --events 20 --unique-ports 18 --duration 10
python sentinel.py analyze --query "correlate firewall events"
```

To enable Gemini explanations, set `GEMINI_API_KEY` and optionally
`GEMINI_MODEL`. Gemini receives the selected alert context; its free-form
claims are not shown. Sentinel validates proposed evidence against the alert
and restricts investigation steps to an allow-list. Without a key, local
evidence-bound analysis still works.

## Detection and data

Vertical scans are grouped by source and destination. Horizontal detection
looks for a source probing many hosts on a small set of ports. Slow, SYN, and
connection-failure patterns are only classified when configured thresholds
are met and telemetry supports the distinction. Otherwise Sentinel reports a
**possible scan**.

The Isolation Forest is unsupervised and requires at least 30 normal feature
samples per source before scoring. Its raw decision score is not a probability.
Suspicious windows are excluded from normal training samples.

By default, Sentinel stores its SQLite event and incident database at
`~/.sentinel.db`, alert JSON Lines at `~/.sentinel_alerts.jsonl`, and model
history at `~/.nmap_ai_baseline.json`. Override paths with the detector's
`--database-file`, `--alert-file`, and `--model-file` options.

## Project layout

The repository keeps the runtime in four cohesive Python modules, one
consolidated regression test file, this guide, the dependency list, and
`.gitignore`—eight project files total. The runtime modules group telemetry,
detection, analysis, and the terminal/API surfaces.

## Tests

Run the full regression suite:

```sh
python -m unittest -v test_sentinel
```

The tests cover platform adapters, detection, anomaly scoring, incident
persistence, rotation, API behavior, and evidence validation. They cannot
verify operating-system audit settings, real firewall behavior, permissions,
or production incident response.
