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
- **Optional online research:** Gemini Google Search grounding returns source
  links; Sentinel asks before each external query. Answers can be incomplete,
  and no AI can guarantee 100% factual accuracy.
- **Opt-in file utilities:** coarse analysis of one local text log and
  non-recursive metadata collection for selected evidence-file extensions,
  plus streaming SHA-2 file hashing.
- **Intent-aware terminal assistant:** routes familiar requests to local log,
  evidence, hashing, and alert tools, and explains Sentinel's behavioral
  detection scope without presenting it as general AI knowledge.
- **Animated terminal experience:** colored startup banner, scanning progress
  animation, live incident output, and interactive alert commands. Animation
  and colors are disabled in non-interactive output; `NO_COLOR` disables color.
- **CLI-only interface:** inspect live alerts and incidents directly in the
  terminal; no web server or dashboard is installed.

## Requirements

- Python 3.10 or newer
- Internet access for the initial dependency installation
- Permission to read the selected firewall or sensor log
- Optional: `GEMINI_API_KEY` for user-approved online search and cloud analysis

## Installation

Clone the repository and enter its directory:

```sh
git clone https://github.com/Yuvraj-26-k/Sentinel-AI.git
cd Sentinel-AI
```

On Linux, install the `sentinel` command once:

### Linux

```sh
sh install_sentinel.sh
```

This creates `.venv`, installs the project, and installs a user-level `sentinel`
launcher in `~/.local/bin`. Manual environment activation is not required. If
`~/.local/bin` is missing from `PATH`, the installer asks before adding it to
`~/.profile`; open a new shell afterward. If you decline, use the printed
`export` command for that shell. After pulling source updates, re-run the
installer if project dependencies changed. It does not fetch Git updates or
run system package commands. The first interactive launch opens the feature
dashboard and latest-report panel.

On first launch with the default UFW source, Sentinel checks whether UFW and
its log are available. If UFW is missing, it offers to install it using the
detected system package manager; if logging appears disabled, it separately
asks whether to run `sudo ufw logging on`. Both actions require your explicit
confirmation. Sentinel never enables the firewall or changes firewall rules.
If you decline setup, it opens the console without live monitoring and tells
you how to select another installed source.

Make sure your account can read `/var/log/ufw.log`; Sentinel does not run the
monitor as root. On systems with ACL support, you can grant read access with:

```sh
sudo setfacl -m "u:$USER:r" /var/log/ufw.log
```

### macOS

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

The default source streams macOS unified logs with the built-in `log` utility.
Some records omit network endpoints; those records cannot be used for port
scan detection.

### Windows PowerShell

Install Python 3.10 or newer, then run:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
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

After installing the project for your platform, start the monitor and live
alert console with one command:

```sh
sentinel
```

On Linux, use the user-level launcher installed above. On macOS and Windows,
activate the virtual environment from the installation steps; in Windows
PowerShell, if script activation is restricted, run
`.\.venv\Scripts\sentinel.exe`. The automatic monitor uses
the platform's default source: UFW on Linux, Windows Filtering Platform on
Windows, and unified logs on macOS. One `Ctrl+C` or `quit` stops the console
and its monitor. Use `sentinel --no-monitor` to open only the console.
Use `sentinel --no-animation` to skip the startup progress effects while
keeping the banner and interactive console.

The console accepts these commands:

| Command | What it does |
| --- | --- |
| `status` | Show recent alerts |
| `alerts` / `recent` | List recent incidents |
| `explain` | Show evidence and safe investigation steps |
| `logs PATH` | Analyze one log file; optionally add `--output REPORT` |
| `collect DIRECTORY` | List evidence-file metadata; optionally save a report |
| `hash FILE` | Print a SHA-2 digest without printing file contents |
| `password generate` / `password check` | Generate or check a secret interactively |
| `features` | Clear the screen and show features with a latest-report panel |
| `report` | Show the latest non-secret report |
| `help` | Show commands |
| `quit` | Exit the console |

File-tool commands can also be run directly as `sentinel logs ...`,
`sentinel collect ...`, and `sentinel hash ...`. In the console, natural
requests such as `analyze logs "path with spaces"` and `collect evidence
"directory"` route to these same local commands. `analyze alert` and `explain`
show the newest alert using its recorded evidence.

Interactive file analysis, hashing, explanations, and online answers ask before
saving a report under `~/.sentinel/reports/`; decline to keep it on screen only.
Generated passwords are never included in saved reports. `features` shows a
two-panel overview; its feature list does not show scan history.

### Online research and privacy

Set `GEMINI_API_KEY` and, optionally, `GEMINI_WEB_MODEL` to enable current web
research through Gemini Google Search grounding. For each free-form online
question, Sentinel asks before sending that question to Google/Gemini. It does
not attach alerts or local logs to a web-research query. `explain` separately
asks before sending alert telemetry for cloud evidence selection. Answers show
available citations and an uncertainty warning; search coverage, sources, and
model output can be wrong or incomplete, so verify important information with
primary sources. Without a key, local monitoring and tools continue to work.

### Analyze logs and collect evidence files

The standalone utilities do not start the monitor or interactive console.
Analyze a single local text log and optionally save the report:

```sh
sentinel logs /path/to/application.log
sentinel logs /path/to/application.log --output /path/to/log-report.txt
```

The report includes byte, line, word, and character totals; case-sensitive
substring counts for `INFO`, `WARNING`, and `ERROR`; unique email candidates;
and unique IP addresses validated with Python's `ipaddress` module. Invalid IP
candidates are omitted. Input is decoded as UTF-8 with invalid byte sequences
replaced. These are coarse, file-level indicators and statistics—not
normalized network telemetry, traffic analysis, or proof of malicious activity.
The command reads only the file explicitly named.

Collect metadata from matching regular files in one directory, without
descending into subdirectories:

```sh
sentinel collect /path/to/evidence
sentinel collect /path/to/evidence --output /path/to/evidence-report.txt
```

The collector includes only case-sensitive `.txt`, `.log`, `.pdf`, `.docx`,
`.exe`, `.bat`, and `.ps1` extensions, and reports each filename, extension,
size, and absolute path. A new report destination is written after scanning,
so it is not included in that scan. An existing matching file in the scanned
directory is never overwritten as a report destination. Inaccessible entries
are reported and cause a non-zero exit status; report write failures are
reported as errors.

These utilities adapt only the useful behaviors identified from shallow
inspection of the source tool repositories; they are not full ports of those
projects. They do not recurse, execute files, inspect document contents, or
send data to a service. Use `python -m sentinel logs ...` and
`python -m sentinel collect ...` as equivalents when invoking from a source
checkout.

### Hash files and handle passwords safely

Hash one file with SHA-256 (the default) or another allow-listed SHA-2
algorithm:

```sh
sentinel hash /path/to/evidence.bin
sentinel hash /path/to/evidence.bin --algorithm sha512
sentinel hash /path/to/evidence.bin --output /path/to/digest-report.txt
```

Files are read in chunks. Only the path, algorithm, and digest are shown; file
contents are never printed or persisted. A digest report is strictly
create-only: an existing output path is rejected, and the source file cannot
be used as the output path.

Password tools are opt-in and require an interactive terminal:

```sh
sentinel password generate --length 24
sentinel password check
```

Generation uses Python's `secrets` module and accepts lengths from 8 through
256 (default 20). The generated secret is shown once in the terminal and is
never saved; generation refuses redirected/non-interactive output. The checker
uses hidden input and reports only a simple composition heuristic (minimum
length, lowercase, uppercase, digit, and symbol), not entropy or a guarantee
of password strength. Password text is not logged, saved, or sent to Gemini.

For source-checkout invocation, the equivalents are
`python -m sentinel hash ...` and `python -m sentinel password ...`.

The baseline and source status are saved when Sentinel stops. Animation is
shown only in a terminal and can be disabled by redirecting output. Set
`NO_COLOR=1` to disable colors.

### Select a source

Pass a source to the monitor. File-based sources start at the current end of
the file and follow new records:

```sh
sentinel --source ufw
sentinel --source windows-firewall --log-file "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
sentinel --source suricata --log-file /var/log/suricata/eve.json
sentinel --source zeek --log-file /usr/local/zeek/logs/current/conn.log
```

Supported sources are `auto`, `ufw`, `windows-firewall`, `windows-native`,
`macos-unified`, `suricata`, and `zeek`. UFW is the default Linux source;
Windows Firewall W3C files and the native Windows event stream are separate
options. Suricata consumes EVE JSON and Zeek consumes `conn.log` TSV.

Additional thresholds can be configured, for example:

```sh
sentinel --source auto --scan-window-seconds 60 --vertical-ports 15 --horizontal-hosts 10 --slow-window-seconds 900
```

Run `sentinel --help` to see console options or
`python -m sentinel monitor --help` for all thresholds and data-file options.
Events without a destination port are retained where supported but
cannot contribute to port-scan detection.

### Optional local analysis and Gemini

Run a local example analysis or search the built-in triage guidance:

```sh
python -m sentinel analyze --source 192.0.2.10 --events 20 --unique-ports 18 --duration 10
python -m sentinel analyze --query "correlate firewall events"
```

The Isolation Forest is a behavioral anomaly scorer over recorded network
event features after sufficient normal history; it is not a general-purpose
language model or source of broad factual knowledge. To enable optional Gemini
explanations, set `GEMINI_API_KEY` and optionally
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
history at `~/.nmap_ai_baseline.json`. Override paths with the monitor's
`--database-file`, `--alert-file`, and `--model-file` options.

## Project layout

The repository has eight tracked project files: four cohesive runtime modules,
one consolidated test file, this guide, the package/install configuration, and
`.gitignore`.

## Tests

Run the full regression suite:

```sh
python -m unittest -v test_sentinel
```

The tests cover platform adapters, detection, anomaly scoring, incident
persistence, rotation, CLI behavior, and evidence validation. They cannot
verify operating-system audit settings, real firewall behavior, permissions,
or production incident response.
