# Nmap AI Detector

A small defensive prototype that monitors `/var/log/ufw.log` and alerts when a source IP probes many destination ports within a short window.

## Installation

The core detector and RAG agent use only Python's standard library. The optional cloud-LLM HTTP client is listed in `requirements.txt`.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

No API key is included or required for local detection and RAG. A cloud provider and an environment variable such as `LLM_API_KEY` must be configured separately before adding a provider adapter.

```bash
cd /home/yuvi/nmap_ai_detector
sudo ufw logging on
sudo python3 nmap_detector.py
```

If your system stores firewall events in a different file, specify it explicitly:

```bash
sudo python3 nmap_detector.py --log-file /path/to/firewall.log
```

If `/var/log/ufw.log` is missing, the detector now exits with instructions instead of crashing.

Configuration values are at the top of `nmap_detector.py`:

- `LOG_FILE`: firewall log path
- `WINDOW_SECONDS`: rolling detection window
- `PORT_THRESHOLD`: unique ports required for an alert
- `ALERT_COOLDOWN`: seconds between repeated alerts for one source

## Authorized test

From a machine you own or are authorized to test:

```bash
nmap -sS -p 1-100 <authorized-test-host>
```

## Self-learning mode

Use the new detector to learn a baseline of normal activity:

```bash
sudo python3 smart_detector.py
```

It stores its baseline in `~/.nmap_ai_baseline.json`. You can choose another location:

```bash
sudo python3 smart_detector.py --log-file /path/to/firewall.log --model-file /path/to/baseline.json
```

The learner ignores suspicious windows while updating its baseline. It reports unusual behavior and never changes firewall rules automatically. Keep blocking manual until you have reviewed the alerts. Delete the model file to reset learning.

This is a focused anomaly detector, not a general-purpose AI like Claude. It does not require external packages or an internet connection.

## One-command startup

From the project directory, run:

```bash
./sentinel
```

The launcher automatically:

- Creates `.venv` if needed
- Installs `requirements.txt`
- Enables UFW logging when UFW is installed
- Starts `smart_detector.py`
- Opens the interactive Sentinel chatbot
- Stops the detector when you quit Sentinel

The launcher may ask for your sudo password to enable UFW logging. Use `Ctrl-C` or type `quit` to stop safely. If you want the command available as `sentinel` without `./`, run:

```bash
mkdir -p ~/.local/bin
ln -sf "$PWD/sentinel" ~/.local/bin/sentinel
export PATH="$HOME/.local/bin:$PATH"
```

Optional settings:

```bash
export SENTINEL_LOG_FILE=/var/log/ufw.log
export SENTINEL_ALERT_FILE="$HOME/.sentinel_alerts.jsonl"
export SENTINEL_MODEL_FILE="$HOME/.nmap_ai_baseline.json"
```


## Sysmon and SQLAlchemy

Sentinel now includes:

- `sysmon_adapter.py`: normalizes exported Windows Sysmon XML events.
- `alert_store.py`: stores normalized alerts in SQLite through SQLAlchemy.
- `~/.sentinel.db`: default local alert database.

Sentinel automatically stores JSONL alerts in the SQLAlchemy database and can show recent history with `status` or `alerts`. Use another database path with:

```bash
python sentinel.py --database-file /path/to/sentinel.db
```

On Windows, install Sysmon from Microsoft's official Sysinternals documentation and configure Windows Event Log collection. Sysmon is not installed automatically by Sentinel because it requires administrator privileges and an OS-specific configuration. Export or forward Sysmon event XML to the adapter before ingestion. Linux and macOS continue using their native log sources.


## Operating systems

The Python core works on Linux, Windows, and macOS.

- **Linux/macOS:** run `./sentinel`. Linux attempts UFW logging; macOS/Linux can use `SENTINEL_LOG_FILE` for another log.
- **Windows:** install Python 3, then double-click `sentinel.bat` or run `./sentinel.ps1` from PowerShell. Windows does not use UFW, so the launcher monitors `firewall.log` in the project directory by default.

On Windows, use Windows Firewall logging or another authorized telemetry source and set its path:

```powershell
$env:SENTINEL_LOG_FILE = "C:\path\to\firewall.log"
.\sentinel.bat
```

The launcher creates the correct platform virtual environment, installs dependencies, starts the detector, and opens the chatbot. It does not install OS firewall tools or change firewall rules automatically.

## Manual two-terminal mode

Run the detector in one terminal and Sentinel in another:

```bash
sudo python smart_detector.py --alert-file ~/.sentinel_alerts.jsonl
python sentinel.py
```

Sentinel supports:

```text
status
alerts
recent
what happened
explain
help
quit
```

The optional Gemini integration is enabled only when `GEMINI_API_KEY` exists:

```bash
export GEMINI_API_KEY="your-replacement-key"
export GEMINI_MODEL="gemini-2.0-flash"
python sentinel.py
```

Type `explain` to request a cloud explanation. If the key is missing or Gemini is unavailable, Sentinel automatically uses its local explanation. Never commit or paste an API key. Revoke any key that has been exposed.

When a new scan alert arrives, Sentinel prints a boxed alert immediately. Automatic blocking remains disabled.

## RAG, agentic analysis, and ML

`rag_agent.py` adds a local SentinelAI workflow:

```bash
python3 rag_agent.py --source 192.0.2.10 --events 20 --unique-ports 18 --duration 10
```

The agent performs four safe steps:

1. **Observe:** accepts scan features and reads the persisted ML baseline.
2. **Reason:** combines port count, probe rate, and anomaly score into confidence.
3. **Retrieve:** searches Markdown guidance in `knowledge/` and returns cited excerpts.
4. **Recommend:** produces JSON with classification, signals, evidence, and a response recommendation.

Search the RAG knowledge base directly:

```bash
python3 rag_agent.py --query "stealth encrypted scan response"
```

This implementation uses transparent local keyword retrieval and the existing statistical ML baseline. It does not call a cloud LLM, execute arbitrary tools, or block IPs. Add reviewed Markdown documents to `knowledge/` to expand its grounded guidance. For richer packet-level ML, connect Zeek or Suricata telemetry rather than relying on UFW alone.
