# Nmap AI Detector

A small defensive prototype that monitors `/var/log/ufw.log` and alerts when a source IP probes many destination ports within a short window.

## Run

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
