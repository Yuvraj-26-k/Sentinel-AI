# Architecture

```mermaid
flowchart LR
    CLI[CLI: sentinel scan] --> TCP[Bounded Python TCP probes]
    TCP --> Evidence[Port states and optional service evidence]
    Evidence --> Local[Local summary and JSON report]
    Evidence -->|Only with --ai| Gemini[Gemini explanation]
    Logs[Authorized firewall and sensor logs] --> Adapters[telemetry.py adapters]
    Adapters --> Detection[detection.py rules and anomaly scoring]
    Detection --> Console[sentinel.py console and incident history]
    Console --> Analyst[analyst.py guidance and opt-in cloud analysis]
```

The scanner works independently of the monitoring dependencies. Port-database
hints, remote observations and AI text are separate from connection results.
The monitor consumes event sources; it is not the active TCP scanner. Cloud
analysis requires the relevant explicit opt-in/consent described in each flow.
Read the [scanner guide](../README.md) or [monitoring reference](MONITORING.md).
