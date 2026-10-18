# Port Scan Triage

A port scan is more credible when multiple signals agree: many unique destination ports, a high probe rate, repeated activity over time, or an anomaly score far from the source's learned baseline.

## Recommended response

1. Confirm the source is not an approved administrator, monitoring system, or vulnerability scanner.
2. Correlate firewall events with Zeek or Suricata connection metadata.
3. Review the destination host and exposed services.
4. Preserve timestamps and source addresses for investigation.
5. Do not automatically block based on one alert.

## Stealth and encrypted traffic

Encryption hides payload content but usually leaves metadata such as source, destination, port, timing, and volume. Firewall-only logs can miss slow, distributed, or allowed-connection scans. Use Zeek or Suricata for richer telemetry.
