"""Validate AI analyst references against fields present in actual telemetry."""

EVIDENCE_FIELDS = {
    "source",
    "destination",
    "events",
    "unique_ports",
    "destination_port",
    "protocol",
    "source_platform",
    "source_type",
    "source_event",
    "event_timestamp",
    "rate",
    "destination_diversity",
    "mean_interarrival_seconds",
    "interarrival_std_seconds",
    "active_span_seconds",
    "rule_signals",
    "window_seconds",
    "port_scan_threshold",
    "fast_probe_min_events",
    "fast_probe_rate_threshold",
    "ml_anomaly_score",
    "ml_model",
    "ml_is_anomaly",
    "historical_baseline_samples",
    "statistical_anomaly_score",
}

INVESTIGATION_STEPS = {
    "correlate_network": "Correlate the source and destination with firewall, Zeek, or Suricata records.",
    "review_host": "Review endpoint process and authentication telemetry for the same time window.",
    "verify_owner": "Verify the source and destination ownership and whether the activity was authorized.",
    "preserve_evidence": "Preserve the relevant logs and timestamps before changing system state.",
}


def validate_analysis(alert, proposal):
    """Return only evidence-backed observations and approved investigation steps."""
    if not isinstance(proposal, dict):
        return {"observations": [], "investigation_steps": []}
    observations = []
    seen = set()
    evidence = proposal.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = []
    for reference in evidence:
        if not isinstance(reference, dict):
            continue
        field = reference.get("field")
        if (
            not isinstance(field, str)
            or field not in EVIDENCE_FIELDS
            or field in seen
            or field not in alert
            or alert[field] is None
            or reference.get("value") != alert[field]
        ):
            continue
        seen.add(field)
        observations.append({"field": field, "value": alert[field]})
    steps = []
    proposed_steps = proposal.get("investigation_steps", [])
    if not isinstance(proposed_steps, list):
        proposed_steps = []
    for step_id in proposed_steps:
        if (
            isinstance(step_id, str)
            and step_id in INVESTIGATION_STEPS
            and step_id not in steps
        ):
            steps.append(step_id)
    return {
        "observations": observations,
        "investigation_steps": [INVESTIGATION_STEPS[step] for step in steps],
    }
