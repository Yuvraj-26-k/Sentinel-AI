"""Evidence-bound local security alert analyst."""

from evidence_validator import EVIDENCE_FIELDS, validate_analysis


def local_analysis(alert):
    rule_signals = alert.get("rule_signals") or []
    if not rule_signals and alert.get("event") == "possible_port_scan":
        rule_signals = ["unique_ports_threshold"]

    evidence_fields = [
        "source",
        "destination",
        "events",
        "unique_ports",
        "destination_port",
        "protocol",
        "source_platform",
        "source_type",
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
    ]
    evidence = [
        {"field": field, "value": alert[field]}
        for field in evidence_fields
        if field in EVIDENCE_FIELDS and alert.get(field) is not None
    ]
    steps = ["correlate_network", "review_host", "verify_owner"]
    if alert.get("event") == "possible_port_scan":
        steps.append("preserve_evidence")
    verified = validate_analysis(
        alert,
        {"evidence": evidence, "investigation_steps": steps},
    )
    rationale = []
    if "unique_ports_threshold" in rule_signals:
        rationale.append(
            f"{alert.get('unique_ports')} unique destination ports met the "
            f"configured {alert.get('port_scan_threshold', 15)}-port scan threshold "
            f"within {alert.get('window_seconds', 60)} seconds."
        )
    if "high_volume_fast_probing" in rule_signals:
        rationale.append(
            f"The event volume met the {alert.get('fast_probe_min_events', 15)}-event "
            f"threshold and its port rate met {alert.get('fast_probe_rate_threshold', 1.0)} "
            "unique ports per second."
        )
    if "historical_statistical_deviation" in rule_signals:
        rationale.append(
            "The activity differs from this source's learned statistical baseline."
        )
    if alert.get("ml_is_anomaly") is True:
        rationale.append(
            "The Isolation Forest flagged this behavior against "
            f"{alert.get('historical_baseline_samples')} prior normal windows "
            f"(raw anomaly score {alert.get('ml_anomaly_score')})."
        )
    if not rationale:
        rationale.append(
            "The event was retained for review based on the alert's recorded telemetry."
        )
    return {
        "classification": alert.get("event", "network_activity"),
        "assessment": "Suspicious activity requiring review; this alert is not proof of compromise.",
        "rationale": rationale,
        "evidence": verified["observations"],
        "investigation_steps": verified["investigation_steps"],
        "automatic_response": "disabled",
    }


def verified_ai_analysis(alert, proposal):
    if proposal is None:
        return None
    result = validate_analysis(alert, proposal)
    if not result["observations"] and not result["investigation_steps"]:
        return None
    return result


def format_analysis(analysis):
    lines = [
        f"Assessment: {analysis['assessment']}",
        f"Classification: {analysis['classification']}",
    ]
    lines.append("Why it matters:")
    lines.extend(f"- {reason}" for reason in analysis["rationale"])
    lines.append("Verified evidence:")
    for item in analysis["evidence"]:
        lines.append(f"- {item['field']}: {item['value']}")
    lines.append("Investigation steps:")
    lines.extend(f"- {step}" for step in analysis["investigation_steps"])
    lines.append("Automatic response: disabled")
    return "\n".join(lines)
