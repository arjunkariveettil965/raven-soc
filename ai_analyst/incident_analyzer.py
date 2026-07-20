from __future__ import annotations

from typing import Any

import pandas as pd

from ai_analyst.schemas import create_empty_analysis


def _normalize_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if pd.isna(value):
        return ""
    return str(value)


def _coerce_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [_normalize_text(item) for item in value if _normalize_text(item)]
    if isinstance(value, str):
        return [_normalize_text(value)]
    return []


def _coerce_numeric(value: object, default: float = 0.0) -> float:
    try:
        numeric_value = float(value)
    except (TypeError, ValueError):
        return default
    return numeric_value


def analyze_incident_deterministically(
    incident: pd.Series | dict,
    timeline: pd.DataFrame,
    environment_profile: dict[str, object],
    attack_pattern: dict[str, object] | None,
) -> dict[str, object]:
    """Create a deterministic analyst-style incident analysis without external APIs."""

    if isinstance(incident, pd.Series):
        incident_data = incident.to_dict()
    elif isinstance(incident, dict):
        incident_data = incident
    else:
        incident_data = {}

    analysis = create_empty_analysis()

    incident_type = _normalize_text(incident_data.get("IncidentType")) or _normalize_text(
        attack_pattern.get("pattern_name") if attack_pattern else None
    )
    threat_type = incident_type or "Unknown"
    severity = _normalize_text(incident_data.get("IncidentSeverity")) or _normalize_text(
        attack_pattern.get("default_severity") if attack_pattern else None
    ) or "Medium"
    if severity not in {"Critical", "High", "Medium", "Low"}:
        severity = "Medium"

    base_confidence = _coerce_numeric(
        incident_data.get("IncidentConfidence"),
        default=_coerce_numeric(incident_data.get("MaximumConfidenceScore"), default=55.0),
    )
    if base_confidence <= 0:
        base_confidence = 55.0

    environment_adjustment = int(environment_profile.get("EnvironmentRiskAdjustment", 0)) if isinstance(environment_profile, dict) else 0
    if not isinstance(environment_profile, dict):
        environment_adjustment = 0
    confidence = min(100.0, base_confidence + environment_adjustment)

    related_alert_types = _coerce_list(incident_data.get("RelatedAlertTypes"))
    related_alert_ids = _coerce_list(incident_data.get("RelatedAlertIDs"))
    mitre_techniques = _coerce_list(incident_data.get("MITRETechniques"))
    if not mitre_techniques and attack_pattern:
        mitre_techniques = _coerce_list(attack_pattern.get("mitre_techniques"))

    observed_evidence: list[str] = []
    if isinstance(timeline, pd.DataFrame) and not timeline.empty:
        for _, row in timeline.iterrows():
            alert_type = _normalize_text(row.get("AlertType"))
            evidence = _normalize_text(row.get("Evidence"))
            if alert_type and evidence:
                observed_evidence.append(f"{alert_type}: {evidence}")
            elif alert_type:
                observed_evidence.append(alert_type)

    affected_device = _normalize_text(incident_data.get("AffectedDevice"))
    affected_user = _normalize_text(incident_data.get("AffectedUser"))
    source_ip = _normalize_text(incident_data.get("SourceIP"))

    if attack_pattern:
        summary = _normalize_text(attack_pattern.get("summary"))
        investigation_steps = _coerce_list(attack_pattern.get("investigation_steps"))
    else:
        summary = ""
        investigation_steps = []

    if not summary:
        if related_alert_types:
            summary = f"Observed {', '.join(related_alert_types)} activity on {affected_device or 'the affected device'}."
        else:
            summary = "Observed suspicious activity without a strong pattern match."

    incident_action = _normalize_text(incident_data.get("RecommendedActionID"))
    if incident_action in {
        "ISOLATE_DEVICE",
        "DISABLE_USER",
        "BLOCK_DESTINATION_IP",
        "COLLECT_EVIDENCE",
        "INCREASE_MONITORING",
        "NO_ACTION",
    }:
        recommended_action = incident_action
    elif threat_type == "Multi-Stage Intrusion" or threat_type == "Account Compromise with Malicious Execution" or threat_type == "Account Compromise with Suspicious Execution" or threat_type == "Possible Malware Execution and Command and Control" or threat_type == "Malware Download and Execution" or threat_type == "Command-and-Control Beaconing":
        recommended_action = "ISOLATE_DEVICE"
    elif threat_type == "Password Spray Attempt":
        recommended_action = "BLOCK_DESTINATION_IP" if source_ip else "INCREASE_MONITORING"
    elif threat_type == "Possible Account Compromise":
        recommended_action = "DISABLE_USER"
    elif threat_type == "Brute-Force Attempt":
        recommended_action = "BLOCK_DESTINATION_IP" if source_ip else "INCREASE_MONITORING"
    elif threat_type == "uncertain":
        recommended_action = "COLLECT_EVIDENCE"
    else:
        recommended_action = "NO_ACTION"

    if not related_alert_types:
        recommended_action = "NO_ACTION"

    target = ""
    if recommended_action == "ISOLATE_DEVICE":
        target = affected_device
    elif recommended_action == "DISABLE_USER":
        target = affected_user
    elif recommended_action == "BLOCK_DESTINATION_IP":
        target = source_ip
    elif recommended_action in {"COLLECT_EVIDENCE", "INCREASE_MONITORING"}:
        target = affected_device or affected_user or source_ip

    requires_approval = bool(
        environment_profile.get("RequiresHumanApproval", False)
        or bool(incident_data.get("RequiresApproval", False))
        or recommended_action in {"ISOLATE_DEVICE", "DISABLE_USER"}
        or confidence < int(environment_profile.get("automatic_response_threshold", 70))
        or (affected_device and affected_device.lower() in {item.lower() for item in environment_profile.get("critical_devices", []) or []})
    )

    if not related_alert_types:
        status = "benign"
        severity = "Low"
        confidence = max(0.0, min(100.0, confidence))
    elif severity == "Critical" and confidence >= 80:
        status = "malicious"
    elif severity in {"High", "Critical"} or confidence >= 60:
        status = "suspicious"
    elif confidence < 60 and observed_evidence:
        status = "uncertain"
    else:
        status = "benign"

    suspicion_reason = ""
    if observed_evidence:
        suspicion_reason = (
            f"Observed {len(observed_evidence)} evidence items consistent with {threat_type.lower()}"
        )
    else:
        suspicion_reason = "Insufficient observed evidence for a confident determination."

    inferences = [
        f"Inference: The sequence of observed alerts is consistent with {threat_type.lower()}.",
    ]
    if investigation_steps:
        inferences.append(f"Inference: The recommended investigation steps align with the observed evidence.")
    if not observed_evidence:
        inferences.append("Inference: The case remains uncertain because no timeline evidence was supplied.")

    analysis.update(
        {
            "Status": status,
            "ThreatType": threat_type or "Unknown",
            "Severity": severity,
            "Confidence": round(confidence, 1),
            "Summary": summary,
            "SuspicionReason": suspicion_reason,
            "ObservedEvidence": observed_evidence,
            "Inferences": inferences,
            "MITRETechniques": mitre_techniques,
            "RecommendedActionID": recommended_action,
            "Target": target,
            "RequiresApproval": requires_approval,
            "EvidenceIDs": related_alert_ids,
        }
    )

    return analysis
