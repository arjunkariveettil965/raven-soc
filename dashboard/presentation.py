from __future__ import annotations

from datetime import datetime
from typing import Any

import pandas as pd

from core.coverage import CORRELATION_COVERAGE, DETECTION_COVERAGE


MISSING_VALUE = "N/A"


STAGE_BY_TACTIC = {
    "Initial Access / Persistence": "Initial Access",
    "Credential Access": "Credential Access",
    "Execution": "Execution",
    "Persistence": "Persistence",
    "Command and Control": "Command and Control",
    "Exfiltration": "Exfiltration",
}


CORRELATION_EXPLANATIONS = {
    "Multi-Stage Intrusion": [
        "same device or user",
        "authentication failures",
        "success after failures",
        "PowerShell execution",
        "outbound connection",
    ],
    "Password Spray Attempt": [
        "same source IP",
        "multiple distinct users",
        "failed logins within the configured window",
    ],
    "Malware Download and Execution": [
        "same machine",
        "download-capable process",
        "subsequent suspicious execution",
        "inside the correlation window",
    ],
    "Command-and-Control Beaconing": [
        "same machine and destination",
        "repeated outbound connections",
        "near-regular timing",
    ],
}


def format_display_value(value: object) -> str:
    if value is None:
        return MISSING_VALUE
    if isinstance(value, pd.Timestamp):
        if pd.isna(value):
            return MISSING_VALUE
        return value.strftime("%d %b %Y, %H:%M:%S")
    if isinstance(value, datetime):
        return value.strftime("%d %b %Y, %H:%M:%S")
    if isinstance(value, float) and pd.isna(value):
        return MISSING_VALUE
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else MISSING_VALUE
    return str(value)


def build_incident_summary(
    incident: dict[str, object],
    analysis: dict[str, object],
    metadata: dict[str, object],
) -> dict[str, str]:
    return {
        "Incident Type": format_display_value(incident.get("IncidentType") or incident.get("CorrelationPattern")),
        "Status": format_display_value(analysis.get("Status")),
        "Severity": format_display_value(analysis.get("Severity") or incident.get("IncidentSeverity") or incident.get("HighestAlertSeverity")),
        "Confidence": format_display_value(analysis.get("Confidence") or incident.get("IncidentConfidence")),
        "Target": format_display_value(analysis.get("Target") or incident.get("Target")),
        "User": format_display_value(incident.get("AffectedUser")),
        "Source IP": format_display_value(incident.get("SourceIP")),
        "Destination IP": format_display_value(incident.get("DestinationIP")),
        "Correlation Pattern": format_display_value(incident.get("CorrelationPattern") or incident.get("PatternID")),
        "Alert Count": format_display_value(incident.get("AlertCount")),
        "First Seen": format_display_value(incident.get("FirstSeen")),
        "Last Seen": format_display_value(incident.get("LastSeen")),
        "Recommended Action": format_display_value(analysis.get("RecommendedActionID") or incident.get("RecommendedActionID")),
        "Requires Approval": "Yes" if bool(analysis.get("RequiresApproval", incident.get("RequiresApproval", False))) else "No",
        "Analyst Mode": format_display_value(metadata.get("AnalystMode")),
        "Model Name": format_display_value(metadata.get("ModelName")),
        "Used Fallback": "Yes" if metadata.get("UsedFallback") else "No",
    }


def build_pipeline_status(result: dict[str, object] | None) -> list[dict[str, str]]:
    stages = [
        ("Events Generated or Ingested", "events"),
        ("Alerts Detected", "alerts"),
        ("Alerts Correlated", "incidents"),
        ("Incident Classified", "selected_incident"),
        ("Analyst Completed", "analysis"),
        ("Defender Recommendation Produced", "synthetic_defender_response"),
    ]
    if result is None:
        return [{"Stage": stage, "Status": "Not Triggered"} for stage, _ in stages]
    rows: list[dict[str, str]] = []
    for stage, key in stages:
        value = result.get(key)
        if key == "synthetic_defender_response":
            status = "Completed" if value else "Not Triggered"
        elif isinstance(value, pd.DataFrame):
            status = "Completed" if not value.empty else "Not Triggered"
        else:
            status = "Completed" if value is not None else "Not Triggered"
        rows.append({"Stage": stage, "Status": status})
    if result.get("analyst_metadata", {}).get("UsedFallback"):
        rows[4]["Status"] = "Failed safely"
    return rows


def build_attack_chain(timeline: pd.DataFrame) -> list[dict[str, str]]:
    if not isinstance(timeline, pd.DataFrame) or timeline.empty:
        return []
    chain: list[dict[str, str]] = []
    for _, row in timeline.sort_values("TimelineTime").iterrows():
        tactic = format_display_value(row.get("MITRETactic"))
        stage = STAGE_BY_TACTIC.get(tactic, tactic)
        chain.append(
            {
                "Stage": stage,
                "Timestamp": format_display_value(row.get("TimelineTime")),
                "Alert": format_display_value(row.get("AlertType")),
                "Evidence": format_display_value(row.get("Evidence")),
                "MITRE Technique": format_display_value(row.get("MITRETechnique")),
                "Affected Entity": format_display_value(row.get("DeviceName") or row.get("UserName") or row.get("SourceIP")),
            }
        )
    return chain


def explain_correlation(incident: dict[str, object]) -> list[str]:
    pattern = str(incident.get("CorrelationPattern") or incident.get("IncidentType") or "").strip()
    return list(CORRELATION_EXPLANATIONS.get(pattern, []))


def diagnostics_visible(presentation_mode: bool, used_fallback: bool) -> bool:
    return (not presentation_mode) or used_fallback


def defender_state(response: dict[str, object] | None, requires_approval: bool, rejected: bool = False) -> str:
    if rejected:
        return "Rejected"
    if response and response.get("Permitted") and response.get("Executed"):
        return "Approved Simulation"
    if requires_approval:
        return "Awaiting Approval"
    return "No Action Required"
