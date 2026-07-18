from __future__ import annotations

from collections import defaultdict
from typing import Any

import pandas as pd


INCIDENT_COLUMNS = [
    "IncidentID",
    "AffectedDevice",
    "AffectedUser",
    "SourceIP",
    "FirstSeen",
    "LastSeen",
    "AlertCount",
    "CorrelationScore",
    "RelatedAlertTypes",
    "RelatedAlertIDs",
    "MITRETactics",
    "MITRETechniques",
    "HighestAlertSeverity",
    "MaximumConfidenceScore",
]

SEVERITY_PRIORITY = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
MITRE_STAGE_LINKS = {
    ("Credential Access", "Initial Access / Persistence"),
    ("Initial Access / Persistence", "Execution"),
    ("Execution", "Command and Control"),
    ("Credential Access", "Execution"),
    ("Execution", "Credential Access"),
}


def _empty_incident_frame() -> pd.DataFrame:
    """Return an empty incident DataFrame with the expected schema."""

    return pd.DataFrame(columns=INCIDENT_COLUMNS)


def _require_alert_columns(alerts: pd.DataFrame) -> None:
    """Validate that the alert DataFrame contains the required columns."""

    if not isinstance(alerts, pd.DataFrame):
        raise TypeError("correlate_alerts expects a pandas DataFrame.")

    required_columns = {
        "AlertID",
        "AlertTime",
        "DeviceName",
        "UserName",
        "SourceIP",
        "AlertType",
        "AlertSeverity",
        "ConfidenceScore",
        "MITRETactic",
        "MITRETechnique",
    }

    missing_columns = required_columns - set(alerts.columns)

    if missing_columns:
        raise ValueError(
            "correlate_alerts is missing required columns: "
            f"{sorted(missing_columns)}"
        )


def _normalize_text(value: object) -> str:
    """Normalize string-like input for deterministic incident fields."""

    if value is None:
        return ""

    if isinstance(value, str):
        normalized_value = value.strip()
        return normalized_value or ""

    if pd.isna(value):
        return ""

    return str(value)


def _alert_severity_rank(severity: str) -> int:
    """Return the severity ranking used for incident summaries."""

    normalized_severity = _normalize_text(severity).capitalize()
    return SEVERITY_PRIORITY.get(normalized_severity, 0)


def _pairwise_correlation_score(
    first_alert: pd.Series,
    second_alert: pd.Series,
) -> int:
    """Calculate the correlation score for a pair of alerts."""

    score = 0

    if _normalize_text(first_alert.get("DeviceName")) and _normalize_text(first_alert.get("DeviceName")) == _normalize_text(second_alert.get("DeviceName")):
        score += 30

    first_user = _normalize_text(first_alert.get("UserName"))
    second_user = _normalize_text(second_alert.get("UserName"))
    if first_user and second_user and first_user == second_user:
        score += 20

    first_source = _normalize_text(first_alert.get("SourceIP"))
    second_source = _normalize_text(second_alert.get("SourceIP"))
    if first_source and second_source and first_source == second_source:
        score += 20

    first_time = pd.to_datetime(first_alert.get("AlertTime"), errors="coerce")
    second_time = pd.to_datetime(second_alert.get("AlertTime"), errors="coerce")
    if pd.notna(first_time) and pd.notna(second_time):
        if abs((second_time - first_time).total_seconds()) <= 600:
            score += 15

    first_tactic = _normalize_text(first_alert.get("MITRETactic"))
    second_tactic = _normalize_text(second_alert.get("MITRETactic"))
    if first_tactic and second_tactic:
        if (first_tactic, second_tactic) in MITRE_STAGE_LINKS or (
            second_tactic,
            first_tactic,
        ) in MITRE_STAGE_LINKS:
            score += 15

    return score


def correlate_alerts(
    alerts: pd.DataFrame,
    correlation_window_minutes: int = 30,
    minimum_correlation_score: int = 50,
) -> pd.DataFrame:
    """
    Correlate related alerts into incidents based on device, identity,
    time proximity and compatible MITRE stages.
    """

    if not isinstance(correlation_window_minutes, int) or correlation_window_minutes <= 0:
        raise ValueError("correlation_window_minutes must be a positive integer.")

    if not isinstance(minimum_correlation_score, int) or not 0 <= minimum_correlation_score <= 100:
        raise ValueError("minimum_correlation_score must be between 0 and 100.")

    _require_alert_columns(alerts)

    if alerts.empty:
        return _empty_incident_frame()

    working_alerts = alerts.copy()
    working_alerts["AlertTime"] = pd.to_datetime(
        working_alerts["AlertTime"],
        errors="coerce",
    )
    working_alerts["FirstSeen"] = pd.to_datetime(
        working_alerts["FirstSeen"],
        errors="coerce",
    )
    working_alerts["LastSeen"] = pd.to_datetime(
        working_alerts["LastSeen"],
        errors="coerce",
    )
    working_alerts = working_alerts.sort_values("AlertTime").reset_index(drop=True)

    if working_alerts.empty:
        return _empty_incident_frame()

    parent = list(range(len(working_alerts)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(first_index: int, second_index: int) -> None:
        first_root = find(first_index)
        second_root = find(second_index)
        if first_root != second_root:
            parent[second_root] = first_root

    for left_index in range(len(working_alerts)):
        for right_index in range(left_index + 1, len(working_alerts)):
            left_alert = working_alerts.iloc[left_index]
            right_alert = working_alerts.iloc[right_index]

            left_device = _normalize_text(left_alert.get("DeviceName"))
            right_device = _normalize_text(right_alert.get("DeviceName"))
            if not left_device or not right_device or left_device != right_device:
                continue

            left_time = pd.to_datetime(left_alert.get("AlertTime"), errors="coerce")
            right_time = pd.to_datetime(right_alert.get("AlertTime"), errors="coerce")
            if pd.isna(left_time) or pd.isna(right_time):
                continue

            if abs((right_time - left_time).total_seconds()) > correlation_window_minutes * 60:
                continue

            score = _pairwise_correlation_score(left_alert, right_alert)
            if score >= minimum_correlation_score and score >= 50:
                union(left_index, right_index)

    incident_groups: dict[int, list[int]] = defaultdict(list)
    for index in range(len(working_alerts)):
        incident_groups[find(index)].append(index)

    incidents: list[dict[str, Any]] = []

    for incident_index, alert_indices in enumerate(incident_groups.values(), start=1):
        incident_alerts = working_alerts.iloc[alert_indices].copy()
        incident_alerts = incident_alerts.sort_values("AlertTime").reset_index(drop=True)

        if len(incident_alerts) < 2:
            continue

        related_alert_types = list(dict.fromkeys(_normalize_text(value) for value in incident_alerts["AlertType"].tolist()))
        related_alert_ids = list(dict.fromkeys(_normalize_text(value) for value in incident_alerts["AlertID"].tolist()))
        related_mitre_tactics = list(
            dict.fromkeys(_normalize_text(value) for value in incident_alerts["MITRETactic"].tolist())
        )
        related_mitre_techniques = list(
            dict.fromkeys(_normalize_text(value) for value in incident_alerts["MITRETechnique"].tolist())
        )

        incident_scores = []
        for left_index in range(len(incident_alerts)):
            for right_index in range(left_index + 1, len(incident_alerts)):
                incident_scores.append(
                    _pairwise_correlation_score(
                        incident_alerts.iloc[left_index],
                        incident_alerts.iloc[right_index],
                    )
                )

        incidents.append(
            {
                "IncidentID": f"INCIDENT-{incident_index:03d}",
                "AffectedDevice": _normalize_text(incident_alerts.iloc[0].get("DeviceName")),
                "AffectedUser": _normalize_text(incident_alerts.iloc[0].get("UserName")),
                "SourceIP": _normalize_text(incident_alerts.iloc[0].get("SourceIP")),
                "FirstSeen": incident_alerts.iloc[0]["AlertTime"],
                "LastSeen": incident_alerts.iloc[-1]["AlertTime"],
                "AlertCount": int(len(incident_alerts)),
                "CorrelationScore": int(max(incident_scores)) if incident_scores else 0,
                "RelatedAlertTypes": related_alert_types,
                "RelatedAlertIDs": related_alert_ids,
                "MITRETactics": related_mitre_tactics,
                "MITRETechniques": related_mitre_techniques,
                "HighestAlertSeverity": max(
                    ( _normalize_text(value) for value in incident_alerts["AlertSeverity"].tolist() ),
                    key=_alert_severity_rank,
                    default="Low",
                ),
                "MaximumConfidenceScore": float(
                    incident_alerts["ConfidenceScore"].max()
                ),
            }
        )

    if not incidents:
        return _empty_incident_frame()

    incidents_frame = pd.DataFrame(incidents)
    incidents_frame = incidents_frame.sort_values("FirstSeen").reset_index(drop=True)
    return incidents_frame[INCIDENT_COLUMNS]
