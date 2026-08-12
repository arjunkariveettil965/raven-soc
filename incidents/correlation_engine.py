from __future__ import annotations

from collections import defaultdict
import hashlib
import json
from pathlib import Path
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
    "PatternID",
    "CorrelationPattern",
    "CorrelationWindowMinutes",
    "RecommendedActionID",
    "RequiresApproval",
    "Target",
]

SEVERITY_PRIORITY = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
MITRE_STAGE_LINKS = {
    ("Credential Access", "Initial Access / Persistence"),
    ("Initial Access / Persistence", "Execution"),
    ("Execution", "Command and Control"),
    ("Credential Access", "Execution"),
    ("Execution", "Credential Access"),
}
DEFAULT_PATTERN_PATH = Path(__file__).resolve().parents[1] / "knowledge_base" / "correlation_patterns" / "patterns.json"


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


def load_correlation_patterns(pattern_path: str | Path | None = None) -> list[dict[str, object]]:
    path = Path(pattern_path) if pattern_path is not None else DEFAULT_PATTERN_PATH
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, list):
        return []
    return [dict(item) for item in payload if isinstance(item, dict)]


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


def _severity_from_rank(rank: int) -> str:
    for severity, severity_rank in SEVERITY_PRIORITY.items():
        if severity_rank == rank:
            return severity
    return "Low"


def _coerce_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [_normalize_text(item) for item in value if _normalize_text(item)]
    text = _normalize_text(value)
    return [text] if text else []


def _stable_incident_id(pattern_id: str, alert_ids: list[str]) -> str:
    payload = json.dumps([pattern_id, sorted(alert_ids)], sort_keys=True)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return f"INC-{pattern_id}-{digest}"


def _first_non_empty(alerts: pd.DataFrame, column: str) -> str:
    if column not in alerts.columns:
        return ""
    for value in alerts[column].tolist():
        text = _normalize_text(value)
        if text:
            return text
    return ""


def _target_for_action(action_id: str, alerts: pd.DataFrame) -> str:
    if action_id == "ISOLATE_DEVICE":
        return _first_non_empty(alerts, "DeviceName")
    if action_id == "DISABLE_USER":
        return _first_non_empty(alerts, "UserName")
    if action_id == "BLOCK_DESTINATION_IP":
        return _first_non_empty(alerts, "SourceIP")
    if action_id in {"COLLECT_EVIDENCE", "INCREASE_MONITORING"}:
        return _first_non_empty(alerts, "DeviceName") or _first_non_empty(alerts, "UserName") or _first_non_empty(alerts, "SourceIP")
    return ""


def _collect_mitre_techniques(alerts: pd.DataFrame, fallback: list[str]) -> list[str]:
    techniques: list[str] = []
    if "MITRETechniques" in alerts.columns:
        for value in alerts["MITRETechniques"].tolist():
            for item in _coerce_list(value):
                if item and item not in techniques:
                    techniques.append(item)
    for value in alerts["MITRETechnique"].tolist():
        text = _normalize_text(value)
        if text and text not in techniques:
            techniques.append(text)
    for value in fallback:
        if value and value not in techniques:
            techniques.append(value)
    return techniques


def _build_incident_from_alerts(
    incident_alerts: pd.DataFrame,
    pattern: dict[str, object],
    incident_number: int,
) -> dict[str, Any]:
    incident_alerts = incident_alerts.sort_values("AlertTime").reset_index(drop=True)
    related_alert_ids = list(dict.fromkeys(_normalize_text(value) for value in incident_alerts["AlertID"].tolist()))
    related_alert_types = list(dict.fromkeys(_normalize_text(value) for value in incident_alerts["AlertType"].tolist()))
    related_tactics = list(dict.fromkeys(_normalize_text(value) for value in incident_alerts["MITRETactic"].tolist()))
    pattern_id = _normalize_text(pattern.get("PatternID")) or f"LEGACY-{incident_number:03d}"
    action_id = _normalize_text(pattern.get("RecommendedActionID")) or "COLLECT_EVIDENCE"
    highest_rank = max((_alert_severity_rank(value) for value in incident_alerts["AlertSeverity"].tolist()), default=1)
    confidence = min(100.0, float(incident_alerts["ConfidenceScore"].max()) + max(0, len(incident_alerts) - 1) * 3.0)
    return {
        "IncidentID": _stable_incident_id(pattern_id, related_alert_ids),
        "AffectedDevice": _first_non_empty(incident_alerts, "DeviceName"),
        "AffectedUser": _first_non_empty(incident_alerts, "UserName"),
        "SourceIP": _first_non_empty(incident_alerts, "SourceIP"),
        "FirstSeen": incident_alerts.iloc[0]["AlertTime"],
        "LastSeen": incident_alerts.iloc[-1]["AlertTime"],
        "AlertCount": int(len(incident_alerts)),
        "CorrelationScore": min(100, 60 + len(incident_alerts) * 10),
        "RelatedAlertTypes": related_alert_types,
        "RelatedAlertIDs": related_alert_ids,
        "MITRETactics": related_tactics,
        "MITRETechniques": _collect_mitre_techniques(incident_alerts, _coerce_list(pattern.get("MITRETechniques"))),
        "HighestAlertSeverity": _severity_from_rank(highest_rank),
        "MaximumConfidenceScore": float(incident_alerts["ConfidenceScore"].max()),
        "PatternID": pattern_id,
        "CorrelationPattern": _normalize_text(pattern.get("IncidentType")) or "Legacy Correlation",
        "CorrelationWindowMinutes": int(pattern.get("WindowMinutes", 30) or 30),
        "RecommendedActionID": action_id,
        "RequiresApproval": bool(pattern.get("RequiresApproval", action_id in {"ISOLATE_DEVICE", "DISABLE_USER"})),
        "Target": _target_for_action(action_id, incident_alerts),
    }


def _entity_values_match(alerts: pd.DataFrame, fields: list[str]) -> bool:
    for field in fields:
        if field not in alerts.columns:
            return False
        values = {_normalize_text(value) for value in alerts[field].tolist() if _normalize_text(value)}
        if len(values) != 1:
            return False
    return True


def _match_pattern_incidents(working_alerts: pd.DataFrame, patterns: list[dict[str, object]]) -> list[dict[str, Any]]:
    incidents: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, tuple[str, ...]]] = set()
    for pattern in patterns:
        required_types = set(_coerce_list(pattern.get("RequiredAlertTypes")))
        optional_types = set(_coerce_list(pattern.get("OptionalAlertTypes")))
        if not required_types:
            continue
        window_minutes = int(pattern.get("WindowMinutes", 30) or 30)
        entity_fields = _coerce_list(pattern.get("EntityMatch"))
        pattern_types = required_types | optional_types
        candidate_alerts = working_alerts[working_alerts["AlertType"].isin(pattern_types)].copy()
        if candidate_alerts.empty:
            continue
        for _, seed in candidate_alerts[candidate_alerts["AlertType"].isin(required_types)].iterrows():
            start_time = pd.to_datetime(seed.get("AlertTime"), errors="coerce")
            if pd.isna(start_time):
                continue
            window_alerts = candidate_alerts[
                (candidate_alerts["AlertTime"] >= start_time - pd.Timedelta(minutes=window_minutes))
                & (candidate_alerts["AlertTime"] <= start_time + pd.Timedelta(minutes=window_minutes))
            ].copy()
            if entity_fields:
                for field in entity_fields:
                    seed_value = _normalize_text(seed.get(field))
                    window_alerts = window_alerts[window_alerts[field].astype(str).str.strip() == seed_value]
            types_in_window = set(_normalize_text(value) for value in window_alerts["AlertType"].tolist())
            if not required_types.issubset(types_in_window):
                continue
            if entity_fields and not _entity_values_match(window_alerts, entity_fields):
                continue
            alert_ids = tuple(sorted(_normalize_text(value) for value in window_alerts["AlertID"].tolist()))
            key = (_normalize_text(pattern.get("PatternID")), alert_ids)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            incidents.append(_build_incident_from_alerts(window_alerts, pattern, len(incidents) + 1))
    return incidents


def _apply_machine_criticality(
    incidents: list[dict[str, Any]],
    machine_inventory: pd.DataFrame | None,
) -> None:
    if machine_inventory is None or not isinstance(machine_inventory, pd.DataFrame) or machine_inventory.empty:
        return
    if "DeviceName" not in machine_inventory.columns or "DeviceCriticality" not in machine_inventory.columns:
        return
    criticality_by_device = {
        _normalize_text(row.get("DeviceName")): _normalize_text(row.get("DeviceCriticality"))
        for _, row in machine_inventory.iterrows()
    }
    criticality_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    for incident in incidents:
        criticality = criticality_by_device.get(_normalize_text(incident.get("AffectedDevice")), "")
        rank = criticality_rank.get(criticality, 0)
        if rank >= 4:
            incident["HighestAlertSeverity"] = "Critical"
            incident["MaximumConfidenceScore"] = min(100.0, float(incident.get("MaximumConfidenceScore", 0)) + 5.0)
        elif rank == 3 and _alert_severity_rank(_normalize_text(incident.get("HighestAlertSeverity"))) < SEVERITY_PRIORITY["High"]:
            incident["HighestAlertSeverity"] = "High"
            incident["MaximumConfidenceScore"] = min(100.0, float(incident.get("MaximumConfidenceScore", 0)) + 3.0)


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
    machine_inventory: pd.DataFrame | None = None,
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
    for optional_column in ["DestinationIP", "ProcessName"]:
        if optional_column not in working_alerts.columns:
            working_alerts[optional_column] = ""

    if working_alerts.empty:
        return _empty_incident_frame()

    pattern_incidents = _match_pattern_incidents(working_alerts, load_correlation_patterns())
    pattern_alert_ids = {
        alert_id
        for incident in pattern_incidents
        for alert_id in incident.get("RelatedAlertIDs", [])
    }

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
            left_user = _normalize_text(left_alert.get("UserName"))
            right_user = _normalize_text(right_alert.get("UserName"))
            left_ip = _normalize_text(left_alert.get("SourceIP"))
            right_ip = _normalize_text(right_alert.get("SourceIP"))

            has_shared_pivot = (
                (left_device and left_device == right_device) or
                (left_user and left_user == right_user) or
                (left_ip and left_ip == right_ip)
            )
            if not has_shared_pivot:
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
    incidents.extend(pattern_incidents)

    for incident_index, alert_indices in enumerate(incident_groups.values(), start=1):
        incident_alerts = working_alerts.iloc[alert_indices].copy()
        incident_alerts = incident_alerts.sort_values("AlertTime").reset_index(drop=True)

        if len(incident_alerts) < 2:
            continue
        if set(_normalize_text(value) for value in incident_alerts["AlertID"].tolist()).issubset(pattern_alert_ids):
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

        legacy_pattern = {
            "PatternID": f"LEGACY_CORRELATION_{incident_index:03d}",
            "IncidentType": "Legacy Correlation",
            "WindowMinutes": correlation_window_minutes,
            "RecommendedActionID": "COLLECT_EVIDENCE",
            "RequiresApproval": True,
        }
        incident_record = _build_incident_from_alerts(incident_alerts, legacy_pattern, incident_index)
        incident_record.update(
            {
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
        incidents.append(incident_record)

    if not incidents:
        return _empty_incident_frame()

    _apply_machine_criticality(incidents, machine_inventory)
    incidents_frame = pd.DataFrame(incidents)
    incidents_frame = incidents_frame.sort_values("FirstSeen").reset_index(drop=True)
    return incidents_frame[INCIDENT_COLUMNS]
