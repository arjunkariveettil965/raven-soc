from __future__ import annotations

from typing import Any

import pandas as pd


SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def _as_set(value: object) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        return {str(item) for item in value if str(item)}
    return {str(value)}


def evaluate_scenario_result(
    scenario: dict[str, object],
    alerts: pd.DataFrame,
    incidents: pd.DataFrame,
) -> dict[str, object]:
    expected_incident = str(scenario.get("ExpectedIncidentType", ""))
    expected_alerts = _as_set(scenario.get("ExpectedAlertTypes"))
    expected_mitre = _as_set(scenario.get("ExpectedMITRETechniques"))
    expected_target = str(scenario.get("ExpectedTarget", ""))
    expected_actions = _as_set(scenario.get("ExpectedRecommendedActions"))

    actual_alerts = set(alerts["AlertType"].astype(str).tolist()) if isinstance(alerts, pd.DataFrame) and not alerts.empty else set()
    actual_incidents = incidents if isinstance(incidents, pd.DataFrame) else pd.DataFrame()
    actual_incident_types = set(actual_incidents.get("IncidentType", pd.Series(dtype=str)).astype(str).tolist())
    if "CorrelationPattern" in actual_incidents.columns:
        actual_incident_types |= set(actual_incidents["CorrelationPattern"].astype(str).tolist())

    matched_rows = actual_incidents[
        (actual_incidents.get("IncidentType", pd.Series(dtype=str)).astype(str) == expected_incident)
        | (actual_incidents.get("CorrelationPattern", pd.Series(dtype=str)).astype(str) == expected_incident)
    ] if not actual_incidents.empty else pd.DataFrame()
    matched = not matched_rows.empty
    selected = matched_rows.iloc[0].to_dict() if matched else {}
    actual_mitre = _as_set(selected.get("MITRETechniques"))
    actual_action = str(selected.get("RecommendedActionID", ""))
    actual_target = str(selected.get("Target") or selected.get("AffectedDevice") or selected.get("SourceIP") or "")
    expected_min_severity = str(scenario.get("ExpectedMinimumSeverity", "Low"))
    actual_severity = str(selected.get("IncidentSeverity") or selected.get("HighestAlertSeverity") or "Low")

    missing_alerts = sorted(expected_alerts - actual_alerts)
    missing_mitre = sorted(expected_mitre - actual_mitre)
    unexpected_incidents = sorted(actual_incident_types - {expected_incident, ""})
    mitre_coverage = 1.0 if not expected_mitre else (len(expected_mitre & actual_mitre) / len(expected_mitre))
    result = {
        "Detected": bool(actual_alerts),
        "IncidentTypeMatched": matched,
        "SeveritySatisfied": SEVERITY_RANK.get(actual_severity, 0) >= SEVERITY_RANK.get(expected_min_severity, 0),
        "MITRECoverage": mitre_coverage,
        "ExpectedAlertsFound": sorted(expected_alerts & actual_alerts),
        "MissingExpectedAlerts": missing_alerts,
        "UnexpectedIncidents": unexpected_incidents,
        "TargetMatched": (not expected_target) or expected_target == actual_target or expected_target == str(selected.get("AffectedDevice", "")) or expected_target == str(selected.get("SourceIP", "")),
        "RecommendedActionAccepted": actual_action in expected_actions,
    }
    result["OverallPassed"] = bool(
        result["Detected"]
        and result["IncidentTypeMatched"]
        and result["SeveritySatisfied"]
        and not missing_alerts
        and mitre_coverage > 0
        and result["TargetMatched"]
        and result["RecommendedActionAccepted"]
    )
    return result
