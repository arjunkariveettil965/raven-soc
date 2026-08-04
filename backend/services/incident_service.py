from __future__ import annotations

from typing import Any

from backend.repositories import IncidentRepository
from backend.schemas.common import serialize_api_value


def _as_string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if value is None:
        return []
    text = str(value).strip()
    return [text] if text else []


def _select_related_alerts(
    incident: dict[str, Any],
    alert_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    related_alert_ids = set(_as_string_list(incident.get("RelatedAlertIDs")))
    related_alert_types = set(_as_string_list(incident.get("RelatedAlertTypes")))
    alerts_payload: list[dict[str, Any]] = []
    for item in alert_records:
        if not isinstance(item, dict):
            continue
        alert_id = str(item.get("AlertID", "")).strip()
        alert_type = str(item.get("AlertType", "")).strip()
        if related_alert_ids and alert_id and alert_id in related_alert_ids:
            alerts_payload.append(dict(item))
        elif (not related_alert_ids) and related_alert_types and alert_type in related_alert_types:
            alerts_payload.append(dict(item))
    return alerts_payload


def build_incident_alert_collections(
    incident: dict[str, Any],
    alert_records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    alerts_payload = _select_related_alerts(incident, alert_records)
    highest_severity = str(incident.get("HighestAlertSeverity") or incident.get("IncidentSeverity") or "Medium")

    alert_mappings: list[dict[str, Any]] = []
    correlated_indicators: list[dict[str, Any]] = []
    for item in alerts_payload:
        alert_type = str(item.get("AlertType", "")).strip()
        if not alert_type:
            continue
        alert_mapping = {
            "AlertID": str(item.get("AlertID", "")).strip(),
            "RuleName": alert_type,
            "Severity": str(item.get("AlertSeverity", "")).strip() or highest_severity,
            "Tactic": str(item.get("MITRETactic", "")).strip(),
            "Technique": str(item.get("MITRETechnique", "")).strip(),
            "Evidence": str(item.get("Evidence", "")).strip(),
        }
        alert_mappings.append(alert_mapping)
        correlated_indicators.append(
            {
                "Indicator": alert_type,
                "RuleName": alert_type,
                "Severity": alert_mapping["Severity"],
                "Tactic": alert_mapping["Tactic"],
                "Technique": alert_mapping["Technique"],
            }
        )

    return alerts_payload, alert_mappings, correlated_indicators


def _build_alert_collections(
    repository: IncidentRepository,
    stored: object,
    incident: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    run_id = str(getattr(stored, "run_id"))
    run = repository.get_run(run_id)
    run_alerts = run.result.get("Alerts") if run is not None else []
    alert_records = [dict(item) for item in run_alerts if isinstance(item, dict)] if isinstance(run_alerts, list) else []
    return build_incident_alert_collections(incident, alert_records)


def _build_defender_recommendation(stored: object, incident: dict[str, Any]) -> dict[str, Any] | None:
    if isinstance(incident.get("DefenderRecommendation"), dict):
        return dict(incident["DefenderRecommendation"])

    analysis = getattr(stored, "analysis", {}) or {}
    if not isinstance(analysis, dict):
        return None

    action_id = str(analysis.get("RecommendedActionID", "")).strip()
    if not action_id:
        return None

    decision = getattr(stored, "action_decision")
    status = str(decision.get("Decision", "")).strip() if isinstance(decision, dict) else ""
    if not status:
        status = "pending" if bool(analysis.get("RequiresApproval", True)) else "auto-executed"

    return {
        "ActionID": action_id,
        "Mitigation": action_id.replace("_", " "),
        "Target": str(analysis.get("Target") or incident.get("Target") or incident.get("AffectedDevice") or ""),
        "Rationale": str(analysis.get("SuspicionReason") or analysis.get("Summary") or ""),
        "RequiresApproval": bool(analysis.get("RequiresApproval", True)),
        "Status": status,
        "Message": str(decision.get("Message", "")).strip() if isinstance(decision, dict) else "",
    }


def _format_stored_incident(repository: IncidentRepository, stored: object) -> dict[str, object]:
    incident = dict(getattr(stored, "incident"))
    incident["RunID"] = getattr(stored, "run_id")
    timeline = list(getattr(stored, "timeline", []))
    incident["AttackPathTimeline"] = timeline
    incident["Timeline"] = timeline

    alerts, alert_mappings, correlated_indicators = _build_alert_collections(
        repository=repository,
        stored=stored,
        incident=incident,
    )
    incident["Alerts"] = alerts
    incident["AlertMappings"] = alert_mappings
    incident["CorrelatedIndicators"] = correlated_indicators

    if getattr(stored, "analysis", None):
        incident["AnalystResult"] = getattr(stored, "analysis")
    if getattr(stored, "analyst_metadata", None):
        incident["AnalystMetadata"] = getattr(stored, "analyst_metadata")

    defender_recommendation = _build_defender_recommendation(stored, incident)
    if defender_recommendation is not None:
        incident["DefenderRecommendation"] = defender_recommendation

    if getattr(stored, "action_decision") is not None:
        incident["ActionDecision"] = getattr(stored, "action_decision")
    return serialize_api_value(incident)  # type: ignore[return-value]


def list_incidents(
    repository: IncidentRepository,
    limit: int = 50,
    severity: str | None = None,
    incident_type: str | None = None,
) -> list[dict[str, object]]:
    return [
        _format_stored_incident(repository, stored)
        for stored in repository.list_incidents(limit=limit, severity=severity, incident_type=incident_type)
    ]


def get_incident(repository: IncidentRepository, incident_id: str) -> dict[str, object] | None:
    stored = repository.get_incident(incident_id)
    if stored is None:
        return None
    return _format_stored_incident(repository, stored)
