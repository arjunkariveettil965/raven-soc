from __future__ import annotations

from backend.repositories import IncidentRepository
from backend.schemas.common import serialize_api_value


def _format_stored_incident(stored: object) -> dict[str, object]:
    incident = dict(getattr(stored, "incident"))
    incident["RunID"] = getattr(stored, "run_id")
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
        _format_stored_incident(stored)
        for stored in repository.list_incidents(limit=limit, severity=severity, incident_type=incident_type)
    ]


def get_incident(repository: IncidentRepository, incident_id: str) -> dict[str, object] | None:
    stored = repository.get_incident(incident_id)
    if stored is None:
        return None
    return _format_stored_incident(stored)
