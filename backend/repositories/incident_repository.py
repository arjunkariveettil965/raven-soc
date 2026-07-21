from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock
from typing import Any


@dataclass
class StoredIncident:
    run_id: str
    incident_id: str
    incident: dict[str, Any]
    timeline: list[dict[str, Any]]
    analysis: dict[str, Any]
    analyst_metadata: dict[str, Any]
    environment_profile: dict[str, Any]
    action_decision: dict[str, Any] | None = None


@dataclass
class StoredRun:
    run_id: str
    result: dict[str, Any]


class IncidentRepository:
    """Process-local incident store for API-created scenario runs.

    Phase 9A intentionally keeps this in memory. State resets when the API
    process restarts and no SQLite migration is required.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._incidents: dict[str, StoredIncident] = {}
        self._runs: dict[str, StoredRun] = {}

    def store_run(self, run_id: str, result: dict[str, Any], incidents: list[StoredIncident]) -> None:
        with self._lock:
            self._runs[run_id] = StoredRun(run_id=run_id, result=result)
            for incident in incidents:
                self._incidents[incident.incident_id] = incident

    def list_incidents(
        self,
        limit: int = 50,
        severity: str | None = None,
        incident_type: str | None = None,
    ) -> list[StoredIncident]:
        with self._lock:
            incidents = list(self._incidents.values())

        if severity:
            wanted = severity.strip().lower()
            incidents = [
                item
                for item in incidents
                if str(item.incident.get("IncidentSeverity") or item.incident.get("Severity") or "").lower() == wanted
            ]
        if incident_type:
            wanted_type = incident_type.strip().lower()
            incidents = [
                item
                for item in incidents
                if wanted_type in str(item.incident.get("IncidentType") or item.incident.get("CorrelationPattern") or "").lower()
            ]
        return incidents[: max(0, int(limit))]

    def get_incident(self, incident_id: str) -> StoredIncident | None:
        with self._lock:
            return self._incidents.get(incident_id)

    def record_action_decision(self, incident_id: str, decision: dict[str, Any]) -> None:
        with self._lock:
            incident = self._incidents[incident_id]
            incident.action_decision = dict(decision)
