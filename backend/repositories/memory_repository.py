from __future__ import annotations

from threading import Lock
from typing import Any

from backend.repositories.base import RepositoryConflictError, StoredIncident, StoredRun


class MemoryIncidentRepository:
    def __init__(self) -> None:
        self._lock = Lock()
        self._incidents: dict[str, StoredIncident] = {}
        self._runs: dict[str, StoredRun] = {}
        self._analyses: dict[str, dict[str, Any]] = {}

    def initialize(self) -> None:
        return None

    def health(self) -> dict[str, object]:
        return {"available": True, "backend": "memory", "path_display": "memory", "persistent": False, "schema_initialized": True}

    def save_run(self, run_id: str, result: dict[str, Any], incidents: list[StoredIncident]) -> None:
        with self._lock:
            self._runs[run_id] = StoredRun(run_id=run_id, result=dict(result))
            for incident in incidents:
                self._incidents[incident.incident_id] = incident

    store_run = save_run

    def get_run(self, run_id: str) -> StoredRun | None:
        with self._lock:
            return self._runs.get(run_id)

    def list_runs(self, limit: int = 50, scenario_label: str | None = None, difficulty: str | None = None, created_after: str | None = None, created_before: str | None = None) -> list[StoredRun]:
        with self._lock:
            runs = list(self._runs.values())
        if scenario_label:
            runs = [run for run in runs if scenario_label.lower() in str(run.result.get("ScenarioLabel", "")).lower()]
        if difficulty:
            runs = [run for run in runs if str(run.result.get("Difficulty", "")).lower() == difficulty.lower()]
        return runs[: max(0, int(limit))]

    def list_incidents(self, limit: int = 50, severity: str | None = None, incident_type: str | None = None) -> list[StoredIncident]:
        with self._lock:
            incidents = list(self._incidents.values())
        if severity:
            wanted = severity.strip().lower()
            incidents = [item for item in incidents if str(item.incident.get("IncidentSeverity") or item.incident.get("Severity") or "").lower() == wanted]
        if incident_type:
            wanted_type = incident_type.strip().lower()
            incidents = [item for item in incidents if wanted_type in str(item.incident.get("IncidentType") or item.incident.get("CorrelationPattern") or "").lower()]
        return incidents[: max(0, int(limit))]

    def get_incident(self, incident_id: str) -> StoredIncident | None:
        with self._lock:
            return self._incidents.get(incident_id)

    def save_analysis(self, incident_id: str, analysis: dict[str, Any], metadata: dict[str, Any]) -> None:
        with self._lock:
            stored = self._incidents[incident_id]
            stored.analysis = dict(analysis)
            stored.analyst_metadata = dict(metadata)
            self._analyses[incident_id] = {"AnalystResult": dict(analysis), "AnalystMetadata": dict(metadata)}

    def get_latest_analysis(self, incident_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._analyses.get(incident_id)

    def save_action_decision(self, incident_id: str, decision: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            existing = self._incidents[incident_id].action_decision
            if existing is not None:
                if existing.get("Decision") != decision.get("Decision"):
                    raise RepositoryConflictError("Incident already has a conflicting action decision.")
                return existing
            self._incidents[incident_id].action_decision = dict(decision)
            return dict(decision)

    def get_action_decision(self, incident_id: str) -> dict[str, Any] | None:
        with self._lock:
            incident = self._incidents.get(incident_id)
            return None if incident is None else incident.action_decision

    def update_incident_payload_and_timeline(self, incident_id: str, incident: dict[str, Any], timeline: list[dict[str, Any]]) -> None:
        with self._lock:
            stored = self._incidents.get(incident_id)
            if stored is not None:
                stored.incident = dict(incident)
                stored.timeline = list(timeline)

    def clear_for_tests(self) -> None:
        with self._lock:
            self._incidents.clear()
            self._runs.clear()
            self._analyses.clear()
