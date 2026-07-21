from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


class RepositoryError(RuntimeError):
    pass


class RepositoryUnavailableError(RepositoryError):
    pass


class RepositoryConflictError(RepositoryError):
    pass


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


class IncidentRepository(Protocol):
    def initialize(self) -> None: ...
    def health(self) -> dict[str, object]: ...
    def save_run(self, run_id: str, result: dict[str, Any], incidents: list[StoredIncident]) -> None: ...
    def get_run(self, run_id: str) -> StoredRun | None: ...
    def list_runs(self, limit: int = 50, scenario_label: str | None = None, difficulty: str | None = None, created_after: str | None = None, created_before: str | None = None) -> list[StoredRun]: ...
    def list_incidents(self, limit: int = 50, severity: str | None = None, incident_type: str | None = None) -> list[StoredIncident]: ...
    def get_incident(self, incident_id: str) -> StoredIncident | None: ...
    def save_analysis(self, incident_id: str, analysis: dict[str, Any], metadata: dict[str, Any]) -> None: ...
    def get_latest_analysis(self, incident_id: str) -> dict[str, Any] | None: ...
    def save_action_decision(self, incident_id: str, decision: dict[str, Any]) -> dict[str, Any]: ...
    def get_action_decision(self, incident_id: str) -> dict[str, Any] | None: ...
    def clear_for_tests(self) -> None: ...
