from __future__ import annotations

from backend.repositories import IncidentRepository


incident_repository = IncidentRepository()


def get_incident_repository() -> IncidentRepository:
    return incident_repository
