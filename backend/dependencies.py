from __future__ import annotations

from backend.repositories import IncidentRepository, MemoryIncidentRepository, SQLiteIncidentRepository
from backend.settings import settings


incident_repository: IncidentRepository
if settings.repository_backend.lower() == "memory":
    incident_repository = MemoryIncidentRepository()
else:
    incident_repository = SQLiteIncidentRepository(settings.api_database_path)


def get_incident_repository() -> IncidentRepository:
    return incident_repository
