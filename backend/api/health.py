from __future__ import annotations

from fastapi import APIRouter, Depends

from backend.dependencies import get_incident_repository
from backend.repositories import IncidentRepository
from backend.settings import settings


router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
def health(repository: IncidentRepository = Depends(get_incident_repository)) -> dict[str, object]:
    database = repository.health()
    database_available = bool(database.get("available"))
    return {
        "status": "healthy" if database_available else "unhealthy",
        "service": settings.service_name,
        "version": settings.version,
        "database": database,
        "ollama": {
            "configured_url": settings.ollama_url,
            "default_model": settings.default_ollama_model,
            "checked": False,
        },
        "capabilities": {
            "scenario_lab": True,
            "detection": True,
            "correlation": True,
            "hybrid_analyst": True,
            "simulated_defender": True,
        },
    }
