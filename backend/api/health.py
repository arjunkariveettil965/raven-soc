from __future__ import annotations

from fastapi import APIRouter, Depends

from ai_analyst.ollama_client import DEFAULT_OLLAMA_MODEL, DEFAULT_OLLAMA_URL
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
            "configured_url": DEFAULT_OLLAMA_URL,
            "default_model": DEFAULT_OLLAMA_MODEL,
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
