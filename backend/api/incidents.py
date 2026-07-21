from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.dependencies import get_incident_repository
from backend.repositories import IncidentRepository
from backend.schemas.incidents import IncidentListResponse, IncidentResponse
from backend.services.incident_service import get_incident, list_incidents


router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=IncidentListResponse)
def get_incidents(
    limit: int = Query(50, ge=1, le=500),
    severity: str | None = None,
    incident_type: str | None = None,
    repository: IncidentRepository = Depends(get_incident_repository),
) -> dict[str, object]:
    return {
        "Incidents": list_incidents(
            repository=repository,
            limit=limit,
            severity=severity,
            incident_type=incident_type,
        )
    }


@router.get("/{incident_id}", response_model=IncidentResponse)
def retrieve_incident(
    incident_id: str,
    repository: IncidentRepository = Depends(get_incident_repository),
) -> dict[str, object]:
    incident = get_incident(repository, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return {"Incident": incident}
