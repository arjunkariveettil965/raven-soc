from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from backend.dependencies import get_incident_repository
from backend.repositories import IncidentRepository
from backend.schemas.analyst import AnalyzeIncidentRequest, AnalyzeIncidentResponse
from backend.services.analyst_service import analyze_incident


router = APIRouter(prefix="/incidents", tags=["analyst"])


@router.post("/{incident_id}/analyze", response_model=AnalyzeIncidentResponse)
def analyze_stored_incident(
    incident_id: str,
    request: AnalyzeIncidentRequest,
    repository: IncidentRepository = Depends(get_incident_repository),
) -> dict[str, object]:
    result = analyze_incident(
        repository=repository,
        incident_id=incident_id,
        mode=request.mode,
        ollama_model=request.ollama_model,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    analysis, metadata = result
    return {
        "IncidentID": incident_id,
        "AnalystResult": analysis,
        "AnalystMetadata": metadata,
    }
