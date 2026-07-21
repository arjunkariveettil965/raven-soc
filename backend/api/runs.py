from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.dependencies import get_incident_repository
from backend.repositories import IncidentRepository
from backend.schemas.runs import RunDetailResponse, RunListResponse
from backend.services.run_service import get_run_detail, list_runs


router = APIRouter(prefix="/runs", tags=["runs"])


@router.get("", response_model=RunListResponse)
def get_runs(
    limit: int = Query(50, ge=1, le=500),
    scenario_label: str | None = None,
    difficulty: str | None = None,
    created_after: str | None = None,
    created_before: str | None = None,
    repository: IncidentRepository = Depends(get_incident_repository),
) -> dict[str, object]:
    return {
        "Runs": list_runs(
            repository=repository,
            limit=limit,
            scenario_label=scenario_label,
            difficulty=difficulty,
            created_after=created_after,
            created_before=created_before,
        )
    }


@router.get("/{run_id}", response_model=RunDetailResponse)
def retrieve_run(
    run_id: str,
    repository: IncidentRepository = Depends(get_incident_repository),
) -> dict[str, object]:
    detail = get_run_detail(repository, run_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Run not found.")
    return detail
