from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from backend.dependencies import get_incident_repository
from backend.repositories import IncidentRepository
from backend.schemas.scenarios import ScenarioRegistryItem, ScenarioRunRequest, ScenarioRunResponse
from backend.services.scenario_service import get_scenario_registry, run_scenario


router = APIRouter(prefix="/scenarios", tags=["scenarios"])


@router.get("", response_model=list[ScenarioRegistryItem])
def list_supported_scenarios() -> list[dict[str, object]]:
    return get_scenario_registry()


@router.post("/run", response_model=ScenarioRunResponse)
def run_supported_scenario(
    request: ScenarioRunRequest,
    repository: IncidentRepository = Depends(get_incident_repository),
) -> dict[str, object]:
    try:
        return run_scenario(request, repository)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except RuntimeError as error:
        raise HTTPException(status_code=500, detail="Scenario pipeline failed safely.") from error
