from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException

from backend.dependencies import get_incident_repository
from backend.repositories import IncidentRepository
from backend.schemas.actions import ActionDecisionResponse
from backend.services.action_service import ActionConflictError, approve_action, reject_action


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/actions", tags=["actions"])


@router.post("/{incident_id}/approve", response_model=ActionDecisionResponse)
def approve_incident_action(
    incident_id: str,
    repository: IncidentRepository = Depends(get_incident_repository),
) -> dict[str, object]:
    try:
        result = approve_action(repository, incident_id)
    except ActionConflictError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    if result is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    logger.info("Simulated action approved: incident_id=%s action_id=%s", incident_id, result.get("ActionID"))
    return result


@router.post("/{incident_id}/reject", response_model=ActionDecisionResponse)
def reject_incident_action(
    incident_id: str,
    repository: IncidentRepository = Depends(get_incident_repository),
) -> dict[str, object]:
    try:
        result = reject_action(repository, incident_id)
    except ActionConflictError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    if result is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    logger.info("Simulated action rejected: incident_id=%s action_id=%s", incident_id, result.get("ActionID"))
    return result
