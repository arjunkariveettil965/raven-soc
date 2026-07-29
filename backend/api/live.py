from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from backend.schemas.live import (
    LiveAlertsResponse,
    LiveEventsResponse,
    LiveIncidentsResponse,
    LiveResumeRequest,
    LiveStartRequest,
    LiveStatusResponse,
)
from backend.services.live_monitoring_service import live_monitoring_service


router = APIRouter(prefix="/live", tags=["live-monitoring"])


@router.get("/status", response_model=LiveStatusResponse)
def get_live_status() -> dict[str, object]:
    return live_monitoring_service.get_status()


@router.post("/start", response_model=LiveStatusResponse)
def start_live_monitoring(request: LiveStartRequest) -> dict[str, object]:
    try:
        return live_monitoring_service.start(
            scenario_name=request.scenario_name,
            speed=request.speed,
            seed=request.seed,
        )
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@router.post("/pause", response_model=LiveStatusResponse)
def pause_live_monitoring() -> dict[str, object]:
    return live_monitoring_service.pause()


@router.post("/resume", response_model=LiveStatusResponse)
def resume_live_monitoring(request: LiveResumeRequest | None = None) -> dict[str, object]:
    speed = request.speed if request is not None else None
    try:
        return live_monitoring_service.resume(speed=speed)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@router.post("/reset", response_model=LiveStatusResponse)
def reset_live_monitoring() -> dict[str, object]:
    return live_monitoring_service.reset()


@router.get("/events", response_model=LiveEventsResponse)
def get_live_events(limit: int = Query(200, ge=1, le=1000)) -> dict[str, object]:
    return {"events": live_monitoring_service.get_events(limit=limit)}


@router.get("/alerts", response_model=LiveAlertsResponse)
def get_live_alerts(limit: int = Query(200, ge=1, le=1000)) -> dict[str, object]:
    return {"alerts": live_monitoring_service.get_alerts(limit=limit)}


@router.get("/incidents", response_model=LiveIncidentsResponse)
def get_live_incidents(limit: int = Query(100, ge=1, le=500)) -> dict[str, object]:
    return {"incidents": live_monitoring_service.get_incidents(limit=limit)}

