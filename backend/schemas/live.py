from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator

from backend.schemas.common import StrictBaseModel
from backend.services.live_monitoring_service import SUPPORTED_SCENARIOS, SUPPORTED_SPEEDS


class LiveStartRequest(StrictBaseModel):
    scenario_name: str = "Multi Stage Intrusion"
    speed: float = 1.0
    seed: int | None = None

    @field_validator("scenario_name")
    @classmethod
    def validate_scenario_name(cls, value: str) -> str:
        scenario_name = value.strip()
        if scenario_name not in SUPPORTED_SCENARIOS:
            raise ValueError(f"Unsupported scenario: {value!r}.")
        return scenario_name

    @field_validator("speed")
    @classmethod
    def validate_speed(cls, value: float) -> float:
        normalized = float(value)
        if normalized not in SUPPORTED_SPEEDS:
            raise ValueError(f"Unsupported speed: {value!r}.")
        return normalized


class LiveResumeRequest(StrictBaseModel):
    speed: float | None = None

    @field_validator("speed")
    @classmethod
    def validate_optional_speed(cls, value: float | None) -> float | None:
        if value is None:
            return None
        normalized = float(value)
        if normalized not in SUPPORTED_SPEEDS:
            raise ValueError(f"Unsupported speed: {value!r}.")
        return normalized


class LiveStatusResponse(StrictBaseModel):
    status: str
    scenario: str
    speed: float
    event_count: int
    queue_size: int
    alert_count: int
    incident_count: int
    current_mitre_tactic: str
    current_severity: str
    latest_event: dict[str, Any] | None
    latest_alert: dict[str, Any] | None
    latest_incident: dict[str, Any] | None
    last_error: str | None
    updated_at: str
    supported_scenarios: list[str]
    supported_speeds: list[float]


class LiveEventsResponse(StrictBaseModel):
    events: list[dict[str, Any]]


class LiveAlertsResponse(StrictBaseModel):
    alerts: list[dict[str, Any]]


class LiveIncidentsResponse(StrictBaseModel):
    incidents: list[dict[str, Any]]


class LiveLimitRequest(StrictBaseModel):
    limit: int = Field(200, ge=1, le=1000)

