from __future__ import annotations

from typing import Any

from backend.schemas.common import StrictBaseModel


class IncidentListResponse(StrictBaseModel):
    Incidents: list[dict[str, Any]]


class IncidentResponse(StrictBaseModel):
    Incident: dict[str, Any]
