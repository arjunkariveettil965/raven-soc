from __future__ import annotations

from typing import Any

from backend.schemas.common import StrictBaseModel


class RunListResponse(StrictBaseModel):
    Runs: list[dict[str, Any]]


class RunDetailResponse(StrictBaseModel):
    Run: dict[str, Any]
    Incidents: list[dict[str, Any]]
