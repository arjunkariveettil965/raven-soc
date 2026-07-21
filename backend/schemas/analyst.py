from __future__ import annotations

from typing import Any

from pydantic import field_validator

from backend.schemas.common import AnalystMode, StrictBaseModel


class AnalyzeIncidentRequest(StrictBaseModel):
    mode: AnalystMode = AnalystMode.deterministic
    ollama_model: str | None = None

    @field_validator("ollama_model")
    @classmethod
    def strip_model(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None


class AnalyzeIncidentResponse(StrictBaseModel):
    IncidentID: str
    AnalystResult: dict[str, Any]
    AnalystMetadata: dict[str, Any]
