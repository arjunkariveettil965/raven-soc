from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import field_validator

from backend.schemas.common import AnalystMode, StrictBaseModel


class ScenarioMode(str, Enum):
    select = "select"
    random = "random"


class Difficulty(str, Enum):
    easy = "Easy"
    medium = "Medium"
    hard = "Hard"


class NoiseLevel(str, Enum):
    none = "None"
    low = "Low"
    medium = "Medium"
    high = "High"


class ScenarioRegistryItem(StrictBaseModel):
    ScenarioName: str
    Description: str
    SupportedDifficulties: list[str]
    SupportedNoiseLevels: list[str]


class ScenarioRunRequest(StrictBaseModel):
    scenario_mode: ScenarioMode = ScenarioMode.select
    scenario_name: str | None = None
    difficulty: Difficulty = Difficulty.medium
    noise_level: NoiseLevel = NoiseLevel.low
    seed: int
    environment: str | None = "Finance SME"
    analyst_mode: AnalystMode = AnalystMode.deterministic
    ollama_model: str | None = None
    reveal_answer: bool = False

    @field_validator("scenario_name", "environment", "ollama_model")
    @classmethod
    def strip_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None

        stripped = value.strip()
        return stripped or None


class ScenarioRunResponse(StrictBaseModel):
    RunID: str
    ScenarioLabel: str
    ScenarioMode: str
    Seed: int | None
    Difficulty: str
    NoiseLevel: str
    EventCount: int
    AttackEventCount: int
    BenignEventCount: int
    Alerts: list[dict[str, Any]]
    Incidents: list[dict[str, Any]]
    SelectedIncident: dict[str, Any] | None
    AnalystResult: dict[str, Any]
    AnalystMetadata: dict[str, Any]
    DefenderRecommendation: dict[str, Any] | None
    Evaluation: dict[str, Any]
    AnswerRevealed: bool