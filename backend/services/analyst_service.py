from __future__ import annotations

import logging

import pandas as pd

from ai_analyst import agent as analyst_agent
from ai_analyst.ollama_client import DEFAULT_OLLAMA_MODEL, DEFAULT_OLLAMA_URL
from backend.repositories import IncidentRepository
from backend.schemas.common import AnalystMode, serialize_api_value


logger = logging.getLogger(__name__)


def _safe_metadata(metadata: dict[str, object]) -> dict[str, object]:
    safe = dict(metadata)
    safe.pop("RawModelOutput", None)
    return serialize_api_value(safe)  # type: ignore[return-value]


def analyze_incident(
    repository: IncidentRepository,
    incident_id: str,
    mode: AnalystMode,
    ollama_model: str | None = None,
) -> tuple[dict[str, object], dict[str, object]] | None:
    stored = repository.get_incident(incident_id)
    if stored is None:
        return None

    model = ollama_model or DEFAULT_OLLAMA_MODEL
    analysis = analyst_agent.run_analyst_agent(
        incident=stored.incident,
        timeline=pd.DataFrame(stored.timeline),
        environment_name=str(stored.environment_profile.get("EnvironmentName", "Finance SME")),
        mode=mode.value.lower(),
        ollama_model=model,
        ollama_base_url=DEFAULT_OLLAMA_URL,
    )
    metadata = analyst_agent.get_last_analyst_metadata()
    if metadata.get("UsedFallback"):
        logger.warning("[Hybrid Analyst Fallback] %s", metadata.get("FallbackReason"))

    stored.analysis = dict(analysis)
    stored.analyst_metadata = _safe_metadata(metadata)
    repository.save_analysis(incident_id, stored.analysis, stored.analyst_metadata)
    return (
        serialize_api_value(analysis),  # type: ignore[arg-type,return-value]
        stored.analyst_metadata,
    )


def get_latest_analysis(repository: IncidentRepository, incident_id: str) -> dict[str, object] | None:
    if repository.get_incident(incident_id) is None:
        return None
    latest = repository.get_latest_analysis(incident_id)
    return serialize_api_value(latest) if latest is not None else None  # type: ignore[return-value]
