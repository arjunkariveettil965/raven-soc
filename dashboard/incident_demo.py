from __future__ import annotations

from ai_analyst.ollama_client import check_ollama_health
from core import scenario_pipeline


def run_synthetic_incident_pipeline(*args, **kwargs) -> dict[str, object]:
    scenario_pipeline.check_ollama_health = check_ollama_health
    return scenario_pipeline.run_synthetic_incident_pipeline(*args, **kwargs)


def run_synthetic_defender_response(*args, **kwargs) -> dict[str, object]:
    return scenario_pipeline.run_synthetic_defender_response(*args, **kwargs)


__all__ = ["run_synthetic_defender_response", "run_synthetic_incident_pipeline"]
