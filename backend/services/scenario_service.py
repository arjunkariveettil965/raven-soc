from __future__ import annotations

import logging
from uuid import uuid4

import pandas as pd

from backend.repositories import IncidentRepository, StoredIncident
from backend.schemas.common import serialize_api_value
from backend.schemas.scenarios import ScenarioMode, ScenarioRunRequest
from backend.settings import settings
from core.scenario_pipeline import run_synthetic_defender_response, run_synthetic_incident_pipeline
from data_generation.scenario_lab import DIFFICULTIES, NOISE_LEVELS, list_scenarios


logger = logging.getLogger(__name__)


def get_scenario_registry() -> list[dict[str, object]]:
    return [
        {
            "ScenarioName": item["ScenarioName"],
            "Description": item["Description"],
            "SupportedDifficulties": sorted(DIFFICULTIES),
            "SupportedNoiseLevels": sorted(NOISE_LEVELS),
        }
        for item in list_scenarios()
    ]


def _safe_analyst_metadata(metadata: dict[str, object]) -> dict[str, object]:
    safe = dict(metadata)
    safe.pop("RawModelOutput", None)
    return serialize_api_value(safe)  # type: ignore[return-value]


def _hidden_evaluation(evaluation: dict[str, object], reveal_answer: bool) -> dict[str, object]:
    safe = dict(evaluation)
    if not reveal_answer:
        for key in (
            "ExpectedAlertsFound",
            "MissingExpectedAlerts",
            "UnexpectedIncidents",
        ):
            safe.pop(key, None)
    return serialize_api_value(safe)  # type: ignore[return-value]


def _scenario_label(scenario: dict[str, object], random_hidden: bool) -> str:
    if random_hidden:
        return "Hidden Random Scenario"
    return str(scenario.get("ScenarioName", "Synthetic Scenario"))


def run_scenario(request: ScenarioRunRequest, repository: IncidentRepository) -> dict[str, object]:
    run_id = str(uuid4())
    random_hidden = request.scenario_mode is ScenarioMode.random and not request.reveal_answer
    scenario_name = request.scenario_name or "multi_stage_intrusion"
    dashboard_mode = "Random Scenario" if request.scenario_mode is ScenarioMode.random else "Select Scenario"
    analyst_mode = "hybrid" if request.analyst_mode.value == "Hybrid" else "deterministic"
    model = request.ollama_model or settings.default_ollama_model

    logger.info("Scenario run started: mode=%s difficulty=%s", request.scenario_mode.value, request.difficulty.value)
    result = run_synthetic_incident_pipeline(
        environment_name=request.environment or "Finance SME",
        analyst_mode=analyst_mode,
        ollama_model=model,
        scenario_name=scenario_name,
        scenario_mode=dashboard_mode,
        seed=request.seed,
        difficulty=request.difficulty.value,
        noise_level=request.noise_level.value,
    )

    scenario = dict(result.get("scenario", {}))
    selected_incident = result.get("selected_incident")
    selected_incident_dict = (
        selected_incident.to_dict()
        if hasattr(selected_incident, "to_dict")
        else dict(selected_incident or {})
    )
    incident_id = str(selected_incident_dict.get("IncidentID", run_id))

    analyst_metadata = _safe_analyst_metadata(dict(result.get("analyst_metadata", {})))
    defender_recommendation = run_synthetic_defender_response(
        analysis=dict(result.get("analysis", {})),
        environment_profile=dict(result.get("environment_profile", {})),
        human_approved=False,
    )

    api_response = {
        "RunID": run_id,
        "ScenarioLabel": _scenario_label(scenario, random_hidden),
        "ScenarioMode": request.scenario_mode.value,
        "Seed": scenario.get("Seed", request.seed),
        "Difficulty": scenario.get("Difficulty", request.difficulty.value),
        "NoiseLevel": request.noise_level.value,
        "EventCount": len(result.get("events", [])),
        "AttackEventCount": len(scenario.get("AttackEventIDs", [])),
        "BenignEventCount": len(scenario.get("BenignEventIDs", [])),
        "Alerts": serialize_api_value(result.get("alerts", pd.DataFrame())),
        "Incidents": serialize_api_value(result.get("incidents", pd.DataFrame())),
        "SelectedIncident": serialize_api_value(selected_incident_dict) if selected_incident_dict else None,
        "AnalystResult": serialize_api_value(result.get("analysis", {})),
        "AnalystMetadata": analyst_metadata,
        "DefenderRecommendation": serialize_api_value(defender_recommendation),
        "Evaluation": _hidden_evaluation(dict(result.get("scenario_evaluation", {})), request.reveal_answer),
        "AnswerRevealed": bool(request.reveal_answer),
    }

    if selected_incident_dict:
        stored = StoredIncident(
            run_id=run_id,
            incident_id=incident_id,
            incident=serialize_api_value(selected_incident_dict),  # type: ignore[arg-type]
            timeline=serialize_api_value(result.get("timeline", pd.DataFrame())),  # type: ignore[arg-type]
            analysis=serialize_api_value(result.get("analysis", {})),  # type: ignore[arg-type]
            analyst_metadata=analyst_metadata,
            environment_profile=serialize_api_value(result.get("environment_profile", {})),  # type: ignore[arg-type]
        )
        repository.save_run(run_id, api_response, [stored])
        logger.info("Incident created: incident_id=%s run_id=%s", incident_id, run_id)
    else:
        repository.save_run(run_id, api_response, [])

    if request.scenario_mode is ScenarioMode.random and request.reveal_answer:
        logger.info("Random scenario revealed: %s", scenario.get("ScenarioName", "Synthetic Scenario"))
    logger.info("Scenario run completed: run_id=%s", run_id)
    return api_response
