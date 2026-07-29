from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from ai_analyst.ollama_client import DEFAULT_OLLAMA_MODEL
from backend.repositories import IncidentRepository


@pytest.fixture()
def client(monkeypatch):
    import backend.dependencies as dependencies
    from backend.main import app

    dependencies.incident_repository = IncidentRepository()
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


def _valid_model_response():
    return {
        "Status": "confirmed",
        "ThreatType": "Credential Access",
        "Severity": "high",
        "Confidence": 90,
        "Summary": "Credential attacks were followed by suspicious execution activity.",
        "SuspicionReason": "The trusted evidence shows failed authentication, later success, and suspicious process activity.",
        "Inferences": ["Inference: the activity is consistent with a confirmed intrusion."],
        "RecommendedActionID": "ISOLATE_DEVICE",
        "RequiresApproval": True,
    }


def _run_selected(client: TestClient, **overrides):
    payload = {
        "scenario_mode": "select",
        "scenario_name": "multi_stage_intrusion",
        "difficulty": "Medium",
        "noise_level": "Low",
        "seed": 20260721,
        "environment": "Finance SME",
        "analyst_mode": "Deterministic",
    }
    payload.update(overrides)
    response = client.post("/api/v1/scenarios/run", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def test_root_openapi_health_and_default_model(client):
    assert client.get("/").json() == {
        "name": "RAVEN-SOC API",
        "status": "available",
        "version": "0.1.0",
    }
    assert client.get("/openapi.json").status_code == 200
    health = client.get("/api/v1/health").json()
    assert health["ollama"]["default_model"] == DEFAULT_OLLAMA_MODEL
    assert health["ollama"]["checked"] is False
    assert health["capabilities"]["hybrid_analyst"] is True


def test_list_supported_scenarios(client):
    scenarios = client.get("/api/v1/scenarios").json()
    names = {item["ScenarioName"] for item in scenarios}
    assert {
        "Multi-Stage Intrusion",
        "Password Spray Attempt",
        "Malware Download and Execution",
        "Command-and-Control Beaconing",
    } <= names
    assert all("SupportedDifficulties" in item for item in scenarios)


def test_selected_and_random_scenario_runs_hide_and_reveal_answers(client):
    selected = _run_selected(client)
    assert selected["ScenarioLabel"] == "Multi-Stage Intrusion"
    assert selected["SelectedIncident"] is not None
    assert selected["DefenderRecommendation"]["Executed"] is False

    hidden = _run_selected(client, scenario_mode="random")
    assert hidden["ScenarioLabel"] == "Hidden Random Scenario"
    assert hidden["AnswerRevealed"] is False

    revealed = _run_selected(client, scenario_mode="random", reveal_answer=True)
    assert revealed["ScenarioLabel"] != "Hidden Random Scenario"
    assert revealed["AnswerRevealed"] is True


def test_same_seed_is_reproducible_for_scenario_outputs(client):
    first = _run_selected(client, seed=101)
    second = _run_selected(client, seed=101)

    assert first["EventCount"] == second["EventCount"]
    assert first["AttackEventCount"] == second["AttackEventCount"]
    assert first["SelectedIncident"]["IncidentType"] == second["SelectedIncident"]["IncidentType"]


def test_invalid_scenario_and_difficulty_are_rejected(client):
    bad_scenario = _run_selected
    response = client.post(
        "/api/v1/scenarios/run",
        json={
            "scenario_mode": "select",
            "scenario_name": "not_real",
            "difficulty": "Medium",
            "noise_level": "Low",
            "seed": 1,
            "analyst_mode": "Deterministic",
        },
    )
    assert response.status_code == 422
    response = client.post(
        "/api/v1/scenarios/run",
        json={
            "scenario_mode": "select",
            "scenario_name": "multi_stage_intrusion",
            "difficulty": "Impossible",
            "noise_level": "Low",
            "seed": 1,
            "analyst_mode": "Deterministic",
        },
    )
    assert response.status_code == 422
    assert bad_scenario


def test_no_incident_case_is_returned_safely(client, monkeypatch):
    import backend.services.scenario_service as scenario_service

    def fake_pipeline(**kwargs):
        return {
            "scenario": {
                "ScenarioName": "No Incident",
                "Seed": kwargs["seed"],
                "Difficulty": kwargs["difficulty"],
                "AttackEventIDs": [],
                "BenignEventIDs": [],
            },
            "events": [],
            "alerts": [],
            "incidents": [],
            "selected_incident": {},
            "analysis": {},
            "environment_profile": {},
            "analyst_metadata": {},
            "scenario_evaluation": {"Detected": False},
            "timeline": [],
        }

    monkeypatch.setattr(scenario_service, "run_synthetic_incident_pipeline", fake_pipeline)
    result = _run_selected(client)
    assert result["SelectedIncident"] is None
    assert result["EventCount"] == 0


def test_incident_list_retrieve_filters_and_datetime_serialization(client):
    result = _run_selected(client)
    incident_id = result["SelectedIncident"]["IncidentID"]

    listed = client.get("/api/v1/incidents").json()["Incidents"]
    assert any(item["IncidentID"] == incident_id for item in listed)
    assert client.get(f"/api/v1/incidents/{incident_id}").json()["Incident"]["IncidentID"] == incident_id
    assert client.get("/api/v1/incidents/missing").status_code == 404
    assert client.get("/api/v1/incidents", params={"severity": result["SelectedIncident"]["IncidentSeverity"]}).json()["Incidents"]
    assert client.get("/api/v1/incidents", params={"incident_type": "Intrusion"}).json()["Incidents"]
    assert isinstance(result["SelectedIncident"]["FirstSeen"], str)


def test_deterministic_and_hybrid_analysis_do_not_expose_raw_model_output(client, monkeypatch):
    import ai_analyst.agent as analyst_agent

    result = _run_selected(client)
    incident_id = result["SelectedIncident"]["IncidentID"]

    deterministic = client.post(
        f"/api/v1/incidents/{incident_id}/analyze",
        json={"mode": "Deterministic"},
    ).json()
    assert deterministic["AnalystResult"]["RecommendedActionID"] in {"ISOLATE_DEVICE", "COLLECT_EVIDENCE", "INCREASE_MONITORING"}

    monkeypatch.setattr(analyst_agent, "generate_structured_analysis", lambda **kwargs: _valid_model_response())
    hybrid = client.post(
        f"/api/v1/incidents/{incident_id}/analyze",
        json={"mode": "Hybrid", "ollama_model": "custom-local"},
    ).json()
    assert hybrid["AnalystMetadata"]["AnalystMode"] == "ollama"
    assert hybrid["AnalystMetadata"]["ModelName"] == "custom-local"
    assert hybrid["AnalystMetadata"]["UsedFallback"] is False
    assert "RawModelOutput" not in hybrid["AnalystMetadata"]

    monkeypatch.setattr(analyst_agent, "generate_structured_analysis", lambda **kwargs: {"Status": "maybe"})
    fallback = client.post(
        f"/api/v1/incidents/{incident_id}/analyze",
        json={"mode": "Hybrid"},
    ).json()
    assert fallback["AnalystMetadata"]["UsedFallback"] is True
    assert "RawModelOutput" not in fallback["AnalystMetadata"]
    assert client.post("/api/v1/incidents/missing/analyze", json={"mode": "Deterministic"}).status_code == 404


def test_coverage_endpoint_reuses_dashboard_coverage(client):
    coverage = client.get("/api/v1/coverage").json()
    rule_ids = {item["RuleID"] for item in coverage["DetectionRules"]}
    pattern_ids = {item["PatternID"] for item in coverage["CorrelationPatterns"]}
    assert "AUTH_PASSWORD_SPRAY" in rule_ids
    assert "COMMAND_CONTROL_BEACONING" in pattern_ids
    assert all(item["ImplementationStatus"] == "Implemented" for item in coverage["DetectionRules"])


def test_actions_are_simulation_only_and_conflicts_are_rejected(client):
    result = _run_selected(client)
    incident_id = result["SelectedIncident"]["IncidentID"]

    approve = client.post(
        f"/api/v1/actions/{incident_id}/approve",
        json={"ActionID": "DISABLE_USER"},
    )
    assert approve.status_code == 200
    approved = approve.json()
    assert approved["ActionID"] == result["AnalystResult"]["RecommendedActionID"]
    assert approved["ExecutionMode"] == "Simulation Only"
    assert "No real endpoint" in approved["Message"]
    assert client.post(f"/api/v1/actions/{incident_id}/reject").status_code == 409
    assert client.post("/api/v1/actions/missing/approve").status_code == 404

    other = _run_selected(client, seed=20260722)
    reject = client.post(f"/api/v1/actions/{other['SelectedIncident']['IncidentID']}/reject")
    assert reject.status_code == 200
    assert reject.json()["Decision"] == "rejected"
    assert client.post(f"/api/v1/actions/{other['SelectedIncident']['IncidentID']}/approve").status_code == 409


def test_phase9_regression_imports_still_work():
    import importlib.util

    assert importlib.util.find_spec("app") is not None
    assert importlib.util.find_spec("dashboard.presentation") is not None
    assert importlib.util.find_spec("dashboard.incident_demo") is not None
