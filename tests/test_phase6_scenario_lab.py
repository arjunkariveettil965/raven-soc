from __future__ import annotations

import random
from unittest.mock import patch

import pandas as pd
import pytest

from ai_analyst.agent import get_last_analyst_metadata
from ai_analyst.schemas import ALLOWED_ACTION_IDS
from dashboard.incident_demo import run_synthetic_incident_pipeline
from dashboard.scenario_evaluation import evaluate_scenario_result
from data_generation.scenario_lab import (
    DIFFICULTIES,
    NOISE_LEVELS,
    generate_random_scenario,
    generate_scenario,
    list_scenarios,
)
from detection.alert_engine import analyze_security_events
from incidents.correlation_engine import correlate_alerts
from incidents.incident_classifier import classify_incidents


EXPECTED_SCENARIOS = {
    "multi_stage_intrusion",
    "password_spray_attempt",
    "malware_download_execution",
    "command_control_beaconing",
}


def _events_signature(scenario: dict[str, object]) -> list[tuple[object, ...]]:
    events = scenario["GeneratedEvents"]
    assert isinstance(events, pd.DataFrame)
    return list(
        events[
            [
                "EventID",
                "EventTime",
                "DeviceName",
                "UserName",
                "SourceIP",
                "DestinationIP",
                "ProcessName",
                "CommandLine",
            ]
        ].itertuples(index=False, name=None)
    )


def _run_detection(scenario: dict[str, object]) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    events = scenario["GeneratedEvents"]
    alerts = analyze_security_events(events)
    incidents = correlate_alerts(alerts)
    classified = classify_incidents(incidents)
    if not incidents.empty and not classified.empty:
        incidents = incidents.copy()
        for column in classified.columns:
            incidents[column] = classified[column].values
    return alerts, incidents, classified


def test_scenario_registry_lists_all_four_scenarios() -> None:
    assert {scenario["ScenarioID"] for scenario in list_scenarios()} == EXPECTED_SCENARIOS


def test_unknown_scenario_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown synthetic scenario"):
        generate_scenario("not real", seed=1)


def test_random_selection_uses_allowlist() -> None:
    for seed in range(20):
        assert generate_random_scenario(seed=seed)["ScenarioID"] in EXPECTED_SCENARIOS


def test_same_seed_produces_identical_scenario() -> None:
    first = generate_scenario("Password Spray Attempt", seed=42, difficulty="Medium", noise_level="Low")
    second = generate_scenario("Password Spray Attempt", seed=42, difficulty="Medium", noise_level="Low")

    assert _events_signature(first) == _events_signature(second)


def test_different_seed_changes_randomized_values() -> None:
    first = generate_scenario("Password Spray Attempt", seed=42)
    second = generate_scenario("Password Spray Attempt", seed=43)

    assert _events_signature(first) != _events_signature(second)


def test_global_random_state_is_not_mutated() -> None:
    random.seed(12345)
    before = random.getstate()
    generate_scenario("Command-and-Control Beaconing", seed=100)
    after = random.getstate()

    assert before == after


@pytest.mark.parametrize("scenario_id", sorted(EXPECTED_SCENARIOS))
def test_each_scenario_produces_valid_events_and_expected_incident(scenario_id: str) -> None:
    scenario = generate_scenario(scenario_id, seed=101, difficulty="Medium", noise_level="Low")
    events = scenario["GeneratedEvents"]

    assert isinstance(events, pd.DataFrame)
    assert not events.empty
    assert set(scenario["AttackEventIDs"]).issubset(set(events["EventID"]))
    assert events["EventTime"].is_monotonic_increasing

    alerts, incidents, _ = _run_detection(scenario)
    evaluation = evaluate_scenario_result(scenario, alerts, incidents)

    assert evaluation["IncidentTypeMatched"] is True
    assert set(scenario["ExpectedAlertTypes"]).issubset(set(alerts["AlertType"]))
    assert set(scenario["ExpectedRecommendedActions"]).issubset(ALLOWED_ACTION_IDS)
    assert not incidents.empty
    assert incidents.iloc[0]["RequiresApproval"] in {True, False}


@pytest.mark.parametrize("noise_level", ["Low", "Medium", "High"])
def test_noise_levels_preserve_intended_detection(noise_level: str) -> None:
    scenario = generate_scenario("Malware Download and Execution", seed=300, difficulty="Medium", noise_level=noise_level)
    alerts, incidents, _ = _run_detection(scenario)

    assert evaluate_scenario_result(scenario, alerts, incidents)["OverallPassed"] is True


def test_benign_only_generation_does_not_create_scenario_incident() -> None:
    scenario = generate_scenario("Password Spray Attempt", seed=77, noise_level="High")
    events = scenario["GeneratedEvents"]
    benign = events[events["EventID"].isin(scenario["BenignEventIDs"])]
    alerts = analyze_security_events(benign)
    incidents = correlate_alerts(alerts)

    assert scenario["ExpectedIncidentType"] not in set(incidents.get("CorrelationPattern", pd.Series(dtype=str)).astype(str))


def test_benign_events_are_not_in_attack_evidence_ids_for_password_spray() -> None:
    scenario = generate_scenario("Password Spray Attempt", seed=88, noise_level="High")
    alerts, _, _ = _run_detection(scenario)
    spray_alert = alerts[alerts["AlertType"] == "Password Spray"].iloc[0]

    assert set(spray_alert["EventIDs"]).isdisjoint(set(scenario["BenignEventIDs"]))


def test_noise_preserves_chronological_ordering() -> None:
    scenario = generate_scenario("Multi-Stage Intrusion", seed=90, noise_level="High")

    assert scenario["GeneratedEvents"]["EventTime"].is_monotonic_increasing


@pytest.mark.parametrize("difficulty", sorted(DIFFICULTIES))
def test_supported_difficulties_remain_detectable(difficulty: str) -> None:
    scenario = generate_scenario("Command-and-Control Beaconing", seed=500, difficulty=difficulty, noise_level="Low")
    alerts, incidents, _ = _run_detection(scenario)

    assert evaluate_scenario_result(scenario, alerts, incidents)["OverallPassed"] is True


def test_invalid_difficulty_rejected() -> None:
    with pytest.raises(ValueError, match="Unsupported difficulty"):
        generate_scenario("Multi-Stage Intrusion", seed=1, difficulty="Impossible")


def test_noise_levels_are_declared() -> None:
    assert NOISE_LEVELS == {"None", "Low", "Medium", "High"}


def test_random_scenario_can_be_reproduced_by_seed() -> None:
    first = generate_random_scenario(seed=900, difficulty="Hard", noise_level="Medium")
    second = generate_random_scenario(seed=900, difficulty="Hard", noise_level="Medium")

    assert first["ScenarioID"] == second["ScenarioID"]
    assert _events_signature(first) == _events_signature(second)


def test_random_selection_can_generate_all_allowed_scenarios() -> None:
    observed = {generate_random_scenario(seed=seed)["ScenarioID"] for seed in range(100)}

    assert observed == EXPECTED_SCENARIOS


def test_answer_key_is_not_present_in_detection_events() -> None:
    scenario = generate_random_scenario(seed=5)
    events = scenario["GeneratedEvents"]

    forbidden_columns = {"ExpectedIncidentType", "ExpectedAlertTypes", "AttackEventIDs", "BenignEventIDs"}
    assert forbidden_columns.isdisjoint(set(events.columns))


def test_evaluation_reports_missing_alert() -> None:
    scenario = generate_scenario("Password Spray Attempt", seed=44)
    alerts, incidents, _ = _run_detection(scenario)
    alerts = alerts[alerts["AlertType"] != "Password Spray"]
    result = evaluate_scenario_result(scenario, alerts, incidents)

    assert "Password Spray" in result["MissingExpectedAlerts"]
    assert result["OverallPassed"] is False


def test_evaluation_reports_wrong_incident_type() -> None:
    scenario = generate_scenario("Password Spray Attempt", seed=44)
    alerts, incidents, _ = _run_detection(scenario)
    incidents = incidents.copy()
    incidents.loc[0, "CorrelationPattern"] = "Wrong Incident"
    incidents.loc[0, "IncidentType"] = "Wrong Incident"
    result = evaluate_scenario_result(scenario, alerts, incidents)

    assert result["IncidentTypeMatched"] is False


def test_evaluation_partial_mitre_coverage() -> None:
    scenario = generate_scenario("Multi-Stage Intrusion", seed=45)
    alerts, incidents, _ = _run_detection(scenario)
    incidents = incidents.copy()
    incidents.loc[0, "MITRETechniques"] = ["T1110 - Brute Force"]
    result = evaluate_scenario_result(scenario, alerts, incidents)

    assert 0 < result["MITRECoverage"] < 1


def test_pipeline_runs_selected_scenario_through_hybrid_with_mocked_ollama() -> None:
    model_output = {
        "Status": "confirmed",
        "ThreatType": "Password Spray Attempt",
        "Severity": "high",
        "Confidence": 90,
        "Summary": "Local model explanation based only on supplied password spray evidence.",
        "SuspicionReason": "One source attempted authentication against many users.",
        "Inferences": ["Inference: The pattern is consistent with password spraying."],
        "RecommendedActionID": "BLOCK_DESTINATION_IP",
        "RequiresApproval": True,
    }
    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_output):
        result = run_synthetic_incident_pipeline(
            analyst_mode="hybrid",
            scenario_name="password_spray_attempt",
            seed=99,
            difficulty="Easy",
            noise_level="Low",
        )
    metadata = get_last_analyst_metadata()

    assert result["scenario"]["ScenarioID"] == "password_spray_attempt"
    assert result["scenario_evaluation"]["OverallPassed"] is True
    assert metadata["UsedFallback"] is False


def test_defender_response_remains_simulation_only() -> None:
    result = run_synthetic_incident_pipeline(
        scenario_name="malware_download_execution",
        seed=111,
        difficulty="Easy",
        noise_level="None",
    )
    from dashboard.incident_demo import run_synthetic_defender_response

    response = run_synthetic_defender_response(
        analysis=result["analysis"],
        environment_profile=result["environment_profile"],
        human_approved=True,
    )

    assert "simulation only" in response["SimulationMessage"].lower()
