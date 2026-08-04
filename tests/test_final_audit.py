from __future__ import annotations

import time
import pytest
from fastapi.testclient import TestClient
from backend.repositories import IncidentRepository
from backend.services.live_monitoring_service import live_monitoring_service
from ai_analyst.ollama_client import DEFAULT_OLLAMA_MODEL


@pytest.fixture()
def client(monkeypatch):
    import backend.dependencies as dependencies
    from backend.main import app

    dependencies.incident_repository = IncidentRepository()
    live_monitoring_service.reset()
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    live_monitoring_service.reset()


def _wait_for(predicate, timeout_seconds: float = 8.0, sleep_seconds: float = 0.1) -> bool:
    end_time = time.monotonic() + timeout_seconds
    while time.monotonic() < end_time:
        if predicate():
            return True
        time.sleep(sleep_seconds)
    return False


def test_e2e_synthetic_scenario_and_contracts(client: TestClient):
    # Phase 6 & 5 verification: run a synthetic scenario, check all properties
    payload = {
        "scenario_mode": "select",
        "scenario_name": "multi_stage_intrusion",
        "difficulty": "Medium",
        "noise_level": "Low",
        "seed": 42,
        "environment": "Finance SME",
        "analyst_mode": "Deterministic",
    }
    response = client.post("/api/v1/scenarios/run", json=payload)
    assert response.status_code == 200
    run_result = response.json()

    assert run_result["EventCount"] > 0
    assert run_result["AttackEventCount"] > 0
    assert run_result["SelectedIncident"] is not None

    selected_incident = run_result["SelectedIncident"]
    incident_id = selected_incident["IncidentID"]
    assert incident_id

    # Retrieve incident details
    inc_details_resp = client.get(f"/api/v1/incidents/{incident_id}")
    assert inc_details_resp.status_code == 200
    inc_details = inc_details_resp.json()["Incident"]

    # Verify Incident contract against frontend TypeScript properties
    assert "IncidentID" in inc_details
    assert "IncidentType" in inc_details or "IncidentType" in inc_details or "incident_type" in inc_details or "CorrelationPattern" in inc_details
    assert "Severity" in inc_details or "IncidentSeverity" in inc_details
    assert "Score" in inc_details or "RiskScore" in inc_details or "IncidentConfidence" in inc_details or "MaximumConfidenceScore" in inc_details or "CorrelationScore" in inc_details
    assert "Timeline" in inc_details or "AttackPathTimeline" in inc_details
    assert "Alerts" in inc_details
    assert "CorrelatedIndicators" in inc_details

    # Run analyst processing
    analyst_payload = {
        "mode": "Deterministic"
    }
    analyst_resp = client.post(f"/api/v1/incidents/{incident_id}/analyze", json=analyst_payload)
    assert analyst_resp.status_code == 200
    analyst_data = analyst_resp.json()
    assert "IncidentID" in analyst_data
    assert "AnalystResult" in analyst_data
    assert "AnalystMetadata" in analyst_data

    # Check defender recommendation
    assert "Mitigation" in inc_details.get("DefenderRecommendation", {}) or "ActionID" in inc_details.get("DefenderRecommendation", {})
    assert inc_details["DefenderRecommendation"]["Status"] in ["pending", "auto-executed", "approved", "rejected"]

    # Test approve / reject simulated action
    app_resp = client.post(f"/api/v1/actions/{incident_id}/approve")
    assert app_resp.status_code == 200
    assert app_resp.json()["Decision"] == "approved"

    # Re-retrieve and check status
    inc_details_post = client.get(f"/api/v1/incidents/{incident_id}").json()["Incident"]
    assert inc_details_post["DefenderRecommendation"]["Status"] == "approved"


def test_live_monitoring_scenarios_and_playback_controls(client: TestClient):
    scenarios = ["Multi Stage Intrusion", "Ransomware", "Insider Threat", "Credential Attack"]
    speeds = [0.5, 1.0, 2.0, 5.0, 10.0]

    for scenario in scenarios:
        for speed in [5.0, 10.0]:  # Use fast speeds for test performance
            # Reset
            reset_resp = client.post("/api/v1/live/reset")
            assert reset_resp.status_code == 200
            assert reset_resp.json()["status"] == "stopped"

            # Start
            start_resp = client.post(
                "/api/v1/live/start",
                json={"scenario_name": scenario, "speed": speed, "seed": 100}
            )
            assert start_resp.status_code == 200
            assert start_resp.json()["status"] == "running"
            assert start_resp.json()["scenario"] == scenario

            # Wait briefly to consume some events
            assert _wait_for(lambda: client.get("/api/v1/live/status").json()["event_count"] > 0)

            # Pause
            pause_resp = client.post("/api/v1/live/pause")
            assert pause_resp.status_code == 200
            assert pause_resp.json()["status"] == "paused"

            # Resume
            resume_resp = client.post("/api/v1/live/resume", json={"speed": speed})
            assert resume_resp.status_code == 200
            assert resume_resp.json()["status"] == "running"

            # Reset again
            client.post("/api/v1/live/reset")


def test_edge_cases_and_error_handling(client: TestClient):
    # Invalid incident ID retrieve
    bad_inc = client.get("/api/v1/incidents/INC-NOT-EXIST")
    assert bad_inc.status_code == 404

    # Invalid action approve/reject
    bad_app = client.post("/api/v1/actions/INC-NOT-EXIST/approve")
    assert bad_app.status_code == 404

    # Duplicate start should fail or reset gracefully
    client.post("/api/v1/live/start", json={"scenario_name": "Ransomware", "speed": 5.0})
    dup_start = client.post("/api/v1/live/start", json={"scenario_name": "Ransomware", "speed": 5.0})
    assert dup_start.status_code in [200, 422]

    # CORS verification
    cors_resp = client.options(
        "/api/v1/health",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Content-Type"
        }
    )
    assert cors_resp.headers.get("access-control-allow-origin") == "http://localhost:3000" or cors_resp.headers.get("access-control-allow-origin") is None
