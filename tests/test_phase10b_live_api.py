from __future__ import annotations

import time

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from backend.services.live_monitoring_service import live_monitoring_service


@pytest.fixture()
def client():
    from backend.main import app

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


def test_live_status_and_supported_controls(client: TestClient):
    status = client.get("/api/v1/live/status")
    assert status.status_code == 200
    payload = status.json()
    assert "Multi Stage Intrusion" in payload["supported_scenarios"]
    assert payload["supported_speeds"] == [0.5, 1.0, 2.0, 5.0, 10.0]


def test_live_start_pause_resume_reset_and_speed_changes(client: TestClient):
    started = client.post(
        "/api/v1/live/start",
        json={"scenario_name": "Credential Attack", "speed": 2.0, "seed": 20260729},
    )
    assert started.status_code == 200
    assert started.json()["status"] == "running"
    assert started.json()["speed"] == 2.0
    assert started.json()["scenario"] == "Credential Attack"

    assert _wait_for(lambda: client.get("/api/v1/live/status").json()["event_count"] > 0)

    paused = client.post("/api/v1/live/pause")
    assert paused.status_code == 200
    assert paused.json()["status"] == "paused"
    paused_count = paused.json()["event_count"]
    time.sleep(0.6)
    paused_again = client.get("/api/v1/live/status").json()["event_count"]
    assert paused_again == paused_count

    resumed = client.post("/api/v1/live/resume", json={"speed": 10.0})
    assert resumed.status_code == 200
    assert resumed.json()["status"] == "running"
    assert resumed.json()["speed"] == 10.0
    assert _wait_for(lambda: client.get("/api/v1/live/status").json()["event_count"] > paused_count)

    reset = client.post("/api/v1/live/reset")
    assert reset.status_code == 200
    assert reset.json()["status"] == "stopped"
    assert reset.json()["event_count"] == 0


def test_live_event_alert_incident_generation_and_api_payloads(client: TestClient):
    started = client.post(
        "/api/v1/live/start",
        json={"scenario_name": "Multi Stage Intrusion", "speed": 10.0, "seed": 20260729},
    )
    assert started.status_code == 200

    assert _wait_for(lambda: client.get("/api/v1/live/status").json()["event_count"] >= 8, timeout_seconds=10.0)
    assert _wait_for(lambda: client.get("/api/v1/live/status").json()["alert_count"] >= 1, timeout_seconds=12.0)
    assert _wait_for(lambda: client.get("/api/v1/live/status").json()["incident_count"] >= 1, timeout_seconds=14.0)

    events = client.get("/api/v1/live/events")
    alerts = client.get("/api/v1/live/alerts")
    incidents = client.get("/api/v1/live/incidents")
    assert events.status_code == 200
    assert alerts.status_code == 200
    assert incidents.status_code == 200

    event_payload = events.json()["events"]
    alert_payload = alerts.json()["alerts"]
    incident_payload = incidents.json()["incidents"]
    assert event_payload
    assert alert_payload
    assert incident_payload
    assert {
        "timestamp",
        "hostname",
        "user",
        "event_id",
        "description",
        "mitre_tactic",
        "mitre_technique",
        "severity",
        "source",
        "event_type",
    } <= set(event_payload[-1].keys())
    assert "AlertType" in alert_payload[-1]
    assert "Incident" in incident_payload[-1]
    assert "AnalystResult" in incident_payload[-1]
    assert "DefenderRecommendation" in incident_payload[-1]
    inner = incident_payload[-1]["Incident"]
    assert inner.get("CorrelatedIndicators")
    assert inner.get("Alerts")
    assert inner["CorrelatedIndicators"][0].get("Tactic")


def test_live_api_rejects_invalid_inputs(client: TestClient):
    bad_speed = client.post(
        "/api/v1/live/start",
        json={"scenario_name": "Credential Attack", "speed": 3.0},
    )
    assert bad_speed.status_code == 422

    bad_scenario = client.post(
        "/api/v1/live/start",
        json={"scenario_name": "Unknown Scenario", "speed": 1.0},
    )
    assert bad_scenario.status_code == 422

