from __future__ import annotations

import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from backend.services.live_monitoring_service import live_monitoring_service
from backend.settings import settings


@pytest.fixture()
def client():
    from backend.main import app

    live_monitoring_service.reset()
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    live_monitoring_service.reset()


def _wait_for(predicate, timeout_seconds: float = 15.0, sleep_seconds: float = 0.5) -> bool:
    end_time = time.monotonic() + timeout_seconds
    while time.monotonic() < end_time:
        if predicate():
            return True
        time.sleep(sleep_seconds)
    return False


def test_unified_incident_resolution_and_actions(client: TestClient):
    from backend.dependencies import get_incident_repository
    from backend.repositories.sqlite_repository import StoredIncident
    
    repository = get_incident_repository()
    incident_data = {
        "IncidentID": "INC-TEST-123",
        "IncidentType": "Multi-Stage Intrusion",
        "Severity": "Critical"
    }
    analysis_data = {
        "Status": "malicious",
        "RecommendedActionID": "ISOLATE_DEVICE",
        "Target": "Test-PC"
    }
    stored_incident = StoredIncident(
        run_id="run-test",
        incident_id=incident_data["IncidentID"],
        incident=incident_data,
        timeline=[],
        analysis=analysis_data,
        analyst_metadata={},
        environment_profile={},
        action_decision=None
    )
    repository.save_run("run-test", {"status": "completed"}, [stored_incident])
    
    # 1 & 9: Persisted incident testing
    res = client.get("/api/v1/incidents")
    assert res.status_code == 200
    incidents = res.json().get("Incidents", [])
    assert incidents, "Expected at least one seeded persisted incident"
    
    persisted_incident = incidents[0]
    persisted_id = persisted_incident["IncidentID"]
    
    # 1. A persisted incident resolves with source="repository", is_ephemeral=False, actions_supported=True
    get_res = client.get(f"/api/v1/incidents/{persisted_id}")
    assert get_res.status_code == 200
    details = get_res.json().get("Incident", {})
    assert details.get("source") == "repository"
    assert details.get("is_ephemeral") is False
    assert details.get("actions_supported") is True
    
    # 9. A persisted incident can still be approved using the existing path
    app_res = client.post(f"/api/v1/actions/{persisted_id}/approve")
    assert app_res.status_code == 200
    assert app_res.json().get("Decision") == "approved"
    
    # 8. An invalid incident still returns 404
    inv_res = client.get("/api/v1/incidents/INC-INVALID-999")
    assert inv_res.status_code == 404
    inv_app_res = client.post("/api/v1/actions/INC-INVALID-999/approve")
    assert inv_app_res.status_code == 404

    # 2 & 3: Live incident testing
    client.post("/api/v1/live/start", json={"scenario_name": "Multi Stage Intrusion", "speed": 10.0})
    
    def live_incident_generated():
        r = client.get("/api/v1/live/incidents")
        return len(r.json().get("incidents", [])) > 0
        
    assert _wait_for(live_incident_generated, timeout_seconds=15.0), "Live incident was not generated in time"
    client.post("/api/v1/live/pause")
    
    live_incidents = client.get("/api/v1/live/incidents").json().get("incidents", [])
    live_id = live_incidents[0]["Incident"]["IncidentID"]
    
    # 2. A live simulation incident resolves with source="live_simulation", is_ephemeral=True, actions_supported=True
    get_live_res = client.get(f"/api/v1/incidents/{live_id}")
    assert get_live_res.status_code == 200
    live_details = get_live_res.json().get("Incident", {})
    assert live_details.get("source") == "live_simulation"
    assert live_details.get("is_ephemeral") is True
    assert live_details.get("actions_supported") is True
    
    # 3. A live incident can be approved
    app_live_res = client.post(f"/api/v1/actions/{live_id}/approve")
    assert app_live_res.status_code == 200
    app_payload = app_live_res.json()
    assert app_payload.get("Decision") == "approved"
    assert app_payload.get("ExecutionMode") == "Simulation Only"
    
    # 4 & 5. Approving a live incident updates its in-memory ActionDecision and Timeline
    get_live_res2 = client.get(f"/api/v1/incidents/{live_id}")
    assert get_live_res2.status_code == 200
    live_details2 = get_live_res2.json().get("Incident", {})
    assert live_details2.get("ActionDecision", {}).get("Decision") == "approved"
    timeline = live_details2.get("Timeline", [])
    assert any("Analyst approved action" in str(entry.get("Event", "")) for entry in timeline)
    
    # 6. A live incident remains ephemeral and is NOT inserted into SQLite
    conn = sqlite3.connect(settings.api_database_path)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM api_incidents WHERE incident_id = ?", (live_id,))
    count = cursor.fetchone()[0]
    assert count == 0, "Live incident incorrectly persisted to database"
    conn.close()
    
    # 7. A live incident with an existing conflicting action decision returns conflict
    rej_live_res = client.post(f"/api/v1/actions/{live_id}/reject")
    assert rej_live_res.status_code == 409
