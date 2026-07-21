from __future__ import annotations

import importlib
import inspect
from pathlib import Path
import sqlite3
from uuid import uuid4

import pytest

from backend.repositories import MemoryIncidentRepository, SQLiteIncidentRepository, StoredIncident
from backend.services import scenario_service
from backend.services.action_service import SIMULATION_MESSAGE, approve_action, reject_action
from backend.services.run_service import get_run_detail, list_runs
from core.scenario_pipeline import run_synthetic_incident_pipeline


def _db_path() -> Path:
    directory = Path(".api-test-dbs") / f"phase9b-{uuid4()}"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "api.db"


def _stored_incident(run_id: str = "run-1", incident_id: str = "inc-1") -> StoredIncident:
    incident = {
        "IncidentID": incident_id,
        "IncidentType": "Multi-Stage Intrusion",
        "IncidentSeverity": "Critical",
        "IncidentConfidence": 95,
        "Target": "CFO-PC",
        "RequiresApproval": True,
        "RecommendedActionID": "ISOLATE_DEVICE",
        "FirstSeen": "2026-07-21T10:00:00",
        "LastSeen": "2026-07-21T10:05:00",
    }
    analysis = {
        "Status": "malicious",
        "ThreatType": "Multi-Stage Intrusion",
        "Severity": "Critical",
        "Confidence": 95,
        "Summary": "Synthetic validated incident.",
        "SuspicionReason": "Trusted evidence indicates a multi-stage attack.",
        "ObservedEvidence": ["failed logins"],
        "Inferences": ["Inference: high-confidence intrusion."],
        "MITRETechniques": ["T1059.001 - PowerShell"],
        "RecommendedActionID": "ISOLATE_DEVICE",
        "Target": "CFO-PC",
        "RequiresApproval": True,
        "EvidenceIDs": ["alert-1"],
    }
    return StoredIncident(
        run_id=run_id,
        incident_id=incident_id,
        incident=incident,
        timeline=[{"TimelineTime": "2026-07-21T10:00:00"}],
        analysis=analysis,
        analyst_metadata={"AnalystMode": "deterministic", "ModelName": "gemma3:4b-it-qat", "UsedFallback": False},
        environment_profile={"EnvironmentName": "Finance SME", "critical_devices": ["CFO-PC"]},
    )


def _run_payload(run_id: str = "run-1") -> dict[str, object]:
    return {
        "RunID": run_id,
        "ScenarioLabel": "Multi-Stage Intrusion",
        "ScenarioMode": "select",
        "Seed": 7,
        "Difficulty": "Medium",
        "NoiseLevel": "Low",
        "AnswerRevealed": False,
        "EventCount": 4,
        "AttackEventCount": 4,
        "BenignEventCount": 0,
        "Evaluation": {"Detected": True, "MissingExpectedAlerts": ["hidden"]},
    }


def test_backend_no_longer_imports_dashboard_incident_pipeline():
    source = inspect.getsource(scenario_service)
    assert "dashboard.incident_demo" not in source
    assert "core.scenario_pipeline" in source


def test_streamlit_wrapper_still_exposes_shared_pipeline():
    wrapper = importlib.import_module("dashboard.incident_demo")
    assert callable(wrapper.run_synthetic_incident_pipeline)


def test_same_seed_pipeline_output_remains_equivalent():
    first = run_synthetic_incident_pipeline(seed=20260721, scenario_name="password_spray_attempt")
    second = run_synthetic_incident_pipeline(seed=20260721, scenario_name="password_spray_attempt")
    assert len(first["events"]) == len(second["events"])
    assert first["selected_incident"]["IncidentType"] == second["selected_incident"]["IncidentType"]


def test_sqlite_repository_schema_idempotent_and_persistent():
    db_path = _db_path()
    repo = SQLiteIncidentRepository(db_path)
    repo.initialize()
    repo.initialize()
    repo.save_run("run-1", _run_payload(), [_stored_incident()])

    restarted = SQLiteIncidentRepository(db_path)
    restarted.initialize()
    assert restarted.get_incident("inc-1") is not None
    assert restarted.get_run("run-1") is not None
    assert list_runs(restarted)[0]["RunID"] == "run-1"


def test_run_detail_hides_expected_answer_when_not_revealed():
    repo = SQLiteIncidentRepository(_db_path())
    repo.initialize()
    repo.save_run("run-1", _run_payload(), [_stored_incident()])
    detail = get_run_detail(repo, "run-1")
    assert detail is not None
    assert detail["Incidents"][0]["IncidentID"] == "inc-1"
    assert "MissingExpectedAlerts" not in detail["Run"]["Evaluation"]


def test_filters_datetime_and_latest_analysis_persist():
    repo = SQLiteIncidentRepository(_db_path())
    repo.initialize()
    repo.save_run("run-1", _run_payload(), [_stored_incident()])
    assert repo.list_incidents(severity="Critical")
    assert repo.list_incidents(incident_type="Intrusion")
    latest = repo.get_latest_analysis("inc-1")
    assert latest is not None
    assert latest["AnalystMetadata"]["UsedFallback"] is False
    assert "RawModelOutput" not in latest["AnalystMetadata"]


def test_action_approval_rejection_and_conflict_persist():
    db_path = _db_path()
    repo = SQLiteIncidentRepository(db_path)
    repo.initialize()
    repo.save_run("run-1", _run_payload(), [_stored_incident()])
    approved = approve_action(repo, "inc-1")
    assert approved is not None
    assert approved["Message"] == SIMULATION_MESSAGE
    assert approved["ExecutionMode"] == "Simulation Only"
    assert SQLiteIncidentRepository(db_path).get_action_decision("inc-1")["Decision"] == "approved"
    with pytest.raises(Exception):
        reject_action(repo, "inc-1")


def test_rejection_persists_and_same_decision_is_idempotent():
    repo = SQLiteIncidentRepository(_db_path())
    repo.initialize()
    repo.save_run("run-2", _run_payload("run-2"), [_stored_incident("run-2", "inc-2")])
    rejected = reject_action(repo, "inc-2")
    assert rejected is not None
    assert reject_action(repo, "inc-2")["Decision"] == "rejected"


def test_foreign_keys_and_indexes_exist():
    db_path = _db_path()
    repo = SQLiteIncidentRepository(db_path)
    repo.initialize()
    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        indexes = {row[1] for row in connection.execute("PRAGMA index_list(api_incidents)").fetchall()}
    assert "idx_api_incidents_run_id" in indexes
    assert "idx_api_incidents_type" in indexes
    assert "idx_api_incidents_severity" in indexes


def test_malformed_record_is_safe_repository_error():
    db_path = _db_path()
    repo = SQLiteIncidentRepository(db_path)
    repo.initialize()
    repo.save_run("run-1", _run_payload(), [_stored_incident()])
    with sqlite3.connect(db_path) as connection:
        connection.execute("UPDATE api_incidents SET incident_payload_json = '{bad json' WHERE incident_id = 'inc-1'")
    with pytest.raises(Exception, match="malformed"):
        repo.get_incident("inc-1")


def test_memory_repository_preserved_for_tests():
    repo = MemoryIncidentRepository()
    repo.initialize()
    repo.save_run("run-1", _run_payload(), [_stored_incident()])
    assert repo.get_incident("inc-1") is not None
    repo.clear_for_tests()
    assert repo.get_incident("inc-1") is None


def test_fastapi_lifespan_cors_and_startup_warning_contract():
    pytest.importorskip("fastapi")
    from backend.main import app

    assert not getattr(app.router, "on_startup", [])
    middleware = [item for item in app.user_middleware if item.cls.__name__ == "CORSMiddleware"]
    assert middleware
    origins = middleware[0].kwargs["allow_origins"]
    assert "*" not in origins
    assert "http://localhost:5173" in origins
