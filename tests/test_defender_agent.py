from ai_analyst.schemas import create_empty_analysis
from response.defender_agent import run_defender_agent


def test_isolation_requires_approval() -> None:
    analysis = create_empty_analysis()
    analysis.update(
        {
            "RecommendedActionID": "ISOLATE_DEVICE",
            "Confidence": 95.0,
            "Target": "CFO-PC",
            "RequiresApproval": True,
        }
    )
    response = run_defender_agent(analysis, {"critical_devices": ["CFO-PC"]}, human_approved=False)
    assert response["Permitted"] is False
    assert response["Executed"] is False
    assert response["RequiresApproval"] is True
    assert response["ExecutionMode"] == "Advisory"


def test_approved_isolation_is_simulated() -> None:
    analysis = create_empty_analysis()
    analysis.update(
        {
            "RecommendedActionID": "ISOLATE_DEVICE",
            "Confidence": 95.0,
            "Target": "CFO-PC",
            "RequiresApproval": True,
        }
    )
    response = run_defender_agent(analysis, {"critical_devices": ["CFO-PC"]}, human_approved=True)
    assert response["Permitted"] is True
    assert response["Executed"] is True
    assert "simulation only" in response["SimulationMessage"].lower()
    assert response["AuditRecord"]["ActionID"] == "ISOLATE_DEVICE"


def test_low_confidence_action_is_rejected() -> None:
    analysis = create_empty_analysis()
    analysis.update(
        {
            "RecommendedActionID": "DISABLE_USER",
            "Confidence": 50.0,
            "Target": "cfo.user",
            "RequiresApproval": True,
        }
    )
    response = run_defender_agent(analysis, {"critical_devices": ["CFO-PC"]}, human_approved=True)
    assert response["Permitted"] is False
    assert response["Executed"] is False


def test_collect_evidence_guarded_mode() -> None:
    analysis = create_empty_analysis()
    analysis.update(
        {
            "RecommendedActionID": "COLLECT_EVIDENCE",
            "Confidence": 60.0,
            "Target": "CFO-PC",
            "RequiresApproval": False,
        }
    )
    response = run_defender_agent(analysis, {"critical_devices": ["CFO-PC"]}, human_approved=False)
    assert response["Permitted"] is True
    assert response["Executed"] is True
    assert response["ExecutionMode"] == "Guarded"


def test_unknown_action_is_rejected() -> None:
    analysis = create_empty_analysis()
    analysis.update(
        {
            "RecommendedActionID": "UNKNOWN_ACTION",
            "Confidence": 99.0,
            "Target": "CFO-PC",
            "RequiresApproval": False,
        }
    )
    response = run_defender_agent(analysis, {"critical_devices": ["CFO-PC"]}, human_approved=False)
    assert response["Permitted"] is False
    assert response["Executed"] is False
