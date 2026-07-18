from dashboard.incident_demo import (
    run_synthetic_defender_response,
    run_synthetic_incident_pipeline,
)


def test_synthetic_pipeline_end_to_end():
    result = run_synthetic_incident_pipeline("Finance SME")

    assert len(result["events"]) == 9
    assert len(result["alerts"]) >= 4
    assert len(result["incidents"]) == 1

    incident = result["selected_incident"]
    incident_type = (
        incident.get("IncidentType")
        if hasattr(incident, "get")
        else incident["IncidentType"]
    )
    assert incident_type == "Multi-Stage Intrusion"

    analysis = result["analysis"]
    assert str(analysis["Status"]).lower() == "malicious"
    assert analysis["RecommendedActionID"] == "ISOLATE_DEVICE"
    assert not result["timeline"].empty
    assert len(result["formatted_timeline"]) == len(result["timeline"])


def test_pipeline_uses_finance_environment():
    result = run_synthetic_incident_pipeline("Finance SME")
    profile = result["environment_profile"]

    assert profile.get("EnvironmentName") == "Finance SME"
    critical_devices = profile.get(
        "critical_devices",
        profile.get("CriticalDevices", []),
    )
    assert "CFO-PC" in critical_devices
    assert result["analysis"]["RequiresApproval"] is True


def test_approved_defender_response():
    result = run_synthetic_incident_pipeline("Finance SME")
    response = run_synthetic_defender_response(
        analysis=result["analysis"],
        environment_profile=result["environment_profile"],
        human_approved=True,
    )

    assert response["Permitted"] is True
    assert response["Executed"] is True
    assert response["ExecutionMode"] in {"Advisory", "Guarded"}
    assert "Simulation only" in response["SimulationMessage"]


def test_unapproved_defender_response():
    result = run_synthetic_incident_pipeline("Finance SME")
    response = run_synthetic_defender_response(
        analysis=result["analysis"],
        environment_profile=result["environment_profile"],
        human_approved=False,
    )

    assert response["Permitted"] is False
    assert response["Executed"] is False
    assert response["RequiresApproval"] is True
    assert response["ExecutionMode"] == "Advisory"