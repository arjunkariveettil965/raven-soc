from unittest.mock import patch

import pandas as pd

from ai_analyst.agent import get_last_analyst_metadata, run_analyst_agent
from ai_analyst.output_validator import validate_analyst_output
from dashboard.incident_demo import (
    run_synthetic_defender_response,
    run_synthetic_incident_pipeline,
)


def _mock_ollama_health():
    return patch(
        "dashboard.incident_demo.check_ollama_health",
        return_value={
            "available": True,
            "base_url": "http://localhost:11434",
            "models": ["gemma3:1b"],
            "error": None,
        },
    )


def _valid_model_analysis_from(deterministic_analysis):
    analysis = dict(deterministic_analysis)
    analysis.update(
        {
            "Summary": "Local model explanation based only on supplied incident evidence.",
            "SuspicionReason": "Local model identified the same staged sequence in the supplied timeline.",
            "Inferences": [
                "Inference: The timeline is consistent with credential access followed by execution.",
            ],
        }
    )
    return analysis


def _fixed_incident_and_timeline():
    incident = {
        "IncidentType": "Brute-Force Attempt",
        "IncidentSeverity": "High",
        "IncidentConfidence": 75.0,
        "AffectedDevice": "TEST-PC",
        "AffectedUser": "test.user",
        "SourceIP": "203.0.113.55",
        "RelatedAlertTypes": ["Failed Login Burst"],
        "RelatedAlertIDs": ["alert-1"],
        "MITRETechniques": ["T1110 - Brute Force"],
    }
    timeline = pd.DataFrame(
        [
            {
                "AlertType": "Failed Login Burst",
                "Evidence": "Five failed attempts observed.",
                "AlertID": "alert-1",
            }
        ]
    )
    return incident, timeline


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


def test_deterministic_mode_does_not_call_ollama():
    with patch("ai_analyst.agent.generate_structured_analysis") as generate_mock:
        with patch("dashboard.incident_demo.check_ollama_health") as health_mock:
            result = run_synthetic_incident_pipeline(
                "Finance SME",
                analyst_mode="deterministic",
            )

    generate_mock.assert_not_called()
    health_mock.assert_not_called()
    assert result["analyst_mode"] == "deterministic"
    assert result["ollama_health"]["available"] is False
    assert result["analyst_metadata"]["UsedFallback"] is False


def test_ollama_failure_uses_deterministic_fallback():
    with patch(
        "ai_analyst.agent.generate_structured_analysis",
        side_effect=RuntimeError("offline"),
    ):
        with patch(
            "dashboard.incident_demo.check_ollama_health",
            return_value={
                "available": False,
                "base_url": "http://localhost:11434",
                "models": [],
                "error": "offline",
            },
        ):
            result = run_synthetic_incident_pipeline(
                "Finance SME",
                analyst_mode="ollama",
            )

    assert result["analysis"]["Status"] == "malicious"
    assert result["analysis"]["RecommendedActionID"] == "ISOLATE_DEVICE"
    assert result["analyst_metadata"]["AnalystMode"] == "ollama"
    assert result["analyst_metadata"]["UsedFallback"] is True
    assert "offline" in result["analyst_metadata"]["FallbackReason"]


def test_hybrid_mode_cannot_downgrade_malicious_result():
    deterministic = run_synthetic_incident_pipeline("Finance SME")
    downgraded = _valid_model_analysis_from(deterministic["analysis"])
    downgraded.update(
        {
            "Status": "benign",
            "ThreatType": "Unknown",
            "Severity": "Low",
            "Confidence": 10.0,
            "ObservedEvidence": [],
            "MITRETechniques": [],
            "RecommendedActionID": "NO_ACTION",
            "Target": "",
            "RequiresApproval": False,
            "EvidenceIDs": [],
        }
    )
    with patch("ai_analyst.agent.generate_structured_analysis", return_value=downgraded):
        with _mock_ollama_health():
            result = run_synthetic_incident_pipeline(
                "Finance SME",
                analyst_mode="hybrid",
            )

    assert result["analysis"]["Status"] == "benign"
    assert result["analysis"]["RecommendedActionID"] == "NO_ACTION"
    assert result["analysis"]["Target"] == "CFO-PC"
    assert result["analysis"]["RequiresApproval"] is True
    assert result["analysis"]["Summary"] == downgraded["Summary"]
    assert result["analyst_metadata"]["UsedFallback"] is False
    assert result["analyst_metadata"]["FallbackReason"] is None


def test_hybrid_invalid_ollama_output_retains_deterministic_explanation():
    deterministic = run_synthetic_incident_pipeline("Finance SME")
    invalid = _valid_model_analysis_from(deterministic["analysis"])
    invalid["RecommendedActionID"] = "NOT_REAL"

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=invalid):
        with _mock_ollama_health():
            result = run_synthetic_incident_pipeline(
                "Finance SME",
                analyst_mode="hybrid",
            )

    assert result["analysis"]["Summary"] == deterministic["analysis"]["Summary"]
    assert result["analysis"]["SuspicionReason"] == deterministic["analysis"]["SuspicionReason"]
    assert result["analysis"]["Inferences"] == deterministic["analysis"]["Inferences"]
    assert result["analyst_metadata"]["UsedFallback"] is True
    assert "failed schema validation" in result["analyst_metadata"]["FallbackReason"]


def test_hybrid_valid_ollama_output_uses_model_explanation():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    valid_model_analysis = _valid_model_analysis_from(deterministic)

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=valid_model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )
    metadata = get_last_analyst_metadata()

    assert analysis["Summary"] == valid_model_analysis["Summary"]
    assert analysis["SuspicionReason"] == valid_model_analysis["SuspicionReason"]
    assert analysis["Inferences"] == valid_model_analysis["Inferences"]
    assert analysis["RecommendedActionID"] == deterministic["RecommendedActionID"]
    assert metadata["UsedFallback"] is False
    assert metadata["FallbackReason"] is None


def test_hybrid_normalizes_harmless_local_slm_variations():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    flexible_model_analysis = _valid_model_analysis_from(deterministic)
    flexible_model_analysis.update(
        {
            "Status": "malicious",
            "Severity": "critical",
            "Confidence": "96%",
            "MITRETechniques": [{"id": "T1059.001", "name": "PowerShell"}],
        }
    )

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=flexible_model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )
    metadata = get_last_analyst_metadata()

    assert analysis["Summary"] == flexible_model_analysis["Summary"]
    assert analysis["SuspicionReason"] == flexible_model_analysis["SuspicionReason"]
    assert metadata["UsedFallback"] is False
    assert metadata["FallbackReason"] is None


def test_hybrid_normalizes_case_insensitive_canonical_status():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = _valid_model_analysis_from(deterministic)
    model_analysis["Status"] = " MALICIOUS "

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )

    assert analysis["Status"] == "malicious"


def test_hybrid_normalizes_confirmed_status_to_malicious():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = _valid_model_analysis_from(deterministic)
    model_analysis["Status"] = "confirmed"

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )

    assert analysis["Status"] == "malicious"


def test_hybrid_normalizes_confirmed_malicious_status_to_malicious():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = _valid_model_analysis_from(deterministic)
    model_analysis["Status"] = "confirmed malicious"

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )

    assert analysis["Status"] == "malicious"


def test_hybrid_normalizes_true_positive_status_to_malicious():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = _valid_model_analysis_from(deterministic)
    model_analysis["Status"] = "true positive"

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )

    assert analysis["Status"] == "malicious"


def test_hybrid_normalizes_status_hyphen_and_underscore_variations():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")

    for status_value in ["confirmed-malicious", "true_positive"]:
        model_analysis = _valid_model_analysis_from(deterministic)
        model_analysis["Status"] = status_value
        with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
            analysis = run_analyst_agent(
                incident,
                timeline,
                environment_name="SME Office",
                mode="hybrid",
            )

        assert analysis["Status"] == "malicious"


def test_hybrid_normalizes_false_positive_status_to_benign():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = _valid_model_analysis_from(deterministic)
    model_analysis["Status"] = "false_positive"
    model_analysis["RecommendedActionID"] = "NO_ACTION"

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )

    assert analysis["Status"] == "benign"


def test_hybrid_normalizes_safe_status_to_benign():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = _valid_model_analysis_from(deterministic)
    model_analysis["Status"] = " safe "
    model_analysis["RecommendedActionID"] = "NO_ACTION"

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )

    assert analysis["Status"] == "benign"


def test_hybrid_canonical_status_values_remain_unchanged():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")

    for canonical_status in ["malicious", "suspicious", "uncertain", "benign"]:
        model_analysis = _valid_model_analysis_from(deterministic)
        model_analysis["Status"] = canonical_status
        with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
            analysis = run_analyst_agent(
                incident,
                timeline,
                environment_name="SME Office",
                mode="hybrid",
            )

        assert analysis["Status"] == canonical_status


def test_hybrid_unknown_status_still_causes_fallback():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = _valid_model_analysis_from(deterministic)
    model_analysis["Status"] = "compromised maybe"

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )
    metadata = get_last_analyst_metadata()

    assert analysis == deterministic
    assert metadata["UsedFallback"] is True
    assert "Status is invalid" in metadata["ValidationErrors"]


def test_hybrid_status_synonym_output_passes_strict_validation():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = _valid_model_analysis_from(deterministic)
    model_analysis["Status"] = "confirmed"

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )

    valid, errors = validate_analyst_output(analysis, incident)
    assert valid is True
    assert errors == []


def test_hybrid_real_style_gemma_response_does_not_fallback():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = {
        "Status": "confirmed",
        "ThreatType": "Credential Access",
        "Severity": "high",
        "Confidence": 90,
        "Summary": "Multiple failed login events indicate credential access activity.",
        "SuspicionReason": "The supplied timeline shows repeated authentication failures for the affected account.",
        "Inferences": [
            "Inference: The alert pattern is consistent with credential access activity.",
        ],
        "RecommendedActionID": "ISOLATE_DEVICE",
        "RequiresApproval": True,
    }

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )
    metadata = get_last_analyst_metadata()
    valid, errors = validate_analyst_output(analysis, incident)

    assert analysis["Status"] == "malicious"
    assert analysis["ThreatType"] == "Credential Access"
    assert analysis["Severity"] == "High"
    assert analysis["Confidence"] == 90
    assert analysis["EvidenceIDs"] == deterministic["EvidenceIDs"]
    assert analysis["Target"] == deterministic["Target"]
    assert metadata["UsedFallback"] is False
    assert metadata["FallbackReason"] is None
    assert valid is True
    assert errors == []


def test_ollama_mode_normalizes_local_slm_response_before_validation():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    flexible_model_analysis = _valid_model_analysis_from(deterministic)
    flexible_model_analysis.update(
        {
            "Severity": "critical",
            "Confidence": 96.7,
            "MITRETechniques": [{"id": "T1059.001", "name": "PowerShell"}],
        }
    )

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=flexible_model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="ollama",
        )
    metadata = get_last_analyst_metadata()

    assert analysis["Severity"] == "Critical"
    assert analysis["Confidence"] == 97
    assert analysis["MITRETechniques"] == deterministic["MITRETechniques"]
    assert metadata["UsedFallback"] is False
    assert metadata["FallbackReason"] is None


def test_hybrid_ignores_invented_model_evidence_ids():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = _valid_model_analysis_from(deterministic)
    model_analysis["EvidenceIDs"] = ["fake-alert-1", "fake-alert-2"]

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )
    metadata = get_last_analyst_metadata()

    assert analysis["EvidenceIDs"] == deterministic["EvidenceIDs"]
    assert metadata["UsedFallback"] is False


def test_hybrid_ignores_invented_model_target():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = _valid_model_analysis_from(deterministic)
    model_analysis["Target"] = "INVENTED-HOST"

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )

    assert analysis["Target"] == deterministic["Target"]


def test_hybrid_omitted_protected_fields_do_not_cause_fallback():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = {
        field: value
        for field, value in _valid_model_analysis_from(deterministic).items()
        if field not in {"ObservedEvidence", "MITRETechniques", "EvidenceIDs", "Target"}
    }

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )
    metadata = get_last_analyst_metadata()

    assert analysis["EvidenceIDs"] == deterministic["EvidenceIDs"]
    assert analysis["Target"] == deterministic["Target"]
    assert metadata["UsedFallback"] is False


def test_hybrid_preserves_model_owned_classification_fields():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = _valid_model_analysis_from(deterministic)
    model_analysis.update(
        {
            "Status": "uncertain",
            "ThreatType": "Credential Attack",
            "Severity": "Medium",
            "Confidence": 61,
        }
    )

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )

    assert analysis["Status"] == "uncertain"
    assert analysis["ThreatType"] == "Credential Attack"
    assert analysis["Severity"] == "Medium"
    assert analysis["Confidence"] == 61


def test_hybrid_preserves_allowed_model_action():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = _valid_model_analysis_from(deterministic)
    model_analysis["RecommendedActionID"] = "INCREASE_MONITORING"

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )

    assert analysis["RecommendedActionID"] == "INCREASE_MONITORING"


def test_hybrid_invalid_model_action_still_causes_fallback():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = _valid_model_analysis_from(deterministic)
    model_analysis["RecommendedActionID"] = "NOT_REAL"

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )
    metadata = get_last_analyst_metadata()

    assert analysis == deterministic
    assert metadata["UsedFallback"] is True
    assert "RecommendedActionID is invalid" in metadata["ValidationErrors"]


def test_hybrid_model_cannot_lower_requires_approval():
    incident, timeline = _fixed_incident_and_timeline()
    incident["IncidentConfidence"] = 40.0
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = _valid_model_analysis_from(deterministic)
    model_analysis["RequiresApproval"] = False

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )

    assert deterministic["RequiresApproval"] is True
    assert analysis["RequiresApproval"] is True


def test_hybrid_final_merged_output_passes_strict_validation():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = _valid_model_analysis_from(deterministic)
    model_analysis.update(
        {
            "EvidenceIDs": ["fake-alert"],
            "Target": "INVENTED-HOST",
        }
    )

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )

    valid, errors = validate_analyst_output(analysis, incident)
    assert valid is True
    assert errors == []


def test_hybrid_valid_decision_with_invented_protected_fields_does_not_fallback():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = _valid_model_analysis_from(deterministic)
    model_analysis.update(
        {
            "EvidenceIDs": ["fake-alert"],
            "Target": "INVENTED-HOST",
        }
    )

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )
    metadata = get_last_analyst_metadata()

    assert metadata["UsedFallback"] is False
    assert metadata["FallbackReason"] is None


def test_local_slm_invalid_output_uses_deterministic_fallback():
    incident, timeline = _fixed_incident_and_timeline()
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    invalid = _valid_model_analysis_from(deterministic)
    invalid["RecommendedActionID"] = "NOT_REAL"

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=invalid):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="ollama",
        )
    metadata = get_last_analyst_metadata()

    assert analysis == deterministic
    assert metadata["UsedFallback"] is True
    assert "failed schema validation" in metadata["FallbackReason"]


def test_sanitized_generic_strings_are_rejected_as_model_explanation():
    deterministic = run_synthetic_incident_pipeline("Finance SME")
    sanitized_text = _valid_model_analysis_from(deterministic["analysis"])
    sanitized_text.update(
        {
            "Summary": "Insufficient evidence to make a confident determination.",
            "SuspicionReason": "The analysis output was invalid and required sanitization.",
            "Inferences": [
                "Inference: The analysis was sanitized due to schema or validation issues.",
            ],
        }
    )

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=sanitized_text):
        with _mock_ollama_health():
            result = run_synthetic_incident_pipeline(
                "Finance SME",
                analyst_mode="hybrid",
            )

    assert result["analysis"]["Summary"] == deterministic["analysis"]["Summary"]
    assert result["analysis"]["SuspicionReason"] == deterministic["analysis"]["SuspicionReason"]
    assert result["analysis"]["Inferences"] == deterministic["analysis"]["Inferences"]
    assert result["analyst_metadata"]["UsedFallback"] is True
    assert "failed schema validation" in result["analyst_metadata"]["FallbackReason"]
