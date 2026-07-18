import pandas as pd

from ai_analyst.agent import build_local_slm_prompt, run_analyst_agent
from ai_analyst.environment_adapter import evaluate_environment_context, get_environment_profile, load_environment_profiles
from ai_analyst.knowledge_base import find_matching_attack_pattern, load_attack_patterns
from ai_analyst.output_validator import sanitize_invalid_analysis, validate_analyst_output
from data_generation.attack_simulator import generate_multistage_attack_scenario
from detection.alert_engine import analyze_security_events
from incidents.correlation_engine import correlate_alerts
from incidents.incident_classifier import classify_incidents
from incidents.timeline_builder import build_incident_timeline


def test_multistage_incident_analysis() -> None:
    events = generate_multistage_attack_scenario()
    alerts = analyze_security_events(events)
    incidents = correlate_alerts(alerts)
    classified_incidents = classify_incidents(incidents)
    incident = incidents.iloc[0]
    timeline = build_incident_timeline(incident, alerts)

    analysis = run_analyst_agent(incident, timeline, environment_name="SME Office")

    assert analysis["Status"] == "malicious"
    assert analysis["ThreatType"] == "Multi-Stage Intrusion"
    assert analysis["Severity"] == "Critical"
    assert 80 <= analysis["Confidence"] <= 100
    assert analysis["RecommendedActionID"] == "ISOLATE_DEVICE"
    assert analysis["Target"] == "CFO-PC"
    assert analysis["RequiresApproval"] is True
    assert analysis["ObservedEvidence"]
    assert set(analysis["EvidenceIDs"]).issubset(set(incident["RelatedAlertIDs"]))


def test_finance_environment_increases_risk() -> None:
    profiles = load_environment_profiles()
    sme_profile = get_environment_profile("SME Office", profiles)
    finance_profile = get_environment_profile("Finance SME", profiles)

    incident = {
        "AffectedDevice": "CFO-PC",
        "AffectedUser": "cfo.user",
        "SourceIP": "203.0.113.50",
        "FirstSeen": "2026-07-18 02:00:00",
        "Country": "Unknown",
    }

    sme_context = evaluate_environment_context(incident, sme_profile)
    finance_context = evaluate_environment_context(incident, finance_profile)

    assert finance_context["EnvironmentRiskAdjustment"] >= sme_context["EnvironmentRiskAdjustment"]
    assert "CFO-PC" in finance_profile["critical_devices"]
    assert finance_context["RequiresHumanApproval"] is True


def test_analyst_output_validation() -> None:
    incident = {
        "IncidentType": "Brute-Force Attempt",
        "IncidentSeverity": "High",
        "IncidentConfidence": 70.0,
        "AffectedDevice": "TEST-PC",
        "AffectedUser": "test.user",
        "SourceIP": "203.0.113.55",
        "RelatedAlertTypes": ["Failed Login Burst"],
        "RelatedAlertIDs": ["alert-1"],
        "MITRETechniques": ["T1110 - Brute Force"],
        "AttackStages": ["Credential Access"],
        "ClassificationReason": "Repeated failures were observed.",
    }
    timeline = pd.DataFrame(
        [
            {
                "AlertType": "Failed Login Burst",
                "Evidence": "Five failed attempts observed.",
                "AlertID": "alert-1",
                "TimelineTime": "2026-07-18 02:00:00",
            }
        ]
    )
    analysis = run_analyst_agent(incident, timeline, environment_name="SME Office")
    valid, errors = validate_analyst_output(analysis, incident)
    assert valid is True
    assert errors == []


def test_invalid_analysis_is_sanitized() -> None:
    incident = {
        "IncidentType": "Brute-Force Attempt",
        "IncidentSeverity": "High",
        "IncidentConfidence": 10.0,
        "AffectedDevice": "TEST-PC",
        "AffectedUser": "test.user",
        "SourceIP": "203.0.113.55",
        "RelatedAlertTypes": ["Failed Login Burst"],
        "RelatedAlertIDs": ["alert-1"],
        "MITRETechniques": ["T1110 - Brute Force"],
        "AttackStages": ["Credential Access"],
        "ClassificationReason": "Repeated failures were observed.",
    }
    analysis = {
        "Status": "malicious",
        "ThreatType": "Brute-Force Attempt",
        "Severity": "Critical",
        "Confidence": 95.0,
        "Summary": "Test",
        "SuspicionReason": "Test",
        "ObservedEvidence": ["Test"],
        "Inferences": ["Test"],
        "MITRETechniques": ["T1110 - Brute Force"],
        "RecommendedActionID": "NOT_REAL",
        "Target": "TEST-PC",
        "RequiresApproval": "yes",
        "EvidenceIDs": ["bad-id"],
    }
    valid, errors = validate_analyst_output(analysis, incident)
    assert valid is False
    sanitized = sanitize_invalid_analysis(errors)
    assert sanitized["Status"] == "uncertain"
    assert sanitized["RecommendedActionID"] == "COLLECT_EVIDENCE"
    assert sanitized["RequiresApproval"] is True


def test_local_slm_prompt_has_safety_boundaries() -> None:
    incident = {"IncidentType": "Brute-Force Attempt"}
    timeline = pd.DataFrame(columns=["AlertType", "Evidence", "AlertID", "TimelineTime"])
    profile = {"environment_name": "SME Office"}
    prompt = build_local_slm_prompt(incident, timeline, profile, None)
    assert "JSON-only" in prompt
    assert "invent evidence" in prompt.lower()
    assert "PowerShell" in prompt
    assert "ISOLATE_DEVICE" in prompt
    assert "uncertain" in prompt.lower()
