import pandas as pd

from data_generation.attack_simulator import (
    generate_account_compromise_scenario,
    generate_multistage_attack_scenario,
)
from detection.alert_engine import analyze_security_events
from incidents.correlation_engine import correlate_alerts
from incidents.incident_classifier import classify_incidents
from incidents.timeline_builder import build_incident_timeline, format_incident_timeline


def test_multistage_alert_correlation() -> None:
    alerts = analyze_security_events(generate_multistage_attack_scenario())

    incidents = correlate_alerts(alerts)

    assert len(incidents) == 1
    assert incidents.iloc[0]["AffectedDevice"] == "CFO-PC"
    assert incidents.iloc[0]["AlertCount"] >= 4
    assert set(incidents.iloc[0]["RelatedAlertTypes"]) >= {
        "Failed Login Burst",
        "Successful Login After Failures",
        "Suspicious PowerShell",
        "Suspicious Outbound Connection",
    }
    assert incidents.iloc[0]["CorrelationScore"] >= 50


def test_incident_classification() -> None:
    alerts = analyze_security_events(generate_multistage_attack_scenario())
    incidents = correlate_alerts(alerts)

    classified = classify_incidents(incidents)

    assert classified.iloc[0]["IncidentType"] == "Multi-Stage Intrusion"
    assert classified.iloc[0]["IncidentSeverity"] == "Critical"
    assert 0 <= classified.iloc[0]["IncidentConfidence"] <= 100
    assert set(
        [
            "Credential Access",
            "Initial Access / Persistence",
            "Execution",
            "Command and Control",
        ]
    ).issubset(set(classified.iloc[0]["AttackStages"]))
    assert classified.iloc[0]["ClassificationReason"]


def test_incident_timeline() -> None:
    alerts = analyze_security_events(generate_multistage_attack_scenario())
    incidents = correlate_alerts(alerts)
    timeline = build_incident_timeline(incidents.iloc[0], alerts)

    assert not timeline.empty
    assert timeline["TimelineTime"].is_monotonic_increasing
    assert "Authentication" in timeline.iloc[0]["AlertType"] or "Login" in timeline.iloc[0]["AlertType"]
    assert timeline.iloc[-1]["AlertType"] == "Suspicious Outbound Connection"
    assert len(format_incident_timeline(timeline)) == len(timeline)


def test_unrelated_devices_create_separate_incidents() -> None:
    cfo_events = generate_account_compromise_scenario(device_name="CFO-PC")
    hr_events = generate_account_compromise_scenario(
        start_time=cfo_events.iloc[0]["EventTime"] + pd.Timedelta(minutes=1),
        device_name="HR-PC",
        user_name="hr.user",
        source_ip="198.51.100.22",
    )

    combined = pd.concat([cfo_events, hr_events], ignore_index=True)
    alerts = analyze_security_events(combined)
    incidents = correlate_alerts(alerts)

    assert len(incidents) == 2
    assert set(incidents["AffectedDevice"]) == {"CFO-PC", "HR-PC"}


def test_empty_correlation_inputs() -> None:
    empty_alerts = pd.DataFrame(columns=[
        "AlertID",
        "AlertTime",
        "DeviceName",
        "UserName",
        "SourceIP",
        "AlertType",
        "AlertSeverity",
        "ConfidenceScore",
        "MITRETactic",
        "MITRETechnique",
        "Evidence",
        "FirstSeen",
        "LastSeen",
        "RelatedEventCount",
    ])

    empty_incidents = correlate_alerts(empty_alerts)
    assert empty_incidents.empty

    classified_empty = classify_incidents(empty_incidents)
    assert classified_empty.empty

    empty_timeline = build_incident_timeline({}, empty_alerts)
    assert empty_timeline.empty

    assert format_incident_timeline(empty_timeline) == []


def test_cross_device_user_correlation() -> None:
    alerts = pd.DataFrame([
        {
            "AlertID": "A1",
            "AlertTime": "2026-07-18 10:00:00",
            "DeviceName": "CFO-PC",
            "UserName": "admin.user",
            "SourceIP": "10.0.0.1",
            "AlertType": "Failed Login Burst",
            "AlertSeverity": "High",
            "ConfidenceScore": 70.0,
            "MITRETactic": "Credential Access",
            "MITRETechnique": "T1110",
            "Evidence": "A1 evidence",
            "FirstSeen": "2026-07-18 10:00:00",
            "LastSeen": "2026-07-18 10:00:00",
            "RelatedEventCount": 5,
        },
        {
            "AlertID": "A2",
            "AlertTime": "2026-07-18 10:05:00",
            "DeviceName": "HR-PC",
            "UserName": "admin.user",
            "SourceIP": "10.0.0.1",
            "AlertType": "Suspicious PowerShell",
            "AlertSeverity": "High",
            "ConfidenceScore": 80.0,
            "MITRETactic": "Execution",
            "MITRETechnique": "T1059.001",
            "Evidence": "A2 evidence",
            "FirstSeen": "2026-07-18 10:05:00",
            "LastSeen": "2026-07-18 10:05:00",
            "RelatedEventCount": 1,
        }
    ])

    incidents = correlate_alerts(alerts, minimum_correlation_score=50)
    assert len(incidents) == 1
    assert incidents.iloc[0]["AlertCount"] == 2
    assert "CFO-PC" in [incidents.iloc[0]["AffectedDevice"], incidents.iloc[0]["Target"]]

