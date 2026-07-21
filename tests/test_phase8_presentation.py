from __future__ import annotations

from datetime import datetime

import pandas as pd

from dashboard.presentation import (
    CORRELATION_COVERAGE,
    DETECTION_COVERAGE,
    build_attack_chain,
    build_incident_summary,
    build_pipeline_status,
    defender_state,
    diagnostics_visible,
    explain_correlation,
    format_display_value,
)
from data_generation.scenario_lab import generate_scenario


def test_format_display_value_handles_missing_and_dates():
    assert format_display_value(None) == "N/A"
    assert format_display_value("") == "N/A"
    assert format_display_value(float("nan")) == "N/A"
    assert format_display_value(datetime(2026, 7, 21, 10, 5, 1)) == "21 Jul 2026, 10:05:01"
    assert format_display_value(pd.Timestamp("2026-07-21T10:05:01")) == "21 Jul 2026, 10:05:01"


def test_pipeline_status_reports_completed_and_failed_safely():
    result = {
        "events": pd.DataFrame([{"EventID": "E1"}]),
        "alerts": pd.DataFrame([{"AlertID": "A1"}]),
        "incidents": pd.DataFrame([{"IncidentID": "I1"}]),
        "selected_incident": {"IncidentID": "I1"},
        "analysis": {"Status": "malicious"},
        "synthetic_defender_response": None,
        "analyst_metadata": {"UsedFallback": True},
    }

    rows = build_pipeline_status(result)

    assert rows[0]["Status"] == "Completed"
    assert rows[4]["Status"] == "Failed safely"
    assert rows[5]["Status"] == "Not Triggered"


def test_incident_summary_uses_analyst_and_metadata_fields():
    summary = build_incident_summary(
        {"IncidentType": "Password Spray Attempt", "AlertCount": 4},
        {
            "Status": "malicious",
            "Severity": "High",
            "Confidence": 96,
            "RecommendedActionID": "BLOCK_DESTINATION_IP",
            "RequiresApproval": False,
        },
        {"AnalystMode": "hybrid", "ModelName": "gemma3:4b-it-qat", "UsedFallback": False},
    )

    assert summary["Incident Type"] == "Password Spray Attempt"
    assert summary["Status"] == "malicious"
    assert summary["Used Fallback"] == "No"


def test_attack_chain_maps_supported_tactics():
    timeline = pd.DataFrame(
        [
            {
                "TimelineTime": pd.Timestamp("2026-07-21T10:02:00"),
                "MITRETactic": "Execution",
                "AlertType": "Suspicious PowerShell",
                "Evidence": "powershell command",
                "MITRETechnique": "T1059.001 - PowerShell",
                "DeviceName": "HOST-1",
            },
            {
                "TimelineTime": pd.Timestamp("2026-07-21T10:01:00"),
                "MITRETactic": "Credential Access",
                "AlertType": "Password Spray",
                "Evidence": "failed logons",
                "MITRETechnique": "T1110.003 - Password Spraying",
                "UserName": "alice",
            },
        ]
    )

    chain = build_attack_chain(timeline)

    assert [row["Stage"] for row in chain] == ["Credential Access", "Execution"]
    assert chain[0]["Alert"] == "Password Spray"


def test_correlation_explanations_cover_phase6_patterns():
    expected = {
        "Multi-Stage Intrusion": "PowerShell execution",
        "Password Spray Attempt": "multiple distinct users",
        "Malware Download and Execution": "download-capable process",
        "Command-and-Control Beaconing": "repeated outbound connections",
    }

    for pattern, phrase in expected.items():
        assert phrase in explain_correlation({"CorrelationPattern": pattern})


def test_diagnostics_visibility_hides_in_presentation_without_fallback():
    assert diagnostics_visible(presentation_mode=True, used_fallback=False) is False
    assert diagnostics_visible(presentation_mode=True, used_fallback=True) is True
    assert diagnostics_visible(presentation_mode=False, used_fallback=False) is True


def test_defender_state_is_presentation_safe():
    assert defender_state(None, requires_approval=True) == "Awaiting Approval"
    assert defender_state(None, requires_approval=False) == "No Action Required"
    assert defender_state({"Permitted": True, "Executed": True}, requires_approval=True) == "Approved Simulation"
    assert defender_state({"Permitted": False, "Executed": False}, requires_approval=True, rejected=True) == "Rejected"


def test_detection_coverage_lists_core_rules_and_patterns():
    detection_ids = {row[0] for row in DETECTION_COVERAGE}
    correlation_ids = {row[0] for row in CORRELATION_COVERAGE}

    assert "AUTH_PASSWORD_SPRAY" in detection_ids
    assert "NETWORK_BEACONING" in detection_ids
    assert "MALWARE_DOWNLOAD_EXECUTION" in correlation_ids
    assert "COMMAND_CONTROL_BEACONING" in correlation_ids


def test_synthetic_malware_urls_are_reserved_and_complete():
    scenario = generate_scenario(
        "malware_download_execution",
        seed=20260721,
        difficulty="Easy",
        noise_level="Low",
    )
    command_lines = [
        str(command)
        for command in scenario["GeneratedEvents"]["CommandLine"].dropna().tolist()
        if str(command).strip()
    ]

    assert any("https://updates.example.test/agent.bin" in command for command in command_lines) or any(
        "https://updates.example.test/loader.hta" in command for command in command_lines
    )
    assert all(command.strip() != "https://" for command in command_lines)
