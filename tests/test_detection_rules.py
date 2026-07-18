import pandas as pd

from data_generation.attack_simulator import (
    generate_account_compromise_scenario,
    generate_multistage_attack_scenario,
    generate_suspicious_network_scenario,
    generate_suspicious_powershell_scenario,
)
from detection.alert_engine import analyze_security_events
from detection.authentication_rules import (
    detect_failed_login_bursts,
    detect_success_after_failures,
)
from detection.network_rules import detect_suspicious_network_connections
from detection.process_rules import detect_suspicious_powershell


def test_failed_login_burst_detection() -> None:
    events = generate_account_compromise_scenario(failed_login_count=6)

    alerts = detect_failed_login_bursts(events, threshold=5, window_minutes=10)

    assert len(alerts) == 1
    assert alerts.iloc[0]["AlertType"] == "Failed Login Burst"
    assert alerts.iloc[0]["AlertSeverity"] == "High"
    assert alerts.iloc[0]["RelatedEventCount"] >= 5


def test_success_after_failures_detection() -> None:
    events = generate_account_compromise_scenario(failed_login_count=5)

    alerts = detect_success_after_failures(events, minimum_failures=3, lookback_minutes=15)

    assert len(alerts) == 1
    assert alerts.iloc[0]["AlertType"] == "Successful Login After Failures"
    assert alerts.iloc[0]["AlertSeverity"] == "Critical"
    assert alerts.iloc[0]["RelatedEventCount"] >= 4


def test_suspicious_powershell_detection() -> None:
    events = generate_suspicious_powershell_scenario()

    alerts = detect_suspicious_powershell(events)

    assert len(alerts) >= 1
    assert alerts.iloc[0]["AlertType"] == "Suspicious PowerShell"
    assert alerts.iloc[0]["AlertSeverity"] == "Critical"
    assert "encodedcommand" in alerts.iloc[0]["Evidence"].lower()


def test_suspicious_network_detection() -> None:
    events = generate_suspicious_network_scenario()

    alerts = detect_suspicious_network_connections(events)

    assert len(alerts) == 1
    assert alerts.iloc[0]["AlertType"] == "Suspicious Outbound Connection"
    assert alerts.iloc[0]["AlertSeverity"] == "High"
    assert alerts.iloc[0]["DeviceName"] == "CFO-PC"


def test_complete_alert_engine() -> None:
    events = generate_multistage_attack_scenario()

    alerts = analyze_security_events(events)

    expected_types = {
        "Failed Login Burst",
        "Successful Login After Failures",
        "Suspicious PowerShell",
        "Suspicious Outbound Connection",
    }

    assert expected_types.issubset(set(alerts["AlertType"]))
    assert len(alerts) >= 4
    assert alerts["AlertTime"].is_monotonic_increasing
    assert alerts["ConfidenceScore"].between(0, 100).all()
    assert alerts["DeviceName"].eq("CFO-PC").all()
