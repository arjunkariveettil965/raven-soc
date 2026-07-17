import pandas as pd

from detection.rule_engine import detect_event_bursts
from incidents.machine_overview import create_machine_overview
from incidents.machine_ranking import (
    add_machine_inventory,
    add_most_common_event_type,
    calculate_machine_risk,
)
from ingestion.normalizer import normalize_windows_event_logs
from response.response_engine import generate_response_recommendations


def create_sample_raw_logs() -> pd.DataFrame:
    """
    Create a small Windows event-log dataset for testing.
    """

    return pd.DataFrame(
        {
            "MachineName": [
                "TEST-PC",
                "TEST-PC",
                "TEST-PC",
                "TEST-PC",
                "TEST-PC",
                "TEST-PC",
            ],
            "Source": [
                "Security",
                "Security",
                "Security",
                "Security",
                "Security",
                "Security",
            ],
            "EntryType": [
                "Error",
                "Error",
                "Error",
                "Error",
                "Error",
                "Information",
            ],
            "TimeGenerated": [
                "2026-07-18 10:00:00",
                "2026-07-18 10:01:00",
                "2026-07-18 10:02:00",
                "2026-07-18 10:03:00",
                "2026-07-18 10:04:00",
                "2026-07-18 10:05:00",
            ],
            "Message": [
                "Security error event",
                "Security error event",
                "Security error event",
                "Security error event",
                "Security error event",
                "Normal information event",
            ],
            "Category": [
                "Authentication",
                "Authentication",
                "Authentication",
                "Authentication",
                "Authentication",
                "System",
            ],
            "country": [
                "India",
                "India",
                "India",
                "India",
                "India",
                "India",
            ],
        }
    )


def create_sample_inventory() -> pd.DataFrame:
    """
    Create a small normalized device inventory.
    """

    return pd.DataFrame(
        {
            "DeviceName": ["TEST-PC"],
            "DeviceRole": ["Testing Workstation"],
            "DeviceOwner": ["Development Team"],
            "DeviceCriticality": ["High"],
        }
    )


def test_log_normalization() -> None:
    raw_logs = create_sample_raw_logs()

    normalized_logs = normalize_windows_event_logs(raw_logs)

    assert len(normalized_logs) == 6
    assert "DeviceName" in normalized_logs.columns
    assert "EventTime" in normalized_logs.columns
    assert "EventSeverity" in normalized_logs.columns

    assert normalized_logs.iloc[0]["DeviceName"] == "TEST-PC"
    assert normalized_logs.iloc[0]["EventSeverity"] == "High"


def test_alert_detection() -> None:
    raw_logs = create_sample_raw_logs()
    normalized_logs = normalize_windows_event_logs(raw_logs)

    alerts = detect_event_bursts(
        normalized_logs,
        threshold=5,
        window_minutes=10,
    )

    assert not alerts.empty
    assert alerts.iloc[0]["DeviceName"] == "TEST-PC"
    assert alerts.iloc[0]["EventCount"] == 5


def test_complete_foundation_pipeline() -> None:
    raw_logs = create_sample_raw_logs()
    inventory = create_sample_inventory()

    normalized_logs = normalize_windows_event_logs(raw_logs)

    alerts = detect_event_bursts(
        normalized_logs,
        threshold=5,
        window_minutes=10,
    )

    overview = create_machine_overview(
        logs=normalized_logs,
        alerts=alerts,
    )

    enriched_overview = add_machine_inventory(
        machine_overview=overview,
        inventory=inventory,
    )

    ranking = calculate_machine_risk(
        machine_overview=enriched_overview,
    )

    ranking = add_most_common_event_type(
        machine_ranking=ranking,
    )

    responses = generate_response_recommendations(
        machine_ranking=ranking,
    )

    assert len(responses) == 1
    assert responses.iloc[0]["DeviceName"] == "TEST-PC"
    assert responses.iloc[0]["DeviceRole"] == "Testing Workstation"
    assert responses.iloc[0]["DeviceCriticality"] == "High"

    assert "RiskScore" in responses.columns
    assert "OverallRisk" in responses.columns
    assert "RecommendedAction" in responses.columns
    assert "ResponseMode" in responses.columns
    assert "IsolationStatus" in responses.columns