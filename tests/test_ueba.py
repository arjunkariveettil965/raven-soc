import pandas as pd

from ueba.anomaly_engine import detect_device_anomalies
from ueba.baseline_engine import build_device_baseline


def create_normal_activity() -> pd.DataFrame:
    """
    Create normal activity for TEST-PC between 9 AM and 10 AM.

    This data is used to teach the UEBA engine what normal
    behaviour looks like.
    """

    event_times = pd.date_range(
        start="2026-07-18 09:00:00",
        periods=20,
        freq="3min",
    )

    return pd.DataFrame(
        {
            "EventTime": event_times,
            "DeviceName": ["TEST-PC"] * 20,
            "UserName": [pd.NA] * 20,
            "EventSource": ["Security"] * 20,
            "EventType": ["Authentication"] * 20,
            "EventResult": ["Success"] * 20,
            "EventSeverity": ["Informational"] * 20,
            "SourceIP": [pd.NA] * 20,
            "DestinationIP": [pd.NA] * 20,
            "ProcessName": [pd.NA] * 20,
            "CommandLine": [pd.NA] * 20,
            "Country": ["India"] * 20,
            "RawMessage": ["Normal security event"] * 20,
        }
    )


def create_abnormal_activity() -> pd.DataFrame:
    """
    Create suspicious activity at 3 AM.

    The activity contains:
    - a new activity hour
    - a new event source
    - a new country
    - several high-severity events
    """

    event_times = pd.date_range(
        start="2026-07-19 03:00:00",
        periods=15,
        freq="1min",
    )

    return pd.DataFrame(
        {
            "EventTime": event_times,
            "DeviceName": ["TEST-PC"] * 15,
            "UserName": [pd.NA] * 15,
            "EventSource": ["PowerShell"] * 15,
            "EventType": ["ProcessExecution"] * 15,
            "EventResult": ["Failure"] * 15,
            "EventSeverity": ["High"] * 15,
            "SourceIP": [pd.NA] * 15,
            "DestinationIP": [pd.NA] * 15,
            "ProcessName": ["powershell.exe"] * 15,
            "CommandLine": [
                "powershell.exe test-command"
            ] * 15,
            "Country": ["Germany"] * 15,
            "RawMessage": [
                "Suspicious test event"
            ] * 15,
        }
    )


def test_device_baseline_creation() -> None:
    """
    Verify that the baseline engine correctly learns the
    normal source, country and device name.
    """

    normal_logs = create_normal_activity()

    baseline = build_device_baseline(
        normal_logs,
        window_minutes=60,
    )

    assert len(baseline) == 1

    assert (
        baseline.iloc[0]["DeviceName"]
        == "TEST-PC"
    )

    assert (
        "Security"
        in baseline.iloc[0]["KnownEventSources"]
    )

    assert (
        "India"
        in baseline.iloc[0]["KnownCountries"]
    )

    assert (
        9
        in baseline.iloc[0]["KnownActiveHours"]
    )


def test_anomalous_activity_detection() -> None:
    """
    Verify that abnormal behaviour is detected and assigned
    a high anomaly score.
    """

    normal_logs = create_normal_activity()
    abnormal_logs = create_abnormal_activity()

    baseline = build_device_baseline(
        normal_logs,
        window_minutes=60,
    )

    anomalies = detect_device_anomalies(
        evaluation_logs=abnormal_logs,
        device_baseline=baseline,
        window_minutes=60,
    )

    assert not anomalies.empty

    anomaly = anomalies.iloc[0]

    assert anomaly["DeviceName"] == "TEST-PC"

    assert anomaly["AnomalyScore"] >= 75

    assert anomaly["AnomalySeverity"] == "Critical"

    assert (
        "Unusual Activity Time"
        in anomaly["AnomalyTypes"]
    )

    assert (
        "New Event Source"
        in anomaly["AnomalyTypes"]
    )

    assert (
        "New Country"
        in anomaly["AnomalyTypes"]
    )

    assert (
        "High-Severity Event Spike"
        in anomaly["AnomalyTypes"]
    )


def test_new_device_detection() -> None:
    """
    Verify that a device absent from the baseline is detected
    as a new device.
    """

    normal_logs = create_normal_activity()

    baseline = build_device_baseline(
        normal_logs,
        window_minutes=60,
    )

    new_device_logs = create_abnormal_activity().copy()

    new_device_logs["DeviceName"] = "UNKNOWN-PC"

    anomalies = detect_device_anomalies(
        evaluation_logs=new_device_logs,
        device_baseline=baseline,
        window_minutes=60,
    )

    assert not anomalies.empty

    anomaly = anomalies.iloc[0]

    assert anomaly["DeviceName"] == "UNKNOWN-PC"

    assert "New Device" in anomaly["AnomalyTypes"]

    assert anomaly["AnomalyScore"] == 40

    assert anomaly["AnomalySeverity"] == "Medium"