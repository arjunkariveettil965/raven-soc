from __future__ import annotations

import uuid
from typing import Any

import pandas as pd


ALERT_COLUMNS = [
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
]


def _empty_alert_frame() -> pd.DataFrame:
    """Return an empty alert DataFrame with the shared schema."""

    return pd.DataFrame(columns=ALERT_COLUMNS)


def _require_columns(
    events: pd.DataFrame,
    required_columns: set[str],
    function_name: str,
) -> None:
    """Validate that the input DataFrame includes the required columns."""

    if not isinstance(events, pd.DataFrame):
        raise TypeError(f"{function_name} expects a pandas DataFrame.")

    missing_columns = required_columns - set(events.columns)

    if missing_columns:
        raise ValueError(
            f"{function_name} is missing required columns: "
            f"{sorted(missing_columns)}"
        )


def _create_alert(
    *,
    alert_time: pd.Timestamp,
    device_name: str,
    user_name: str,
    source_ip: str,
    alert_type: str,
    severity: str,
    confidence: float,
    tactic: str,
    technique: str,
    evidence: str,
    first_seen: pd.Timestamp,
    last_seen: pd.Timestamp,
    related_event_count: int,
    prefix: str,
) -> dict[str, Any]:
    """Create one alert record using the shared schema."""

    return {
        "AlertID": f"{prefix}-{uuid.uuid4().hex[:8]}",
        "AlertTime": alert_time,
        "DeviceName": device_name,
        "UserName": user_name,
        "SourceIP": source_ip,
        "AlertType": alert_type,
        "AlertSeverity": severity,
        "ConfidenceScore": float(confidence),
        "MITRETactic": tactic,
        "MITRETechnique": technique,
        "Evidence": evidence,
        "FirstSeen": first_seen,
        "LastSeen": last_seen,
        "RelatedEventCount": int(related_event_count),
    }


def detect_failed_login_bursts(
    events: pd.DataFrame,
    threshold: int = 5,
    window_minutes: int = 10,
) -> pd.DataFrame:
    """
    Detect repeated failed authentication events within a sliding time window.

    One alert is generated per device/user/source IP combination when the
    threshold is reached.
    """

    if not isinstance(threshold, int) or threshold < 1:
        raise ValueError("threshold must be a positive integer.")

    if not isinstance(window_minutes, int) or window_minutes < 1:
        raise ValueError("window_minutes must be a positive integer.")

    _require_columns(
        events,
        {
            "EventTime",
            "DeviceName",
            "UserName",
            "EventType",
            "EventResult",
            "SourceIP",
        },
        "detect_failed_login_bursts",
    )

    if events.empty:
        return _empty_alert_frame()

    working_events = events.copy()
    working_events["EventTime"] = pd.to_datetime(
        working_events["EventTime"],
        errors="coerce",
    )
    working_events = working_events.dropna(subset=["EventTime"])

    if working_events.empty:
        return _empty_alert_frame()

    working_events = working_events.sort_values("EventTime").reset_index(drop=True)
    failed_auth_events = working_events[
        (working_events["EventType"].astype(str).str.lower() == "authentication")
        & (working_events["EventResult"].astype(str).str.lower() == "failure")
    ].copy()

    if failed_auth_events.empty:
        return _empty_alert_frame()

    alerts: list[dict[str, Any]] = []

    for (device_name, user_name, source_ip), group in (
        failed_auth_events.groupby(
            ["DeviceName", "UserName", "SourceIP"],
            dropna=False,
        )
    ):
        alert_triggered = False
        window_start = 0

        for current_index, row in group.iterrows():
            current_time = row["EventTime"]
            window_start_time = current_time - pd.Timedelta(minutes=window_minutes)

            while window_start < len(group) and group.iloc[window_start]["EventTime"] < window_start_time:
                window_start += 1

            window_events = group.iloc[window_start : current_index + 1]
            event_count = len(window_events)

            if event_count >= threshold and not alert_triggered:
                severity = "Critical" if event_count >= threshold * 2 else "High"
                confidence = min(100.0, 70.0 + (event_count / threshold) * 10.0)

                alerts.append(
                    _create_alert(
                        alert_time=current_time,
                        device_name=device_name,
                        user_name=user_name,
                        source_ip=source_ip,
                        alert_type="Failed Login Burst",
                        severity=severity,
                        confidence=confidence,
                        tactic="Credential Access",
                        technique="T1110 - Brute Force",
                        evidence=(
                            f"{event_count} failed authentication events "
                            f"within {window_minutes} minutes"
                        ),
                        first_seen=window_events.iloc[0]["EventTime"],
                        last_seen=window_events.iloc[-1]["EventTime"],
                        related_event_count=event_count,
                        prefix="login-burst",
                    )
                )
                alert_triggered = True

    if not alerts:
        return _empty_alert_frame()

    return pd.DataFrame(alerts, columns=ALERT_COLUMNS)


def detect_success_after_failures(
    events: pd.DataFrame,
    minimum_failures: int = 3,
    lookback_minutes: int = 15,
) -> pd.DataFrame:
    """
    Detect a successful authentication event that follows repeated failures
    from the same device, user and source IP.
    """

    if not isinstance(minimum_failures, int) or minimum_failures < 1:
        raise ValueError("minimum_failures must be a positive integer.")

    if not isinstance(lookback_minutes, int) or lookback_minutes < 1:
        raise ValueError("lookback_minutes must be a positive integer.")

    _require_columns(
        events,
        {
            "EventTime",
            "DeviceName",
            "UserName",
            "EventType",
            "EventResult",
            "SourceIP",
        },
        "detect_success_after_failures",
    )

    if events.empty:
        return _empty_alert_frame()

    working_events = events.copy()
    working_events["EventTime"] = pd.to_datetime(
        working_events["EventTime"],
        errors="coerce",
    )
    working_events = working_events.dropna(subset=["EventTime"])

    if working_events.empty:
        return _empty_alert_frame()

    working_events = working_events.sort_values("EventTime").reset_index(drop=True)
    successful_auth_events = working_events[
        (working_events["EventType"].astype(str).str.lower() == "authentication")
        & (working_events["EventResult"].astype(str).str.lower() == "success")
    ].copy()

    if successful_auth_events.empty:
        return _empty_alert_frame()

    alerts: list[dict[str, Any]] = []

    for (device_name, user_name, source_ip), group in (
        successful_auth_events.groupby(
            ["DeviceName", "UserName", "SourceIP"],
            dropna=False,
        )
    ):
        alert_triggered = False
        failures_group = working_events[
            (working_events["DeviceName"] == device_name)
            & (working_events["UserName"] == user_name)
            & (working_events["SourceIP"] == source_ip)
            & (working_events["EventType"].astype(str).str.lower() == "authentication")
            & (working_events["EventResult"].astype(str).str.lower() == "failure")
        ].copy()

        for _, row in group.iterrows():
            current_time = row["EventTime"]
            window_start = current_time - pd.Timedelta(minutes=lookback_minutes)
            recent_failures = failures_group[
                (failures_group["EventTime"] >= window_start)
                & (failures_group["EventTime"] <= current_time)
            ]

            if len(recent_failures) >= minimum_failures and not alert_triggered:
                alerts.append(
                    _create_alert(
                        alert_time=current_time,
                        device_name=device_name,
                        user_name=user_name,
                        source_ip=source_ip,
                        alert_type="Successful Login After Failures",
                        severity="Critical",
                        confidence=95.0,
                        tactic="Initial Access / Persistence",
                        technique="T1078 - Valid Accounts",
                        evidence=(
                            f"{len(recent_failures)} failures followed by a success"
                        ),
                        first_seen=recent_failures.iloc[0]["EventTime"],
                        last_seen=current_time,
                        related_event_count=len(recent_failures) + 1,
                        prefix="success-after-failure",
                    )
                )
                alert_triggered = True

    if not alerts:
        return _empty_alert_frame()

    return pd.DataFrame(alerts, columns=ALERT_COLUMNS)
