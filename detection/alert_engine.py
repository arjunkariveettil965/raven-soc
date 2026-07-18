from __future__ import annotations

import pandas as pd

from detection.authentication_rules import ALERT_COLUMNS
from detection.authentication_rules import detect_failed_login_bursts, detect_success_after_failures
from detection.network_rules import detect_suspicious_network_connections
from detection.process_rules import detect_suspicious_powershell


def analyze_security_events(events: pd.DataFrame) -> pd.DataFrame:
    """
    Run the specialized detection rules and return a consolidated alert table.
    """

    if not isinstance(events, pd.DataFrame):
        raise TypeError("analyze_security_events expects a pandas DataFrame.")

    if events.empty:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    alert_frames = []

    failed_login_alerts = detect_failed_login_bursts(events)
    if not failed_login_alerts.empty:
        alert_frames.append(failed_login_alerts)

    success_after_failure_alerts = detect_success_after_failures(events)
    if not success_after_failure_alerts.empty:
        alert_frames.append(success_after_failure_alerts)

    powershell_alerts = detect_suspicious_powershell(events)
    if not powershell_alerts.empty:
        alert_frames.append(powershell_alerts)

    network_alerts = detect_suspicious_network_connections(events)
    if not network_alerts.empty:
        alert_frames.append(network_alerts)

    if not alert_frames:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    combined_alerts = pd.concat(alert_frames, ignore_index=True)
    combined_alerts = combined_alerts[ALERT_COLUMNS]

    combined_alerts["AlertTime"] = pd.to_datetime(
        combined_alerts["AlertTime"],
        errors="coerce",
    )
    combined_alerts["FirstSeen"] = pd.to_datetime(
        combined_alerts["FirstSeen"],
        errors="coerce",
    )
    combined_alerts["LastSeen"] = pd.to_datetime(
        combined_alerts["LastSeen"],
        errors="coerce",
    )
    combined_alerts["ConfidenceScore"] = pd.to_numeric(
        combined_alerts["ConfidenceScore"],
        errors="coerce",
    ).fillna(0)

    combined_alerts = combined_alerts.sort_values(
        ["AlertTime", "ConfidenceScore"],
        ascending=[True, False],
    ).reset_index(drop=True)

    return combined_alerts
