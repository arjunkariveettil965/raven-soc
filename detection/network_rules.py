from __future__ import annotations

import ipaddress
import uuid
from typing import Any

import pandas as pd

from detection.authentication_rules import ALERT_COLUMNS


SUSPICIOUS_PROCESSES = {"powershell", "pwsh", "cmd.exe", "wscript", "cscript"}
EXTERNAL_NETWORKS = [
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
]


def _empty_alert_frame() -> pd.DataFrame:
    """Return an empty alert DataFrame with the shared schema."""

    return pd.DataFrame(columns=ALERT_COLUMNS)


def _require_columns(events: pd.DataFrame) -> None:
    """Validate that the input DataFrame includes the required columns."""

    if not isinstance(events, pd.DataFrame):
        raise TypeError("detect_suspicious_network_connections expects a pandas DataFrame.")

    required_columns = {"EventTime", "DeviceName", "UserName", "EventType", "DestinationIP", "ProcessName", "SourceIP"}
    missing_columns = required_columns - set(events.columns)

    if missing_columns:
        raise ValueError(
            "detect_suspicious_network_connections is missing required columns: "
            f"{sorted(missing_columns)}"
        )


def _is_external_destination(destination_ip: object) -> bool:
    """Return True when the destination falls inside a documented external range."""

    if destination_ip is None:
        return False

    if isinstance(destination_ip, str) and not destination_ip.strip():
        return False

    try:
        ip_value = ipaddress.ip_address(str(destination_ip))
    except ValueError:
        return False

    return any(ip_value in network for network in EXTERNAL_NETWORKS)


def detect_suspicious_network_connections(events: pd.DataFrame) -> pd.DataFrame:
    """
    Detect suspicious outbound network connections from PowerShell, cmd.exe or
    other suspicious processes to external destinations.
    """

    _require_columns(events)

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

    alerts: list[dict[str, Any]] = []

    for _, row in working_events.iterrows():
        event_type = str(row.get("EventType", "")).lower()
        process_name = str(row.get("ProcessName", "")).lower()

        if event_type and "network" not in event_type and "connection" not in event_type:
            continue

        if process_name not in SUSPICIOUS_PROCESSES and not any(
            suspicious_process in process_name for suspicious_process in SUSPICIOUS_PROCESSES
        ):
            continue

        if not _is_external_destination(row.get("DestinationIP")):
            continue

        alerts.append(
            {
                "AlertID": f"network-{uuid.uuid4().hex[:8]}",
                "AlertTime": row["EventTime"],
                "DeviceName": row.get("DeviceName"),
                "UserName": row.get("UserName"),
                "SourceIP": row.get("SourceIP"),
                "AlertType": "Suspicious Outbound Connection",
                "AlertSeverity": "High",
                "ConfidenceScore": 88.0,
                "MITRETactic": "Command and Control",
                "MITRETechnique": "T1071 - Application Layer Protocol",
                "Evidence": (
                    f"Process {row.get('ProcessName')} connected to "
                    f"{row.get('DestinationIP')}"
                ),
                "FirstSeen": row["EventTime"],
                "LastSeen": row["EventTime"],
                "RelatedEventCount": 1,
            }
        )

    if not alerts:
        return _empty_alert_frame()

    return pd.DataFrame(alerts, columns=ALERT_COLUMNS)
