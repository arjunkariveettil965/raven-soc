from __future__ import annotations

import ipaddress
from typing import Any

import pandas as pd

from detection.alert_contract import (
    build_entities,
    enrich_alert_record,
    normalize_event_ids,
    stable_alert_id,
)
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

        record = {
                "AlertID": stable_alert_id("network", ["NET_SUSPICIOUS_OUTBOUND", row["EventTime"], row.get("DeviceName"), row.get("UserName"), row.get("DestinationIP"), row.get("ProcessName")]),
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
        alerts.append(
            enrich_alert_record(
                record,
                rule_id="NET_SUSPICIOUS_OUTBOUND",
                title="Suspicious outbound connection",
                destination_ip=row.get("DestinationIP"),
                process_name=row.get("ProcessName"),
                mitre_techniques=["T1071 - Application Layer Protocol"],
                entities=build_entities(
                    machine=row.get("DeviceName"),
                    user=row.get("UserName"),
                    source_ip=row.get("SourceIP"),
                    destination_ip=row.get("DestinationIP"),
                    process=row.get("ProcessName"),
                ),
                evidence_ids=normalize_event_ids(row.to_frame().T),
            )
        )

    if not alerts:
        return _empty_alert_frame()

    return pd.DataFrame(alerts, columns=ALERT_COLUMNS)


def detect_command_and_control_beaconing(
    events: pd.DataFrame,
    minimum_connections: int = 5,
    observation_window_minutes: int = 30,
    interval_tolerance_ratio: float = 0.25,
) -> pd.DataFrame:
    """Detect regular outbound connections to the same external destination."""

    if minimum_connections < 2 or observation_window_minutes < 1:
        raise ValueError("beaconing thresholds and window must be positive.")
    if interval_tolerance_ratio < 0:
        raise ValueError("interval_tolerance_ratio must be non-negative.")

    _require_columns(events)
    if events.empty:
        return _empty_alert_frame()

    working_events = events.copy()
    working_events["EventTime"] = pd.to_datetime(working_events["EventTime"], errors="coerce")
    working_events = working_events.dropna(subset=["EventTime"]).sort_values("EventTime").reset_index(drop=True)
    network_events = working_events[
        working_events["EventType"].astype(str).str.lower().str.contains("network|connection", regex=True, na=False)
        & working_events["DestinationIP"].apply(_is_external_destination)
    ].copy()
    if network_events.empty:
        return _empty_alert_frame()

    alerts: list[dict[str, Any]] = []
    grouping_columns = ["DeviceName", "UserName", "ProcessName", "DestinationIP"]
    for (device_name, user_name, process_name, destination_ip), group in network_events.groupby(grouping_columns, dropna=False):
        group = group.sort_values("EventTime").reset_index(drop=True)
        if len(group) < minimum_connections:
            continue

        emitted = False
        for start_index in range(0, len(group) - minimum_connections + 1):
            start_time = group.iloc[start_index]["EventTime"]
            end_time = start_time + pd.Timedelta(minutes=observation_window_minutes)
            window_events = group[
                (group["EventTime"] >= start_time)
                & (group["EventTime"] <= end_time)
            ].head(minimum_connections)
            if len(window_events) < minimum_connections:
                continue

            times = pd.to_datetime(window_events["EventTime"], errors="coerce").tolist()
            intervals = [
                (times[index] - times[index - 1]).total_seconds()
                for index in range(1, len(times))
            ]
            if not intervals or min(intervals) <= 0:
                continue
            average_interval = sum(intervals) / len(intervals)
            max_deviation = max(abs(interval - average_interval) for interval in intervals)
            if max_deviation > average_interval * interval_tolerance_ratio:
                continue

            regularity_score = max(0.0, 1.0 - (max_deviation / average_interval if average_interval else 1.0))
            process_text = str(process_name or "").lower()
            suspicious_process_bonus = 8.0 if any(process in process_text for process in SUSPICIOUS_PROCESSES) else 0.0
            confidence = min(100.0, 72.0 + len(window_events) * 3.0 + regularity_score * 12.0 + suspicious_process_bonus)
            severity = "Critical" if confidence >= 92 else "High"
            evidence = (
                f"{len(window_events)} regular outbound connections from {device_name} "
                f"to {destination_ip}; average interval {round(average_interval, 1)} seconds"
            )
            record = {
                "AlertID": stable_alert_id("beacon", ["NETWORK_BEACONING", device_name, user_name, process_name, destination_ip, start_time, len(window_events)]),
                "AlertTime": window_events.iloc[-1]["EventTime"],
                "DeviceName": device_name,
                "UserName": user_name,
                "SourceIP": window_events.iloc[0].get("SourceIP"),
                "AlertType": "Command-and-Control Beaconing",
                "AlertSeverity": severity,
                "ConfidenceScore": confidence,
                "MITRETactic": "Command and Control",
                "MITRETechnique": "T1071 - Application Layer Protocol",
                "Evidence": evidence,
                "FirstSeen": window_events.iloc[0]["EventTime"],
                "LastSeen": window_events.iloc[-1]["EventTime"],
                "RelatedEventCount": len(window_events),
            }
            alerts.append(
                enrich_alert_record(
                    record,
                    rule_id="NETWORK_BEACONING",
                    title="Command-and-control beaconing",
                    destination_ip=destination_ip,
                    process_name=process_name,
                    mitre_techniques=["T1071 - Application Layer Protocol"],
                    entities=build_entities(
                        machine=device_name,
                        user=user_name,
                        source_ip=window_events.iloc[0].get("SourceIP"),
                        destination_ip=destination_ip,
                        process=process_name,
                    ),
                    metadata={
                        "AverageIntervalSeconds": round(average_interval, 2),
                        "MaxIntervalDeviationSeconds": round(max_deviation, 2),
                        "RegularityScore": round(regularity_score, 3),
                    },
                    evidence_ids=normalize_event_ids(window_events),
                )
            )
            emitted = True
            break
        if emitted:
            continue

    if not alerts:
        return _empty_alert_frame()
    return pd.DataFrame(alerts, columns=ALERT_COLUMNS)
