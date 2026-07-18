from __future__ import annotations

import pandas as pd


TIMELINE_COLUMNS = [
    "TimelineTime",
    "AlertID",
    "AlertType",
    "AlertSeverity",
    "MITRETactic",
    "MITRETechnique",
    "Evidence",
]


def _empty_timeline_frame() -> pd.DataFrame:
    """Return an empty incident timeline DataFrame."""

    return pd.DataFrame(columns=TIMELINE_COLUMNS)


def build_incident_timeline(
    incident: pd.Series | dict,
    alerts: pd.DataFrame,
) -> pd.DataFrame:
    """
    Build a chronological timeline for an incident using the alerts linked to it.
    """

    if not isinstance(alerts, pd.DataFrame):
        raise TypeError("build_incident_timeline expects a pandas DataFrame.")

    if alerts.empty:
        return _empty_timeline_frame()

    if isinstance(incident, pd.Series):
        incident_data = incident.to_dict()
    elif isinstance(incident, dict):
        incident_data = incident
    else:
        raise TypeError("incident must be a pandas Series or dict.")

    related_alert_ids = set()
    for alert_id in incident_data.get("RelatedAlertIDs", []):
        if alert_id is not None:
            related_alert_ids.add(str(alert_id))

    if not related_alert_ids:
        return _empty_timeline_frame()

    matching_alerts = alerts[alerts["AlertID"].astype(str).isin(related_alert_ids)].copy()
    if matching_alerts.empty:
        return _empty_timeline_frame()

    matching_alerts["TimelineTime"] = pd.to_datetime(
        matching_alerts["AlertTime"],
        errors="coerce",
    )
    matching_alerts = matching_alerts.dropna(subset=["TimelineTime"])
    if matching_alerts.empty:
        return _empty_timeline_frame()

    matching_alerts = matching_alerts.sort_values("TimelineTime").reset_index(drop=True)
    matching_alerts = matching_alerts[
        [
            "TimelineTime",
            "AlertID",
            "AlertType",
            "AlertSeverity",
            "MITRETactic",
            "MITRETechnique",
            "Evidence",
        ]
    ]
    matching_alerts = matching_alerts.reset_index(drop=True)

    matching_alerts = matching_alerts.sort_values("TimelineTime").reset_index(drop=True)
    matching_alerts["TimelineTime"] = pd.to_datetime(
        matching_alerts["TimelineTime"],
        errors="coerce",
    )

    return matching_alerts


def format_incident_timeline(timeline: pd.DataFrame) -> list[str]:
    """Format the timeline rows as readable strings."""

    if not isinstance(timeline, pd.DataFrame):
        raise TypeError("format_incident_timeline expects a pandas DataFrame.")

    if timeline.empty:
        return []

    formatted_lines: list[str] = []
    for _, row in timeline.iterrows():
        timeline_time = pd.to_datetime(row["TimelineTime"], errors="coerce")
        if pd.isna(timeline_time):
            continue

        time_label = timeline_time.strftime("%H:%M:%S")
        formatted_lines.append(
            f"{time_label} — {row['AlertType']}: {row['Evidence']}"
        )

    return formatted_lines
