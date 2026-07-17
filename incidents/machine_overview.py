import pandas as pd


def create_machine_overview(
    logs: pd.DataFrame,
    alerts: pd.DataFrame,
) -> pd.DataFrame:
    """
    Create a device-level overview using normalized security logs.

    The overview contains:
    - total events
    - informational events
    - medium-severity events
    - high-severity events
    - total alerts
    - medium alerts
    - high alerts
    - most active event source
    """

    required_log_columns = {
        "DeviceName",
        "EventSource",
        "EventSeverity",
    }

    missing_columns = required_log_columns - set(logs.columns)

    if missing_columns:
        raise ValueError(
            "Normalized logs are missing overview columns: "
            f"{sorted(missing_columns)}"
        )

    working_logs = logs.copy()

    working_logs["EventSeverityNormalized"] = (
        working_logs["EventSeverity"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    working_logs["DeviceName"] = (
        working_logs["DeviceName"]
        .astype(str)
        .str.strip()
    )

    working_logs["EventSource"] = (
        working_logs["EventSource"]
        .astype(str)
        .str.strip()
    )

    # Count all events for every device.
    total_events = (
        working_logs.groupby("DeviceName")
        .size()
        .rename("TotalEvents")
    )

    # Count events by normalized severity.
    severity_counts = working_logs.pivot_table(
        index="DeviceName",
        columns="EventSeverityNormalized",
        values="EventSource",
        aggfunc="count",
        fill_value=0,
    )

    for severity in [
        "informational",
        "medium",
        "high",
    ]:
        if severity not in severity_counts.columns:
            severity_counts[severity] = 0

    severity_counts = severity_counts.rename(
        columns={
            "informational": "InformationEvents",
            "medium": "WarningEvents",
            "high": "ErrorEvents",
        }
    )

    # Find the most active source for each device.
    source_counts = (
        working_logs.groupby(
            [
                "DeviceName",
                "EventSource",
            ],
            dropna=False,
        )
        .size()
        .reset_index(name="SourceEventCount")
    )

    most_active_source = (
        source_counts.sort_values(
            by="SourceEventCount",
            ascending=False,
        )
        .drop_duplicates(subset=["DeviceName"])
        .set_index("DeviceName")[
            [
                "EventSource",
                "SourceEventCount",
            ]
        ]
        .rename(
            columns={
                "EventSource": "MostActiveSource",
                "SourceEventCount": "MostActiveSourceEvents",
            }
        )
    )

    # Count generated alerts for every device.
    if alerts.empty:
        alert_summary = pd.DataFrame(
            index=total_events.index,
            data={
                "TotalAlerts": 0,
                "HighSeverityAlerts": 0,
                "MediumSeverityAlerts": 0,
            },
        )

    else:
        required_alert_columns = {
            "DeviceName",
            "Severity",
        }

        missing_alert_columns = (
            required_alert_columns - set(alerts.columns)
        )

        if missing_alert_columns:
            raise ValueError(
                "Alerts are missing overview columns: "
                f"{sorted(missing_alert_columns)}"
            )

        total_alerts = (
            alerts.groupby("DeviceName")
            .size()
            .rename("TotalAlerts")
        )

        high_alerts = (
            alerts[
                alerts["Severity"]
                .astype(str)
                .str.lower()
                == "high"
            ]
            .groupby("DeviceName")
            .size()
            .rename("HighSeverityAlerts")
        )

        medium_alerts = (
            alerts[
                alerts["Severity"]
                .astype(str)
                .str.lower()
                == "medium"
            ]
            .groupby("DeviceName")
            .size()
            .rename("MediumSeverityAlerts")
        )

        alert_summary = pd.concat(
            [
                total_alerts,
                high_alerts,
                medium_alerts,
            ],
            axis=1,
        ).fillna(0)

    machine_overview = pd.concat(
        [
            total_events,
            severity_counts[
                [
                    "InformationEvents",
                    "WarningEvents",
                    "ErrorEvents",
                ]
            ],
            alert_summary,
            most_active_source,
        ],
        axis=1,
    ).fillna(0)

    integer_columns = [
        "TotalEvents",
        "InformationEvents",
        "WarningEvents",
        "ErrorEvents",
        "TotalAlerts",
        "HighSeverityAlerts",
        "MediumSeverityAlerts",
        "MostActiveSourceEvents",
    ]

    machine_overview[integer_columns] = (
        machine_overview[integer_columns]
        .astype(int)
    )

    machine_overview = (
        machine_overview.reset_index()
        .sort_values(
            by=[
                "HighSeverityAlerts",
                "TotalAlerts",
                "ErrorEvents",
                "WarningEvents",
            ],
            ascending=False,
        )
        .reset_index(drop=True)
    )

    return machine_overview