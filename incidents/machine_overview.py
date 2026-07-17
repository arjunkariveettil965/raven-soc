import pandas as pd


def create_machine_overview(
    logs: pd.DataFrame,
    alerts: pd.DataFrame,
) -> pd.DataFrame:
    """
    Create a beginner-friendly summary of activity for every machine.

    The summary includes:
    - total events
    - information events
    - warning events
    - error events
    - detected alerts
    - high-severity alerts
    - most active event source
    """

    required_log_columns = {
        "MachineName",
        "Source",
        "EntryType",
    }

    missing_columns = required_log_columns - set(logs.columns)

    if missing_columns:
        raise ValueError(
            f"Missing required log columns: {sorted(missing_columns)}"
        )

    working_logs = logs.copy()

    # Normalize event type values such as Error, ERROR and error.
    working_logs["EntryTypeNormalized"] = (
        working_logs["EntryType"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    # Count all events for every machine.
    total_events = (
        working_logs.groupby("MachineName")
        .size()
        .rename("TotalEvents")
    )

    # Count event types for every machine.
    event_counts = (
        working_logs.pivot_table(
            index="MachineName",
            columns="EntryTypeNormalized",
            values="Source",
            aggfunc="count",
            fill_value=0,
        )
    )

    # Ensure these columns exist even when a dataset has none of that type.
    for event_type in ["information", "warning", "error"]:
        if event_type not in event_counts.columns:
            event_counts[event_type] = 0

    event_counts = event_counts.rename(
        columns={
            "information": "InformationEvents",
            "warning": "WarningEvents",
            "error": "ErrorEvents",
        }
    )

    # Find the source that generated the most events on each machine.
    source_counts = (
        working_logs.groupby(
            ["MachineName", "Source"],
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
        .drop_duplicates(subset=["MachineName"])
        .set_index("MachineName")[["Source", "SourceEventCount"]]
        .rename(
            columns={
                "Source": "MostActiveSource",
                "SourceEventCount": "MostActiveSourceEvents",
            }
        )
    )

    # Count generated alerts for each machine.
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
        total_alerts = (
            alerts.groupby("MachineName")
            .size()
            .rename("TotalAlerts")
        )

        high_alerts = (
            alerts[
                alerts["Severity"].astype(str).str.lower() == "high"
            ]
            .groupby("MachineName")
            .size()
            .rename("HighSeverityAlerts")
        )

        medium_alerts = (
            alerts[
                alerts["Severity"].astype(str).str.lower() == "medium"
            ]
            .groupby("MachineName")
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
            event_counts[
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
        machine_overview[integer_columns].astype(int)
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
    )

    return machine_overview