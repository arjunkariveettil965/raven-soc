from __future__ import annotations

import pandas as pd


REQUIRED_UEBA_COLUMNS = {
    "EventTime",
    "DeviceName",
    "EventSource",
    "EventSeverity",
    "Country",
}


def split_baseline_and_evaluation_logs(
    normalized_logs: pd.DataFrame,
    baseline_fraction: float = 0.70,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Divide normalized historical logs into two chronological sections.

    The first section is used to learn normal device behaviour.
    The second section is evaluated for anomalies.

    Example:
        baseline_fraction=0.70

        First 70% of events  -> baseline
        Remaining 30%       -> evaluation
    """

    if not 0.50 <= baseline_fraction < 1:
        raise ValueError(
            "baseline_fraction must be between 0.50 and 0.99."
        )

    missing_columns = (
        REQUIRED_UEBA_COLUMNS - set(normalized_logs.columns)
    )

    if missing_columns:
        raise ValueError(
            "Normalized logs are missing UEBA columns: "
            f"{sorted(missing_columns)}"
        )

    working_logs = normalized_logs.copy()

    working_logs["EventTime"] = pd.to_datetime(
        working_logs["EventTime"],
        errors="coerce",
    )

    working_logs = working_logs.dropna(
        subset=[
            "EventTime",
            "DeviceName",
        ]
    )

    working_logs = working_logs.sort_values(
        by="EventTime"
    ).reset_index(drop=True)

    if len(working_logs) < 10:
        raise ValueError(
            "At least 10 valid events are required to create "
            "a UEBA baseline."
        )

    split_position = int(
        len(working_logs) * baseline_fraction
    )

    baseline_logs = working_logs.iloc[
        :split_position
    ].copy()

    evaluation_logs = working_logs.iloc[
        split_position:
    ].copy()

    return baseline_logs, evaluation_logs


def build_device_baseline(
    baseline_logs: pd.DataFrame,
    window_minutes: int = 60,
) -> pd.DataFrame:
    """
    Learn normal behaviour for each device.

    The baseline stores:

    - average events per time window
    - standard deviation of event volume
    - average high-severity events
    - active hours
    - known event sources
    - known countries
    """

    missing_columns = (
        REQUIRED_UEBA_COLUMNS - set(baseline_logs.columns)
    )

    if missing_columns:
        raise ValueError(
            "Baseline logs are missing required columns: "
            f"{sorted(missing_columns)}"
        )

    if window_minutes < 1:
        raise ValueError(
            "window_minutes must be at least 1."
        )

    working_logs = baseline_logs.copy()

    working_logs["EventTime"] = pd.to_datetime(
        working_logs["EventTime"],
        errors="coerce",
    )

    working_logs = working_logs.dropna(
        subset=[
            "EventTime",
            "DeviceName",
        ]
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

    working_logs["EventSeverityNormalized"] = (
        working_logs["EventSeverity"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    working_logs["WindowStart"] = (
        working_logs["EventTime"]
        .dt.floor(f"{window_minutes}min")
    )

    working_logs["EventHour"] = (
        working_logs["EventTime"].dt.hour
    )

    working_logs["IsHighSeverity"] = (
        working_logs["EventSeverityNormalized"]
        == "high"
    ).astype(int)

    hourly_activity = (
        working_logs.groupby(
            [
                "DeviceName",
                "WindowStart",
            ]
        )
        .agg(
            EventCount=(
                "EventTime",
                "size",
            ),
            HighSeverityEventCount=(
                "IsHighSeverity",
                "sum",
            ),
        )
        .reset_index()
    )

    statistical_baseline = (
        hourly_activity.groupby("DeviceName")
        .agg(
            MeanEventsPerWindow=(
                "EventCount",
                "mean",
            ),
            StdEventsPerWindow=(
                "EventCount",
                "std",
            ),
            MeanHighSeverityPerWindow=(
                "HighSeverityEventCount",
                "mean",
            ),
            StdHighSeverityPerWindow=(
                "HighSeverityEventCount",
                "std",
            ),
            BaselineWindows=(
                "WindowStart",
                "count",
            ),
        )
        .reset_index()
    )

    standard_deviation_columns = [
        "StdEventsPerWindow",
        "StdHighSeverityPerWindow",
    ]

    statistical_baseline[
        standard_deviation_columns
    ] = statistical_baseline[
        standard_deviation_columns
    ].fillna(0)

    active_hours = (
        working_logs.groupby("DeviceName")[
            "EventHour"
        ]
        .apply(
            lambda values: tuple(
                sorted(
                    set(
                        int(value)
                        for value in values
                    )
                )
            )
        )
        .rename("KnownActiveHours")
        .reset_index()
    )

    known_sources = (
        working_logs.groupby("DeviceName")[
            "EventSource"
        ]
        .apply(_create_known_value_tuple)
        .rename("KnownEventSources")
        .reset_index()
    )

    known_countries = (
        working_logs.groupby("DeviceName")[
            "Country"
        ]
        .apply(_create_known_value_tuple)
        .rename("KnownCountries")
        .reset_index()
    )

    first_seen = (
        working_logs.groupby("DeviceName")[
            "EventTime"
        ]
        .min()
        .rename("BaselineFirstSeen")
        .reset_index()
    )

    last_seen = (
        working_logs.groupby("DeviceName")[
            "EventTime"
        ]
        .max()
        .rename("BaselineLastSeen")
        .reset_index()
    )

    total_events = (
        working_logs.groupby("DeviceName")
        .size()
        .rename("BaselineTotalEvents")
        .reset_index()
    )

    baseline = statistical_baseline.merge(
        active_hours,
        on="DeviceName",
        how="left",
    )

    baseline = baseline.merge(
        known_sources,
        on="DeviceName",
        how="left",
    )

    baseline = baseline.merge(
        known_countries,
        on="DeviceName",
        how="left",
    )

    baseline = baseline.merge(
        first_seen,
        on="DeviceName",
        how="left",
    )

    baseline = baseline.merge(
        last_seen,
        on="DeviceName",
        how="left",
    )

    baseline = baseline.merge(
        total_events,
        on="DeviceName",
        how="left",
    )

    numeric_columns = [
        "MeanEventsPerWindow",
        "StdEventsPerWindow",
        "MeanHighSeverityPerWindow",
        "StdHighSeverityPerWindow",
    ]

    baseline[numeric_columns] = (
        baseline[numeric_columns].round(2)
    )

    return baseline.sort_values(
        by="DeviceName"
    ).reset_index(drop=True)


def _create_known_value_tuple(
    values: pd.Series,
) -> tuple[str, ...]:
    """
    Convert a column into a clean tuple of known values.
    """

    cleaned_values = set()

    invalid_values = {
        "",
        "nan",
        "none",
        "<na>",
        "null",
    }

    for value in values:
        cleaned_value = str(value).strip()

        if cleaned_value.lower() not in invalid_values:
            cleaned_values.add(cleaned_value)

    return tuple(sorted(cleaned_values))