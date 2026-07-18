from __future__ import annotations

import pandas as pd


REQUIRED_LOG_COLUMNS = {
    "EventTime",
    "DeviceName",
    "EventSource",
    "EventSeverity",
    "Country",
}

REQUIRED_BASELINE_COLUMNS = {
    "DeviceName",
    "MeanEventsPerWindow",
    "StdEventsPerWindow",
    "MeanHighSeverityPerWindow",
    "StdHighSeverityPerWindow",
    "KnownActiveHours",
    "KnownEventSources",
    "KnownCountries",
}


def detect_device_anomalies(
    evaluation_logs: pd.DataFrame,
    device_baseline: pd.DataFrame,
    window_minutes: int = 60,
    standard_deviation_multiplier: float = 3.0,
) -> pd.DataFrame:
    """
    Compare current device activity against the learned baseline.

    Detected UEBA anomaly types:

    - New Device
    - Unusual Event Volume
    - High-Severity Event Spike
    - Unusual Activity Time
    - New Event Source
    - New Country
    """

    missing_log_columns = (
        REQUIRED_LOG_COLUMNS - set(evaluation_logs.columns)
    )

    if missing_log_columns:
        raise ValueError(
            "Evaluation logs are missing UEBA columns: "
            f"{sorted(missing_log_columns)}"
        )

    missing_baseline_columns = (
        REQUIRED_BASELINE_COLUMNS
        - set(device_baseline.columns)
    )

    if missing_baseline_columns:
        raise ValueError(
            "Device baseline is missing required columns: "
            f"{sorted(missing_baseline_columns)}"
        )

    if window_minutes < 1:
        raise ValueError(
            "window_minutes must be at least 1."
        )

    if standard_deviation_multiplier <= 0:
        raise ValueError(
            "standard_deviation_multiplier must be greater than 0."
        )

    working_logs = evaluation_logs.copy()

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

    working_logs["IsHighSeverity"] = (
        working_logs["EventSeverityNormalized"]
        == "high"
    ).astype(int)

    baseline_lookup = device_baseline.set_index(
        "DeviceName"
    )

    anomaly_records = []

    grouped_windows = working_logs.groupby(
        [
            "DeviceName",
            "WindowStart",
        ]
    )

    for (
        device_name,
        window_start,
    ), window_logs in grouped_windows:

        event_count = len(window_logs)

        high_severity_count = int(
            window_logs["IsHighSeverity"].sum()
        )

        current_sources = _clean_values(
            window_logs["EventSource"]
        )

        current_countries = _clean_values(
            window_logs["Country"]
        )

        anomaly_types = []
        evidence = []
        anomaly_score = 0

        baseline_mean_events = 0.0
        baseline_std_events = 0.0
        baseline_mean_high = 0.0
        baseline_std_high = 0.0

        if device_name not in baseline_lookup.index:
            anomaly_types.append("New Device")

            evidence.append(
                f"{device_name} did not appear in the learned baseline."
            )

            anomaly_score += 40

        else:
            baseline_row = baseline_lookup.loc[
                device_name
            ]

            baseline_mean_events = float(
                baseline_row["MeanEventsPerWindow"]
            )

            baseline_std_events = float(
                baseline_row["StdEventsPerWindow"]
            )

            baseline_mean_high = float(
                baseline_row[
                    "MeanHighSeverityPerWindow"
                ]
            )

            baseline_std_high = float(
                baseline_row[
                    "StdHighSeverityPerWindow"
                ]
            )

            known_hours = set(
                baseline_row["KnownActiveHours"]
            )

            known_sources = set(
                baseline_row["KnownEventSources"]
            )

            known_countries = set(
                baseline_row["KnownCountries"]
            )

            volume_threshold = max(
                baseline_mean_events
                + (
                    standard_deviation_multiplier
                    * baseline_std_events
                ),
                baseline_mean_events * 2,
                10,
            )

            if event_count > volume_threshold:
                anomaly_types.append(
                    "Unusual Event Volume"
                )

                evidence.append(
                    f"{event_count} events were observed; "
                    f"the expected level was approximately "
                    f"{baseline_mean_events:.2f}."
                )

                anomaly_score += 30

            high_severity_threshold = max(
                baseline_mean_high
                + (
                    standard_deviation_multiplier
                    * baseline_std_high
                ),
                baseline_mean_high * 2,
                3,
            )

            if (
                high_severity_count
                > high_severity_threshold
            ):
                anomaly_types.append(
                    "High-Severity Event Spike"
                )

                evidence.append(
                    f"{high_severity_count} high-severity events "
                    f"were observed; the expected level was "
                    f"approximately {baseline_mean_high:.2f}."
                )

                anomaly_score += 35

            current_hour = int(window_start.hour)

            if (
                known_hours
                and current_hour not in known_hours
            ):
                anomaly_types.append(
                    "Unusual Activity Time"
                )

                evidence.append(
                    f"Activity occurred at hour {current_hour}, "
                    f"which was not present in the device baseline."
                )

                anomaly_score += 15

            new_sources = (
                current_sources - known_sources
            )

            if new_sources:
                anomaly_types.append(
                    "New Event Source"
                )

                evidence.append(
                    "Previously unseen event sources: "
                    + ", ".join(sorted(new_sources))
                )

                anomaly_score += min(
                    25,
                    10 + len(new_sources) * 5,
                )

            new_countries = (
                current_countries - known_countries
            )

            if new_countries:
                anomaly_types.append(
                    "New Country"
                )

                evidence.append(
                    "Previously unseen countries: "
                    + ", ".join(sorted(new_countries))
                )

                anomaly_score += min(
                    30,
                    15 + len(new_countries) * 5,
                )

        anomaly_score = min(
            anomaly_score,
            100,
        )

        if anomaly_score == 0:
            continue

        anomaly_records.append(
            {
                "DeviceName": device_name,
                "WindowStart": window_start,
                "WindowEnd": (
                    window_start
                    + pd.Timedelta(
                        minutes=window_minutes
                    )
                ),
                "EventCount": event_count,
                "HighSeverityEventCount": (
                    high_severity_count
                ),
                "AnomalyTypes": " | ".join(
                    anomaly_types
                ),
                "Evidence": " ".join(evidence),
                "AnomalyScore": anomaly_score,
                "AnomalySeverity": (
                    assign_anomaly_severity(
                        anomaly_score
                    )
                ),
                "BaselineMeanEvents": (
                    round(
                        baseline_mean_events,
                        2,
                    )
                ),
                "BaselineStdEvents": (
                    round(
                        baseline_std_events,
                        2,
                    )
                ),
                "BaselineMeanHighSeverity": (
                    round(
                        baseline_mean_high,
                        2,
                    )
                ),
            }
        )

    anomaly_columns = [
        "DeviceName",
        "WindowStart",
        "WindowEnd",
        "EventCount",
        "HighSeverityEventCount",
        "AnomalyTypes",
        "Evidence",
        "AnomalyScore",
        "AnomalySeverity",
        "BaselineMeanEvents",
        "BaselineStdEvents",
        "BaselineMeanHighSeverity",
    ]

    if not anomaly_records:
        return pd.DataFrame(
            columns=anomaly_columns
        )

    anomalies = pd.DataFrame(
        anomaly_records
    )

    return anomalies.sort_values(
        by=[
            "AnomalyScore",
            "WindowStart",
        ],
        ascending=[
            False,
            False,
        ],
    ).reset_index(drop=True)


def assign_anomaly_severity(
    anomaly_score: int,
) -> str:
    """
    Convert the numerical anomaly score into a severity level.
    """

    if anomaly_score >= 75:
        return "Critical"

    if anomaly_score >= 50:
        return "High"

    if anomaly_score >= 25:
        return "Medium"

    return "Low"


def _clean_values(
    values: pd.Series,
) -> set[str]:
    """
    Remove null-like values and return clean unique values.
    """

    invalid_values = {
        "",
        "nan",
        "none",
        "<na>",
        "null",
    }

    cleaned_values = set()

    for value in values:
        cleaned_value = str(value).strip()

        if cleaned_value.lower() not in invalid_values:
            cleaned_values.add(cleaned_value)

    return cleaned_values