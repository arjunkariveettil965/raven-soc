from pathlib import Path

import pandas as pd
import streamlit as st

from database.database import (
    count_security_events,
    initialize_database,
    load_security_events,
    save_security_events,
)
from detection.rule_engine import detect_event_bursts
from incidents.machine_overview import create_machine_overview
from incidents.machine_ranking import (
    add_machine_inventory,
    add_most_common_event_type,
    add_ueba_summary,
    calculate_machine_risk,
    summarize_ueba_anomalies,
)
from ingestion.normalizer import normalize_windows_event_logs
from response.response_engine import (
    generate_response_recommendations,
)
from ueba.anomaly_engine import detect_device_anomalies
from ueba.baseline_engine import (
    build_device_baseline,
    split_baseline_and_evaluation_logs,
)



def format_hour(hour: int) -> str:
    """
    Convert a 24-hour integer into a readable 12-hour format.

    Examples:
    0  -> 12 AM
    6  -> 6 AM
    13 -> 1 PM
    17 -> 5 PM
    """

    hour = int(hour)

    if hour == 0:
        return "12 AM"

    if hour < 12:
        return f"{hour} AM"

    if hour == 12:
        return "12 PM"

    return f"{hour - 12} PM"


st.set_page_config(
    page_title="RAVEN-SOC",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ RAVEN-SOC")
st.subheader(
    "Real-Time AI Vigilance, Event Normalization "
    "and Security Operations Center"
)

st.info(
    "Upload a security log file to normalize events, detect threats, "
    "learn device behaviour, identify anomalies, rank affected devices "
    "and generate response recommendations."
)

initialize_database()

if "stored_security_events" not in st.session_state:
    st.session_state["stored_security_events"] = pd.DataFrame()

recent_event_limit = st.number_input(
    "Number of recent stored events to load",
    min_value=1,
    max_value=1000,
    value=100,
    step=50,
)

st.subheader("Security Event Database")

st.metric(
    "Stored Security Events",
    count_security_events(),
)

if st.button("Load Recent Stored Events"):
    try:
        stored_events = load_security_events(
            limit=recent_event_limit,
        )

        st.session_state["stored_security_events"] = stored_events

    except Exception as error:
        st.error(
            f"Unable to load stored events: {error}"
        )

if "stored_security_events" in st.session_state:
    stored_events = st.session_state["stored_security_events"]

    if not stored_events.empty:
        st.subheader("Recent Stored Events")
        st.dataframe(
            stored_events,
            use_container_width=True,
        )

    else:
        st.info(
            "No stored events have been loaded yet."
        )

uploaded_file = st.file_uploader(
    "Upload a CSV security log",
    type=["csv"],
)

if uploaded_file is not None:
    try:
        # ---------------------------------------------------------
        # Load and clean raw logs
        # ---------------------------------------------------------
        logs = pd.read_csv(uploaded_file)

        if "Unnamed: 0" in logs.columns:
            logs = logs.drop(columns=["Unnamed: 0"])

        if logs.empty:
            raise pd.errors.EmptyDataError

        # ---------------------------------------------------------
        # Normalize logs
        # ---------------------------------------------------------
        normalized_logs = normalize_windows_event_logs(logs)

        st.caption(
            "Save the normalized events from the current upload "
            "to the database."
        )

        if st.button(
            "Save Normalized Events to Database",
            type="primary",
        ):
            try:
                save_result = save_security_events(
                    normalized_logs=normalized_logs,
                )

                updated_total = count_security_events()

                st.success(
                    "Received "
                    f"{save_result['received']:,} events. "
                    f"Inserted {save_result['inserted']:,}. "
                    f"Duplicates skipped {save_result['duplicates_skipped']:,}. "
                    f"Database total {updated_total:,}."
                )

                st.rerun()

            except Exception as error:
                st.error(
                    f"Unable to save events: {error}"
                )

        # ---------------------------------------------------------
        # UEBA baseline and anomaly processing
        # ---------------------------------------------------------
        baseline_logs, evaluation_logs = (
            split_baseline_and_evaluation_logs(
                normalized_logs=normalized_logs,
                baseline_fraction=0.70,
            )
        )

        device_baseline = build_device_baseline(
            baseline_logs=baseline_logs,
            window_minutes=60,
        )

        ueba_anomalies = detect_device_anomalies(
            evaluation_logs=evaluation_logs,
            device_baseline=device_baseline,
            window_minutes=60,
            standard_deviation_multiplier=3.0,
        )

        st.success(
            "Security log uploaded, normalized and analysed successfully."
        )

        # ---------------------------------------------------------
        # Log overview
        # ---------------------------------------------------------
        st.subheader("Log Overview")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Total Events",
            len(logs),
        )

        col2.metric(
            "Raw Columns",
            len(logs.columns),
        )

        col3.metric(
            "Normalized Columns",
            len(normalized_logs.columns),
        )

        col4.metric(
            "Devices Identified",
            normalized_logs["DeviceName"].nunique(
                dropna=True,
            ),
        )

        # ---------------------------------------------------------
        # Raw security events
        # ---------------------------------------------------------
        st.subheader("Raw Security Events")

        st.caption(
            "Original events as received from the uploaded dataset."
        )

        st.dataframe(
            logs,
            width="stretch",
            hide_index=True,
        )

        # ---------------------------------------------------------
        # Raw column information
        # ---------------------------------------------------------
        st.subheader("Raw Column Information")

        raw_column_summary = pd.DataFrame(
            {
                "Column": logs.columns,
                "Data Type": logs.dtypes.astype(str).values,
                "Missing Values": logs.isnull().sum().values,
                "Unique Values": logs.nunique(
                    dropna=True,
                ).values,
            }
        )

        st.dataframe(
            raw_column_summary,
            width="stretch",
            hide_index=True,
        )

        # ---------------------------------------------------------
        # Normalized security events
        # ---------------------------------------------------------
        st.subheader("Normalized Security Events")

        st.caption(
            "Events converted into the common RAVEN-SOC schema. "
            "Unavailable source fields remain empty."
        )

        normalized_col1, normalized_col2, normalized_col3 = (
            st.columns(3)
        )

        normalized_col1.metric(
            "Normalized Events",
            len(normalized_logs),
        )

        normalized_col2.metric(
            "Events With Valid Time",
            int(
                normalized_logs["EventTime"]
                .notna()
                .sum()
            ),
        )

        normalized_col3.metric(
            "Event Sources",
            normalized_logs["EventSource"].nunique(
                dropna=True,
            ),
        )

        st.dataframe(
            normalized_logs,
            width="stretch",
            hide_index=True,
        )

        with st.expander("View Normalized Schema Details"):
            normalized_summary = pd.DataFrame(
                {
                    "Normalized Field": normalized_logs.columns,
                    "Data Type": (
                        normalized_logs.dtypes
                        .astype(str)
                        .values
                    ),
                    "Missing Values": (
                        normalized_logs.isnull()
                        .sum()
                        .values
                    ),
                    "Unique Values": (
                        normalized_logs.nunique(
                            dropna=True,
                        ).values
                    ),
                }
            )

            st.dataframe(
                normalized_summary,
                width="stretch",
                hide_index=True,
            )

        # ---------------------------------------------------------
        # UEBA analytics
        # ---------------------------------------------------------
        st.subheader("UEBA Analytics")

        st.caption(
            "The first 70% of events are used to learn normal "
            "device behaviour. The remaining 30% are evaluated "
            "for behavioural anomalies."
        )

        (
            ueba_col1,
            ueba_col2,
            ueba_col3,
            ueba_col4,
            ueba_col5,
        ) = st.columns(5)

        ueba_col1.metric(
            "Baseline Events",
            len(baseline_logs),
        )

        ueba_col2.metric(
            "Evaluation Events",
            len(evaluation_logs),
        )

        ueba_col3.metric(
            "Devices Baselined",
            device_baseline["DeviceName"].nunique(),
        )

        ueba_col4.metric(
            "Detected Anomalies",
            len(ueba_anomalies),
        )

        critical_anomalies = 0

        if not ueba_anomalies.empty:
            critical_anomalies = int(
                (
                    ueba_anomalies["AnomalySeverity"]
                    == "Critical"
                ).sum()
            )

        ueba_col5.metric(
            "Critical Anomalies",
            critical_anomalies,
        )

        display_device_baseline = device_baseline.copy()

        display_device_baseline["KnownActiveHours"] = (
            display_device_baseline["KnownActiveHours"].apply(
                lambda hours: tuple(
                    format_hour(hour)
                    for hour in hours
                )
            )
        )

        with st.expander("View Learned Device Baselines"):
            st.dataframe(
                display_device_baseline,
                width="stretch",
                hide_index=True,
            )

        st.markdown("#### Detected Behavioural Anomalies")

        if ueba_anomalies.empty:
            st.success(
                "No behavioural anomalies were detected "
                "in the evaluation period."
            )

        else:
            anomaly_columns = [
                "DeviceName",
                "WindowStart",
                "WindowEnd",
                "EventCount",
                "HighSeverityEventCount",
                "AnomalyTypes",
                "AnomalyScore",
                "AnomalySeverity",
                "Evidence",
                "BaselineMeanEvents",
                "BaselineStdEvents",
                "BaselineMeanHighSeverity",
            ]

            available_anomaly_columns = [
                column
                for column in anomaly_columns
                if column in ueba_anomalies.columns
            ]

            st.dataframe(
                ueba_anomalies[
                    available_anomaly_columns
                ],
                width="stretch",
                hide_index=True,
            )

        # ---------------------------------------------------------
        # Detection settings
        # ---------------------------------------------------------
        st.subheader("Detection Settings")

        settings_col1, settings_col2 = st.columns(2)

        with settings_col1:
            threshold = st.slider(
                "Minimum events required to generate an alert",
                min_value=2,
                max_value=50,
                value=5,
            )

        with settings_col2:
            window_minutes = st.slider(
                "Detection time window in minutes",
                min_value=1,
                max_value=60,
                value=10,
            )

        # ---------------------------------------------------------
        # Detection using normalized logs
        # ---------------------------------------------------------
        alerts = detect_event_bursts(
            normalized_logs,
            threshold=threshold,
            window_minutes=window_minutes,
        )

        st.subheader("Detected Security Alerts")

        if alerts.empty:
            st.success(
                "No repeated medium or high-severity event "
                "bursts were detected."
            )

        else:
            alert_col1, alert_col2, alert_col3 = st.columns(3)

            alert_col1.metric(
                "Total Alerts",
                len(alerts),
            )

            alert_col2.metric(
                "High Severity",
                int(
                    (
                        alerts["Severity"] == "High"
                    ).sum()
                ),
            )

            alert_col3.metric(
                "Medium Severity",
                int(
                    (
                        alerts["Severity"] == "Medium"
                    ).sum()
                ),
            )

            st.dataframe(
                alerts,
                width="stretch",
                hide_index=True,
            )

        # ---------------------------------------------------------
        # Device overview
        # ---------------------------------------------------------
        st.subheader("Device Overview")

        machine_overview = create_machine_overview(
            logs=normalized_logs,
            alerts=alerts,
        )

        inventory_path = Path(
            "data/machine_inventory.csv"
        )

        if inventory_path.exists():
            machine_inventory = pd.read_csv(
                inventory_path
            )

        else:
            machine_inventory = pd.DataFrame(
                columns=[
                    "DeviceName",
                    "DeviceRole",
                    "DeviceOwner",
                    "DeviceCriticality",
                ]
            )

            st.warning(
                "machine_inventory.csv was not found. "
                "Devices will use default inventory values."
            )

        machine_overview = add_machine_inventory(
            machine_overview=machine_overview,
            inventory=machine_inventory,
        )

        ueba_summary = summarize_ueba_anomalies(
            ueba_anomalies=ueba_anomalies,
        )

        machine_overview = add_ueba_summary(
            machine_overview=machine_overview,
            ueba_summary=ueba_summary,
        )

        machine_ranking = calculate_machine_risk(
            machine_overview=machine_overview,
        )

        machine_ranking = add_most_common_event_type(
            machine_ranking=machine_ranking,
        )

        response_recommendations = (
            generate_response_recommendations(
                machine_ranking=machine_ranking,
            )
        )

        (
            machine_col1,
            machine_col2,
            machine_col3,
            machine_col4,
        ) = st.columns(4)

        machine_col1.metric(
            "Devices Monitored",
            machine_ranking["DeviceName"].nunique(),
        )

        machine_col2.metric(
            "Devices With Alerts",
            int(
                (
                    machine_ranking["TotalAlerts"] > 0
                ).sum()
            ),
        )

        machine_col3.metric(
            "Devices With High Alerts",
            int(
                (
                    machine_ranking[
                        "HighSeverityAlerts"
                    ]
                    > 0
                ).sum()
            ),
        )

        machine_col4.metric(
            "Critical-Risk Devices",
            int(
                (
                    machine_ranking["OverallRisk"]
                    == "Critical"
                ).sum()
            ),
        )

        # ---------------------------------------------------------
        # Device activity and risk ranking
        # ---------------------------------------------------------
        st.subheader("Device Activity and Risk Ranking")

        ranking_columns = [
            "Rank",
            "DeviceName",
            "DeviceRole",
            "DeviceOwner",
            "DeviceCriticality",
            "TotalEvents",
            "InformationEvents",
            "WarningEvents",
            "ErrorEvents",
            "MostCommonEventType",
            "MostActiveSource",
            "MostActiveSourceEvents",
            "TotalAlerts",
            "MediumSeverityAlerts",
            "HighSeverityAlerts",
            "TotalUEBAAnomalies",
            "CriticalUEBAAnomalies",
            "MaximumAnomalyScore",
            "UEBARiskContribution",
            "RiskScore",
            "OverallRisk",
        ]

        available_ranking_columns = [
            column
            for column in ranking_columns
            if column in machine_ranking.columns
        ]

        st.dataframe(
            machine_ranking[
                available_ranking_columns
            ],
            width="stretch",
            hide_index=True,
        )

        # ---------------------------------------------------------
        # Response recommendations
        # ---------------------------------------------------------
        st.subheader("Response Recommendations")

        (
            response_col1,
            response_col2,
            response_col3,
        ) = st.columns(3)

        response_col1.metric(
            "Automatic Isolation Decisions",
            int(
                (
                    response_recommendations[
                        "ResponseMode"
                    ]
                    == "Automatic Isolation"
                ).sum()
            ),
        )

        response_col2.metric(
            "Pending Analyst Approval",
            int(
                (
                    response_recommendations[
                        "ResponseMode"
                    ]
                    == "Analyst Approval Required"
                ).sum()
            ),
        )

        response_col3.metric(
            "Simulated Isolated Devices",
            int(
                (
                    response_recommendations[
                        "IsolationStatus"
                    ]
                    == "Simulated Isolated"
                ).sum()
            ),
        )

        response_columns = [
            "DeviceName",
            "DeviceRole",
            "DeviceOwner",
            "DeviceCriticality",
            "OverallRisk",
            "HighSeverityAlerts",
            "MediumSeverityAlerts",
            "RecommendedAction",
            "ResponseMode",
            "IsolationStatus",
        ]

        available_response_columns = [
            column
            for column in response_columns
            if column in response_recommendations.columns
        ]

        st.dataframe(
            response_recommendations[
                available_response_columns
            ],
            width="stretch",
            hide_index=True,
        )

        # ---------------------------------------------------------
        # Device inspection
        # ---------------------------------------------------------
        st.subheader("Inspect a Device")

        selected_device = st.selectbox(
            "Select a device to inspect",
            options=machine_ranking[
                "DeviceName"
            ].tolist(),
        )

        selected_device_summary = machine_ranking[
            machine_ranking["DeviceName"]
            == selected_device
        ]

        st.markdown("#### Device Summary")

        st.dataframe(
            selected_device_summary[
                available_ranking_columns
            ],
            width="stretch",
            hide_index=True,
        )

        selected_device_alerts = alerts[
            alerts["DeviceName"] == selected_device
        ]

        st.markdown("#### Alerts for Selected Device")

        if selected_device_alerts.empty:
            st.info(
                "No source-level alerts were generated "
                "for this device."
            )

        else:
            st.dataframe(
                selected_device_alerts,
                width="stretch",
                hide_index=True,
            )

        selected_device_anomalies = ueba_anomalies[
            ueba_anomalies["DeviceName"]
            == selected_device
        ]

        st.markdown("#### UEBA Anomalies for Selected Device")

        if selected_device_anomalies.empty:
            st.info(
                "No behavioural anomalies were detected "
                "for this device."
            )

        else:
            st.dataframe(
                selected_device_anomalies,
                width="stretch",
                hide_index=True,
            )

        selected_device_response = (
            response_recommendations[
                response_recommendations["DeviceName"]
                == selected_device
            ]
        )

        st.markdown("#### Response Recommendation")

        st.dataframe(
            selected_device_response[
                available_response_columns
            ],
            width="stretch",
            hide_index=True,
        )

        selected_normalized_events = normalized_logs[
            normalized_logs["DeviceName"]
            == selected_device
        ]

        st.markdown(
            "#### Normalized Events for Selected Device"
        )

        if selected_normalized_events.empty:
            st.info(
                "No normalized events were found "
                "for this device."
            )

        else:
            st.dataframe(
                selected_normalized_events,
                width="stretch",
                hide_index=True,
            )

    except ValueError as error:
        st.error(
            "Normalization, detection, UEBA, analysis or "
            f"response error: {error}"
        )

    except pd.errors.EmptyDataError:
        st.error(
            "The uploaded CSV file is empty."
        )

    except pd.errors.ParserError:
        st.error(
            "The uploaded file could not be parsed "
            "as a valid CSV."
        )

    except FileNotFoundError as error:
        st.error(
            "A required project file could not be found: "
            f"{error}"
        )

    except Exception as error:
        st.error(
            f"Unable to process the uploaded file: {error}"
        )

else:
    st.warning(
        "No security log has been uploaded yet."
    )