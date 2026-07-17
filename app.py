from pathlib import Path

import pandas as pd
import streamlit as st

from detection.rule_engine import detect_event_bursts
from incidents.machine_overview import create_machine_overview
from incidents.machine_ranking import (
    add_machine_inventory,
    add_most_common_event_type,
    calculate_machine_risk,
)
from ingestion.normalizer import normalize_windows_event_logs
from response.response_engine import (
    generate_response_recommendations,
)


st.set_page_config(
    page_title="AI-SOC Platform",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ AI-SOC Platform")
st.subheader("GenAI-Driven Security Operations Platform for SMEs")

st.info(
    "Upload a security log file to normalize, inspect, detect threats, "
    "rank affected devices and generate response recommendations."
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

        st.success(
            "Security log uploaded and normalized successfully."
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
                dropna=True
            ),
        )

        # ---------------------------------------------------------
        # Raw events
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
                    dropna=True
                ).values,
            }
        )

        st.dataframe(
            raw_column_summary,
            width="stretch",
            hide_index=True,
        )

        # ---------------------------------------------------------
        # Normalized events
        # ---------------------------------------------------------
        st.subheader("Normalized Security Events")

        st.caption(
            "Events converted into the common AI-SOC schema. "
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
                dropna=True
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
                            dropna=True
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
                "No repeated medium or high-severity event bursts "
                "were detected."
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

        machine_col1, machine_col2, machine_col3, machine_col4 = (
            st.columns(4)
        )

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
        # Device risk ranking
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

        response_col1, response_col2, response_col3 = (
            st.columns(3)
        )

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
            "Normalization, detection, analysis or response "
            f"error: {error}"
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