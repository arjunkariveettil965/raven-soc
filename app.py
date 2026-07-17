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


st.set_page_config(
    page_title="AI-SOC Platform",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ AI-SOC Platform")
st.subheader("Autonomous Security Operations Platform for SMEs")

st.info(
    "Upload a security log file to inspect events and begin threat analysis."
)

uploaded_file = st.file_uploader(
    "Upload a CSV security log",
    type=["csv"],
)

if uploaded_file is not None:
    try:
        logs = pd.read_csv(uploaded_file)

        # Remove an unnecessary CSV index column if present.
        if "Unnamed: 0" in logs.columns:
            logs = logs.drop(columns=["Unnamed: 0"])

        st.success("Security log uploaded successfully.")

        # ---------------------------------------------------------
        # Log overview
        # ---------------------------------------------------------
        st.subheader("Log Overview")

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Total Events",
            len(logs),
        )

        col2.metric(
            "Total Columns",
            len(logs.columns),
        )

        col3.metric(
            "Missing Values",
            int(logs.isnull().sum().sum()),
        )

        # ---------------------------------------------------------
        # Raw security events
        # ---------------------------------------------------------
        st.subheader("Security Events")

        st.dataframe(
            logs,
            width="stretch",
            hide_index=True,
        )

        # ---------------------------------------------------------
        # Column information
        # ---------------------------------------------------------
        st.subheader("Column Information")

        column_summary = pd.DataFrame(
            {
                "Column": logs.columns,
                "Data Type": logs.dtypes.astype(str).values,
                "Missing Values": logs.isnull().sum().values,
                "Unique Values": logs.nunique().values,
            }
        )

        st.dataframe(
            column_summary,
            width="stretch",
            hide_index=True,
        )

        # ---------------------------------------------------------
        # Detection controls
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
        # Source-level alert detection
        # ---------------------------------------------------------
        alerts = detect_event_bursts(
            logs,
            threshold=threshold,
            window_minutes=window_minutes,
        )

        st.subheader("Detected Security Alerts")

        if alerts.empty:
            st.success(
                "No repeated warning or error bursts were detected."
            )

        else:
            alert_col1, alert_col2, alert_col3 = st.columns(3)

            alert_col1.metric(
                "Total Alerts",
                len(alerts),
            )

            alert_col2.metric(
                "High Severity",
                int((alerts["Severity"] == "High").sum()),
            )

            alert_col3.metric(
                "Medium Severity",
                int((alerts["Severity"] == "Medium").sum()),
            )

            st.dataframe(
                alerts,
                width="stretch",
                hide_index=True,
            )

        # ---------------------------------------------------------
        # Machine-level overview
        # ---------------------------------------------------------
        st.subheader("Machine Overview")

        machine_overview = create_machine_overview(
            logs=logs,
            alerts=alerts,
        )

        # Load business-role and criticality information.
        inventory_path = Path("data/machine_inventory.csv")

        if inventory_path.exists():
            machine_inventory = pd.read_csv(inventory_path)

        else:
            machine_inventory = pd.DataFrame(
                columns=[
                    "MachineName",
                    "Role",
                    "Owner",
                    "Criticality",
                ]
            )

            st.warning(
                "machine_inventory.csv was not found. "
                "Unlisted machines will use default values."
            )

        # Add role, owner and criticality.
        machine_overview = add_machine_inventory(
            machine_overview=machine_overview,
            inventory=machine_inventory,
        )

        # Calculate risk and rank machines.
        machine_ranking = calculate_machine_risk(
            machine_overview=machine_overview,
        )

        # Add the most common event type.
        machine_ranking = add_most_common_event_type(
            machine_ranking=machine_ranking,
        )

        machine_col1, machine_col2, machine_col3, machine_col4 = (
            st.columns(4)
        )

        machine_col1.metric(
            "Machines Monitored",
            machine_ranking["MachineName"].nunique(),
        )

        machine_col2.metric(
            "Machines With Alerts",
            int((machine_ranking["TotalAlerts"] > 0).sum()),
        )

        machine_col3.metric(
            "Machines With High Alerts",
            int(
                (
                    machine_ranking["HighSeverityAlerts"] > 0
                ).sum()
            ),
        )

        machine_col4.metric(
            "Critical-Risk Machines",
            int(
                (
                    machine_ranking["OverallRisk"] == "Critical"
                ).sum()
            ),
        )

        # ---------------------------------------------------------
        # Computer activity ranking
        # ---------------------------------------------------------
        st.subheader("Computer Activity and Risk Ranking")

        ranking_columns = [
            "Rank",
            "MachineName",
            "Role",
            "Owner",
            "Criticality",
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
            machine_ranking[available_ranking_columns],
            width="stretch",
            hide_index=True,
        )

        # ---------------------------------------------------------
        # Beginner-friendly machine inspection
        # ---------------------------------------------------------
        st.subheader("Inspect a Machine")

        selected_machine = st.selectbox(
            "Select a computer to inspect",
            options=machine_ranking["MachineName"].tolist(),
        )

        selected_machine_summary = machine_ranking[
            machine_ranking["MachineName"] == selected_machine
        ]

        st.dataframe(
            selected_machine_summary[available_ranking_columns],
            width="stretch",
            hide_index=True,
        )

        selected_machine_alerts = alerts[
            alerts["MachineName"] == selected_machine
        ]

        st.markdown("#### Alerts for Selected Machine")

        if selected_machine_alerts.empty:
            st.info(
                "No source-level alerts were generated for this machine."
            )

        else:
            st.dataframe(
                selected_machine_alerts,
                width="stretch",
                hide_index=True,
            )

    except ValueError as error:
        st.error(
            f"Detection or analysis error: {error}"
        )

    except pd.errors.EmptyDataError:
        st.error(
            "The uploaded CSV file is empty."
        )

    except pd.errors.ParserError:
        st.error(
            "The uploaded file could not be parsed as a valid CSV."
        )

    except FileNotFoundError as error:
        st.error(
            f"A required project file could not be found: {error}"
        )

    except Exception as error:
        st.error(
            f"Unable to process the uploaded file: {error}"
        )

else:
    st.warning(
        "No security log has been uploaded yet."
    )