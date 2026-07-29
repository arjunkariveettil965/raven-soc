from __future__ import annotations

import pandas as pd
import streamlit as st

from backend.services.live_monitoring_service import (
    SUPPORTED_SCENARIOS,
    SUPPORTED_SPEEDS,
    live_monitoring_service,
)


def _pipeline_status_rows(
    *,
    event_count: int,
    alert_count: int,
    incident_count: int,
    has_latest_incident: bool,
) -> list[dict[str, str]]:
    return [
        {"Stage": "Synthetic events generated", "Status": "Completed" if event_count > 0 else "Not Triggered"},
        {"Stage": "Detection engine alerts", "Status": "Completed" if alert_count > 0 else "Not Triggered"},
        {"Stage": "Correlation and classification", "Status": "Completed" if incident_count > 0 else "Not Triggered"},
        {"Stage": "Analyst response", "Status": "Completed" if has_latest_incident else "Not Triggered"},
        {"Stage": "Defender recommendation", "Status": "Completed" if has_latest_incident else "Not Triggered"},
    ]


def _latest_field(payload: dict[str, object] | None, field: str, default: str = "N/A") -> str:
    if payload is None:
        return default
    value = payload.get(field)
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _render_live_panels() -> None:
    status = live_monitoring_service.get_status()
    events = live_monitoring_service.get_events(limit=300)
    alerts = live_monitoring_service.get_alerts(limit=200)
    incidents = live_monitoring_service.get_incidents(limit=100)

    connection_columns = st.columns([1, 2, 2])
    connection_columns[0].metric("Connection", "Connected")
    connection_columns[1].metric("Engine Status", str(status["status"]).capitalize())
    connection_columns[2].metric("Current Scenario", str(status["scenario"]))

    metrics = st.columns(8)
    metrics[0].metric("Events Received", int(status["event_count"]))
    metrics[1].metric("Alerts Created", int(status["alert_count"]))
    metrics[2].metric("Incidents Created", int(status["incident_count"]))
    metrics[3].metric("Current MITRE Tactic", str(status["current_mitre_tactic"] or "N/A"))
    metrics[4].metric("Current Severity", str(status["current_severity"] or "N/A"))
    metrics[5].metric("Playback Speed", f"{status['speed']}x")
    metrics[6].metric("Queue Size", int(status["queue_size"]))
    metrics[7].metric("Last Update", str(status["updated_at"]))

    latest_event = status.get("latest_event")
    latest_alert = status.get("latest_alert")
    latest_incident = status.get("latest_incident")
    latest_cols = st.columns(3)
    latest_cols[0].metric("Latest Event", _latest_field(latest_event if isinstance(latest_event, dict) else None, "description"))
    latest_cols[1].metric("Latest Alert", _latest_field(latest_alert if isinstance(latest_alert, dict) else None, "AlertType"))
    incident_payload = latest_incident["Incident"] if isinstance(latest_incident, dict) and isinstance(latest_incident.get("Incident"), dict) else None
    latest_cols[2].metric("Latest Incident", _latest_field(incident_payload, "IncidentType"))

    st.subheader("Pipeline Status")
    st.dataframe(
        pd.DataFrame(
            _pipeline_status_rows(
                event_count=int(status["event_count"]),
                alert_count=int(status["alert_count"]),
                incident_count=int(status["incident_count"]),
                has_latest_incident=latest_incident is not None,
            )
        ),
        width="stretch",
        hide_index=True,
    )

    event_frame = pd.DataFrame(events)
    if not event_frame.empty and "mitre_tactic" in event_frame.columns:
        st.subheader("MITRE ATT&CK Timeline")
        tactic_counts = (
            event_frame["mitre_tactic"]
            .fillna("Unknown")
            .astype(str)
            .value_counts()
            .rename_axis("MITRE Tactic")
            .reset_index(name="Event Count")
        )
        st.bar_chart(
            tactic_counts,
            x="MITRE Tactic",
            y="Event Count",
            horizontal=False,
            width="stretch",
        )
    else:
        st.subheader("MITRE ATT&CK Timeline")
        st.info("No MITRE timeline data yet.")

    st.subheader("Live Event Table")
    if event_frame.empty:
        st.info("No live events yet.")
    else:
        st.dataframe(event_frame.tail(200), width="stretch", hide_index=True)

    st.subheader("Alert Panel")
    alert_frame = pd.DataFrame(alerts)
    if alert_frame.empty:
        st.info("No alerts yet.")
    else:
        st.dataframe(alert_frame.tail(200), width="stretch", hide_index=True)

    st.subheader("Incident Panel")
    incident_frame = pd.DataFrame(incidents)
    if incident_frame.empty:
        st.info("No incidents yet.")
    else:
        st.dataframe(incident_frame.tail(100), width="stretch", hide_index=True)


st.title("🛰️ Live Monitoring")
st.caption("Isolated synthetic live SOC monitoring with real-time pipeline updates.")

if "live_monitor_page_scenario" not in st.session_state:
    st.session_state["live_monitor_page_scenario"] = "Multi Stage Intrusion"
if "live_monitor_page_speed" not in st.session_state:
    st.session_state["live_monitor_page_speed"] = 1.0

control_columns = st.columns([2, 1, 1, 1, 1, 1])
with control_columns[0]:
    selected_scenario = st.selectbox(
        "Scenario selector",
        list(SUPPORTED_SCENARIOS.keys()),
        key="live_monitor_page_scenario",
    )
with control_columns[1]:
    selected_speed = st.selectbox(
        "Playback speed",
        sorted(SUPPORTED_SPEEDS),
        key="live_monitor_page_speed",
    )
with control_columns[2]:
    if st.button("Start", use_container_width=True):
        live_monitoring_service.start(
            scenario_name=str(selected_scenario),
            speed=float(selected_speed),
        )
with control_columns[3]:
    if st.button("Pause", use_container_width=True):
        live_monitoring_service.pause()
with control_columns[4]:
    if st.button("Resume", use_container_width=True):
        live_monitoring_service.resume(speed=float(selected_speed))
with control_columns[5]:
    if st.button("Reset", use_container_width=True):
        live_monitoring_service.reset()


@st.fragment(run_every=1)
def live_monitor_refresh() -> None:
    _render_live_panels()


live_monitor_refresh()

