from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from dashboard.incident_demo import (
    run_synthetic_defender_response,
    run_synthetic_incident_pipeline,
)
from ai_analyst.ollama_client import DEFAULT_OLLAMA_MODEL, DEFAULT_OLLAMA_URL, check_ollama_health
from database.database import (
    count_security_events,
    initialize_database,
    load_security_events,
    save_security_events,
)
from collector.live_pipeline import (
    initialize_missing_checkpoints_at_current_position,
    reset_channels_to_current_position,
    run_live_collection,
    run_monitoring_cycle,
)
from collector.monitoring_state import (
    alert_notification_message,
    validate_poll_interval,
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


def streamlit_fragment(*, run_every: int | None):
    return st.fragment(run_every=run_every)


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

for state_key, default_value in {
    "synthetic_pipeline_result": None,
    "synthetic_defender_response": None,
    "synthetic_action_approved": False,
    "synthetic_action_rejected": False,
    "live_collection_result": None,
    "live_collection_channels": ["System", "Application"],
    "live_collection_limit": 100,
    "live_monitoring_enabled": False,
    "live_monitoring_active_interval": 15,
    "live_monitoring_seen_alert_ids": set(),
    "live_monitoring_last_result": None,
    "live_monitoring_cycle_count": 0,
    "live_monitoring_last_error": None,
    "live_monitoring_start_from_current": True,
    "live_monitoring_setup_status": {},
    "live_checkpoint_reset_result": None,
}.items():
    if state_key not in st.session_state:
        st.session_state[state_key] = default_value

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


# =============================================================
# Live Windows Event Log ingestion
# =============================================================
st.divider()
st.header("Live Windows Event Ingestion")
st.caption(
    "Read new local Windows Event Log records, normalize them and persist them to the RAVEN-SOC database."
)

live_channels = st.multiselect(
    "Windows log channels",
    ["System", "Application", "Security"],
    default=["System", "Application"],
    key="live_collection_channels",
)

live_limit = st.number_input(
    "Maximum new events per channel",
    min_value=1,
    max_value=1000,
    value=100,
    step=50,
    key="live_collection_limit",
)

selected_monitoring_interval = st.number_input(
    "Automatic polling interval in seconds",
    min_value=5,
    max_value=300,
    value=15,
    step=5,
    key="live_monitoring_interval",
)

live_start_from_current = st.checkbox(
    "Start from current log position",
    value=True,
    key="live_monitoring_start_from_current",
)

control_columns = st.columns(4)

if st.button("Collect New Windows Events"):
    if not live_channels:
        st.warning("Select at least one Windows log channel.")
    else:
        try:
            with st.spinner("Collecting new local Windows Event Log records..."):
                st.session_state["live_collection_result"] = run_live_collection(
                    channels=list(live_channels),
                    max_events_per_channel=int(live_limit),
                )
            st.success("Live collection completed.")
        except Exception as error:
            st.session_state["live_collection_result"] = None
            st.error(f"Unable to collect Windows events: {error}")

with control_columns[0]:
    if st.button("Start Automatic Monitoring"):
        if not live_channels:
            st.warning("Select at least one Windows log channel.")
        else:
            try:
                st.session_state["live_monitoring_active_interval"] = (
                    validate_poll_interval(selected_monitoring_interval)
                )
                if live_start_from_current:
                    st.session_state["live_monitoring_setup_status"] = (
                        initialize_missing_checkpoints_at_current_position(
                            channels=list(live_channels),
                        )
                    )
                st.session_state["live_monitoring_enabled"] = True
                st.session_state["live_monitoring_last_error"] = None
            except Exception as error:
                st.session_state["live_monitoring_enabled"] = False
                st.session_state["live_monitoring_last_error"] = str(error)
                st.error(f"Unable to start automatic monitoring: {error}")

with control_columns[1]:
    if st.button("Stop Automatic Monitoring"):
        st.session_state["live_monitoring_enabled"] = False

with control_columns[2]:
    if st.button("Reset Selected Channels to Current Position"):
        if not live_channels:
            st.warning("Select at least one Windows log channel.")
        else:
            st.session_state["live_monitoring_enabled"] = False
            reset_result = reset_channels_to_current_position(
                channels=list(live_channels),
            )
            st.session_state["live_checkpoint_reset_result"] = reset_result

            if reset_result["reset_count"] > 0:
                st.session_state["live_collection_result"] = None
                reset_channels = [
                    channel
                    for channel, result in reset_result["channel_results"].items()
                    if result["reset"]
                ]
                st.success(
                    f"{' and '.join(reset_channels)} checkpoints were moved to the current log position. Future collections will include only newer records."
                )

            for reset_error in reset_result["errors"]:
                if "Security log access was denied" in reset_error:
                    st.warning(
                        "Security log access was denied. Run VS Code as Administrator only when testing that channel, or continue using System and Application logs."
                    )
                else:
                    st.error(reset_error)

with control_columns[3]:
    if st.session_state["live_monitoring_enabled"]:
        st.success("Automatic monitoring is active.")
    else:
        st.info("Automatic monitoring is stopped.")

st.caption(
    "Resetting checkpoints does not delete historical events already stored in SQLite. It only changes where future Windows log collection resumes."
)


def show_checkpoint_reset_result() -> None:
    reset_result = st.session_state.get("live_checkpoint_reset_result")
    if reset_result is None:
        return

    reset_status = pd.DataFrame(
        reset_result.get("channel_results", {}).values()
    )
    if reset_status.empty:
        return

    st.subheader("Checkpoint Reset Result")
    st.dataframe(
        reset_status[
            [
                "channel",
                "previous_checkpoint",
                "new_checkpoint",
                "reset",
                "error",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )


def show_live_result(live_result: dict[str, object] | None) -> None:
    show_checkpoint_reset_result()

    if live_result is None:
        st.info("No live collection result is available yet.")
        return

    if live_result.get("errors"):
        for live_error in live_result["errors"]:
            if "Security log access was denied" in live_error:
                st.warning(
                    "Security log access was denied. Run VS Code as Administrator only when testing that channel, or continue using System and Application logs."
                )
            else:
                st.error(live_error)

    new_alerts = live_result.get("new_alerts", pd.DataFrame())
    if isinstance(new_alerts, pd.DataFrame) and not new_alerts.empty:
        st.subheader("Latest Unseen Alerts")
        for _, alert in new_alerts.iterrows():
            severity = str(
                alert.get("AlertSeverity", alert.get("Severity", "Info"))
            ).strip().lower()
            message = alert_notification_message(alert)
            if severity == "critical":
                st.error(message)
            elif severity in {"high", "medium"}:
                st.warning(message)
            else:
                st.info(message)
        st.dataframe(
            new_alerts,
            use_container_width=True,
            hide_index=True,
        )

    live_metric_columns = st.columns(8)
    live_metric_columns[0].metric(
        "Monitoring Status",
        "Active" if st.session_state["live_monitoring_enabled"] else "Stopped",
    )
    live_metric_columns[1].metric(
        "Polling Interval",
        (
            f"{int(st.session_state['live_monitoring_active_interval'])}s active"
            if st.session_state["live_monitoring_enabled"]
            else f"{int(st.session_state['live_monitoring_interval'])}s configured"
        ),
    )
    live_metric_columns[2].metric(
        "Completed Cycles",
        int(st.session_state["live_monitoring_cycle_count"]),
    )
    live_metric_columns[3].metric(
        "New Raw Events",
        int(live_result.get("received", 0)),
    )
    live_metric_columns[4].metric(
        "New Alerts",
        int(live_result.get("new_alert_count", len(live_result.get("alerts", [])))),
    )
    live_metric_columns[5].metric(
        "Inserted",
        int(live_result.get("inserted", 0)),
    )
    live_metric_columns[6].metric(
        "Duplicates Skipped",
        int(live_result.get("duplicates_skipped", 0)),
    )
    live_metric_columns[7].metric(
        "Database Total",
        int(live_result.get("database_total", 0)),
    )

    st.caption(
        f"Last Collection Time: {live_result.get('last_collection_time', 'N/A')}"
    )
    st.caption(
        f"Last Error: {st.session_state['live_monitoring_last_error'] or 'None'}"
    )

    setup_status = pd.DataFrame(
        st.session_state.get("live_monitoring_setup_status", {}).values()
    )
    if not setup_status.empty:
        st.subheader("Automatic Monitoring Setup")
        st.dataframe(
            setup_status,
            use_container_width=True,
            hide_index=True,
        )

    channel_status = pd.DataFrame(
        live_result.get("channel_results", {}).values()
    )
    if not channel_status.empty:
        st.subheader("Channel Checkpoints")
        st.dataframe(
            channel_status,
            use_container_width=True,
            hide_index=True,
        )

    raw_live_events = live_result.get("raw_events", pd.DataFrame())
    st.subheader("Recent Collected Raw Events")
    if raw_live_events.empty:
        st.info("No new raw events were collected.")
    else:
        st.dataframe(
            raw_live_events.tail(100),
            use_container_width=True,
            hide_index=True,
        )

    normalized_live_events = live_result.get(
        "normalized_events",
        pd.DataFrame(),
    )
    st.subheader("Normalized Live Events")
    if normalized_live_events.empty:
        st.info("No live events were normalized.")
    else:
        st.dataframe(
            normalized_live_events,
            use_container_width=True,
            hide_index=True,
        )

    live_alerts = live_result.get("alerts", pd.DataFrame())
    st.subheader("Alerts Generated From This Collection")
    if live_alerts.empty:
        st.success("No alerts were generated from this collection.")
    else:
        st.dataframe(
            live_alerts,
            use_container_width=True,
            hide_index=True,
        )


fragment_run_every = (
    int(st.session_state["live_monitoring_active_interval"])
    if st.session_state["live_monitoring_enabled"]
    else None
)


@streamlit_fragment(run_every=fragment_run_every)
def automatic_live_monitor() -> None:
    if not st.session_state["live_monitoring_enabled"]:
        st.info("Automatic monitoring is stopped.")
        return

    if not st.session_state["live_collection_channels"]:
        st.session_state["live_monitoring_last_error"] = (
            "Select at least one Windows log channel."
        )
        st.warning(st.session_state["live_monitoring_last_error"])
        return

    try:
        monitoring_result = run_monitoring_cycle(
            channels=list(st.session_state["live_collection_channels"]),
            max_events_per_channel=int(st.session_state["live_collection_limit"]),
            seen_alert_ids=set(st.session_state["live_monitoring_seen_alert_ids"]),
        )
        st.session_state["live_monitoring_last_result"] = monitoring_result
        st.session_state["live_monitoring_cycle_count"] += 1
        st.session_state["live_monitoring_seen_alert_ids"] = set(
            monitoring_result["seen_alert_ids"]
        )
        st.session_state["live_monitoring_last_error"] = None

        new_alerts = monitoring_result.get("new_alerts", pd.DataFrame())
        if isinstance(new_alerts, pd.DataFrame) and not new_alerts.empty:
            warning_alerts = []
            for _, alert in new_alerts.iterrows():
                severity = str(
                    alert.get("AlertSeverity", alert.get("Severity", ""))
                ).strip().lower()
                if severity in {"medium", "high", "critical"}:
                    warning_alerts.append(alert)

            for alert in warning_alerts[:3]:
                st.toast(
                    alert_notification_message(alert),
                    icon="ðŸš¨",
                )

            remaining_count = len(warning_alerts) - 3
            if remaining_count > 0:
                st.toast(
                    f"{remaining_count} additional alerts detected.",
                    icon="ðŸš¨",
                )
    except Exception as error:
        st.session_state["live_monitoring_last_error"] = str(error)
        st.error(f"Automatic monitoring cycle failed: {error}")

    show_live_result(st.session_state["live_monitoring_last_result"])


automatic_live_monitor()

visible_live_result = (
    st.session_state["live_monitoring_last_result"]
    if st.session_state["live_monitoring_enabled"]
    else st.session_state["live_collection_result"]
)

if not st.session_state["live_monitoring_enabled"]:
    show_live_result(visible_live_result)


# =============================================================
# RAVEN-SOC synthetic incident-response demonstration
# =============================================================
st.divider()
st.header("RAVEN-SOC Incident Response Lab")
st.caption(
    "Run a safe synthetic multi-stage attack through detection, "
    "correlation, classification, Analyst Agent reasoning and "
    "simulated Defender response."
)

incident_lab_environment = st.selectbox(
    "Environment profile",
    [
        "SME Office",
        "Finance SME",
        "Healthcare",
        "Educational Institution",
        "Development Environment",
    ],
    index=1,
    key="incident_lab_environment",
)

analyst_mode_label = st.selectbox(
    "Analyst mode",
    [
        "Deterministic",
        "Local SLM",
        "Hybrid",
    ],
    index=0,
    key="incident_lab_analyst_mode",
)
analyst_mode_map = {
    "Deterministic": "deterministic",
    "Local SLM": "ollama",
    "Hybrid": "hybrid",
}
incident_lab_analyst_mode = analyst_mode_map[analyst_mode_label]
incident_lab_ollama_model = st.text_input(
    "Local Ollama model",
    value=DEFAULT_OLLAMA_MODEL,
    key="incident_lab_ollama_model",
)
mode_captions = {
    "deterministic": "Rule-grounded constrained Analyst Agent.",
    "ollama": "Local Ollama model with strict structured-output validation and deterministic fallback.",
    "hybrid": "Deterministic security decision with local-model assistance for explanation.",
}
st.caption(mode_captions[incident_lab_analyst_mode])

if incident_lab_analyst_mode in {"ollama", "hybrid"}:
    ollama_health = check_ollama_health(base_url=DEFAULT_OLLAMA_URL)
    if ollama_health.get("available"):
        st.success("Ollama is available.")
        available_models = ollama_health.get("models", [])
        st.write("Available models:", available_models)
        if incident_lab_ollama_model not in available_models:
            st.warning(
                f"{incident_lab_ollama_model} was not found. "
                "Deterministic fallback will be used if the local model call fails."
            )
    else:
        st.warning(
            "Ollama is unavailable. Deterministic fallback will be used."
        )
        st.caption(str(ollama_health.get("error") or "No health details returned."))

run_lab_col, reset_lab_col = st.columns([3, 1])

with run_lab_col:
    run_synthetic_attack = st.button(
        "Run Synthetic Multi-Stage Attack",
        type="primary",
        width="stretch",
    )

with reset_lab_col:
    reset_incident_lab = st.button(
        "Reset Incident Lab",
        width="stretch",
    )

if reset_incident_lab:
    st.session_state["synthetic_pipeline_result"] = None
    st.session_state["synthetic_defender_response"] = None
    st.session_state["synthetic_action_approved"] = False
    st.session_state["synthetic_action_rejected"] = False
    st.rerun()

if run_synthetic_attack:
    try:
        with st.spinner("Running the RAVEN-SOC incident pipeline..."):
            st.session_state["synthetic_pipeline_result"] = (
                run_synthetic_incident_pipeline(
                    environment_name=incident_lab_environment,
                    analyst_mode=incident_lab_analyst_mode,
                    ollama_model=incident_lab_ollama_model,
                )
            )
        st.session_state["synthetic_defender_response"] = None
        st.session_state["synthetic_action_approved"] = False
        st.session_state["synthetic_action_rejected"] = False
        st.success("Synthetic incident pipeline completed successfully.")
    except Exception as error:
        st.session_state["synthetic_pipeline_result"] = None
        st.error(f"Unable to run the synthetic incident pipeline: {error}")

synthetic_result = st.session_state["synthetic_pipeline_result"]

if synthetic_result is not None:
    events = synthetic_result["events"]
    specialist_alerts = synthetic_result["alerts"]
    correlated_incidents = synthetic_result["incidents"]
    selected_incident = synthetic_result["selected_incident"]
    incident_timeline = synthetic_result["timeline"]
    formatted_timeline = synthetic_result["formatted_timeline"]
    analyst_analysis = synthetic_result["analysis"]
    environment_profile = synthetic_result["environment_profile"]
    analyst_metadata = synthetic_result.get("analyst_metadata", {})

    if isinstance(selected_incident, pd.Series):
        incident_record = selected_incident.to_dict()
    else:
        incident_record = dict(selected_incident)

    incident_confidence = incident_record.get(
        "IncidentConfidence",
        incident_record.get("Confidence", "N/A"),
    )
    analyst_confidence = analyst_analysis.get("Confidence", "N/A")

    st.subheader("Pipeline Summary")
    summary_columns = st.columns(5)
    summary_columns[0].metric("Synthetic Events", len(events))
    summary_columns[1].metric("Generated Alerts", len(specialist_alerts))
    summary_columns[2].metric(
        "Correlated Incidents",
        len(correlated_incidents),
    )
    summary_columns[3].metric("Incident Confidence", incident_confidence)
    summary_columns[4].metric("Analyst Confidence", analyst_confidence)

    with st.expander("1. Synthetic Security Events", expanded=False):
        event_columns = [
            "EventTime",
            "DeviceName",
            "UserName",
            "WindowsEventID",
            "EventType",
            "EventResult",
            "EventSeverity",
            "SourceIP",
            "DestinationIP",
            "ProcessName",
            "ParentProcessName",
            "CommandLine",
            "RawMessage",
        ]
        available_event_columns = [
            column for column in event_columns if column in events.columns
        ]
        st.dataframe(
            events[available_event_columns],
            width="stretch",
            hide_index=True,
        )

    with st.expander("2. Specialist Detection Alerts", expanded=True):
        alert_columns = [
            "AlertTime",
            "DeviceName",
            "UserName",
            "AlertType",
            "AlertSeverity",
            "ConfidenceScore",
            "MITRETactic",
            "MITRETechnique",
            "Evidence",
        ]
        available_alert_columns = [
            column
            for column in alert_columns
            if column in specialist_alerts.columns
        ]
        st.dataframe(
            specialist_alerts[available_alert_columns],
            width="stretch",
            hide_index=True,
        )

    st.subheader("3. Correlated Incident")
    incident_metric_columns = st.columns(3)
    incident_metric_columns[0].metric(
        "Severity",
        incident_record.get("IncidentSeverity", "Unknown"),
    )
    incident_metric_columns[1].metric(
        "Confidence",
        incident_confidence,
    )
    incident_metric_columns[2].metric(
        "Alert Count",
        incident_record.get("AlertCount", len(specialist_alerts)),
    )

    incident_details = {
        "Incident ID": incident_record.get("IncidentID", "N/A"),
        "Incident Type": incident_record.get("IncidentType", "Unknown"),
        "Correlation Pattern": incident_record.get("CorrelationPattern", incident_record.get("PatternID", "N/A")),
        "Matched Alerts": incident_record.get("RelatedAlertTypes", []),
        "Correlation Window": incident_record.get("CorrelationWindowMinutes", "N/A"),
        "Affected Device": incident_record.get("AffectedDevice", "N/A"),
        "Affected User": incident_record.get("AffectedUser", "N/A"),
        "Source IP": incident_record.get("SourceIP", "N/A"),
        "Recommended Action": incident_record.get("RecommendedActionID", "N/A"),
        "Target": incident_record.get("Target", "N/A"),
        "Requires Approval": incident_record.get("RequiresApproval", "N/A"),
        "First Seen": incident_record.get("FirstSeen", "N/A"),
        "Last Seen": incident_record.get("LastSeen", "N/A"),
    }
    st.json(incident_details)
    st.markdown("**Attack Stages**")
    st.write(incident_record.get("AttackStages", []))
    st.markdown("**MITRE Techniques**")
    st.write(incident_record.get("MITRETechniques", []))
    st.markdown("**Classification Reason**")
    st.write(incident_record.get("ClassificationReason", "Not provided."))

    st.subheader("4. Incident Timeline")
    if formatted_timeline:
        for timeline_entry in formatted_timeline:
            st.markdown(f"- {timeline_entry}")
    else:
        st.info("No formatted timeline entries were returned.")

    with st.expander("View Structured Timeline"):
        st.dataframe(
            incident_timeline,
            width="stretch",
            hide_index=True,
        )

    st.subheader("5. RAVEN Analyst Agent")
    analyst_metrics = st.columns(3)
    analyst_metrics[0].metric(
        "Status",
        analyst_analysis.get("Status", "Unknown"),
    )
    analyst_metrics[1].metric(
        "Severity",
        analyst_analysis.get("Severity", "Unknown"),
    )
    analyst_metrics[2].metric(
        "Confidence",
        analyst_confidence,
    )

    st.markdown("**Threat Type**")
    st.write(analyst_analysis.get("ThreatType", "Unknown"))
    st.markdown("**Summary**")
    st.write(analyst_analysis.get("Summary", "No summary provided."))
    st.markdown("**Suspicion Reason**")
    st.write(
        analyst_analysis.get(
            "SuspicionReason",
            "No suspicion reason provided.",
        )
    )

    evidence_col, inference_col = st.columns(2)
    with evidence_col:
        st.markdown("#### Observed Evidence")
        observed_evidence = analyst_analysis.get("ObservedEvidence", [])
        if observed_evidence:
            for evidence in observed_evidence:
                st.markdown(f"- {evidence}")
        else:
            st.info("No observed evidence was returned.")

    with inference_col:
        st.markdown("#### Analyst Inferences")
        inferences = analyst_analysis.get("Inferences", [])
        if inferences:
            for inference in inferences:
                st.markdown(f"- {inference}")
        else:
            st.info("No analyst inferences were returned.")

    st.markdown("**MITRE Techniques**")
    st.write(analyst_analysis.get("MITRETechniques", []))
    st.markdown("**Evidence IDs**")
    st.write(analyst_analysis.get("EvidenceIDs", []))
    st.markdown("**Analyst Execution**")
    execution_columns = st.columns(4)
    execution_columns[0].metric("Analyst Mode", analyst_metadata.get("AnalystMode", "deterministic"))
    execution_columns[1].metric("Model Name", analyst_metadata.get("ModelName", DEFAULT_OLLAMA_MODEL))
    execution_columns[2].metric(
        "Used Fallback",
        "Yes" if analyst_metadata.get("UsedFallback") else "No",
    )
    execution_columns[3].metric(
        "Fallback Reason",
        analyst_metadata.get("FallbackReason") or "None",
    )
    diagnostic_columns = st.columns(2)
    diagnostic_columns[0].metric(
        "Normalization Applied",
        "Yes" if analyst_metadata.get("NormalizationApplied") else "No",
    )
    diagnostic_columns[1].metric(
        "Raw Model Output Available",
        "Yes" if analyst_metadata.get("RawModelOutputAvailable") else "No",
    )
    fallback_reason = analyst_metadata.get("FallbackReason")
    if fallback_reason:
        if analyst_metadata.get("UsedFallback"):
            st.error(str(fallback_reason))
        else:
            st.warning(str(fallback_reason))

    validation_errors = analyst_metadata.get("ValidationErrors", [])
    if validation_errors:
        st.markdown("**ValidationErrors**")
        st.json(validation_errors)

    with st.expander("Hybrid Analyst Diagnostics", expanded=False):
        if analyst_metadata.get("UsedFallback"):
            raw_model_output = analyst_metadata.get("RawModelOutput")
            if raw_model_output:
                st.code(str(raw_model_output)[:5000])
            else:
                st.info("No local model output was captured for this fallback.")
        else:
            st.info("No Hybrid Analyst fallback occurred.")
    st.caption(mode_captions.get(str(analyst_metadata.get("AnalystMode", "deterministic")), mode_captions["deterministic"]))

    st.subheader("6. Defender Action Center")
    recommended_action = analyst_analysis.get(
        "RecommendedActionID",
        "NO_ACTION",
    )
    action_target = analyst_analysis.get("Target", "N/A")
    requires_approval = bool(
        analyst_analysis.get("RequiresApproval", False)
    )

    action_columns = st.columns(3)
    action_columns[0].metric("Recommended Action", recommended_action)
    action_columns[1].metric("Target", action_target)
    action_columns[2].metric(
        "Requires Approval",
        "Yes" if requires_approval else "No",
    )

    approve_column, reject_column = st.columns(2)
    with approve_column:
        approve_action = st.button(
            "Approve Simulated Action",
            type="primary",
            width="stretch",
        )
    with reject_column:
        reject_action = st.button(
            "Reject Action",
            width="stretch",
        )

    if approve_action:
        try:
            st.session_state["synthetic_action_approved"] = True
            st.session_state["synthetic_action_rejected"] = False
            st.session_state["synthetic_defender_response"] = (
                run_synthetic_defender_response(
                    analysis=analyst_analysis,
                    environment_profile=environment_profile,
                    human_approved=True,
                )
            )
        except Exception as error:
            st.error(f"Unable to evaluate the Defender action: {error}")

    if reject_action:
        st.session_state["synthetic_action_approved"] = False
        st.session_state["synthetic_action_rejected"] = True
        rejection_reason = "The analyst rejected the recommended action."
        st.session_state["synthetic_defender_response"] = {
            "ActionID": recommended_action,
            "Target": action_target,
            "Permitted": False,
            "Executed": False,
            "ExecutionMode": "Advisory",
            "RequiresApproval": requires_approval,
            "HumanApproved": False,
            "DecisionReason": rejection_reason,
            "SimulationMessage": "No simulated response was performed.",
            "AuditRecord": {
                "Timestamp": datetime.now(UTC).isoformat(),
                "ActionID": recommended_action,
                "Target": action_target,
                "Permitted": False,
                "Executed": False,
                "ExecutionMode": "Advisory",
                "Reason": rejection_reason,
            },
        }

    defender_response = st.session_state["synthetic_defender_response"]
    if defender_response is not None:
        st.subheader("Defender Decision")

        if defender_response.get("Executed") is True:
            st.success(
                defender_response.get(
                    "SimulationMessage",
                    "The simulated action was completed.",
                )
            )
        elif (
            defender_response.get("RequiresApproval")
            and not defender_response.get("HumanApproved")
            and not st.session_state["synthetic_action_rejected"]
        ):
            st.warning(
                defender_response.get(
                    "DecisionReason",
                    "Human approval is still required.",
                )
            )
        else:
            st.info(
                defender_response.get(
                    "SimulationMessage",
                    "No simulated action was executed.",
                )
            )

        defender_fields = [
            "ActionID",
            "Target",
            "Permitted",
            "Executed",
            "ExecutionMode",
            "RequiresApproval",
            "HumanApproved",
            "DecisionReason",
            "SimulationMessage",
        ]
        st.json(
            {
                field: defender_response.get(field)
                for field in defender_fields
            }
        )

        with st.expander("Response Audit Record"):
            st.json(defender_response.get("AuditRecord", {}))

st.divider()

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
