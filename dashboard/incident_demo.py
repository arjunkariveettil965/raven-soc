"""End-to-end helpers for the RAVEN-SOC synthetic incident lab.

This module deliberately contains no Streamlit calls so the pipeline can be
unit-tested independently from the UI.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from ai_analyst import agent as analyst_agent
from ai_analyst import environment_adapter
from ai_analyst.ollama_client import DEFAULT_OLLAMA_MODEL, DEFAULT_OLLAMA_URL, check_ollama_health
from data_generation import attack_simulator
from detection import alert_engine
from incidents import correlation_engine, incident_classifier, timeline_builder
from response import defender_agent


def _as_dataframe(value: Any, label: str) -> pd.DataFrame:
    if isinstance(value, pd.DataFrame):
        return value.copy()
    if isinstance(value, pd.Series):
        return value.to_frame().T
    if isinstance(value, list):
        return pd.DataFrame(value)
    if isinstance(value, dict):
        return pd.DataFrame([value])
    raise TypeError(f"{label} must be convertible to a pandas DataFrame.")


def _row_to_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, pd.Series):
        return value.to_dict()
    if isinstance(value, dict):
        return dict(value)
    raise TypeError("Expected a dictionary-like incident record.")


def _normalize_environment_profile(
    profile: dict[str, Any],
    requested_name: str,
) -> dict[str, Any]:
    """Add stable dashboard keys while preserving the source profile fields."""

    normalized = dict(profile)
    environment_name = (
        normalized.get("EnvironmentName")
        or normalized.get("environment_name")
        or normalized.get("name")
        or requested_name
    )
    critical_devices = (
        normalized.get("critical_devices")
        or normalized.get("CriticalDevices")
        or []
    )

    if isinstance(critical_devices, str):
        critical_devices = [critical_devices]
    else:
        critical_devices = list(critical_devices)

    normalized["EnvironmentName"] = str(environment_name)
    normalized["critical_devices"] = critical_devices
    return normalized


def _normalize_incident(
    correlated_incident: pd.Series | dict[str, Any],
    classified_incident: pd.Series | dict[str, Any],
) -> pd.Series:
    """Merge correlation and classification fields into the Analyst contract."""

    incident = _row_to_dict(correlated_incident)
    incident.update(_row_to_dict(classified_incident))
    return pd.Series(incident)


def _invoke_analyst_agent(
    incident: pd.Series,
    timeline: pd.DataFrame,
    environment_name: str,
    analyst_mode: str,
    ollama_model: str,
    ollama_base_url: str,
) -> dict[str, object]:
    analysis = analyst_agent.run_analyst_agent(
        incident=incident,
        timeline=timeline,
        environment_name=environment_name,
        mode=analyst_mode,
        ollama_model=ollama_model,
        ollama_base_url=ollama_base_url,
    )
    if not isinstance(analysis, dict):
        raise TypeError("The Analyst Agent must return a dictionary.")
    return analysis


def _invoke_defender_agent(
    analysis: dict[str, object],
    environment_profile: dict[str, object],
    human_approved: bool,
) -> dict[str, object]:
    result = defender_agent.run_defender_agent(
        analysis=analysis,
        environment_profile=environment_profile,
        human_approved=human_approved,
    )
    if not isinstance(result, dict):
        raise TypeError("The Defender Agent must return a dictionary.")
    return result


def run_synthetic_incident_pipeline(
    environment_name: str = "Finance SME",
    analyst_mode: str = "deterministic",
    ollama_model: str = DEFAULT_OLLAMA_MODEL,
    ollama_base_url: str = DEFAULT_OLLAMA_URL,
) -> dict[str, object]:
    """Run one safe synthetic attack through the complete RAVEN-SOC pipeline."""

    events = _as_dataframe(
        attack_simulator.generate_multistage_attack_scenario(),
        "synthetic events",
    )

    alerts = _as_dataframe(
        alert_engine.analyze_security_events(events=events),
        "alerts",
    )
    if alerts.empty:
        raise RuntimeError("The synthetic scenario produced no security alerts.")

    correlated_incidents = _as_dataframe(
        correlation_engine.correlate_alerts(alerts=alerts),
        "correlated incidents",
    )
    if correlated_incidents.empty:
        raise RuntimeError("The generated alerts produced no correlated incident.")

    classifications = _as_dataframe(
        incident_classifier.classify_incidents(incidents=correlated_incidents),
        "classified incidents",
    )
    if classifications.empty:
        raise RuntimeError("Incident classification returned no incident.")

    selected_incident = _normalize_incident(
        correlated_incident=correlated_incidents.iloc[0],
        classified_incident=classifications.iloc[0],
    )
    incidents = pd.DataFrame([selected_incident.to_dict()])

    timeline = _as_dataframe(
        timeline_builder.build_incident_timeline(
            incident=selected_incident,
            alerts=alerts,
        ),
        "incident timeline",
    )
    formatted_timeline = list(
        timeline_builder.format_incident_timeline(timeline=timeline)
    )

    profile = environment_adapter.get_environment_profile(
        environment_name=environment_name,
    )
    if not isinstance(profile, dict):
        raise TypeError("Environment profile loader must return a dictionary.")
    environment_profile = _normalize_environment_profile(profile, environment_name)

    analysis = _invoke_analyst_agent(
        incident=selected_incident,
        timeline=timeline,
        environment_name=environment_name,
        analyst_mode=analyst_mode,
        ollama_model=ollama_model,
        ollama_base_url=ollama_base_url,
    )
    analyst_metadata = analyst_agent.get_last_analyst_metadata()
    if analyst_mode in {"ollama", "hybrid"}:
        ollama_health = check_ollama_health(base_url=ollama_base_url)
    else:
        ollama_health = {
            "available": False,
            "base_url": ollama_base_url,
            "models": [],
            "error": "Health check not required in deterministic mode.",
        }

    return {
        "events": events,
        "alerts": alerts,
        "incidents": incidents,
        "selected_incident": selected_incident,
        "timeline": timeline,
        "formatted_timeline": formatted_timeline,
        "analysis": analysis,
        "environment_profile": environment_profile,
        "analyst_mode": analyst_mode,
        "ollama_model": ollama_model,
        "ollama_health": ollama_health,
        "analyst_metadata": analyst_metadata,
    }


def run_synthetic_defender_response(
    analysis: dict[str, object],
    environment_profile: dict[str, object],
    human_approved: bool,
) -> dict[str, object]:
    """Evaluate and simulate the approved Defender response."""

    return _invoke_defender_agent(
        analysis=analysis,
        environment_profile=environment_profile,
        human_approved=human_approved,
    )
