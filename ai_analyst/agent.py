from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from ai_analyst.environment_adapter import (
    evaluate_environment_context,
    get_environment_profile,
    load_environment_profiles,
)
from ai_analyst.incident_analyzer import analyze_incident_deterministically
from ai_analyst.knowledge_base import find_matching_attack_pattern, load_attack_patterns
from ai_analyst.output_validator import sanitize_invalid_analysis, validate_analyst_output


def run_analyst_agent(
    incident: pd.Series | dict,
    timeline: pd.DataFrame,
    environment_name: str = "SME Office",
) -> dict[str, object]:
    """Run the deterministic analyst workflow and return a validated analysis."""

    profiles = load_environment_profiles()
    environment_profile = get_environment_profile(environment_name, profiles)
    attack_patterns = load_attack_patterns()
    attack_pattern = find_matching_attack_pattern(incident, attack_patterns)

    environment_context = evaluate_environment_context(incident, environment_profile)
    environment_profile = {**environment_profile, **environment_context}

    analysis = analyze_incident_deterministically(
        incident=incident,
        timeline=timeline,
        environment_profile=environment_profile,
        attack_pattern=attack_pattern,
    )

    valid, errors = validate_analyst_output(analysis, incident)
    if valid:
        return analysis
    return sanitize_invalid_analysis(errors)


def build_local_slm_prompt(
    incident: pd.Series | dict,
    timeline: pd.DataFrame,
    environment_profile: dict[str, object],
    attack_pattern: dict[str, object] | None,
) -> str:
    """Create a deterministic prompt for a future local SLM integration."""

    incident_type = "Unknown"
    if isinstance(incident, pd.Series):
        incident_data = incident.to_dict()
    elif isinstance(incident, dict):
        incident_data = incident
    else:
        incident_data = {}
    incident_type = str(incident_data.get("IncidentType", "Unknown"))

    allowed_actions = [
        "ISOLATE_DEVICE",
        "DISABLE_USER",
        "BLOCK_DESTINATION_IP",
        "COLLECT_EVIDENCE",
        "INCREASE_MONITORING",
        "NO_ACTION",
    ]

    prompt = (
        "You are the RAVEN-SOC Analyst Agent. "
        "Return JSON-only output. "
        "Do not invent evidence. "
        "Do not generate shell, PowerShell, or OS commands. "
        "Separate observations from inferences. "
        "If evidence is insufficient, return Status='uncertain'. "
        f"IncidentType={incident_type}. "
        f"Environment={environment_profile.get('environment_name', 'SME Office')}. "
        f"AllowedActionIDs={','.join(allowed_actions)}. "
        f"AttackPattern={attack_pattern.get('pattern_name') if attack_pattern else 'None'}."
    )
    return prompt
