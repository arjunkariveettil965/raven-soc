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
from ai_analyst.ollama_client import DEFAULT_OLLAMA_MODEL, DEFAULT_OLLAMA_URL, generate_structured_analysis
from ai_analyst.schemas import ALLOWED_ACTION_IDS, ANALYST_OUTPUT_FIELDS
from ai_analyst.output_validator import sanitize_invalid_analysis, validate_analyst_output


LOCAL_SLM_VALIDATION_FALLBACK_REASON = (
    "Local SLM output failed schema validation; deterministic explanation retained."
)
GENERIC_SANITIZER_TEXT = {
    "Insufficient evidence to make a confident determination.",
    "The analysis output was invalid and required sanitization.",
    "The analysis was sanitized due to schema or validation issues.",
    "Inference: The analysis was sanitized due to schema or validation issues.",
}

LAST_ANALYST_METADATA: dict[str, object] = {
    "AnalystMode": "deterministic",
    "ModelName": DEFAULT_OLLAMA_MODEL,
    "UsedFallback": False,
    "FallbackReason": None,
}


def get_last_analyst_metadata() -> dict[str, object]:
    return dict(LAST_ANALYST_METADATA)


def _set_last_analyst_metadata(
    mode: str,
    model: str,
    used_fallback: bool,
    fallback_reason: str | None,
) -> None:
    LAST_ANALYST_METADATA.update(
        {
            "AnalystMode": mode,
            "ModelName": model,
            "UsedFallback": used_fallback,
            "FallbackReason": fallback_reason,
        }
    )


def _build_analyst_json_schema() -> dict[str, object]:
    string_fields = ["Status", "ThreatType", "Severity", "Summary", "SuspicionReason", "RecommendedActionID", "Target"]
    array_fields = ["ObservedEvidence", "Inferences", "MITRETechniques", "EvidenceIDs"]
    properties: dict[str, object] = {
        field: {"type": "string"} for field in string_fields
    }
    properties.update({field: {"type": "array", "items": {"type": "string"}} for field in array_fields})
    properties["Confidence"] = {"type": "number", "minimum": 0, "maximum": 100}
    properties["RequiresApproval"] = {"type": "boolean"}
    properties["RecommendedActionID"] = {"type": "string", "enum": sorted(ALLOWED_ACTION_IDS)}
    return {
        "type": "object",
        "properties": properties,
        "required": ANALYST_OUTPUT_FIELDS,
        "additionalProperties": False,
    }


def _prepare_deterministic_analysis(
    incident: pd.Series | dict,
    timeline: pd.DataFrame,
    environment_name: str = "SME Office",
) -> tuple[dict[str, object], dict[str, object], dict[str, object] | None]:
    """Run the deterministic analyst workflow and return context for reuse."""

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
        return analysis, environment_profile, attack_pattern
    return sanitize_invalid_analysis(errors), environment_profile, attack_pattern


def _validate_or_sanitize(analysis: dict[str, object], incident: pd.Series | dict) -> dict[str, object]:
    valid, errors = validate_analyst_output(analysis, incident)
    if valid:
        return analysis
    return sanitize_invalid_analysis(errors)


def _validate_ollama_analysis(
    analysis: dict[str, object],
    incident: pd.Series | dict,
) -> tuple[bool, str | None]:
    valid, errors = validate_analyst_output(analysis, incident)
    if not valid:
        return False, f"{LOCAL_SLM_VALIDATION_FALLBACK_REASON} Errors: {'; '.join(errors)}"

    summary = analysis.get("Summary")
    if not isinstance(summary, str) or not summary.strip():
        return False, "Local SLM Summary was missing or empty; deterministic explanation retained."
    if summary.strip() in GENERIC_SANITIZER_TEXT:
        return False, LOCAL_SLM_VALIDATION_FALLBACK_REASON

    suspicion_reason = analysis.get("SuspicionReason")
    if not isinstance(suspicion_reason, str) or not suspicion_reason.strip():
        return False, "Local SLM SuspicionReason was missing or empty; deterministic explanation retained."
    if suspicion_reason.strip() in GENERIC_SANITIZER_TEXT:
        return False, LOCAL_SLM_VALIDATION_FALLBACK_REASON

    inferences = analysis.get("Inferences")
    if not isinstance(inferences, list) or not inferences:
        return False, "Local SLM Inferences were missing or empty; deterministic explanation retained."
    for inference in inferences:
        if not isinstance(inference, str) or not inference.strip():
            return False, "Local SLM Inferences contained an invalid value; deterministic explanation retained."
        if inference.strip() in GENERIC_SANITIZER_TEXT:
            return False, LOCAL_SLM_VALIDATION_FALLBACK_REASON

    return True, None


def _merge_hybrid_analysis(
    deterministic_analysis: dict[str, object],
    ollama_analysis: dict[str, object],
    incident: pd.Series | dict,
) -> tuple[dict[str, object], bool, str | None]:
    valid_ollama, fallback_reason = _validate_ollama_analysis(ollama_analysis, incident)
    if not valid_ollama:
        return deterministic_analysis, True, fallback_reason

    merged = dict(deterministic_analysis)
    for field in ["Summary", "SuspicionReason", "Inferences"]:
        merged[field] = ollama_analysis[field]

    valid, _ = validate_analyst_output(merged, incident)
    if valid:
        return merged, False, None
    return deterministic_analysis, True, LOCAL_SLM_VALIDATION_FALLBACK_REASON


def run_analyst_agent(
    incident: pd.Series | dict,
    timeline: pd.DataFrame,
    environment_name: str = "SME Office",
    mode: str = "deterministic",
    ollama_model: str = DEFAULT_OLLAMA_MODEL,
    ollama_base_url: str = DEFAULT_OLLAMA_URL,
) -> dict[str, object]:
    """Run the analyst workflow and return a validated strict analysis."""

    normalized_mode = str(mode).strip().lower()
    if normalized_mode not in {"deterministic", "ollama", "hybrid"}:
        normalized_mode = "deterministic"

    deterministic_analysis, environment_profile, attack_pattern = _prepare_deterministic_analysis(
        incident=incident,
        timeline=timeline,
        environment_name=environment_name,
    )

    if normalized_mode == "deterministic":
        _set_last_analyst_metadata("deterministic", ollama_model, False, None)
        return deterministic_analysis

    prompt = build_local_slm_prompt(
        incident=incident,
        timeline=timeline,
        environment_profile=environment_profile,
        attack_pattern=attack_pattern,
    )

    try:
        ollama_analysis = generate_structured_analysis(
            prompt=prompt,
            schema=_build_analyst_json_schema(),
            model=ollama_model,
            base_url=ollama_base_url,
        )
        valid_ollama, validation_reason = _validate_ollama_analysis(ollama_analysis, incident)
        if not valid_ollama:
            raise RuntimeError(validation_reason or LOCAL_SLM_VALIDATION_FALLBACK_REASON)
    except Exception as error:
        _set_last_analyst_metadata(normalized_mode, ollama_model, True, str(error))
        return deterministic_analysis

    if normalized_mode == "ollama":
        _set_last_analyst_metadata("ollama", ollama_model, False, None)
        return _validate_or_sanitize(ollama_analysis, incident)

    hybrid_analysis, used_fallback, fallback_reason = _merge_hybrid_analysis(
        deterministic_analysis,
        ollama_analysis,
        incident,
    )
    _set_last_analyst_metadata(
        "hybrid",
        ollama_model,
        used_fallback,
        fallback_reason,
    )
    return hybrid_analysis


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
