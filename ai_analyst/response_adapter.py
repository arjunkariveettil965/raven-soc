from __future__ import annotations

import re
from typing import Any

from ai_analyst.schemas import (
    ALLOWED_ACTION_IDS,
    ALLOWED_SEVERITIES,
    ALLOWED_STATUSES,
    ANALYST_OUTPUT_FIELDS,
)


_SEVERITY_BY_LOWER = {severity.lower(): severity for severity in ALLOWED_SEVERITIES}


def _status_key(value: str) -> str:
    return re.sub(r"[\s_-]+", " ", value.strip().lower())


_STATUS_BY_KEY = {_status_key(status): status for status in ALLOWED_STATUSES}
_STATUS_SYNONYMS = {
    "confirmed": "malicious",
    "confirmed malicious": "malicious",
    "true positive": "malicious",
    "false positive": "benign",
    "safe": "benign",
}
_ACTION_BY_UPPER = {action.upper(): action for action in ALLOWED_ACTION_IDS}
MODEL_OWNED_FIELDS = [
    "Status",
    "ThreatType",
    "Severity",
    "Confidence",
    "Summary",
    "SuspicionReason",
    "Inferences",
    "RecommendedActionID",
    "RequiresApproval",
]
BASELINE_OWNED_FIELDS = [
    "ObservedEvidence",
    "MITRETechniques",
    "EvidenceIDs",
    "Target",
]


def _normalize_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _normalize_string_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        normalized: list[str] = []
        for item in value:
            if isinstance(item, dict):
                text = _normalize_mitre_technique(item)
            else:
                text = _normalize_text(item)
            if text:
                normalized.append(text)
        return normalized
    text = _normalize_text(value)
    return [text] if text else []


def _normalize_mitre_technique(value: object) -> str:
    if isinstance(value, dict):
        technique_id = _normalize_text(value.get("id") or value.get("technique_id") or value.get("techniqueId"))
        name = _normalize_text(value.get("name") or value.get("technique") or value.get("description"))
        if technique_id and name:
            return f"{technique_id} - {name}"
        return technique_id or name
    return _normalize_text(value)


def _normalize_confidence(value: object) -> object:
    if isinstance(value, str):
        match = re.search(r"-?\d+(?:\.\d+)?", value)
        if not match:
            return value
        value = match.group(0)
    try:
        return int(round(float(value)))
    except (TypeError, ValueError):
        return value


def _normalize_bool(value: object) -> object:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "y", "1"}:
            return True
        if normalized in {"false", "no", "n", "0"}:
            return False
    return value


def normalize_model_analysis(
    analysis: dict[str, object],
    deterministic_baseline: dict[str, object] | None = None,
) -> dict[str, object]:
    """Coerce local model decisions and merge protected fields from the baseline."""

    normalized: dict[str, object] = {}
    output_fields = MODEL_OWNED_FIELDS if deterministic_baseline is not None else ANALYST_OUTPUT_FIELDS
    for field in output_fields:
        if field in analysis:
            normalized[field] = analysis[field]

    status = normalized.get("Status")
    if isinstance(status, str):
        status_text = status.strip()
        status_key = _status_key(status_text)
        normalized["Status"] = _STATUS_BY_KEY.get(
            status_key,
            _STATUS_SYNONYMS.get(status_key, status_text),
        )

    severity = normalized.get("Severity")
    if isinstance(severity, str):
        normalized["Severity"] = _SEVERITY_BY_LOWER.get(severity.strip().lower(), severity.strip())

    action_id = normalized.get("RecommendedActionID")
    if isinstance(action_id, str):
        normalized["RecommendedActionID"] = _ACTION_BY_UPPER.get(action_id.strip().upper(), action_id.strip())

    for field in ["ThreatType", "Summary", "SuspicionReason", "Target"]:
        if field in normalized:
            normalized[field] = _normalize_text(normalized[field])

    if "Confidence" in normalized:
        normalized["Confidence"] = _normalize_confidence(normalized["Confidence"])

    for field in ["ObservedEvidence", "Inferences", "EvidenceIDs"]:
        if field in normalized:
            normalized[field] = _normalize_string_list(normalized[field])

    if "MITRETechniques" in normalized:
        normalized["MITRETechniques"] = _normalize_string_list(normalized["MITRETechniques"])

    if "RequiresApproval" in normalized:
        normalized["RequiresApproval"] = _normalize_bool(normalized["RequiresApproval"])

    if deterministic_baseline is not None:
        for field in BASELINE_OWNED_FIELDS:
            normalized[field] = deterministic_baseline.get(field)
        normalized["RequiresApproval"] = bool(
            normalized.get("RequiresApproval")
            or deterministic_baseline.get("RequiresApproval")
        )

    return normalized


def normalize_local_slm_analysis(
    analysis: dict[str, object],
    deterministic_baseline: dict[str, object] | None = None,
) -> dict[str, object]:
    """Backward-compatible wrapper for local SLM response normalization."""

    return normalize_model_analysis(analysis, deterministic_baseline)
