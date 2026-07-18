from __future__ import annotations

from typing import Any

import pandas as pd

from ai_analyst.schemas import ALLOWED_ACTION_IDS, ALLOWED_SEVERITIES, ALLOWED_STATUSES, ANALYST_OUTPUT_FIELDS, create_empty_analysis


def validate_analyst_output(
    analysis: dict[str, object],
    incident: pd.Series | dict,
) -> tuple[bool, list[str]]:
    """Validate that the analysis matches the required analyst schema."""

    errors: list[str] = []
    if not isinstance(analysis, dict):
        return False, ["analysis must be a dictionary"]

    if set(analysis.keys()) != set(ANALYST_OUTPUT_FIELDS):
        errors.append("analysis fields do not match the required schema")

    if isinstance(incident, pd.Series):
        incident_data = incident.to_dict()
    elif isinstance(incident, dict):
        incident_data = incident
    else:
        incident_data = {}

    allowed_context_values = {
        str(incident_data.get("AffectedDevice", "")),
        str(incident_data.get("AffectedUser", "")),
        str(incident_data.get("SourceIP", "")),
        "",
    }

    if analysis.get("Status") not in ALLOWED_STATUSES:
        errors.append("Status is invalid")
    if analysis.get("Severity") not in ALLOWED_SEVERITIES:
        errors.append("Severity is invalid")
    if analysis.get("RecommendedActionID") not in ALLOWED_ACTION_IDS:
        errors.append("RecommendedActionID is invalid")

    confidence = analysis.get("Confidence")
    try:
        confidence_value = float(confidence)
    except (TypeError, ValueError):
        errors.append("Confidence must be numeric")
    else:
        if not 0 <= confidence_value <= 100:
            errors.append("Confidence must be between 0 and 100")

    summary = analysis.get("Summary")
    if not isinstance(summary, str):
        errors.append("Summary must be a string")
    elif not summary and analysis.get("Status") != "benign":
        errors.append("Summary must be non-empty unless status is benign")

    evidence_ids = analysis.get("EvidenceIDs")
    if not isinstance(evidence_ids, list):
        errors.append("EvidenceIDs must be a list")
    else:
        incident_ids = {str(item) for item in incident_data.get("RelatedAlertIDs", []) or []}
        for evidence_id in evidence_ids:
            if str(evidence_id) not in incident_ids:
                errors.append("EvidenceID does not belong to the incident")

    if not isinstance(analysis.get("MITRETechniques"), list):
        errors.append("MITRETechniques must be a list")
    if not isinstance(analysis.get("ObservedEvidence"), list):
        errors.append("ObservedEvidence must be a list")
    if not isinstance(analysis.get("Inferences"), list):
        errors.append("Inferences must be a list")
    if not isinstance(analysis.get("RequiresApproval"), bool):
        errors.append("RequiresApproval must be boolean")

    target = analysis.get("Target", "")
    if not isinstance(target, str):
        errors.append("Target must be a string")
    elif target not in allowed_context_values:
        if analysis.get("RecommendedActionID") != "NO_ACTION":
            errors.append("Target is not valid for the incident context")

    return not errors, errors


def sanitize_invalid_analysis(errors: list[str]) -> dict[str, object]:
    """Return a safe uncertain analysis for invalid or incomplete outputs."""

    analysis = create_empty_analysis()
    analysis.update(
        {
            "Status": "uncertain",
            "ThreatType": "Unknown",
            "Severity": "Low",
            "Confidence": 25.0,
            "Summary": "Insufficient evidence to make a confident determination.",
            "SuspicionReason": "The analysis output was invalid and required sanitization.",
            "ObservedEvidence": [],
            "Inferences": ["Inference: The analysis was sanitized due to schema or validation issues."],
            "MITRETechniques": [],
            "RecommendedActionID": "COLLECT_EVIDENCE",
            "Target": "",
            "RequiresApproval": True,
            "EvidenceIDs": [],
        }
    )
    return analysis
