from __future__ import annotations

ALLOWED_STATUSES = {"malicious", "suspicious", "uncertain", "benign"}
ALLOWED_SEVERITIES = {"Critical", "High", "Medium", "Low"}
ALLOWED_ACTION_IDS = {
    "ISOLATE_DEVICE",
    "DISABLE_USER",
    "BLOCK_DESTINATION_IP",
    "COLLECT_EVIDENCE",
    "INCREASE_MONITORING",
    "NO_ACTION",
}

ANALYST_OUTPUT_FIELDS = [
    "Status",
    "ThreatType",
    "Severity",
    "Confidence",
    "Summary",
    "SuspicionReason",
    "ObservedEvidence",
    "Inferences",
    "MITRETechniques",
    "RecommendedActionID",
    "Target",
    "RequiresApproval",
    "EvidenceIDs",
]


def create_empty_analysis() -> dict[str, object]:
    """Return a safe default analysis payload with the approved schema."""

    return {
        "Status": "uncertain",
        "ThreatType": "Unknown",
        "Severity": "Low",
        "Confidence": 0.0,
        "Summary": "",
        "SuspicionReason": "",
        "ObservedEvidence": [],
        "Inferences": [],
        "MITRETechniques": [],
        "RecommendedActionID": "NO_ACTION",
        "Target": "",
        "RequiresApproval": True,
        "EvidenceIDs": [],
    }
