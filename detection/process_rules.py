from __future__ import annotations

import re
import uuid
from typing import Any

import pandas as pd

from detection.authentication_rules import ALERT_COLUMNS


SUSPICIOUS_PATTERNS = [
    "encodedcommand",
    "-enc",
    "downloadstring",
    "invoke-expression",
    "iex",
    "frombase64string",
    "certutil",
    "rundll32",
    "regsvr32",
]


def _empty_alert_frame() -> pd.DataFrame:
    """Return an empty alert DataFrame with the shared schema."""

    return pd.DataFrame(columns=ALERT_COLUMNS)


def _require_columns(events: pd.DataFrame) -> None:
    """Validate that the input DataFrame includes the required columns."""

    if not isinstance(events, pd.DataFrame):
        raise TypeError("detect_suspicious_powershell expects a pandas DataFrame.")

    required_columns = {"EventTime", "DeviceName", "UserName", "ProcessName", "CommandLine", "SourceIP"}
    missing_columns = required_columns - set(events.columns)

    if missing_columns:
        raise ValueError(
            "detect_suspicious_powershell is missing required columns: "
            f"{sorted(missing_columns)}"
        )


def detect_suspicious_powershell(events: pd.DataFrame) -> pd.DataFrame:
    """
    Detect suspicious PowerShell or pwsh activity based on command-line patterns.
    """

    _require_columns(events)

    if events.empty:
        return _empty_alert_frame()

    working_events = events.copy()
    working_events["EventTime"] = pd.to_datetime(
        working_events["EventTime"],
        errors="coerce",
    )
    working_events = working_events.dropna(subset=["EventTime"])

    if working_events.empty:
        return _empty_alert_frame()

    alerts: list[dict[str, Any]] = []

    for _, row in working_events.iterrows():
        process_name = str(row.get("ProcessName", "")).lower()
        command_line = str(row.get("CommandLine", "")).lower()
        candidate_text = f"{process_name} {command_line}".strip()

        if not re.search(r"(?:powershell|pwsh)", candidate_text):
            continue

        matched_patterns = [
            pattern for pattern in SUSPICIOUS_PATTERNS if pattern in candidate_text
        ]

        if not matched_patterns:
            continue

        alerts.append(
            {
                "AlertID": f"powershell-{uuid.uuid4().hex[:8]}",
                "AlertTime": row["EventTime"],
                "DeviceName": row.get("DeviceName"),
                "UserName": row.get("UserName"),
                "SourceIP": row.get("SourceIP"),
                "AlertType": "Suspicious PowerShell",
                "AlertSeverity": "Critical",
                "ConfidenceScore": 92.0,
                "MITRETactic": "Execution",
                "MITRETechnique": "T1059.001 - PowerShell",
                "Evidence": f"Matched patterns: {', '.join(matched_patterns)}",
                "FirstSeen": row["EventTime"],
                "LastSeen": row["EventTime"],
                "RelatedEventCount": 1,
            }
        )

    if not alerts:
        return _empty_alert_frame()

    return pd.DataFrame(alerts, columns=ALERT_COLUMNS)
