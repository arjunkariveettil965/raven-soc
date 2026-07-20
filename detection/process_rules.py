from __future__ import annotations

import re
from typing import Any

import pandas as pd

from detection.alert_contract import (
    build_entities,
    enrich_alert_record,
    normalize_event_ids,
    stable_alert_id,
)
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
DOWNLOAD_CAPABLE_PROCESSES = {
    "powershell.exe",
    "powershell",
    "pwsh",
    "cmd.exe",
    "cmd",
    "certutil.exe",
    "certutil",
    "bitsadmin.exe",
    "bitsadmin",
    "mshta.exe",
    "mshta",
}
LOLBIN_PROCESSES = {
    "rundll32.exe",
    "rundll32",
    "regsvr32.exe",
    "regsvr32",
    "wscript.exe",
    "wscript",
    "cscript.exe",
    "cscript",
}
USER_EXECUTION_PARENTS = {"chrome.exe", "msedge.exe", "firefox.exe", "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
DOWNLOAD_PATTERNS = {"http://", "https://", "downloadstring", "invoke-webrequest", "iwr ", "curl ", "wget ", "urlcache", "/transfer"}
EXECUTION_EXTENSIONS = {".exe", ".dll", ".ps1", ".vbs", ".js", ".hta", ".scr", ".bat"}


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

        record = {
                "AlertID": stable_alert_id("powershell", ["PROC_SUSPICIOUS_POWERSHELL", row["EventTime"], row.get("DeviceName"), row.get("UserName"), row.get("CommandLine")]),
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
        alerts.append(
            enrich_alert_record(
                record,
                rule_id="PROC_SUSPICIOUS_POWERSHELL",
                title="Suspicious PowerShell execution",
                process_name=row.get("ProcessName"),
                mitre_techniques=["T1059.001 - PowerShell"],
                entities=build_entities(
                    machine=row.get("DeviceName"),
                    user=row.get("UserName"),
                    source_ip=row.get("SourceIP"),
                    process=row.get("ProcessName"),
                ),
                metadata={"MatchedPatterns": matched_patterns},
                evidence_ids=normalize_event_ids(row.to_frame().T),
            )
        )

    if not alerts:
        return _empty_alert_frame()

    return pd.DataFrame(alerts, columns=ALERT_COLUMNS)


def _process_basename(value: object) -> str:
    return str(value or "").strip().lower().split("\\")[-1]


def detect_malware_delivery_activity(events: pd.DataFrame) -> pd.DataFrame:
    """Detect download-capable execution and suspicious file execution alerts."""

    _require_columns(events)
    if events.empty:
        return _empty_alert_frame()

    working_events = events.copy()
    working_events["EventTime"] = pd.to_datetime(working_events["EventTime"], errors="coerce")
    working_events = working_events.dropna(subset=["EventTime"]).sort_values("EventTime").reset_index(drop=True)
    if working_events.empty:
        return _empty_alert_frame()

    alerts: list[dict[str, Any]] = []
    for _, row in working_events.iterrows():
        process_name = _process_basename(row.get("ProcessName"))
        command_line = str(row.get("CommandLine", "")).lower()
        event_type = str(row.get("EventType", "")).lower()
        parent_process = _process_basename(row.get("ParentProcessName", ""))
        candidate = f"{process_name} {command_line}"

        matched_download = [pattern for pattern in DOWNLOAD_PATTERNS if pattern in candidate]
        if process_name in DOWNLOAD_CAPABLE_PROCESSES and matched_download:
            technique = "T1059.001 - PowerShell" if "powershell" in process_name or "pwsh" in process_name else "T1105 - Ingress Tool Transfer"
            record = {
                "AlertID": stable_alert_id("malware-download", ["PROC_DOWNLOAD_CAPABLE", row["EventTime"], row.get("DeviceName"), row.get("UserName"), command_line]),
                "AlertTime": row["EventTime"],
                "DeviceName": row.get("DeviceName"),
                "UserName": row.get("UserName"),
                "SourceIP": row.get("SourceIP"),
                "AlertType": "Suspicious Download Command",
                "AlertSeverity": "High",
                "ConfidenceScore": 82.0,
                "MITRETactic": "Command and Control",
                "MITRETechnique": technique,
                "Evidence": f"{row.get('ProcessName')} used download-capable indicators: {', '.join(matched_download)}",
                "FirstSeen": row["EventTime"],
                "LastSeen": row["EventTime"],
                "RelatedEventCount": 1,
            }
            alerts.append(
                enrich_alert_record(
                    record,
                    rule_id="PROC_DOWNLOAD_CAPABLE",
                    title="Suspicious download-capable process",
                    process_name=row.get("ProcessName"),
                    mitre_techniques=[technique, "T1105 - Ingress Tool Transfer"],
                    evidence_ids=normalize_event_ids(row.to_frame().T),
                    metadata={"MatchedDownloadIndicators": matched_download},
                )
            )

        execution_indicator = any(extension in command_line for extension in EXECUTION_EXTENSIONS)
        lolbin_indicator = process_name in LOLBIN_PROCESSES
        user_execution = parent_process in USER_EXECUTION_PARENTS and execution_indicator
        if (lolbin_indicator and execution_indicator) or user_execution or ("process" in event_type and execution_indicator and process_name not in DOWNLOAD_CAPABLE_PROCESSES):
            technique = "T1218 - System Binary Proxy Execution" if lolbin_indicator else "T1204 - User Execution"
            record = {
                "AlertID": stable_alert_id("malware-exec", ["PROC_SUSPICIOUS_EXECUTION", row["EventTime"], row.get("DeviceName"), row.get("UserName"), process_name, command_line]),
                "AlertTime": row["EventTime"],
                "DeviceName": row.get("DeviceName"),
                "UserName": row.get("UserName"),
                "SourceIP": row.get("SourceIP"),
                "AlertType": "Suspicious File Execution",
                "AlertSeverity": "High",
                "ConfidenceScore": 84.0,
                "MITRETactic": "Execution",
                "MITRETechnique": technique,
                "Evidence": f"{row.get('ProcessName')} execution context matched malware-delivery indicators",
                "FirstSeen": row["EventTime"],
                "LastSeen": row["EventTime"],
                "RelatedEventCount": 1,
            }
            alerts.append(
                enrich_alert_record(
                    record,
                    rule_id="PROC_SUSPICIOUS_EXECUTION",
                    title="Suspicious executable or script execution",
                    process_name=row.get("ProcessName"),
                    mitre_techniques=[technique],
                    evidence_ids=normalize_event_ids(row.to_frame().T),
                    metadata={"ParentProcessName": parent_process, "ExecutionIndicator": execution_indicator},
                )
            )

    if not alerts:
        return _empty_alert_frame()
    return pd.DataFrame(alerts, columns=ALERT_COLUMNS)
