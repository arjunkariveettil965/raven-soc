import pandas as pd


NORMALIZED_COLUMNS = [
    "EventTime",
    "DeviceName",
    "UserName",
    "EventSource",
    "EventType",
    "EventResult",
    "EventSeverity",
    "SourceIP",
    "DestinationIP",
    "ProcessName",
    "CommandLine",
    "Country",
    "RawMessage",
]


def normalize_windows_event_logs(
    logs: pd.DataFrame,
) -> pd.DataFrame:
    """
    Convert the current Windows event-log dataset into a common
    ASIM-inspired schema.

    Fields that do not exist in the source data are left empty.
    """

    required_columns = {
        "MachineName",
        "Source",
        "EntryType",
        "TimeGenerated",
        "Message",
    }

    missing_columns = required_columns - set(logs.columns)

    if missing_columns:
        raise ValueError(
            "Cannot normalize this Windows event dataset. "
            f"Missing columns: {sorted(missing_columns)}"
        )

    normalized = pd.DataFrame(index=logs.index)

    normalized["EventTime"] = pd.to_datetime(
        logs["TimeGenerated"],
        errors="coerce",
    )

    normalized["DeviceName"] = logs["MachineName"].astype(str)

    normalized["UserName"] = pd.NA

    normalized["EventSource"] = logs["Source"].astype(str)

    normalized["EventType"] = (
        logs["Category"].astype(str)
        if "Category" in logs.columns
        else "WindowsEvent"
    )

    normalized["EventResult"] = logs["EntryType"].apply(
        map_event_result
    )

    normalized["EventSeverity"] = logs["EntryType"].apply(
        map_event_severity
    )

    normalized["SourceIP"] = pd.NA
    normalized["DestinationIP"] = pd.NA
    normalized["ProcessName"] = pd.NA
    normalized["CommandLine"] = pd.NA

    normalized["Country"] = (
        logs["country"].astype(str)
        if "country" in logs.columns
        else pd.NA
    )

    normalized["RawMessage"] = logs["Message"].astype(str)

    return normalized[NORMALIZED_COLUMNS]


def map_event_result(entry_type: object) -> str:
    """
    Convert Windows entry types into a general event-result field.
    """

    value = str(entry_type).strip().lower()

    if value == "information":
        return "Success"

    if value == "warning":
        return "Partial"

    if value == "error":
        return "Failure"

    return "Unknown"


def map_event_severity(entry_type: object) -> str:
    """
    Convert Windows entry types into a normalized severity field.
    """

    value = str(entry_type).strip().lower()

    severity_map = {
        "information": "Informational",
        "warning": "Medium",
        "error": "High",
    }

    return severity_map.get(value, "Unknown")