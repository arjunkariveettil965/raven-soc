from __future__ import annotations

import sys
from typing import Any

import pandas as pd

try:
    import pywintypes
    import win32con
    import win32evtlog
    import win32evtlogutil
except ImportError:
    pywintypes = None
    win32con = None
    win32evtlog = None
    win32evtlogutil = None


RAW_EVENT_COLUMNS = [
    "RecordID",
    "TimeGenerated",
    "MachineName",
    "Channel",
    "Source",
    "EventID",
    "EventCategory",
    "EventTypeCode",
    "EntryType",
    "UserName",
    "Message",
    "RawData",
]

SUPPORTED_CHANNELS = {"System", "Application", "Security"}


def is_windows_platform() -> bool:
    return sys.platform.startswith("win")


def entry_type_name(event_type_code: int) -> str:
    if win32con is not None:
        event_type_map = {
            win32con.EVENTLOG_ERROR_TYPE: "Error",
            win32con.EVENTLOG_WARNING_TYPE: "Warning",
            win32con.EVENTLOG_INFORMATION_TYPE: "Information",
            win32con.EVENTLOG_AUDIT_SUCCESS: "Audit Success",
            win32con.EVENTLOG_AUDIT_FAILURE: "Audit Failure",
        }
    else:
        event_type_map = {
            1: "Error",
            2: "Warning",
            4: "Information",
            8: "Audit Success",
            16: "Audit Failure",
        }

    return event_type_map.get(int(event_type_code), "Unknown")


def _empty_raw_events() -> pd.DataFrame:
    return pd.DataFrame(columns=RAW_EVENT_COLUMNS)


def _is_access_denied(error: BaseException) -> bool:
    winerror = getattr(error, "winerror", None)
    if winerror is None and getattr(error, "args", None):
        try:
            winerror = int(error.args[0])
        except (TypeError, ValueError):
            winerror = None
    return winerror == 5


def _safe_message(event: Any, channel: str) -> str:
    try:
        return str(win32evtlogutil.SafeFormatMessage(event, channel))
    except Exception as error:
        return f"Unable to format Windows Event Log message: {error}"


def _safe_raw_data(raw_data: Any) -> str:
    if raw_data is None:
        return ""
    if isinstance(raw_data, bytes):
        return raw_data.hex()
    return str(raw_data)


def _safe_username(event: Any) -> str:
    sid = getattr(event, "Sid", None)
    if sid is None:
        return ""
    return str(sid)


def _event_to_row(event: Any, channel: str) -> dict[str, object]:
    event_type_code = int(getattr(event, "EventType", 0) or 0)

    return {
        "RecordID": int(getattr(event, "RecordNumber", 0) or 0),
        "TimeGenerated": getattr(event, "TimeGenerated", None),
        "MachineName": str(getattr(event, "ComputerName", "") or ""),
        "Channel": channel,
        "Source": str(getattr(event, "SourceName", "") or ""),
        "EventID": int(getattr(event, "EventID", 0) or 0) & 0xFFFF,
        "EventCategory": int(getattr(event, "EventCategory", 0) or 0),
        "EventTypeCode": event_type_code,
        "EntryType": entry_type_name(event_type_code),
        "UserName": _safe_username(event),
        "Message": _safe_message(event, channel),
        "RawData": _safe_raw_data(getattr(event, "Data", None)),
    }


def collect_windows_events(
    channel: str,
    after_record_id: int = 0,
    max_events: int = 200,
) -> pd.DataFrame:
    if channel not in SUPPORTED_CHANNELS:
        raise ValueError(
            f"Unsupported Windows Event Log channel: {channel!r}"
        )

    if not 1 <= int(max_events) <= 1000:
        raise ValueError("max_events must be between 1 and 1000.")

    if not is_windows_platform():
        raise RuntimeError("Windows Event Log collection requires Windows.")

    if win32evtlog is None or win32con is None or win32evtlogutil is None:
        raise RuntimeError("pywin32 is required for Windows Event Log collection.")

    handle = None
    rows: list[dict[str, object]] = []

    try:
        handle = win32evtlog.OpenEventLog(None, channel)
        read_flags = (
            win32evtlog.EVENTLOG_FORWARDS_READ
            | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        while len(rows) < int(max_events):
            events = win32evtlog.ReadEventLog(handle, read_flags, 0)
            if not events:
                break

            for event in events:
                record_id = int(getattr(event, "RecordNumber", 0) or 0)
                if record_id <= int(after_record_id):
                    continue

                rows.append(_event_to_row(event, channel))
                if len(rows) >= int(max_events):
                    break

    except Exception as error:
        if channel == "Security" and _is_access_denied(error):
            raise PermissionError(
                "Security log access was denied. Run VS Code as Administrator "
                "only when testing that channel, or continue using System and "
                "Application logs."
            ) from error
        raise
    finally:
        if handle is not None:
            win32evtlog.CloseEventLog(handle)

    if not rows:
        return _empty_raw_events()

    events_frame = pd.DataFrame(rows, columns=RAW_EVENT_COLUMNS)
    events_frame = events_frame.sort_values("RecordID").reset_index(drop=True)
    return events_frame


def get_newest_record_id(
    channel: str,
) -> int:
    if channel not in SUPPORTED_CHANNELS:
        raise ValueError(
            f"Unsupported Windows Event Log channel: {channel!r}"
        )

    if not is_windows_platform():
        raise RuntimeError("Windows Event Log collection requires Windows.")

    if win32evtlog is None:
        raise RuntimeError("pywin32 is required for Windows Event Log collection.")

    handle = None

    try:
        handle = win32evtlog.OpenEventLog(None, channel)
        oldest_record_id = int(win32evtlog.GetOldestEventLogRecord(handle))
        record_count = int(win32evtlog.GetNumberOfEventLogRecords(handle))

        if record_count <= 0:
            return 0

        return oldest_record_id + record_count - 1
    except Exception as error:
        if channel == "Security" and _is_access_denied(error):
            raise PermissionError(
                "Security log access was denied. Run VS Code as Administrator "
                "only when testing that channel, or continue using System and "
                "Application logs."
            ) from error
        raise
    finally:
        if handle is not None:
            win32evtlog.CloseEventLog(handle)
