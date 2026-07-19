from types import SimpleNamespace

import pandas as pd
import pytest

import collector.windows_event_collector as collector


class FakeWin32Con:
    EVENTLOG_ERROR_TYPE = 1
    EVENTLOG_WARNING_TYPE = 2
    EVENTLOG_INFORMATION_TYPE = 4
    EVENTLOG_AUDIT_SUCCESS = 8
    EVENTLOG_AUDIT_FAILURE = 16


class FakeWin32EventLog:
    EVENTLOG_FORWARDS_READ = 4
    EVENTLOG_SEQUENTIAL_READ = 1

    def __init__(
        self,
        batches=None,
        open_error=None,
        oldest_record_id=1,
        record_count=0,
    ):
        self.batches = list(batches or [])
        self.open_error = open_error
        self.oldest_record_id = oldest_record_id
        self.record_count = record_count
        self.closed_handles = []

    def OpenEventLog(self, machine, channel):
        if self.open_error is not None:
            raise self.open_error
        return f"handle-{channel}"

    def ReadEventLog(self, handle, flags, offset):
        if self.batches:
            return self.batches.pop(0)
        return []

    def CloseEventLog(self, handle):
        self.closed_handles.append(handle)

    def GetOldestEventLogRecord(self, handle):
        return self.oldest_record_id

    def GetNumberOfEventLogRecords(self, handle):
        return self.record_count


class FakeFormatter:
    @staticmethod
    def SafeFormatMessage(event, channel):
        if getattr(event, "format_fails", False):
            raise RuntimeError("format failed")
        return event.message


def fake_event(record_id, event_type=4, message="message"):
    return SimpleNamespace(
        RecordNumber=record_id,
        TimeGenerated=pd.Timestamp("2026-07-19 10:00:00"),
        ComputerName="WORKSTATION-1",
        SourceName="Service Control Manager",
        EventID=0x4000002A,
        EventCategory=0,
        EventType=event_type,
        Sid=None,
        Data=b"\x01\x02",
        message=message,
    )


def install_fake_win32(monkeypatch, fake_log):
    monkeypatch.setattr(collector, "is_windows_platform", lambda: True)
    monkeypatch.setattr(collector, "win32con", FakeWin32Con)
    monkeypatch.setattr(collector, "win32evtlog", fake_log)
    monkeypatch.setattr(collector, "win32evtlogutil", FakeFormatter)


def test_unsupported_channel_rejected():
    with pytest.raises(ValueError, match="Unsupported"):
        collector.collect_windows_events("Setup")


def test_invalid_max_events_rejected():
    with pytest.raises(ValueError, match="max_events"):
        collector.collect_windows_events("System", max_events=0)


def test_non_windows_platform_rejected(monkeypatch):
    monkeypatch.setattr(collector, "is_windows_platform", lambda: False)

    with pytest.raises(RuntimeError, match="requires Windows"):
        collector.collect_windows_events("System")


def test_empty_result_has_stable_schema(monkeypatch):
    fake_log = FakeWin32EventLog(batches=[[]])
    install_fake_win32(monkeypatch, fake_log)

    result = collector.collect_windows_events("System")

    assert result.empty
    assert list(result.columns) == collector.RAW_EVENT_COLUMNS


def test_mocked_events_are_filtered_by_record_id(monkeypatch):
    fake_log = FakeWin32EventLog(
        batches=[[fake_event(1), fake_event(3), fake_event(5)], []]
    )
    install_fake_win32(monkeypatch, fake_log)

    result = collector.collect_windows_events("System", after_record_id=2)

    assert result["RecordID"].tolist() == [3, 5]


def test_mocked_results_are_ordered_oldest_to_newest(monkeypatch):
    fake_log = FakeWin32EventLog(
        batches=[[fake_event(10), fake_event(8), fake_event(9)], []]
    )
    install_fake_win32(monkeypatch, fake_log)

    result = collector.collect_windows_events("Application")

    assert result["RecordID"].tolist() == [8, 9, 10]


def test_event_type_mapping_works(monkeypatch):
    monkeypatch.setattr(collector, "win32con", FakeWin32Con)

    assert collector.entry_type_name(1) == "Error"
    assert collector.entry_type_name(2) == "Warning"
    assert collector.entry_type_name(4) == "Information"
    assert collector.entry_type_name(8) == "Audit Success"
    assert collector.entry_type_name(16) == "Audit Failure"
    assert collector.entry_type_name(999) == "Unknown"


def test_permission_failure_becomes_clear_permission_error(monkeypatch):
    error = OSError(5, "access denied")
    fake_log = FakeWin32EventLog(open_error=error)
    install_fake_win32(monkeypatch, fake_log)

    with pytest.raises(PermissionError, match="Security log access was denied"):
        collector.collect_windows_events("Security")


def test_handles_are_closed(monkeypatch):
    fake_log = FakeWin32EventLog(batches=[[fake_event(1)], []])
    install_fake_win32(monkeypatch, fake_log)

    collector.collect_windows_events("System")

    assert fake_log.closed_handles == ["handle-System"]


def test_newest_record_id_is_returned(monkeypatch):
    fake_log = FakeWin32EventLog(oldest_record_id=10, record_count=5)
    install_fake_win32(monkeypatch, fake_log)

    assert collector.get_newest_record_id("System") == 14


def test_newest_record_id_empty_channel_returns_zero(monkeypatch):
    fake_log = FakeWin32EventLog(oldest_record_id=10, record_count=0)
    install_fake_win32(monkeypatch, fake_log)

    assert collector.get_newest_record_id("Application") == 0


def test_newest_record_id_unsupported_channel_rejected():
    with pytest.raises(ValueError, match="Unsupported"):
        collector.get_newest_record_id("Setup")


def test_newest_record_id_permission_failure_is_clear(monkeypatch):
    error = OSError(5, "access denied")
    fake_log = FakeWin32EventLog(open_error=error)
    install_fake_win32(monkeypatch, fake_log)

    with pytest.raises(PermissionError, match="Security log access was denied"):
        collector.get_newest_record_id("Security")


def test_newest_record_id_handle_is_closed(monkeypatch):
    fake_log = FakeWin32EventLog(oldest_record_id=1, record_count=3)
    install_fake_win32(monkeypatch, fake_log)

    collector.get_newest_record_id("System")

    assert fake_log.closed_handles == ["handle-System"]
