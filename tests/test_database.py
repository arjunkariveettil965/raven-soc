import sqlite3
from pathlib import Path

import pandas as pd

import database.database as database_module


def create_sample_normalized_events() -> pd.DataFrame:
    """
    Create normalized security events for database testing.
    """

    return pd.DataFrame(
        {
            "EventTime": [
                "2026-07-18 10:00:00",
                "2026-07-18 10:01:00",
            ],
            "DeviceName": [
                "TEST-PC",
                "SERVER-01",
            ],
            "UserName": [
                "test-user",
                "administrator",
            ],
            "EventSource": [
                "Security",
                "Sysmon",
            ],
            "EventType": [
                "Authentication",
                "Process Creation",
            ],
            "EventResult": [
                "Failure",
                "Success",
            ],
            "EventSeverity": [
                "High",
                "Medium",
            ],
            "SourceIP": [
                "192.168.1.10",
                "192.168.1.20",
            ],
            "DestinationIP": [
                "192.168.1.100",
                "192.168.1.101",
            ],
            "ProcessName": [
                "",
                "powershell.exe",
            ],
            "CommandLine": [
                "",
                "powershell.exe -EncodedCommand TEST",
            ],
            "Country": [
                "India",
                "India",
            ],
            "RawMessage": [
                "Repeated authentication failure",
                "PowerShell process created",
            ],
        }
    )


def test_security_event_database(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """
    Verify that the SQLite layer can initialize, save,
    count and load normalized security events.
    """

    temporary_database_path = (
        tmp_path / "test_raven_soc.db"
    )

    monkeypatch.setattr(
        database_module,
        "DATABASE_DIRECTORY",
        tmp_path,
    )

    monkeypatch.setattr(
        database_module,
        "DATABASE_PATH",
        temporary_database_path,
    )

    database_module.initialize_database()

    assert temporary_database_path.exists()
    assert database_module.count_security_events() == 0

    sample_events = create_sample_normalized_events()

    inserted_count = database_module.save_security_events(
        normalized_logs=sample_events,
    )

    assert inserted_count == 2
    assert database_module.count_security_events() == 2

    stored_events = database_module.load_security_events()

    assert len(stored_events) == 2

    assert {
        "EventID",
        "EventTime",
        "DeviceName",
        "EventSeverity",
        "StoredAt",
    }.issubset(stored_events.columns)

    # Events are loaded newest first.
    assert stored_events.iloc[0]["DeviceName"] == "SERVER-01"
    assert stored_events.iloc[1]["DeviceName"] == "TEST-PC"

    assert (
        stored_events.iloc[0]["ProcessName"]
        == "powershell.exe"
    )

    assert (
        stored_events.iloc[0]["EventSeverity"]
        == "Medium"
    )

    limited_events = database_module.load_security_events(
        limit=1,
    )

    assert len(limited_events) == 1
    assert limited_events.iloc[0]["DeviceName"] == "SERVER-01"

    with sqlite3.connect(temporary_database_path) as connection:
        table = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'security_events'
            """
        ).fetchone()

    assert table is not None