import sqlite3
from pathlib import Path

import pandas as pd
import pytest

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


def configure_test_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """
    Point the database module to a temporary SQLite file.
    """

    temporary_database_path = (
        tmp_path / "test_raven_soc.db"
    )

    monkeypatch.setattr(
        database_module,
        "DATABASE_PATH",
        temporary_database_path,
        raising=False,
    )

    return temporary_database_path


def test_security_event_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Verify initialization, duplicate prevention,
    WAL mode, indexes, loading and limiting.
    """

    temporary_database_path = configure_test_database(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
    )

    database_module.initialize_database()

    assert temporary_database_path.exists()
    assert database_module.count_security_events() == 0

    sample_events = create_sample_normalized_events()

    first_save_result = database_module.save_security_events(
        normalized_logs=sample_events,
    )

    assert first_save_result == {
        "received": 2,
        "inserted": 2,
        "duplicates_skipped": 0,
    }

    assert database_module.count_security_events() == 2

    second_save_result = database_module.save_security_events(
        normalized_logs=sample_events,
    )

    assert second_save_result == {
        "received": 2,
        "inserted": 0,
        "duplicates_skipped": 2,
    }

    assert database_module.count_security_events() == 2

    duplicate_batch = pd.DataFrame(
        [
            sample_events.iloc[0].to_dict(),
            sample_events.iloc[0].to_dict(),
            sample_events.iloc[1].to_dict(),
        ]
    )

    duplicate_batch_result = database_module.save_security_events(
        normalized_logs=duplicate_batch,
    )

    assert duplicate_batch_result == {
        "received": 3,
        "inserted": 0,
        "duplicates_skipped": 3,
    }

    assert database_module.count_security_events() == 2

    changed_events = sample_events.copy()

    changed_events.loc[
        0,
        "RawMessage",
    ] = "Changed authentication failure"

    changed_event_result = database_module.save_security_events(
        normalized_logs=changed_events,
    )

    assert changed_event_result == {
        "received": 2,
        "inserted": 1,
        "duplicates_skipped": 1,
    }

    assert database_module.count_security_events() == 3

    stored_events = database_module.load_security_events()

    assert len(stored_events) == 3

    expected_columns = {
        "EventID",
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
        "StoredAt",
    }

    assert expected_columns.issubset(
        set(stored_events.columns)
    )

    # The changed TEST-PC event was inserted last,
    # so it is returned first.
    assert stored_events.iloc[0]["DeviceName"] == "TEST-PC"
    assert (
        stored_events.iloc[0]["RawMessage"]
        == "Changed authentication failure"
    )

    assert stored_events.iloc[1]["DeviceName"] == "SERVER-01"
    assert stored_events.iloc[2]["DeviceName"] == "TEST-PC"

    assert (
        stored_events.iloc[1]["ProcessName"]
        == "powershell.exe"
    )

    assert (
        stored_events.iloc[1]["EventSeverity"]
        == "Medium"
    )

    limited_events = database_module.load_security_events(
        limit=1,
    )

    assert len(limited_events) == 1
    assert limited_events.iloc[0]["DeviceName"] == "TEST-PC"
    assert (
        limited_events.iloc[0]["RawMessage"]
        == "Changed authentication failure"
    )

    with pytest.raises(
        ValueError,
        match="greater than zero",
    ):
        database_module.load_security_events(
            limit=0,
        )

    with sqlite3.connect(
        temporary_database_path
    ) as connection:
        table = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'security_events'
            """
        ).fetchone()

        assert table is not None

        journal_mode = connection.execute(
            "PRAGMA journal_mode"
        ).fetchone()[0]

        assert journal_mode.lower() == "wal"

        index_rows = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'index'
              AND tbl_name = 'security_events'
            """
        ).fetchall()

        index_names = {
            row[0]
            for row in index_rows
        }

        required_indexes = {
            "idx_events_fingerprint",
            "idx_events_analysis_status_id",
            "idx_events_device_time",
            "idx_events_type_time",
            "idx_events_windows_event_id_time",
        }

        assert required_indexes.issubset(
            index_names
        )

        stored_fingerprints = connection.execute(
            """
            SELECT event_fingerprint
            FROM security_events
            """
        ).fetchall()

        assert len(stored_fingerprints) == 3

        assert all(
            fingerprint[0] is not None
            and len(fingerprint[0]) == 64
            for fingerprint in stored_fingerprints
        )

        duplicate_fingerprint_count = (
            connection.execute(
                """
                SELECT COUNT(*)
                FROM (
                    SELECT event_fingerprint
                    FROM security_events
                    GROUP BY event_fingerprint
                    HAVING COUNT(*) > 1
                )
                """
            ).fetchone()[0]
        )

        assert duplicate_fingerprint_count == 0