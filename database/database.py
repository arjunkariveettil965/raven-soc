import hashlib
import sqlite3
from pathlib import Path

import pandas as pd


DATABASE_DIRECTORY = Path(__file__).resolve().parent
DATABASE_PATH = DATABASE_DIRECTORY / "raven_soc.db"

FINGERPRINT_FIELDS = [
    "EventTime",
    "DeviceName",
    "UserName",
    "EventSource",
    "EventType",
    "EventResult",
    "SourceIP",
    "DestinationIP",
    "ProcessName",
    "CommandLine",
    "RawMessage",
]


def get_database_connection() -> sqlite3.Connection:
    """
    Create and return a configured SQLite connection.
    """

    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=5.0,
        check_same_thread=False,
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA journal_mode=WAL"
    )

    connection.execute(
        "PRAGMA synchronous=NORMAL"
    )

    connection.execute(
        "PRAGMA busy_timeout=5000"
    )

    connection.execute(
        "PRAGMA foreign_keys=ON"
    )

    connection.execute(
        "PRAGMA wal_autocheckpoint=1000"
    )

    return connection


def _normalize_database_value(
    value: object,
) -> object:
    """
    Convert pandas and Python values into stable SQLite values.
    """

    if value is None:
        return None

    if isinstance(value, pd.Timestamp):
        return value.isoformat()

    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass

    if isinstance(value, str):
        cleaned_value = value.strip()

        if not cleaned_value:
            return None

        return cleaned_value

    return value


def _normalize_fingerprint_value(
    value: object,
) -> str:
    """
    Convert a value into a stable string for fingerprinting.
    """

    normalized_value = _normalize_database_value(
        value
    )

    if normalized_value is None:
        return ""

    return str(normalized_value).strip()


def build_event_fingerprint(
    event_values: dict[str, object],
) -> str:
    """
    Build a deterministic SHA-256 fingerprint for one event.
    """

    fingerprint_parts = [
        _normalize_fingerprint_value(
            event_values.get(field_name)
        )
        for field_name in FINGERPRINT_FIELDS
    ]

    fingerprint_payload = "\x1f".join(
        fingerprint_parts
    )

    return hashlib.sha256(
        fingerprint_payload.encode("utf-8")
    ).hexdigest()


def _get_existing_columns(
    connection: sqlite3.Connection,
) -> set[str]:
    """
    Return the existing columns in security_events.
    """

    rows = connection.execute(
        "PRAGMA table_info(security_events)"
    ).fetchall()

    return {
        str(row["name"])
        for row in rows
    }


def _add_missing_columns(
    connection: sqlite3.Connection,
) -> None:
    """
    Safely add newer columns to an existing database.
    """

    existing_columns = _get_existing_columns(
        connection
    )

    migration_columns = {
        "event_fingerprint": "TEXT",
        "windows_event_id": "INTEGER",
        "parent_process_name": "TEXT",
        "raw_payload": "TEXT",
        "analysis_status": (
            "TEXT NOT NULL DEFAULT 'pending'"
        ),
        "analysis_attempts": (
            "INTEGER NOT NULL DEFAULT 0"
        ),
        "analysis_started_at": "TEXT",
        "analysis_completed_at": "TEXT",
        "analysis_error": "TEXT",
    }

    for column_name, column_definition in (
        migration_columns.items()
    ):
        if column_name in existing_columns:
            continue

        connection.execute(
            f"""
            ALTER TABLE security_events
            ADD COLUMN {column_name}
            {column_definition}
            """
        )

    connection.commit()


def _backfill_existing_fingerprints(
    connection: sqlite3.Connection,
) -> None:
    """
    Create fingerprints for rows saved before fingerprint support.
    """

    rows = connection.execute(
        """
        SELECT
            id,
            event_time,
            device_name,
            user_name,
            event_source,
            event_type,
            event_result,
            source_ip,
            destination_ip,
            process_name,
            command_line,
            raw_message
        FROM security_events
        WHERE event_fingerprint IS NULL
           OR event_fingerprint = ''
        """
    ).fetchall()

    if not rows:
        return

    fingerprint_updates: list[
        tuple[str, int]
    ] = []

    for row in rows:
        event_values = {
            "EventTime": row["event_time"],
            "DeviceName": row["device_name"],
            "UserName": row["user_name"],
            "EventSource": row["event_source"],
            "EventType": row["event_type"],
            "EventResult": row["event_result"],
            "SourceIP": row["source_ip"],
            "DestinationIP": row["destination_ip"],
            "ProcessName": row["process_name"],
            "CommandLine": row["command_line"],
            "RawMessage": row["raw_message"],
        }

        fingerprint = build_event_fingerprint(
            event_values
        )

        fingerprint_updates.append(
            (
                fingerprint,
                int(row["id"]),
            )
        )

    connection.executemany(
        """
        UPDATE security_events
        SET event_fingerprint = ?
        WHERE id = ?
        """,
        fingerprint_updates,
    )

    connection.commit()


def _remove_existing_duplicates(
    connection: sqlite3.Connection,
) -> None:
    """
    Keep the oldest copy of any pre-existing duplicate event.

    This runs before creation of the unique fingerprint index.
    """

    connection.execute(
        """
        DELETE FROM security_events
        WHERE event_fingerprint IS NOT NULL
          AND event_fingerprint != ''
          AND id NOT IN (
              SELECT MIN(id)
              FROM security_events
              WHERE event_fingerprint IS NOT NULL
                AND event_fingerprint != ''
              GROUP BY event_fingerprint
          )
        """
    )

    connection.commit()


def _create_database_indexes(
    connection: sqlite3.Connection,
) -> None:
    """
    Create indexes used by duplicate prevention and analysis.
    """

    connection.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_events_fingerprint
        ON security_events(event_fingerprint)
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_events_analysis_status_id
        ON security_events(
            analysis_status,
            id
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_events_device_time
        ON security_events(
            device_name,
            event_time
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_events_type_time
        ON security_events(
            event_type,
            event_time
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_events_windows_event_id_time
        ON security_events(
            windows_event_id,
            event_time
        )
        """
    )

    connection.commit()


def initialize_database() -> None:
    """
    Create and migrate the RAVEN-SOC database.
    """

    connection = get_database_connection()

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS
            security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL,
                device_name TEXT NOT NULL,
                user_name TEXT,
                event_source TEXT,
                event_type TEXT,
                event_result TEXT,
                event_severity TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                process_name TEXT,
                command_line TEXT,
                country TEXT,
                raw_message TEXT,
                event_fingerprint TEXT,
                windows_event_id INTEGER,
                parent_process_name TEXT,
                raw_payload TEXT,
                analysis_status TEXT
                    NOT NULL
                    DEFAULT 'pending',
                analysis_attempts INTEGER
                    NOT NULL
                    DEFAULT 0,
                analysis_started_at TEXT,
                analysis_completed_at TEXT,
                analysis_error TEXT,
                created_at TEXT
                    DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        connection.commit()

        _add_missing_columns(
            connection
        )

        _backfill_existing_fingerprints(
            connection
        )

        _remove_existing_duplicates(
            connection
        )

        _create_database_indexes(
            connection
        )

    finally:
        connection.close()


def save_security_events(
    normalized_logs: pd.DataFrame,
) -> dict[str, int]:
    """
    Save normalized events while ignoring duplicates.

    Returns:
        received:
            Number of rows supplied.

        inserted:
            Number of genuinely new events saved.

        duplicates_skipped:
            Number of rows ignored because their fingerprints
            already existed.
    """

    if normalized_logs.empty:
        return {
            "received": 0,
            "inserted": 0,
            "duplicates_skipped": 0,
        }

    required_columns = {
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
    }

    missing_columns = (
        required_columns
        - set(normalized_logs.columns)
    )

    if missing_columns:
        raise ValueError(
            "Normalized logs are missing database "
            "columns: "
            f"{sorted(missing_columns)}"
        )

    records: list[
        tuple[object, ...]
    ] = []

    for _, row in normalized_logs.iterrows():
        event_values = {
            column_name:
                _normalize_database_value(
                    row.get(column_name)
                )
            for column_name in required_columns
        }

        fingerprint = build_event_fingerprint(
            event_values
        )

        windows_event_id = (
            _normalize_database_value(
                row.get("WindowsEventID")
            )
            if "WindowsEventID"
            in normalized_logs.columns
            else None
        )

        parent_process_name = (
            _normalize_database_value(
                row.get("ParentProcessName")
            )
            if "ParentProcessName"
            in normalized_logs.columns
            else None
        )

        raw_payload = (
            _normalize_database_value(
                row.get("RawPayload")
            )
            if "RawPayload"
            in normalized_logs.columns
            else None
        )

        records.append(
            (
                event_values["EventTime"],
                event_values["DeviceName"],
                event_values["UserName"],
                event_values["EventSource"],
                event_values["EventType"],
                event_values["EventResult"],
                event_values["EventSeverity"],
                event_values["SourceIP"],
                event_values["DestinationIP"],
                event_values["ProcessName"],
                event_values["CommandLine"],
                event_values["Country"],
                event_values["RawMessage"],
                fingerprint,
                windows_event_id,
                parent_process_name,
                raw_payload,
                "pending",
                0,
                None,
                None,
                None,
            )
        )

    initialize_database()

    connection = get_database_connection()

    try:
        before_changes = connection.total_changes

        connection.executemany(
            """
            INSERT OR IGNORE INTO security_events (
                event_time,
                device_name,
                user_name,
                event_source,
                event_type,
                event_result,
                event_severity,
                source_ip,
                destination_ip,
                process_name,
                command_line,
                country,
                raw_message,
                event_fingerprint,
                windows_event_id,
                parent_process_name,
                raw_payload,
                analysis_status,
                analysis_attempts,
                analysis_started_at,
                analysis_completed_at,
                analysis_error
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            records,
        )

        connection.commit()

        inserted_count = (
            connection.total_changes
            - before_changes
        )

        received_count = len(records)

        return {
            "received": received_count,
            "inserted": inserted_count,
            "duplicates_skipped": (
                received_count
                - inserted_count
            ),
        }

    finally:
        connection.close()


def load_security_events(
    limit: int | None = None,
) -> pd.DataFrame:
    """
    Load security events, newest first.
    """

    initialize_database()

    connection = get_database_connection()

    try:
        query = """
            SELECT
                id AS EventID,
                event_time AS EventTime,
                device_name AS DeviceName,
                user_name AS UserName,
                event_source AS EventSource,
                event_type AS EventType,
                event_result AS EventResult,
                event_severity AS EventSeverity,
                source_ip AS SourceIP,
                destination_ip AS DestinationIP,
                process_name AS ProcessName,
                command_line AS CommandLine,
                country AS Country,
                raw_message AS RawMessage,
                windows_event_id AS WindowsEventID,
                parent_process_name
                    AS ParentProcessName,
                raw_payload AS RawPayload,
                event_fingerprint
                    AS EventFingerprint,
                analysis_status
                    AS AnalysisStatus,
                analysis_attempts
                    AS AnalysisAttempts,
                created_at AS StoredAt
            FROM security_events
            ORDER BY id DESC
        """

        parameters: tuple[int, ...] = ()

        if limit is not None:
            if limit <= 0:
                raise ValueError(
                    "Event limit must be greater "
                    "than zero."
                )

            query += " LIMIT ?"
            parameters = (limit,)

        events = pd.read_sql_query(
            query,
            connection,
            params=parameters,
        )

    finally:
        connection.close()

    if not events.empty:
        events["EventTime"] = pd.to_datetime(
            events["EventTime"],
            errors="coerce",
        )

        events["StoredAt"] = pd.to_datetime(
            events["StoredAt"],
            errors="coerce",
        )

    return events


def count_security_events() -> int:
    """
    Return the total stored-event count.
    """

    initialize_database()

    connection = get_database_connection()

    try:
        result = connection.execute(
            """
            SELECT COUNT(*)
            FROM security_events
            """
        ).fetchone()

        return int(result[0])

    finally:
        connection.close()