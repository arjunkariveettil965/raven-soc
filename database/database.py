import sqlite3
from pathlib import Path

import pandas as pd


DATABASE_DIRECTORY = Path(__file__).resolve().parent
DATABASE_PATH = DATABASE_DIRECTORY / "raven_soc.db"


def get_database_connection() -> sqlite3.Connection:
    """
    Create and return a connection to the RAVEN-SOC SQLite database.

    Row factory allows database rows to behave similarly to dictionaries.
    """

    DATABASE_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        DATABASE_PATH,
        check_same_thread=False,
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database() -> None:
    """
    Create the initial RAVEN-SOC database tables.
    """

    connection = get_database_connection()

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
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
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        connection.commit()

    finally:
        connection.close()


def save_security_events(
    normalized_logs: pd.DataFrame,
) -> int:
    """
    Save normalized security events into SQLite.

    Returns the number of inserted events.
    """

    if normalized_logs.empty:
        return 0

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
            "Normalized logs are missing database columns: "
            f"{sorted(missing_columns)}"
        )

    events_to_save = normalized_logs[
        [
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
    ].copy()

    events_to_save["EventTime"] = pd.to_datetime(
        events_to_save["EventTime"],
        errors="coerce",
    ).astype(str)

    events_to_save = events_to_save.where(
        pd.notna(events_to_save),
        None,
    )

    records = list(
        events_to_save.itertuples(
            index=False,
            name=None,
        )
    )

    connection = get_database_connection()

    try:
        connection.executemany(
            """
            INSERT INTO security_events (
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
                raw_message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            records,
        )

        connection.commit()

        return len(records)

    finally:
        connection.close()


def load_security_events(
    limit: int | None = None,
) -> pd.DataFrame:
    """
    Load stored security events from SQLite.

    When a limit is supplied, the newest events are returned.
    """

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
                created_at AS StoredAt
            FROM security_events
            ORDER BY id DESC
        """

        parameters: tuple[int, ...] = ()

        if limit is not None:
            if limit <= 0:
                raise ValueError(
                    "Event limit must be greater than zero."
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
    Return the number of security events stored in SQLite.
    """

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