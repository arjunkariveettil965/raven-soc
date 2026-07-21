from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import sqlite3
from typing import Any

from backend.repositories.base import (
    RepositoryConflictError,
    RepositoryError,
    RepositoryUnavailableError,
    StoredIncident,
    StoredRun,
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _json_dump(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), default=str, allow_nan=False)


def _json_load(text: str | None) -> object:
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise RepositoryError("Stored JSON payload is malformed.") from error


class SQLiteIncidentRepository:
    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)

    def _connect(self) -> sqlite3.Connection:
        try:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.database_path, timeout=5.0)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            return connection
        except sqlite3.Error as error:
            raise RepositoryUnavailableError("API database is unavailable.") from error

    def initialize(self) -> None:
        try:
            with self._connect() as connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS api_runs (
                        run_id TEXT PRIMARY KEY,
                        scenario_label TEXT NOT NULL,
                        seed INTEGER,
                        difficulty TEXT,
                        noise_level TEXT,
                        scenario_mode TEXT,
                        answer_revealed INTEGER NOT NULL DEFAULT 0,
                        event_count INTEGER NOT NULL DEFAULT 0,
                        attack_event_count INTEGER NOT NULL DEFAULT 0,
                        benign_event_count INTEGER NOT NULL DEFAULT 0,
                        created_at TEXT NOT NULL,
                        run_payload_json TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS api_incidents (
                        incident_id TEXT PRIMARY KEY,
                        run_id TEXT NOT NULL,
                        incident_type TEXT,
                        severity TEXT,
                        confidence REAL,
                        target TEXT,
                        requires_approval INTEGER NOT NULL DEFAULT 0,
                        recommended_action_id TEXT,
                        first_seen TEXT,
                        last_seen TEXT,
                        incident_payload_json TEXT NOT NULL,
                        timeline_json TEXT NOT NULL,
                        environment_profile_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        FOREIGN KEY(run_id) REFERENCES api_runs(run_id) ON DELETE CASCADE
                    );
                    CREATE TABLE IF NOT EXISTS api_analyses (
                        analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        incident_id TEXT NOT NULL,
                        analyst_mode TEXT,
                        model_name TEXT,
                        used_fallback INTEGER NOT NULL DEFAULT 0,
                        fallback_reason TEXT,
                        validation_errors_json TEXT NOT NULL,
                        analyst_result_json TEXT NOT NULL,
                        metadata_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(incident_id) REFERENCES api_incidents(incident_id) ON DELETE CASCADE
                    );
                    CREATE TABLE IF NOT EXISTS api_action_decisions (
                        decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        incident_id TEXT NOT NULL UNIQUE,
                        action_id TEXT NOT NULL,
                        target TEXT,
                        decision TEXT NOT NULL,
                        execution_mode TEXT NOT NULL,
                        message TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(incident_id) REFERENCES api_incidents(incident_id) ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS idx_api_runs_created_at ON api_runs(created_at);
                    CREATE INDEX IF NOT EXISTS idx_api_runs_scenario_label ON api_runs(scenario_label);
                    CREATE INDEX IF NOT EXISTS idx_api_incidents_run_id ON api_incidents(run_id);
                    CREATE INDEX IF NOT EXISTS idx_api_incidents_type ON api_incidents(incident_type);
                    CREATE INDEX IF NOT EXISTS idx_api_incidents_severity ON api_incidents(severity);
                    CREATE INDEX IF NOT EXISTS idx_api_analyses_incident_id ON api_analyses(incident_id);
                    CREATE INDEX IF NOT EXISTS idx_api_actions_incident_id ON api_action_decisions(incident_id);
                    """
                )
        except sqlite3.Error as error:
            raise RepositoryUnavailableError("API database schema initialization failed.") from error

    def health(self) -> dict[str, object]:
        try:
            self.initialize()
            with self._connect() as connection:
                connection.execute("SELECT 1").fetchone()
            return {
                "available": True,
                "backend": "sqlite",
                "path_display": self.database_path.name,
                "persistent": True,
                "schema_initialized": True,
            }
        except RepositoryError:
            return {
                "available": False,
                "backend": "sqlite",
                "path_display": self.database_path.name,
                "persistent": True,
                "schema_initialized": False,
            }

    def save_run(self, run_id: str, result: dict[str, Any], incidents: list[StoredIncident]) -> None:
        created_at = _now()
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT OR REPLACE INTO api_runs (
                        run_id, scenario_label, seed, difficulty, noise_level, scenario_mode,
                        answer_revealed, event_count, attack_event_count, benign_event_count,
                        created_at, run_payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        str(result.get("ScenarioLabel", "")),
                        result.get("Seed"),
                        result.get("Difficulty"),
                        result.get("NoiseLevel"),
                        result.get("ScenarioMode", ""),
                        1 if result.get("AnswerRevealed") else 0,
                        int(result.get("EventCount", 0)),
                        int(result.get("AttackEventCount", 0)),
                        int(result.get("BenignEventCount", 0)),
                        created_at,
                        _json_dump(result),
                    ),
                )
                for stored in incidents:
                    incident = stored.incident
                    connection.execute(
                        """
                        INSERT OR REPLACE INTO api_incidents (
                            incident_id, run_id, incident_type, severity, confidence, target,
                            requires_approval, recommended_action_id, first_seen, last_seen,
                            incident_payload_json, timeline_json, environment_profile_json,
                            created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            stored.incident_id,
                            run_id,
                            incident.get("IncidentType") or incident.get("CorrelationPattern"),
                            incident.get("IncidentSeverity") or incident.get("Severity"),
                            incident.get("IncidentConfidence") or incident.get("Confidence"),
                            incident.get("Target") or incident.get("AffectedDevice") or incident.get("SourceIP"),
                            1 if incident.get("RequiresApproval") else 0,
                            incident.get("RecommendedActionID"),
                            incident.get("FirstSeen"),
                            incident.get("LastSeen"),
                            _json_dump(stored.incident),
                            _json_dump(stored.timeline),
                            _json_dump(stored.environment_profile),
                            created_at,
                            created_at,
                        ),
                    )
                    self._save_analysis(connection, stored.incident_id, stored.analysis, stored.analyst_metadata, created_at)
        except sqlite3.IntegrityError as error:
            raise RepositoryConflictError("API repository constraint conflict.") from error
        except sqlite3.Error as error:
            raise RepositoryUnavailableError("API database write failed.") from error

    store_run = save_run

    def _row_to_run(self, row: sqlite3.Row) -> StoredRun:
        payload = _json_load(row["run_payload_json"])
        if not isinstance(payload, dict):
            raise RepositoryError("Stored run payload is malformed.")
        payload.setdefault("CreatedAt", row["created_at"])
        return StoredRun(run_id=str(row["run_id"]), result=payload)

    def get_run(self, run_id: str) -> StoredRun | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM api_runs WHERE run_id = ?", (run_id,)).fetchone()
        return None if row is None else self._row_to_run(row)

    def list_runs(self, limit: int = 50, scenario_label: str | None = None, difficulty: str | None = None, created_after: str | None = None, created_before: str | None = None) -> list[StoredRun]:
        query = "SELECT * FROM api_runs WHERE 1=1"
        params: list[object] = []
        if scenario_label:
            query += " AND lower(scenario_label) LIKE ?"
            params.append(f"%{scenario_label.lower()}%")
        if difficulty:
            query += " AND lower(difficulty) = ?"
            params.append(difficulty.lower())
        if created_after:
            query += " AND created_at >= ?"
            params.append(created_after)
        if created_before:
            query += " AND created_at <= ?"
            params.append(created_before)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(0, int(limit)))
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._row_to_run(row) for row in rows]

    def _row_to_incident(self, row: sqlite3.Row) -> StoredIncident:
        incident = _json_load(row["incident_payload_json"])
        timeline = _json_load(row["timeline_json"])
        environment_profile = _json_load(row["environment_profile_json"])
        if not isinstance(incident, dict) or not isinstance(timeline, list) or not isinstance(environment_profile, dict):
            raise RepositoryError("Stored incident payload is malformed.")
        latest_analysis = self.get_latest_analysis(str(row["incident_id"])) or {}
        action_decision = self.get_action_decision(str(row["incident_id"]))
        return StoredIncident(
            run_id=str(row["run_id"]),
            incident_id=str(row["incident_id"]),
            incident=incident,
            timeline=timeline,
            analysis=dict(latest_analysis.get("AnalystResult", {})),
            analyst_metadata=dict(latest_analysis.get("AnalystMetadata", {})),
            environment_profile=environment_profile,
            action_decision=action_decision,
        )

    def list_incidents(self, limit: int = 50, severity: str | None = None, incident_type: str | None = None) -> list[StoredIncident]:
        query = "SELECT * FROM api_incidents WHERE 1=1"
        params: list[object] = []
        if severity:
            query += " AND lower(severity) = ?"
            params.append(severity.lower())
        if incident_type:
            query += " AND lower(incident_type) LIKE ?"
            params.append(f"%{incident_type.lower()}%")
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(0, int(limit)))
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._row_to_incident(row) for row in rows]

    def get_incident(self, incident_id: str) -> StoredIncident | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM api_incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        return None if row is None else self._row_to_incident(row)

    def _save_analysis(self, connection: sqlite3.Connection, incident_id: str, analysis: dict[str, Any], metadata: dict[str, Any], created_at: str | None = None) -> None:
        safe_metadata = dict(metadata)
        safe_metadata.pop("RawModelOutput", None)
        connection.execute(
            """
            INSERT INTO api_analyses (
                incident_id, analyst_mode, model_name, used_fallback, fallback_reason,
                validation_errors_json, analyst_result_json, metadata_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                safe_metadata.get("AnalystMode"),
                safe_metadata.get("ModelName"),
                1 if safe_metadata.get("UsedFallback") else 0,
                safe_metadata.get("FallbackReason"),
                _json_dump(safe_metadata.get("ValidationErrors", [])),
                _json_dump(analysis),
                _json_dump(safe_metadata),
                created_at or _now(),
            ),
        )

    def save_analysis(self, incident_id: str, analysis: dict[str, Any], metadata: dict[str, Any]) -> None:
        try:
            with self._connect() as connection:
                self._save_analysis(connection, incident_id, analysis, metadata)
                connection.execute("UPDATE api_incidents SET updated_at = ? WHERE incident_id = ?", (_now(), incident_id))
        except sqlite3.IntegrityError as error:
            raise RepositoryConflictError("Analysis refers to an unknown incident.") from error

    def get_latest_analysis(self, incident_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM api_analyses WHERE incident_id = ? ORDER BY analysis_id DESC LIMIT 1",
                (incident_id,),
            ).fetchone()
        if row is None:
            return None
        analysis = _json_load(row["analyst_result_json"])
        metadata = _json_load(row["metadata_json"])
        if not isinstance(analysis, dict) or not isinstance(metadata, dict):
            raise RepositoryError("Stored analysis payload is malformed.")
        return {"IncidentID": incident_id, "AnalystResult": analysis, "AnalystMetadata": metadata, "CreatedAt": row["created_at"]}

    def save_action_decision(self, incident_id: str, decision: dict[str, Any]) -> dict[str, Any]:
        existing = self.get_action_decision(incident_id)
        if existing is not None:
            if existing.get("Decision") != decision.get("Decision"):
                raise RepositoryConflictError("Incident already has a conflicting action decision.")
            return existing
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO api_action_decisions (
                        incident_id, action_id, target, decision, execution_mode, message, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        decision.get("ActionID"),
                        decision.get("Target"),
                        decision.get("Decision"),
                        decision.get("ExecutionMode"),
                        decision.get("Message"),
                        decision.get("Timestamp") or _now(),
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise RepositoryConflictError("Action decision could not be saved.") from error
        return dict(decision)

    def get_action_decision(self, incident_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM api_action_decisions WHERE incident_id = ?", (incident_id,)).fetchone()
        if row is None:
            return None
        return {
            "IncidentID": str(row["incident_id"]),
            "ActionID": str(row["action_id"]),
            "Target": str(row["target"] or ""),
            "Decision": str(row["decision"]),
            "ExecutionMode": str(row["execution_mode"]),
            "Message": str(row["message"]),
            "Timestamp": str(row["created_at"]),
        }

    def clear_for_tests(self) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM api_action_decisions")
            connection.execute("DELETE FROM api_analyses")
            connection.execute("DELETE FROM api_incidents")
            connection.execute("DELETE FROM api_runs")
