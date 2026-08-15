from __future__ import annotations

from datetime import UTC, datetime
import threading
import time
from typing import Any

import pandas as pd

from ai_analyst import agent as analyst_agent
from ai_analyst import environment_adapter
from ai_analyst.ollama_client import DEFAULT_OLLAMA_MODEL
from backend.schemas.common import serialize_api_value
from backend.services.incident_service import build_incident_alert_collections
from backend.settings import settings
from collector.monitoring_state import find_unseen_alerts
from data_generation.scenario_lab import generate_scenario
from detection.alert_engine import analyze_security_events
from incidents import correlation_engine, incident_classifier, timeline_builder
from response.defender_agent import run_defender_agent


SUPPORTED_SCENARIOS: dict[str, str] = {
    "Multi Stage Intrusion": "multi_stage_intrusion",
    "Ransomware": "malware_download_execution",
    "Insider Threat": "command_control_beaconing",
    "Credential Attack": "password_spray_attempt",
}

SUPPORTED_SPEEDS = {0.5, 1.0, 2.0, 5.0, 10.0}


def _safe_metadata(metadata: dict[str, object]) -> dict[str, object]:
    safe = dict(metadata)
    safe.pop("RawModelOutput", None)
    return serialize_api_value(safe)  # type: ignore[return-value]


def _normalize_incident_row(
    correlated_incident: pd.Series,
    classified_incident: pd.Series,
) -> dict[str, object]:
    incident = dict(correlated_incident.to_dict())
    incident.update(dict(classified_incident.to_dict()))
    return serialize_api_value(incident)  # type: ignore[return-value]


def _event_to_mitre(event: dict[str, Any]) -> tuple[str, str]:
    event_type = str(event.get("EventType", "")).strip().lower()
    event_result = str(event.get("EventResult", "")).strip().lower()
    event_id = int(event.get("WindowsEventID") or 0)
    process_name = str(event.get("ProcessName", "")).strip().lower()
    command_line = str(event.get("CommandLine", "")).strip().lower()

    if event_type == "authentication" and event_result == "failure":
        return ("Credential Access", "T1110 - Brute Force")
    if event_type == "authentication" and event_result == "success":
        return ("Initial Access / Persistence", "T1078 - Valid Accounts")
    if event_id in {1, 4104} or "powershell" in process_name:
        return ("Execution", "T1059.001 - PowerShell")
    if event_type == "network connection" or event_id == 3:
        return ("Command and Control", "T1071 - Application Layer Protocol")
    if any(token in command_line for token in {"certutil", "bitsadmin", "mshta", "rundll32", "regsvr32"}):
        return ("Execution", "T1218 - System Binary Proxy Execution")
    return ("Discovery", "T1082 - System Information Discovery")


def _event_to_live_record(event: dict[str, Any]) -> dict[str, object]:
    tactic, technique = _event_to_mitre(event)
    event_time = pd.to_datetime(event.get("EventTime"), errors="coerce")
    return {
        "timestamp": event_time.isoformat() if pd.notna(event_time) else "",
        "hostname": str(event.get("DeviceName", "") or ""),
        "user": str(event.get("UserName", "") or ""),
        "event_id": int(event.get("WindowsEventID") or 0),
        "description": str(event.get("RawMessage", "") or ""),
        "mitre_tactic": tactic,
        "mitre_technique": technique,
        "severity": str(event.get("EventSeverity", "") or ""),
        "source": str(event.get("EventSource", "") or ""),
        "event_type": str(event.get("EventType", "") or ""),
    }


class LiveMonitoringService:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._worker: threading.Thread | None = None
        self._base_interval_seconds = 1.0
        self._max_events = 1000
        self._max_alerts = 400
        self._max_incidents = 200
        self._reset_state_locked()

    def _reset_state_locked(self) -> None:
        self._status = "stopped"
        self._scenario_name = "Multi Stage Intrusion"
        self._scenario_id = SUPPORTED_SCENARIOS[self._scenario_name]
        self._speed = 1.0
        self._seed = 20260729
        self._seed_cursor = self._seed
        self._batch_events: list[dict[str, Any]] = []
        self._batch_index = 0
        self._events: list[dict[str, object]] = []
        self._alerts: list[dict[str, object]] = []
        self._incidents: list[dict[str, object]] = []
        self._seen_alert_ids: set[str] = set()
        self._seen_incident_ids: set[str] = set()
        self._event_count = 0
        self._alert_count = 0
        self._incident_count = 0
        self._current_mitre_tactic = ""
        self._current_severity = ""
        self._latest_event: dict[str, object] | None = None
        self._latest_alert: dict[str, object] | None = None
        self._latest_incident: dict[str, object] | None = None
        self._environment_name = "Finance SME"
        self._analyst_mode = "deterministic"
        self._ollama_model = settings.default_ollama_model
        self._last_error: str | None = None
        self._updated_at = datetime.now(UTC).isoformat()
        self._all_events_df = pd.DataFrame()

    def _generate_batch_locked(self) -> None:
        scenario = generate_scenario(
            self._scenario_id,
            seed=self._seed_cursor,
            difficulty="Medium",
            noise_level="Low",
            environment=self._environment_name,
        )
        generated = scenario.get("GeneratedEvents", pd.DataFrame())
        if isinstance(generated, pd.DataFrame):
            frame = generated.copy()
        else:
            frame = pd.DataFrame(generated)
        frame["EventTime"] = pd.to_datetime(frame["EventTime"], errors="coerce")
        frame = frame.sort_values(["EventTime", "EventID"]).reset_index(drop=True)
        self._batch_events = [dict(item) for item in frame.to_dict(orient="records")]
        self._batch_index = 0
        self._seed_cursor += 1

    def _record_event_locked(self, event: dict[str, Any]) -> None:
        live_event = _event_to_live_record(event)
        self._events.append(live_event)
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events :]
        self._event_count += 1
        self._latest_event = live_event
        self._current_mitre_tactic = str(live_event.get("mitre_tactic", "") or "")
        self._current_severity = str(live_event.get("severity", "") or "")

        event_frame = pd.DataFrame([event])
        if self._all_events_df.empty:
            self._all_events_df = event_frame
        else:
            self._all_events_df = pd.concat([self._all_events_df, event_frame], ignore_index=True)

        alerts = analyze_security_events(self._all_events_df)
        self._alert_count = int(len(alerts))
        new_alerts, updated_seen_ids = find_unseen_alerts(alerts, self._seen_alert_ids)
        self._seen_alert_ids = updated_seen_ids
        for _, alert in new_alerts.iterrows():
            alert_dict = serialize_api_value(alert.to_dict())  # type: ignore[arg-type]
            self._alerts.append(alert_dict)  # type: ignore[arg-type]
            self._latest_alert = alert_dict  # type: ignore[assignment]
        if len(self._alerts) > self._max_alerts:
            self._alerts = self._alerts[-self._max_alerts :]

        if alerts.empty:
            self._updated_at = datetime.now(UTC).isoformat()
            return

        correlated_incidents = correlation_engine.correlate_alerts(alerts=alerts)
        if correlated_incidents.empty:
            self._updated_at = datetime.now(UTC).isoformat()
            return

        classifications = incident_classifier.classify_incidents(correlated_incidents)
        for index in range(min(len(correlated_incidents), len(classifications))):
            correlated = correlated_incidents.iloc[index]
            classified = classifications.iloc[index]
            incident_payload = _normalize_incident_row(correlated, classified)
            incident_id = str(incident_payload.get("IncidentID", "") or "")
            if not incident_id or incident_id in self._seen_incident_ids:
                continue
            self._seen_incident_ids.add(incident_id)

            timeline = timeline_builder.build_incident_timeline(correlated, alerts)
            analysis = analyst_agent.run_analyst_agent(
                incident=correlated,
                timeline=timeline,
                environment_name=self._environment_name,
                mode=self._analyst_mode,
                ollama_model=self._ollama_model,
                ollama_base_url=settings.ollama_url,
            )
            analyst_metadata = _safe_metadata(analyst_agent.get_last_analyst_metadata())
            profile = environment_adapter.get_environment_profile(environment_name=self._environment_name)
            environment_profile = dict(profile) if isinstance(profile, dict) else {"EnvironmentName": self._environment_name}
            recommendation = run_defender_agent(
                analysis=dict(analysis),
                environment_profile=environment_profile,
                human_approved=False,
            )

            alert_records = [
                serialize_api_value(alert.to_dict())  # type: ignore[arg-type]
                for _, alert in alerts.iterrows()
            ]
            alerts_payload, alert_mappings, correlated_indicators = build_incident_alert_collections(
                incident_payload,
                alert_records,  # type: ignore[arg-type]
            )
            incident_payload["Alerts"] = alerts_payload
            incident_payload["AlertMappings"] = alert_mappings
            incident_payload["CorrelatedIndicators"] = correlated_indicators

            incident_result = {
                "Incident": incident_payload,
                "AnalystResult": serialize_api_value(dict(analysis)),
                "AnalystMetadata": analyst_metadata,
                "DefenderRecommendation": serialize_api_value(dict(recommendation)),
                "Timeline": serialize_api_value(timeline),
            }
            self._incidents.append(incident_result)
            self._latest_incident = incident_result
            self._incident_count = len(self._seen_incident_ids)
        if len(self._incidents) > self._max_incidents:
            self._incidents = self._incidents[-self._max_incidents :]

        self._updated_at = datetime.now(UTC).isoformat()

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                with self._lock:
                    if self._status != "running":
                        interval = 0.1
                    else:
                        if self._batch_index >= len(self._batch_events):
                            self._generate_batch_locked()
                        if self._batch_events:
                            next_event = self._batch_events[self._batch_index]
                            self._batch_index += 1
                            self._record_event_locked(next_event)
                        interval = self._base_interval_seconds / self._speed
                time.sleep(max(0.05, float(interval)))
            except Exception as error:
                with self._lock:
                    self._last_error = str(error)
                    self._updated_at = datetime.now(UTC).isoformat()
                time.sleep(0.2)

    def _ensure_worker_started(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        self._stop_event.clear()
        self._worker = threading.Thread(target=self._run_loop, name="raven-live-monitor", daemon=True)
        self._worker.start()

    def _stop_worker(self) -> None:
        self._stop_event.set()
        worker = self._worker
        self._worker = None
        if worker is not None:
            worker.join(timeout=2.0)

    def start(
        self,
        *,
        scenario_name: str,
        speed: float,
        seed: int | None = None,
        analyst_mode: str = "deterministic",
        ollama_model: str = DEFAULT_OLLAMA_MODEL,
    ) -> dict[str, object]:
        if scenario_name not in SUPPORTED_SCENARIOS:
            raise ValueError(f"Unsupported scenario: {scenario_name!r}.")
        if float(speed) not in SUPPORTED_SPEEDS:
            raise ValueError(f"Unsupported speed: {speed!r}.")

        with self._lock:
            self._stop_worker()
            self._reset_state_locked()
            self._scenario_name = scenario_name
            self._scenario_id = SUPPORTED_SCENARIOS[scenario_name]
            self._speed = float(speed)
            self._seed = int(seed) if seed is not None else int(datetime.now(UTC).timestamp()) % 1_000_000_000
            self._seed_cursor = self._seed
            self._analyst_mode = str(analyst_mode).strip().lower() or "deterministic"
            self._ollama_model = str(ollama_model).strip() or settings.default_ollama_model
            self._generate_batch_locked()
            self._status = "running"
            self._last_error = None
            self._updated_at = datetime.now(UTC).isoformat()
        self._ensure_worker_started()
        return self.get_status()

    def pause(self) -> dict[str, object]:
        with self._lock:
            if self._status == "running":
                self._status = "paused"
                self._updated_at = datetime.now(UTC).isoformat()
        return self.get_status()

    def resume(self, speed: float | None = None) -> dict[str, object]:
        with self._lock:
            if speed is not None:
                if float(speed) not in SUPPORTED_SPEEDS:
                    raise ValueError(f"Unsupported speed: {speed!r}.")
                self._speed = float(speed)
            if self._status in {"paused", "stopped"}:
                self._status = "running"
                self._updated_at = datetime.now(UTC).isoformat()
        self._ensure_worker_started()
        return self.get_status()

    def reset(self) -> dict[str, object]:
        with self._lock:
            self._stop_worker()
            self._reset_state_locked()
        return self.get_status()

    def get_status(self) -> dict[str, object]:
        with self._lock:
            return {
                "status": self._status,
                "scenario": self._scenario_name,
                "speed": self._speed,
                "event_count": self._event_count,
                "queue_size": len(self._events),
                "alert_count": self._alert_count,
                "incident_count": self._incident_count,
                "current_mitre_tactic": self._current_mitre_tactic,
                "current_severity": self._current_severity,
                "latest_event": self._latest_event,
                "latest_alert": self._latest_alert,
                "latest_incident": self._latest_incident,
                "last_error": self._last_error,
                "updated_at": self._updated_at,
                "supported_scenarios": list(SUPPORTED_SCENARIOS.keys()),
                "supported_speeds": sorted(SUPPORTED_SPEEDS),
            }

    def get_events(self, limit: int = 200) -> list[dict[str, object]]:
        with self._lock:
            return list(self._events[-limit:])

    def get_alerts(self, limit: int = 200) -> list[dict[str, object]]:
        with self._lock:
            return list(self._alerts[-limit:])

    def get_incidents(self, limit: int = 100) -> list[dict[str, object]]:
        with self._lock:
            return list(self._incidents[-limit:])

    def get_incident(self, incident_id: str) -> dict[str, object] | None:
        with self._lock:
            for incident_result in self._incidents:
                inc = incident_result.get("Incident")
                if isinstance(inc, dict) and inc.get("IncidentID") == incident_id:
                    return dict(incident_result)
            return None

    def approve_action(self, incident_id: str) -> dict[str, object] | None:
        from backend.services.action_service import ActionConflictError, _decision_payload
        with self._lock:
            for incident_result in self._incidents:
                inc = incident_result.get("Incident")
                if isinstance(inc, dict) and inc.get("IncidentID") == incident_id:
                    existing = incident_result.get("ActionDecision")
                    if existing is not None:
                        if isinstance(existing, dict) and existing.get("Decision") != "approved":
                            raise ActionConflictError("Incident already has a conflicting action decision.")
                        return dict(existing)  # type: ignore[arg-type]

                    analysis = incident_result.get("AnalystResult", {})
                    if not isinstance(analysis, dict):
                        analysis = {}
                    action_id = str(analysis.get("RecommendedActionID", "NO_ACTION"))
                    decision_payload = _decision_payload(
                        incident_id=incident_id,
                        action_id=action_id,
                        target=str(analysis.get("Target", "")),
                        decision="approved",
                    )
                    incident_result["ActionDecision"] = decision_payload

                    timeline = list(incident_result.get("Timeline", []))  # type: ignore[arg-type]
                    timeline.append({
                        "Timestamp": datetime.now(UTC).isoformat(),
                        "Event": f"Analyst approved action {action_id}",
                        "Source": "Analyst",
                    })
                    incident_result["Timeline"] = serialize_api_value(timeline)
                    return decision_payload
            return None

    def reject_action(self, incident_id: str) -> dict[str, object] | None:
        from backend.services.action_service import ActionConflictError, _decision_payload
        with self._lock:
            for incident_result in self._incidents:
                inc = incident_result.get("Incident")
                if isinstance(inc, dict) and inc.get("IncidentID") == incident_id:
                    existing = incident_result.get("ActionDecision")
                    if existing is not None:
                        if isinstance(existing, dict) and existing.get("Decision") != "rejected":
                            raise ActionConflictError("Incident already has a conflicting action decision.")
                        return dict(existing)  # type: ignore[arg-type]

                    analysis = incident_result.get("AnalystResult", {})
                    if not isinstance(analysis, dict):
                        analysis = {}
                    action_id = str(analysis.get("RecommendedActionID", "NO_ACTION"))
                    decision_payload = _decision_payload(
                        incident_id=incident_id,
                        action_id=action_id,
                        target=str(analysis.get("Target", "")),
                        decision="rejected",
                    )
                    incident_result["ActionDecision"] = decision_payload

                    timeline = list(incident_result.get("Timeline", []))  # type: ignore[arg-type]
                    timeline.append({
                        "Timestamp": datetime.now(UTC).isoformat(),
                        "Event": f"Analyst rejected action {action_id}",
                        "Source": "Analyst",
                    })
                    incident_result["Timeline"] = serialize_api_value(timeline)
                    return decision_payload
            return None



live_monitoring_service = LiveMonitoringService()
