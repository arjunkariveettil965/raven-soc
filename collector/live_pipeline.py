from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

from collector.checkpoint_store import (
    get_checkpoint,
    load_checkpoints,
    save_checkpoints,
    update_checkpoint,
)
from collector.monitoring_state import find_unseen_alerts
from collector.windows_event_collector import (
    RAW_EVENT_COLUMNS,
    SUPPORTED_CHANNELS,
    collect_windows_events,
    get_newest_record_id,
)
from database.database import count_security_events, save_security_events
from detection.alert_engine import analyze_security_events
from ingestion.normalizer import NORMALIZED_COLUMNS, normalize_windows_event_logs


def _empty_alerts() -> pd.DataFrame:
    try:
        return analyze_security_events(pd.DataFrame(columns=NORMALIZED_COLUMNS))
    except Exception:
        return pd.DataFrame()


def _alert_severity(alert: pd.Series) -> str:
    severity = alert.get("AlertSeverity", alert.get("Severity", ""))
    try:
        if pd.isna(severity):
            return ""
    except (TypeError, ValueError):
        pass
    return str(severity).strip()


def _has_warning_alerts(alerts: pd.DataFrame) -> bool:
    if alerts.empty:
        return False

    warning_severities = {"medium", "high", "critical"}
    return any(
        _alert_severity(alert).lower() in warning_severities
        for _, alert in alerts.iterrows()
    )


def get_current_log_position(channel: str) -> int:
    return get_newest_record_id(channel)


def _set_checkpoint_exact(
    channel: str,
    record_id: int,
    path: str | Path,
) -> None:
    checkpoints = load_checkpoints(path=path)
    checkpoints[channel] = int(record_id)
    save_checkpoints(checkpoints=checkpoints, path=path)


def initialize_missing_checkpoints_at_current_position(
    channels: list[str],
    checkpoint_path: str | Path = "data/live_checkpoints.json",
) -> dict[str, dict[str, object]]:
    setup_results: dict[str, dict[str, object]] = {}

    for channel in channels:
        existing_checkpoint = get_checkpoint(channel, path=checkpoint_path)
        setup_results[channel] = {
            "channel": channel,
            "existing_checkpoint": existing_checkpoint,
            "initialized": False,
            "checkpoint": existing_checkpoint,
            "error": None,
        }

        if existing_checkpoint > 0:
            continue

        try:
            current_position = get_current_log_position(channel)
            update_checkpoint(
                channel=channel,
                record_id=current_position,
                path=checkpoint_path,
            )
            setup_results[channel]["initialized"] = True
            setup_results[channel]["checkpoint"] = current_position
        except Exception as error:
            setup_results[channel]["error"] = str(error)

    return setup_results


def run_live_collection(
    channels: list[str],
    max_events_per_channel: int = 200,
    checkpoint_path: str | Path = "data/live_checkpoints.json",
) -> dict[str, object]:
    channel_results: dict[str, dict[str, object]] = {}
    collected_frames: list[pd.DataFrame] = []
    errors: list[str] = []

    for channel in channels:
        previous_checkpoint = get_checkpoint(channel, path=checkpoint_path)
        channel_results[channel] = {
            "channel": channel,
            "previous_checkpoint": previous_checkpoint,
            "new_checkpoint": previous_checkpoint,
            "events_collected": 0,
            "error": None,
        }

        try:
            raw_events = collect_windows_events(
                channel=channel,
                after_record_id=previous_checkpoint,
                max_events=max_events_per_channel,
            )
        except Exception as error:
            error_message = str(error)
            channel_results[channel]["error"] = error_message
            errors.append(f"{channel}: {error_message}")
            continue

        if raw_events.empty:
            continue

        channel_results[channel]["events_collected"] = int(len(raw_events))
        channel_results[channel]["new_checkpoint"] = int(raw_events["RecordID"].max())
        collected_frames.append(raw_events)

    raw_events = (
        pd.concat(collected_frames, ignore_index=True)
        if collected_frames
        else pd.DataFrame(columns=RAW_EVENT_COLUMNS)
    )

    normalized_events = pd.DataFrame(columns=NORMALIZED_COLUMNS)
    alerts = _empty_alerts()
    save_result = {
        "received": 0,
        "inserted": 0,
        "duplicates_skipped": 0,
    }

    if not raw_events.empty:
        normalized_events = normalize_windows_event_logs(raw_events)
        save_result = save_security_events(normalized_logs=normalized_events)

        for channel, result in channel_results.items():
            if result["error"] is not None or result["events_collected"] == 0:
                continue
            update_checkpoint(
                channel=channel,
                record_id=int(result["new_checkpoint"]),
                path=checkpoint_path,
            )

        try:
            alerts = analyze_security_events(normalized_events)
        except (TypeError, ValueError) as error:
            errors.append(f"Alert analysis skipped: {error}")
            alerts = _empty_alerts()

    return {
        "channels_requested": list(channels),
        "channel_results": channel_results,
        "raw_events": raw_events,
        "normalized_events": normalized_events,
        "alerts": alerts,
        "received": int(save_result["received"]),
        "inserted": int(save_result["inserted"]),
        "duplicates_skipped": int(save_result["duplicates_skipped"]),
        "database_total": count_security_events(),
        "last_collection_time": datetime.now(UTC).isoformat(),
        "errors": errors,
    }


def run_monitoring_cycle(
    channels: list[str],
    max_events_per_channel: int = 100,
    checkpoint_path: str | Path = "data/live_checkpoints.json",
    seen_alert_ids: set[str] | None = None,
) -> dict[str, object]:
    result = run_live_collection(
        channels=channels,
        max_events_per_channel=max_events_per_channel,
        checkpoint_path=checkpoint_path,
    )

    alerts = result["alerts"]
    if not isinstance(alerts, pd.DataFrame):
        alerts = pd.DataFrame(alerts)
        result["alerts"] = alerts

    new_alerts, updated_seen_alert_ids = find_unseen_alerts(
        alerts=alerts,
        seen_alert_ids=seen_alert_ids or set(),
    )

    result.update(
        {
            "new_alerts": new_alerts,
            "seen_alert_ids": updated_seen_alert_ids,
            "alert_count": int(len(alerts)),
            "new_alert_count": int(len(new_alerts)),
            "has_warning": _has_warning_alerts(new_alerts),
        }
    )

    return result


def reset_channels_to_current_position(
    channels: list[str],
    checkpoint_path: str | Path = "data/live_checkpoints.json",
) -> dict[str, object]:
    if not channels:
        raise ValueError("At least one Windows log channel is required.")

    channel_results: dict[str, dict[str, object]] = {}
    errors: list[str] = []
    reset_count = 0

    for channel in channels:
        previous_checkpoint = get_checkpoint(channel, path=checkpoint_path)
        channel_results[channel] = {
            "channel": channel,
            "previous_checkpoint": previous_checkpoint,
            "new_checkpoint": previous_checkpoint,
            "reset": False,
            "error": None,
        }

        if channel not in SUPPORTED_CHANNELS:
            error_message = f"Unsupported Windows Event Log channel: {channel!r}"
            channel_results[channel]["error"] = error_message
            errors.append(f"{channel}: {error_message}")
            continue

        try:
            newest_record_id = get_newest_record_id(channel)
            _set_checkpoint_exact(
                channel=channel,
                record_id=newest_record_id,
                path=checkpoint_path,
            )
            channel_results[channel]["new_checkpoint"] = newest_record_id
            channel_results[channel]["reset"] = True
            reset_count += 1
        except Exception as error:
            error_message = str(error)
            channel_results[channel]["error"] = error_message
            errors.append(f"{channel}: {error_message}")

    return {
        "channels_requested": list(channels),
        "channel_results": channel_results,
        "reset_count": reset_count,
        "errors": errors,
        "reset_time": datetime.now(UTC).isoformat(),
    }
