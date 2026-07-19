import pandas as pd
import pytest

import collector.live_pipeline as live_pipeline
from collector.checkpoint_store import get_checkpoint, update_checkpoint


def raw_frame(channel="System", record_ids=(1, 2)):
    return pd.DataFrame(
        {
            "RecordID": list(record_ids),
            "TimeGenerated": pd.to_datetime(
                ["2026-07-19 10:00:00"] * len(record_ids)
            ),
            "MachineName": ["WORKSTATION-1"] * len(record_ids),
            "Channel": [channel] * len(record_ids),
            "Source": ["Service"] * len(record_ids),
            "EventID": [42] * len(record_ids),
            "EventCategory": [0] * len(record_ids),
            "EventTypeCode": [4] * len(record_ids),
            "EntryType": ["Information"] * len(record_ids),
            "UserName": [""] * len(record_ids),
            "Message": ["message"] * len(record_ids),
            "RawData": [""] * len(record_ids),
        }
    )


def normalized_frame(count=2):
    return pd.DataFrame(
        {
            "EventTime": pd.to_datetime(["2026-07-19 10:00:00"] * count),
            "DeviceName": ["WORKSTATION-1"] * count,
            "UserName": [pd.NA] * count,
            "EventSource": ["Service"] * count,
            "EventType": ["WindowsEvent"] * count,
            "EventResult": ["Success"] * count,
            "EventSeverity": ["Informational"] * count,
            "SourceIP": [pd.NA] * count,
            "DestinationIP": [pd.NA] * count,
            "ProcessName": [pd.NA] * count,
            "CommandLine": [pd.NA] * count,
            "Country": [pd.NA] * count,
            "RawMessage": ["message"] * count,
        }
    )


def patch_common(monkeypatch):
    monkeypatch.setattr(
        live_pipeline,
        "normalize_windows_event_logs",
        lambda raw_events: normalized_frame(len(raw_events)),
    )
    monkeypatch.setattr(
        live_pipeline,
        "save_security_events",
        lambda normalized_logs: {
            "received": len(normalized_logs),
            "inserted": len(normalized_logs),
            "duplicates_skipped": 0,
        },
    )
    monkeypatch.setattr(
        live_pipeline,
        "analyze_security_events",
        lambda events: pd.DataFrame(columns=["AlertID"]),
    )
    monkeypatch.setattr(live_pipeline, "count_security_events", lambda: 10)


def test_successful_collection_normalizes_and_saves(monkeypatch, tmp_path):
    patch_common(monkeypatch)
    monkeypatch.setattr(
        live_pipeline,
        "collect_windows_events",
        lambda channel, after_record_id, max_events: raw_frame(channel, (1, 2)),
    )

    result = live_pipeline.run_live_collection(
        ["System"],
        checkpoint_path=tmp_path / "checkpoints.json",
    )

    assert result["received"] == 2
    assert result["inserted"] == 2
    assert len(result["normalized_events"]) == 2
    assert result["database_total"] == 10


def test_checkpoint_updates_only_after_success(monkeypatch, tmp_path):
    checkpoint_path = tmp_path / "checkpoints.json"
    patch_common(monkeypatch)
    monkeypatch.setattr(
        live_pipeline,
        "collect_windows_events",
        lambda channel, after_record_id, max_events: raw_frame(channel, (4, 7)),
    )

    live_pipeline.run_live_collection(["System"], checkpoint_path=checkpoint_path)

    assert get_checkpoint("System", path=checkpoint_path) == 7


def test_failed_persistence_does_not_update_checkpoint(monkeypatch, tmp_path):
    checkpoint_path = tmp_path / "checkpoints.json"
    patch_common(monkeypatch)
    monkeypatch.setattr(
        live_pipeline,
        "collect_windows_events",
        lambda channel, after_record_id, max_events: raw_frame(channel, (4, 7)),
    )
    monkeypatch.setattr(
        live_pipeline,
        "save_security_events",
        lambda normalized_logs: (_ for _ in ()).throw(RuntimeError("db failed")),
    )

    with pytest.raises(RuntimeError, match="db failed"):
        live_pipeline.run_live_collection(["System"], checkpoint_path=checkpoint_path)

    assert get_checkpoint("System", path=checkpoint_path) == 0


def test_one_failed_channel_does_not_stop_another(monkeypatch, tmp_path):
    patch_common(monkeypatch)

    def collect(channel, after_record_id, max_events):
        if channel == "Security":
            raise PermissionError("Security log access was denied.")
        return raw_frame(channel, (3,))

    monkeypatch.setattr(live_pipeline, "collect_windows_events", collect)

    result = live_pipeline.run_live_collection(
        ["Security", "System"],
        checkpoint_path=tmp_path / "checkpoints.json",
    )

    assert result["channel_results"]["Security"]["error"]
    assert result["channel_results"]["System"]["events_collected"] == 1
    assert result["received"] == 1


def test_no_events_returns_stable_empty_result(monkeypatch, tmp_path):
    patch_common(monkeypatch)
    monkeypatch.setattr(
        live_pipeline,
        "collect_windows_events",
        lambda channel, after_record_id, max_events: pd.DataFrame(
            columns=live_pipeline.RAW_EVENT_COLUMNS
        ),
    )

    result = live_pipeline.run_live_collection(
        ["System"],
        checkpoint_path=tmp_path / "checkpoints.json",
    )

    assert result["raw_events"].empty
    assert list(result["raw_events"].columns) == live_pipeline.RAW_EVENT_COLUMNS
    assert result["normalized_events"].empty
    assert result["received"] == 0


def test_result_uses_timezone_aware_utc_timestamp(monkeypatch, tmp_path):
    patch_common(monkeypatch)
    monkeypatch.setattr(
        live_pipeline,
        "collect_windows_events",
        lambda channel, after_record_id, max_events: pd.DataFrame(
            columns=live_pipeline.RAW_EVENT_COLUMNS
        ),
    )

    result = live_pipeline.run_live_collection(
        ["System"],
        checkpoint_path=tmp_path / "checkpoints.json",
    )

    parsed = pd.Timestamp(result["last_collection_time"])
    assert parsed.tz is not None
    assert parsed.tzinfo.utcoffset(parsed.to_pydatetime()).total_seconds() == 0


def alert_frame(severity="High", alert_id="alert-1"):
    return pd.DataFrame(
        [
            {
                "AlertID": alert_id,
                "AlertTime": pd.Timestamp("2026-07-19 10:00:00"),
                "DeviceName": "WORKSTATION-1",
                "UserName": "analyst",
                "AlertType": "Suspicious PowerShell",
                "AlertSeverity": severity,
                "Evidence": "encoded command",
            }
        ]
    )


def test_monitoring_cycle_calls_existing_collection_workflow(monkeypatch, tmp_path):
    calls = []

    def fake_live_collection(channels, max_events_per_channel, checkpoint_path):
        calls.append((channels, max_events_per_channel, checkpoint_path))
        return {
            "channels_requested": channels,
            "channel_results": {},
            "raw_events": pd.DataFrame(),
            "normalized_events": pd.DataFrame(),
            "alerts": pd.DataFrame(columns=["AlertID"]),
            "received": 0,
            "inserted": 0,
            "duplicates_skipped": 0,
            "database_total": 0,
            "last_collection_time": "2026-07-19T10:00:00+00:00",
            "errors": [],
        }

    monkeypatch.setattr(live_pipeline, "run_live_collection", fake_live_collection)
    checkpoint_path = tmp_path / "checkpoints.json"

    live_pipeline.run_monitoring_cycle(
        ["System"],
        max_events_per_channel=25,
        checkpoint_path=checkpoint_path,
    )

    assert calls == [(["System"], 25, checkpoint_path)]


def test_monitoring_cycle_returns_unseen_alerts(monkeypatch, tmp_path):
    monkeypatch.setattr(
        live_pipeline,
        "run_live_collection",
        lambda channels, max_events_per_channel, checkpoint_path: {
            "channels_requested": channels,
            "channel_results": {},
            "raw_events": pd.DataFrame(),
            "normalized_events": pd.DataFrame(),
            "alerts": alert_frame("High"),
            "received": 0,
            "inserted": 0,
            "duplicates_skipped": 0,
            "database_total": 0,
            "last_collection_time": "2026-07-19T10:00:00+00:00",
            "errors": [],
        },
    )

    result = live_pipeline.run_monitoring_cycle(
        ["System"],
        checkpoint_path=tmp_path / "checkpoints.json",
    )

    assert len(result["new_alerts"]) == 1
    assert result["new_alert_count"] == 1


def test_already_seen_alerts_are_not_returned_again(monkeypatch, tmp_path):
    alerts = alert_frame("High")
    _, seen_alert_ids = live_pipeline.find_unseen_alerts(alerts, set())
    monkeypatch.setattr(
        live_pipeline,
        "run_live_collection",
        lambda channels, max_events_per_channel, checkpoint_path: {
            "channels_requested": channels,
            "channel_results": {},
            "raw_events": pd.DataFrame(),
            "normalized_events": pd.DataFrame(),
            "alerts": alerts,
            "received": 0,
            "inserted": 0,
            "duplicates_skipped": 0,
            "database_total": 0,
            "last_collection_time": "2026-07-19T10:00:00+00:00",
            "errors": [],
        },
    )

    result = live_pipeline.run_monitoring_cycle(
        ["System"],
        checkpoint_path=tmp_path / "checkpoints.json",
        seen_alert_ids=seen_alert_ids,
    )

    assert result["new_alerts"].empty
    assert result["new_alert_count"] == 0


def test_warning_severity_sets_has_warning(monkeypatch, tmp_path):
    monkeypatch.setattr(
        live_pipeline,
        "run_live_collection",
        lambda channels, max_events_per_channel, checkpoint_path: {
            "channels_requested": channels,
            "channel_results": {},
            "raw_events": pd.DataFrame(),
            "normalized_events": pd.DataFrame(),
            "alerts": alert_frame("Medium"),
            "received": 0,
            "inserted": 0,
            "duplicates_skipped": 0,
            "database_total": 0,
            "last_collection_time": "2026-07-19T10:00:00+00:00",
            "errors": [],
        },
    )

    result = live_pipeline.run_monitoring_cycle(
        ["System"],
        checkpoint_path=tmp_path / "checkpoints.json",
    )

    assert result["has_warning"] is True


def test_informational_only_alerts_do_not_set_has_warning(monkeypatch, tmp_path):
    monkeypatch.setattr(
        live_pipeline,
        "run_live_collection",
        lambda channels, max_events_per_channel, checkpoint_path: {
            "channels_requested": channels,
            "channel_results": {},
            "raw_events": pd.DataFrame(),
            "normalized_events": pd.DataFrame(),
            "alerts": alert_frame("Informational"),
            "received": 0,
            "inserted": 0,
            "duplicates_skipped": 0,
            "database_total": 0,
            "last_collection_time": "2026-07-19T10:00:00+00:00",
            "errors": [],
        },
    )

    result = live_pipeline.run_monitoring_cycle(
        ["System"],
        checkpoint_path=tmp_path / "checkpoints.json",
    )

    assert result["has_warning"] is False


def test_one_failed_channel_does_not_stop_monitoring_result(monkeypatch, tmp_path):
    monkeypatch.setattr(
        live_pipeline,
        "run_live_collection",
        lambda channels, max_events_per_channel, checkpoint_path: {
            "channels_requested": channels,
            "channel_results": {
                "Security": {
                    "channel": "Security",
                    "previous_checkpoint": 0,
                    "new_checkpoint": 0,
                    "events_collected": 0,
                    "error": "Security log access was denied.",
                },
                "System": {
                    "channel": "System",
                    "previous_checkpoint": 0,
                    "new_checkpoint": 3,
                    "events_collected": 1,
                    "error": None,
                },
            },
            "raw_events": raw_frame("System", (3,)),
            "normalized_events": normalized_frame(1),
            "alerts": pd.DataFrame(columns=["AlertID"]),
            "received": 1,
            "inserted": 1,
            "duplicates_skipped": 0,
            "database_total": 1,
            "last_collection_time": "2026-07-19T10:00:00+00:00",
            "errors": ["Security: Security log access was denied."],
        },
    )

    result = live_pipeline.run_monitoring_cycle(
        ["Security", "System"],
        checkpoint_path=tmp_path / "checkpoints.json",
    )

    assert result["received"] == 1
    assert result["errors"] == ["Security: Security log access was denied."]


def test_seen_alert_ids_are_returned(monkeypatch, tmp_path):
    monkeypatch.setattr(
        live_pipeline,
        "run_live_collection",
        lambda channels, max_events_per_channel, checkpoint_path: {
            "channels_requested": channels,
            "channel_results": {},
            "raw_events": pd.DataFrame(),
            "normalized_events": pd.DataFrame(),
            "alerts": alert_frame("High"),
            "received": 0,
            "inserted": 0,
            "duplicates_skipped": 0,
            "database_total": 0,
            "last_collection_time": "2026-07-19T10:00:00+00:00",
            "errors": [],
        },
    )

    result = live_pipeline.run_monitoring_cycle(
        ["System"],
        checkpoint_path=tmp_path / "checkpoints.json",
    )

    assert isinstance(result["seen_alert_ids"], set)
    assert len(result["seen_alert_ids"]) == 1


def test_empty_alert_result_remains_stable(monkeypatch, tmp_path):
    monkeypatch.setattr(
        live_pipeline,
        "run_live_collection",
        lambda channels, max_events_per_channel, checkpoint_path: {
            "channels_requested": channels,
            "channel_results": {},
            "raw_events": pd.DataFrame(),
            "normalized_events": pd.DataFrame(),
            "alerts": pd.DataFrame(columns=["AlertID", "AlertSeverity"]),
            "received": 0,
            "inserted": 0,
            "duplicates_skipped": 0,
            "database_total": 0,
            "last_collection_time": "2026-07-19T10:00:00+00:00",
            "errors": [],
        },
    )

    result = live_pipeline.run_monitoring_cycle(
        ["System"],
        checkpoint_path=tmp_path / "checkpoints.json",
    )

    assert result["new_alerts"].empty
    assert list(result["new_alerts"].columns) == ["AlertID", "AlertSeverity"]
    assert result["alert_count"] == 0
    assert result["new_alert_count"] == 0


def test_selected_channels_reset_to_newest_position(monkeypatch, tmp_path):
    checkpoint_path = tmp_path / "checkpoints.json"
    monkeypatch.setattr(
        live_pipeline,
        "get_newest_record_id",
        lambda channel: {"System": 100, "Application": 200}[channel],
    )

    result = live_pipeline.reset_channels_to_current_position(
        ["System", "Application"],
        checkpoint_path=checkpoint_path,
    )

    assert result["reset_count"] == 2
    assert get_checkpoint("System", path=checkpoint_path) == 100
    assert get_checkpoint("Application", path=checkpoint_path) == 200


def test_unselected_channel_checkpoints_are_preserved(monkeypatch, tmp_path):
    checkpoint_path = tmp_path / "checkpoints.json"
    update_checkpoint("Security", 50, path=checkpoint_path)
    monkeypatch.setattr(
        live_pipeline,
        "get_newest_record_id",
        lambda channel: 100,
    )

    live_pipeline.reset_channels_to_current_position(
        ["System"],
        checkpoint_path=checkpoint_path,
    )

    assert get_checkpoint("System", path=checkpoint_path) == 100
    assert get_checkpoint("Security", path=checkpoint_path) == 50


def test_one_channel_failure_does_not_stop_reset(monkeypatch, tmp_path):
    checkpoint_path = tmp_path / "checkpoints.json"

    def newest_record_id(channel):
        if channel == "Security":
            raise PermissionError("Security log access was denied.")
        return 10

    monkeypatch.setattr(live_pipeline, "get_newest_record_id", newest_record_id)

    result = live_pipeline.reset_channels_to_current_position(
        ["Security", "System"],
        checkpoint_path=checkpoint_path,
    )

    assert result["reset_count"] == 1
    assert result["channel_results"]["Security"]["error"]
    assert get_checkpoint("System", path=checkpoint_path) == 10


def test_reset_result_contains_timezone_aware_timestamp(monkeypatch, tmp_path):
    monkeypatch.setattr(
        live_pipeline,
        "get_newest_record_id",
        lambda channel: 10,
    )

    result = live_pipeline.reset_channels_to_current_position(
        ["System"],
        checkpoint_path=tmp_path / "checkpoints.json",
    )

    parsed = pd.Timestamp(result["reset_time"])
    assert parsed.tz is not None
    assert parsed.tzinfo.utcoffset(parsed.to_pydatetime()).total_seconds() == 0


def test_explicit_reset_may_move_checkpoint_backward(monkeypatch, tmp_path):
    checkpoint_path = tmp_path / "checkpoints.json"
    update_checkpoint("System", 100, path=checkpoint_path)
    monkeypatch.setattr(
        live_pipeline,
        "get_newest_record_id",
        lambda channel: 10,
    )

    live_pipeline.reset_channels_to_current_position(
        ["System"],
        checkpoint_path=checkpoint_path,
    )

    assert get_checkpoint("System", path=checkpoint_path) == 10


def test_normal_update_checkpoint_still_cannot_move_backward(tmp_path):
    checkpoint_path = tmp_path / "checkpoints.json"

    update_checkpoint("System", 100, path=checkpoint_path)
    update_checkpoint("System", 10, path=checkpoint_path)

    assert get_checkpoint("System", path=checkpoint_path) == 100
