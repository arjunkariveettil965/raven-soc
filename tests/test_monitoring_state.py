import pandas as pd
import pytest
from pathlib import Path

from collector.monitoring_state import (
    alert_identity,
    alert_notification_message,
    find_unseen_alerts,
    validate_poll_interval,
)


def test_valid_polling_interval():
    assert validate_poll_interval(15.8) == 15


def test_too_small_interval_rejected():
    with pytest.raises(ValueError, match="at least"):
        validate_poll_interval(4)


def test_too_large_interval_rejected():
    with pytest.raises(ValueError, match="at most"):
        validate_poll_interval(301)


def test_boolean_interval_rejected():
    with pytest.raises(ValueError, match="number"):
        validate_poll_interval(True)


def test_alert_identity_is_stable():
    alert = {
        "AlertID": "alert-1",
        "AlertTime": pd.Timestamp("2026-07-19 10:00:00"),
        "DeviceName": "DESKTOP-ABC",
        "UserName": "analyst",
        "AlertType": "Suspicious PowerShell",
        "Evidence": "encoded command",
    }

    assert alert_identity(alert) == alert_identity(pd.Series(alert))


def test_unseen_alerts_are_returned_once():
    alerts = pd.DataFrame(
        [
            {
                "AlertID": "alert-1",
                "AlertTime": "2026-07-19T10:00:00Z",
                "DeviceName": "DESKTOP-ABC",
                "UserName": "analyst",
                "AlertType": "Suspicious PowerShell",
                "Evidence": "encoded command",
            }
        ]
    )

    unseen_alerts, seen_alert_ids = find_unseen_alerts(alerts, set())
    second_unseen_alerts, _ = find_unseen_alerts(alerts, seen_alert_ids)

    assert len(unseen_alerts) == 1
    assert second_unseen_alerts.empty


def test_input_seen_set_is_not_mutated():
    seen_alert_ids = {"existing"}

    find_unseen_alerts(
        pd.DataFrame([{"AlertID": "alert-1"}]),
        seen_alert_ids,
    )

    assert seen_alert_ids == {"existing"}


def test_notification_message_handles_missing_fields():
    assert (
        alert_notification_message({})
        == "Security alert: Security event on unknown device"
    )


def test_app_start_stores_selected_value_in_active_interval():
    app_source = Path("app.py").read_text(encoding="utf-8")

    assert "selected_monitoring_interval = st.number_input(" in app_source
    assert (
        'st.session_state["live_monitoring_active_interval"] = (\n'
        "                    validate_poll_interval(selected_monitoring_interval)"
    ) in app_source


def test_app_does_not_overwrite_widget_owned_interval_key():
    app_source = Path("app.py").read_text(encoding="utf-8")

    assert 'st.session_state["live_monitoring_interval"] =' not in app_source
    assert "st.session_state.live_monitoring_interval =" not in app_source


def test_app_fragment_polling_uses_active_interval_key():
    app_source = Path("app.py").read_text(encoding="utf-8")
    fragment_start = app_source.index("fragment_run_every =")
    fragment_block = app_source[fragment_start : fragment_start + 200]

    assert 'st.session_state["live_monitoring_active_interval"]' in fragment_block
    assert 'st.session_state["live_monitoring_interval"]' not in fragment_block
