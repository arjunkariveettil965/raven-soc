from __future__ import annotations

import hashlib
import json
from typing import Any

import pandas as pd


DEFAULT_POLL_INTERVAL_SECONDS = 15
MIN_POLL_INTERVAL_SECONDS = 5
MAX_POLL_INTERVAL_SECONDS = 300

ALERT_IDENTITY_FIELDS = [
    "AlertID",
    "AlertTime",
    "DeviceName",
    "UserName",
    "AlertType",
    "Evidence",
]


def validate_poll_interval(value: int | float) -> int:
    if isinstance(value, bool):
        raise ValueError("Polling interval must be a number of seconds.")

    try:
        interval = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("Polling interval must be a number of seconds.") from error

    if interval < MIN_POLL_INTERVAL_SECONDS:
        raise ValueError(
            f"Polling interval must be at least {MIN_POLL_INTERVAL_SECONDS} seconds."
        )

    if interval > MAX_POLL_INTERVAL_SECONDS:
        raise ValueError(
            f"Polling interval must be at most {MAX_POLL_INTERVAL_SECONDS} seconds."
        )

    return interval


def _to_plain_value(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, pd.Timestamp):
        return value.isoformat()

    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass

    return str(value)


def _to_mapping(alert: dict | pd.Series) -> dict[str, Any]:
    if isinstance(alert, pd.Series):
        return alert.to_dict()
    return dict(alert)


def alert_identity(alert: dict | pd.Series) -> str:
    alert_mapping = _to_mapping(alert)
    identity_payload = {
        field: _to_plain_value(alert_mapping.get(field))
        for field in ALERT_IDENTITY_FIELDS
    }
    serialized_payload = json.dumps(
        identity_payload,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(serialized_payload.encode("utf-8")).hexdigest()


def find_unseen_alerts(
    alerts: pd.DataFrame,
    seen_alert_ids: set[str],
) -> tuple[pd.DataFrame, set[str]]:
    updated_seen_alert_ids = set(seen_alert_ids)

    if alerts.empty:
        return alerts.copy(), updated_seen_alert_ids

    unseen_rows = []

    for _, alert in alerts.iterrows():
        identity = alert_identity(alert)
        if identity in updated_seen_alert_ids:
            continue

        updated_seen_alert_ids.add(identity)
        unseen_rows.append(alert)

    if not unseen_rows:
        return alerts.iloc[0:0].copy(), updated_seen_alert_ids

    return pd.DataFrame(unseen_rows, columns=alerts.columns), updated_seen_alert_ids


def alert_notification_message(
    alert: dict | pd.Series,
) -> str:
    alert_mapping = _to_mapping(alert)
    severity = _to_plain_value(
        alert_mapping.get("AlertSeverity", alert_mapping.get("Severity", "Security"))
    ) or "Security"
    alert_type = _to_plain_value(alert_mapping.get("AlertType")) or "Security event"
    device_name = _to_plain_value(alert_mapping.get("DeviceName")) or "unknown device"

    return f"{severity} alert: {alert_type} on {device_name}"
