from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd


def _normalize_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if pd.isna(value):
        return ""
    return str(value)


def _coerce_timestamp(value: object) -> datetime | None:
    if value is None:
        return None
    try:
        timestamp = pd.to_datetime(value, errors="coerce")
    except Exception:
        return None
    if pd.isna(timestamp):
        return None
    return timestamp.to_pydatetime()


def _is_outside_normal_hours(timestamp: datetime | None, profile: dict[str, object]) -> bool:
    if timestamp is None:
        return False
    hours = profile.get("normal_working_hours", {})
    if not isinstance(hours, dict):
        return False
    start_value = hours.get("start")
    end_value = hours.get("end")
    if not isinstance(start_value, str) or not isinstance(end_value, str):
        return False
    try:
        start_time = datetime.strptime(start_value, "%H:%M").time()
        end_time = datetime.strptime(end_value, "%H:%M").time()
    except ValueError:
        return False
    current_time = timestamp.time()
    return not (start_time <= current_time <= end_time)


def load_environment_profiles(
    profile_path: str | Path | None = None,
) -> dict[str, dict[str, object]]:
    """Load environment profiles from the knowledge base JSON file."""

    if profile_path is None:
        profile_path = Path(__file__).resolve().parents[1] / "knowledge_base" / "environment_profiles.json"

    path = Path(profile_path)
    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if isinstance(payload, dict):
        return {str(key): dict(value) for key, value in payload.items()}
    return {}


def get_environment_profile(
    environment_name: str,
    profiles: dict[str, dict[str, object]] | None = None,
) -> dict[str, object]:
    """Return the requested environment profile or a safe default profile."""

    if profiles is None:
        profiles = load_environment_profiles()

    if not profiles:
        return {
            "environment_name": environment_name,
            "critical_roles": [],
            "critical_devices": [],
            "normal_working_hours": {"start": "09:00", "end": "17:00"},
            "approved_admin_tools": [],
            "restricted_countries": [],
            "automatic_response_threshold": 70,
            "critical_devices_require_approval": True,
            "allowed_automatic_actions": ["COLLECT_EVIDENCE", "INCREASE_MONITORING", "NO_ACTION"],
        }

    for profile_name, profile in profiles.items():
        if _normalize_text(profile_name).lower() == _normalize_text(environment_name).lower():
            return dict(profile)

    return {
        "environment_name": environment_name,
        "critical_roles": [],
        "critical_devices": [],
        "normal_working_hours": {"start": "09:00", "end": "17:00"},
        "approved_admin_tools": [],
        "restricted_countries": [],
        "automatic_response_threshold": 70,
        "critical_devices_require_approval": True,
        "allowed_automatic_actions": ["COLLECT_EVIDENCE", "INCREASE_MONITORING", "NO_ACTION"],
    }


def evaluate_environment_context(
    incident: pd.Series | dict,
    environment_profile: dict[str, object],
) -> dict[str, object]:
    """Evaluate environment-specific risk adjustments for an incident."""

    if isinstance(incident, pd.Series):
        incident_data = incident.to_dict()
    elif isinstance(incident, dict):
        incident_data = incident
    else:
        incident_data = {}

    affected_device = _normalize_text(incident_data.get("AffectedDevice"))
    affected_user = _normalize_text(incident_data.get("AffectedUser"))
    source_ip = _normalize_text(incident_data.get("SourceIP"))
    primary_user = affected_user or _normalize_text(incident_data.get("UserName"))
    primary_device = affected_device or _normalize_text(incident_data.get("DeviceName"))

    critical_devices = {
        _normalize_text(item).lower()
        for item in environment_profile.get("critical_devices", []) or []
    }
    critical_roles = {
        _normalize_text(item).lower()
        for item in environment_profile.get("critical_roles", []) or []
    }
    restricted_countries = {
        _normalize_text(item).lower()
        for item in environment_profile.get("restricted_countries", []) or []
    }

    reasons: list[str] = []
    risk_adjustment = 0

    is_critical_device = bool(
        primary_device and primary_device.lower() in critical_devices
    )
    if is_critical_device:
        reasons.append(f"Critical device detected: {primary_device}")
        risk_adjustment += 15

    is_critical_role = False
    if primary_user:
        normalized_user = primary_user.lower()
        is_critical_role = any(role in normalized_user for role in critical_roles)
        if is_critical_role:
            reasons.append(f"Critical role detected: {primary_user}")
            risk_adjustment += 10

    outside_normal_hours = False
    first_seen = incident_data.get("FirstSeen") or incident_data.get("AlertTime") or incident_data.get("EventTime")
    timestamp = _coerce_timestamp(first_seen)
    if _is_outside_normal_hours(timestamp, environment_profile):
        outside_normal_hours = True
        reasons.append("Activity outside normal working hours")
        risk_adjustment += 10

    restricted_country_present = False
    country_value = incident_data.get("Country") or incident_data.get("OriginCountry")
    if _normalize_text(country_value).lower() in restricted_countries:
        restricted_country_present = True
        reasons.append(f"Restricted country detected: {country_value}")
        risk_adjustment += 10

    if source_ip and source_ip.lower().startswith("203.0.113"):
        reasons.append("Source IP is in documentation-only test range")

    if risk_adjustment > 30:
        risk_adjustment = 30

    requires_human_approval = bool(
        environment_profile.get("critical_devices_require_approval", True)
        and is_critical_device
    ) or (risk_adjustment >= 25)

    return {
        "EnvironmentName": _normalize_text(environment_profile.get("environment_name")) or "SME Office",
        "IsCriticalDevice": is_critical_device,
        "IsCriticalRole": is_critical_role,
        "OutsideNormalHours": outside_normal_hours,
        "EnvironmentRiskAdjustment": int(risk_adjustment),
        "RequiresHumanApproval": bool(requires_human_approval),
        "ContextReasons": reasons,
    }
