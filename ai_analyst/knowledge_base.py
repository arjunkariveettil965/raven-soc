from __future__ import annotations

import json
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


def _coerce_string_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [_normalize_text(item) for item in value if _normalize_text(item)]
    if isinstance(value, str):
        return [_normalize_text(value)]
    return []


def load_attack_patterns(
    attack_patterns_path: str | Path | None = None,
) -> dict[str, dict[str, object]]:
    """Load the structured attack pattern knowledge base."""

    if attack_patterns_path is None:
        attack_patterns_path = Path(__file__).resolve().parents[1] / "knowledge_base" / "attack_patterns.json"

    path = Path(attack_patterns_path)
    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if isinstance(payload, dict):
        return {str(key): dict(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return {
            str(item.get("pattern_name") or f"pattern-{index}"): dict(item)
            for index, item in enumerate(payload)
            if isinstance(item, dict)
        }
    return {}


def load_response_playbooks(
    playbook_path: str | Path | None = None,
) -> dict[str, dict[str, object]]:
    """Load the response playbooks knowledge base."""

    if playbook_path is None:
        playbook_path = Path(__file__).resolve().parents[1] / "knowledge_base" / "response_playbooks.json"

    path = Path(playbook_path)
    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if isinstance(payload, dict):
        return {str(key): dict(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return {
            str(item.get("action_id") or f"playbook-{index}"): dict(item)
            for index, item in enumerate(payload)
            if isinstance(item, dict)
        }
    return {}


def find_matching_attack_pattern(
    incident: pd.Series | dict,
    attack_patterns: dict[str, object] | None = None,
) -> dict[str, object] | None:
    """Find the best matching attack pattern for an incident."""

    if attack_patterns is None:
        attack_patterns = load_attack_patterns()

    if isinstance(incident, pd.Series):
        incident_data = incident.to_dict()
    elif isinstance(incident, dict):
        incident_data = incident
    else:
        incident_data = {}

    incident_type = _normalize_text(incident_data.get("IncidentType"))
    related_alert_types = {
        _normalize_text(value)
        for value in _coerce_string_list(incident_data.get("RelatedAlertTypes"))
    }

    if incident_type:
        for pattern_name, pattern in attack_patterns.items():
            if _normalize_text(pattern.get("pattern_name")) == incident_type:
                return dict(pattern)

    best_match: tuple[int, int, dict[str, object]] | None = None
    for pattern_name, pattern in attack_patterns.items():
        required_alerts = {
            _normalize_text(value)
            for value in _coerce_string_list(pattern.get("required_alert_types"))
        }
        if not required_alerts:
            continue
        if required_alerts.issubset(related_alert_types):
            match_count = len(required_alerts & related_alert_types)
            if match_count > 0:
                score = (1, match_count, dict(pattern))
                if best_match is None or score[1] > best_match[1]:
                    best_match = (1, match_count, dict(pattern))

    if best_match is None:
        return None

    return best_match[2]
