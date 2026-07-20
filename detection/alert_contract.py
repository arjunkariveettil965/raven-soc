from __future__ import annotations

import hashlib
import json
from typing import Any

import pandas as pd


CANONICAL_ALERT_COLUMNS = [
    "RuleID",
    "Title",
    "TimeGenerated",
    "MachineName",
    "DestinationIP",
    "ProcessName",
    "Severity",
    "Confidence",
    "MITRETechniques",
    "Entities",
    "Metadata",
    "EvidenceIDs",
    "EventIDs",
]


def stable_alert_id(prefix: str, parts: list[object]) -> str:
    payload = json.dumps([str(part) for part in parts], sort_keys=True, default=str)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{digest}"


def normalize_event_ids(events: pd.DataFrame) -> list[str]:
    if events.empty:
        return []
    if "EventID" in events.columns:
        values = events["EventID"].tolist()
    else:
        values = events.index.tolist()
    return [str(value) for value in values if str(value)]


def build_entities(
    *,
    machine: object = "",
    user: object = "",
    source_ip: object = "",
    destination_ip: object = "",
    process: object = "",
) -> dict[str, str]:
    return {
        "MachineName": str(machine or ""),
        "UserName": str(user or ""),
        "SourceIP": str(source_ip or ""),
        "DestinationIP": str(destination_ip or ""),
        "ProcessName": str(process or ""),
    }


def enrich_alert_record(
    record: dict[str, Any],
    *,
    rule_id: str,
    title: str,
    destination_ip: object = "",
    process_name: object = "",
    mitre_techniques: list[str] | None = None,
    entities: dict[str, str] | None = None,
    metadata: dict[str, object] | None = None,
    evidence_ids: list[str] | None = None,
) -> dict[str, Any]:
    record = dict(record)
    record["RuleID"] = rule_id
    record["Title"] = title
    record["TimeGenerated"] = record.get("AlertTime")
    record["MachineName"] = record.get("DeviceName")
    record["DestinationIP"] = destination_ip or ""
    record["ProcessName"] = process_name or ""
    record["Severity"] = record.get("AlertSeverity")
    record["Confidence"] = record.get("ConfidenceScore")
    record["MITRETechniques"] = mitre_techniques or [str(record.get("MITRETechnique", ""))]
    record["Entities"] = entities or build_entities(
        machine=record.get("DeviceName"),
        user=record.get("UserName"),
        source_ip=record.get("SourceIP"),
        destination_ip=destination_ip,
        process=process_name,
    )
    record["Metadata"] = metadata or {}
    record["EvidenceIDs"] = evidence_ids or []
    record["EventIDs"] = evidence_ids or []
    return record
