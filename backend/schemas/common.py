from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Any

import pandas as pd
from pydantic import BaseModel, ConfigDict


class StrictBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AnalystMode(str, Enum):
    deterministic = "Deterministic"
    hybrid = "Hybrid"


def _serialize_scalar(value: object) -> object:
    if value is None:
        return None
    if isinstance(value, pd.Timestamp):
        if pd.isna(value):
            return None
        return value.isoformat()
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    if hasattr(value, "item"):
        try:
            return value.item()
        except (TypeError, ValueError):
            pass
    return value


def serialize_api_value(value: object) -> object:
    if isinstance(value, pd.DataFrame):
        return [serialize_api_value(record) for record in value.to_dict(orient="records")]
    if isinstance(value, pd.Series):
        return serialize_api_value(value.to_dict())
    if isinstance(value, dict):
        return {str(key): serialize_api_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [serialize_api_value(item) for item in value]
    return _serialize_scalar(value)


class MessageResponse(BaseModel):
    name: str
    status: str
    version: str
