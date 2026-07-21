from __future__ import annotations

from enum import Enum

from backend.schemas.common import StrictBaseModel


class Decision(str, Enum):
    approved = "approved"
    rejected = "rejected"


class ActionDecisionResponse(StrictBaseModel):
    IncidentID: str
    ActionID: str
    Target: str
    Decision: Decision
    ExecutionMode: str
    Message: str
    Timestamp: str
