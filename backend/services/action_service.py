from __future__ import annotations

from datetime import UTC, datetime

from ai_analyst.schemas import ALLOWED_ACTION_IDS
from backend.repositories import IncidentRepository, RepositoryConflictError
from response.defender_agent import run_defender_agent


SIMULATION_MESSAGE = "Simulation recorded. No real endpoint, account, network rule, or process was modified."


class ActionConflictError(RuntimeError):
    pass


def _decision_payload(
    incident_id: str,
    action_id: str,
    target: str,
    decision: str,
) -> dict[str, object]:
    return {
        "IncidentID": incident_id,
        "ActionID": action_id,
        "Target": target,
        "Decision": decision,
        "ExecutionMode": "Simulation Only",
        "Message": SIMULATION_MESSAGE,
        "Timestamp": datetime.now(UTC).isoformat(),
    }


def approve_action(repository: IncidentRepository, incident_id: str) -> dict[str, object] | None:
    stored = repository.get_incident(incident_id)
    if stored is None:
        return None
    existing = repository.get_action_decision(incident_id)
    if existing is not None:
        if existing.get("Decision") != "approved":
            raise ActionConflictError("Incident already has a conflicting action decision.")
        return existing

    action_id = str(stored.analysis.get("RecommendedActionID", "NO_ACTION"))
    if action_id not in ALLOWED_ACTION_IDS:
        raise ActionConflictError("Stored incident recommendation is not in the approved action allowlist.")

    defender_result = run_defender_agent(
        analysis=stored.analysis,
        environment_profile=stored.environment_profile,
        human_approved=True,
    )
    payload = _decision_payload(
        incident_id=incident_id,
        action_id=str(defender_result.get("ActionID", action_id)),
        target=str(defender_result.get("Target", stored.analysis.get("Target", ""))),
        decision="approved",
    )
    try:
        return repository.save_action_decision(incident_id, payload)
    except RepositoryConflictError as error:
        raise ActionConflictError(str(error)) from error


def reject_action(repository: IncidentRepository, incident_id: str) -> dict[str, object] | None:
    stored = repository.get_incident(incident_id)
    if stored is None:
        return None
    existing = repository.get_action_decision(incident_id)
    if existing is not None:
        if existing.get("Decision") != "rejected":
            raise ActionConflictError("Incident already has a conflicting action decision.")
        return existing

    action_id = str(stored.analysis.get("RecommendedActionID", "NO_ACTION"))
    target = str(stored.analysis.get("Target", ""))
    payload = _decision_payload(
        incident_id=incident_id,
        action_id=action_id,
        target=target,
        decision="rejected",
    )
    try:
        return repository.save_action_decision(incident_id, payload)
    except RepositoryConflictError as error:
        raise ActionConflictError(str(error)) from error


def get_action_decision(repository: IncidentRepository, incident_id: str) -> dict[str, object] | None:
    if repository.get_incident(incident_id) is None:
        return None
    return repository.get_action_decision(incident_id)
