from __future__ import annotations

from backend.repositories import IncidentRepository
from backend.schemas.common import serialize_api_value


def list_runs(
    repository: IncidentRepository,
    limit: int = 50,
    scenario_label: str | None = None,
    difficulty: str | None = None,
    created_after: str | None = None,
    created_before: str | None = None,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for run in repository.list_runs(
        limit=limit,
        scenario_label=scenario_label,
        difficulty=difficulty,
        created_after=created_after,
        created_before=created_before,
    ):
        result = dict(run.result)
        rows.append(
            serialize_api_value(
                {
                    "RunID": run.run_id,
                    "ScenarioLabel": result.get("ScenarioLabel"),
                    "Seed": result.get("Seed"),
                    "Difficulty": result.get("Difficulty"),
                    "NoiseLevel": result.get("NoiseLevel"),
                    "ScenarioMode": result.get("ScenarioMode"),
                    "AnswerRevealed": result.get("AnswerRevealed"),
                    "EventCount": result.get("EventCount"),
                    "AttackEventCount": result.get("AttackEventCount"),
                    "BenignEventCount": result.get("BenignEventCount"),
                    "CreatedAt": result.get("CreatedAt"),
                }
            )
        )
    return rows


def get_run_detail(repository: IncidentRepository, run_id: str) -> dict[str, object] | None:
    run = repository.get_run(run_id)
    if run is None:
        return None
    incidents = [
        serialize_api_value({**stored.incident, "ActionDecision": stored.action_decision})
        for stored in repository.list_incidents(limit=500)
        if stored.run_id == run_id
    ]
    detail = serialize_api_value(dict(run.result))
    if isinstance(detail, dict) and not detail.get("AnswerRevealed"):
        evaluation = detail.get("Evaluation")
        if isinstance(evaluation, dict):
            for key in ("ExpectedAlertsFound", "MissingExpectedAlerts", "UnexpectedIncidents"):
                evaluation.pop(key, None)
    return {"Run": detail, "Incidents": incidents}
