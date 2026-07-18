from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from response.action_policy import evaluate_action_policy


def run_defender_agent(
    analysis: dict[str, object],
    environment_profile: dict[str, object],
    human_approved: bool = False,
) -> dict[str, object]:
    """Apply deterministic policy evaluation and simulate the response only when permitted."""

    policy_result = evaluate_action_policy(analysis, environment_profile, human_approved)
    action_id = str(policy_result.get("ActionID", "NO_ACTION"))
    target = str(policy_result.get("Target", ""))
    permitted = bool(policy_result.get("Permitted", False))
    executed = False
    execution_mode = str(policy_result.get("ExecutionMode", "No Action"))
    simulation_message = "Simulation only: no action executed."

    if not permitted:
        simulation_message = "Simulation only: action was not permitted by policy."
    elif action_id == "ISOLATE_DEVICE":
        executed = True
        simulation_message = f"Simulation only: device isolation would be requested for {target}."
    elif action_id == "DISABLE_USER":
        executed = True
        simulation_message = f"Simulation only: account disable would be requested for {target}."
    elif action_id == "BLOCK_DESTINATION_IP":
        executed = True
        simulation_message = f"Simulation only: destination IP block would be requested for {target}."
    elif action_id == "COLLECT_EVIDENCE":
        executed = True
        simulation_message = "Simulation only: relevant logs and process evidence would be collected."
    elif action_id == "INCREASE_MONITORING":
        executed = True
        simulation_message = "Simulation only: monitoring would be increased for the target."

    return {
        "ActionID": action_id,
        "Target": target,
        "Permitted": permitted,
        "Executed": executed,
        "ExecutionMode": execution_mode,
        "RequiresApproval": bool(policy_result.get("RequiresApproval", False)),
        "HumanApproved": bool(human_approved),
        "DecisionReason": str(policy_result.get("DecisionReason", "No action taken.")),
        "SimulationMessage": simulation_message,
        "AuditRecord": {
            "Timestamp": datetime.now(UTC).isoformat(),
            "ActionID": action_id,
            "Target": target,
            "Permitted": permitted,
            "Executed": executed,
            "ExecutionMode": execution_mode,
            "Reason": str(policy_result.get("DecisionReason", "No action taken.")),
        },
    }
