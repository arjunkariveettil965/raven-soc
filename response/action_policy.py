from __future__ import annotations

from typing import Any

ACTION_POLICIES = {
    "ISOLATE_DEVICE": {
        "action_id": "ISOLATE_DEVICE",
        "minimum_confidence": 85,
        "requires_approval": True,
        "reversible": True,
        "allowed_target_types": ["device"],
        "description": "Contain the affected device while preserving evidence.",
    },
    "DISABLE_USER": {
        "action_id": "DISABLE_USER",
        "minimum_confidence": 90,
        "requires_approval": True,
        "reversible": True,
        "allowed_target_types": ["user"],
        "description": "Disable the impacted account pending review.",
    },
    "BLOCK_DESTINATION_IP": {
        "action_id": "BLOCK_DESTINATION_IP",
        "minimum_confidence": 80,
        "requires_approval": True,
        "reversible": True,
        "allowed_target_types": ["ip"],
        "description": "Block the suspicious destination IP at the perimeter.",
    },
    "COLLECT_EVIDENCE": {
        "action_id": "COLLECT_EVIDENCE",
        "minimum_confidence": 0,
        "requires_approval": False,
        "reversible": True,
        "allowed_target_types": ["device", "user", "ip"],
        "description": "Collect relevant evidence and preserve the timeline.",
    },
    "INCREASE_MONITORING": {
        "action_id": "INCREASE_MONITORING",
        "minimum_confidence": 0,
        "requires_approval": False,
        "reversible": True,
        "allowed_target_types": ["device", "user", "ip"],
        "description": "Increase monitoring coverage for the target.",
    },
    "NO_ACTION": {
        "action_id": "NO_ACTION",
        "minimum_confidence": 0,
        "requires_approval": False,
        "reversible": True,
        "allowed_target_types": ["none"],
        "description": "No action is recommended.",
    },
}


def evaluate_action_policy(
    analysis: dict[str, object],
    environment_profile: dict[str, object],
    human_approved: bool = False,
) -> dict[str, object]:
    """Evaluate whether the analyst recommendation can be executed."""

    action_id = str(analysis.get("RecommendedActionID", "NO_ACTION"))
    if action_id not in ACTION_POLICIES:
        return {
            "ActionID": action_id,
            "Target": str(analysis.get("Target", "")),
            "Permitted": False,
            "RequiresApproval": True,
            "HumanApproved": human_approved,
            "DecisionReason": "Unknown action ID.",
            "ExecutionMode": "No Action",
        }

    policy = ACTION_POLICIES[action_id]
    confidence = float(analysis.get("Confidence", 0.0))
    target = str(analysis.get("Target", ""))
    requires_approval = bool(policy["requires_approval"] or analysis.get("RequiresApproval", False))
    is_critical_device = bool(
        target and target.lower() in {str(item).lower() for item in environment_profile.get("critical_devices", []) or []}
    )

    if action_id != "NO_ACTION" and not target:
        return {
            "ActionID": action_id,
            "Target": target,
            "Permitted": False,
            "RequiresApproval": requires_approval,
            "HumanApproved": human_approved,
            "DecisionReason": "A target is required for this action.",
            "ExecutionMode": "No Action",
        }

    if confidence < float(policy["minimum_confidence"]):
        return {
            "ActionID": action_id,
            "Target": target,
            "Permitted": False,
            "RequiresApproval": requires_approval,
            "HumanApproved": human_approved,
            "DecisionReason": "Confidence is below the required threshold.",
            "ExecutionMode": "No Action",
        }

    if requires_approval and not human_approved:
        return {
            "ActionID": action_id,
            "Target": target,
            "Permitted": False,
            "RequiresApproval": True,
            "HumanApproved": human_approved,
            "DecisionReason": "Approval is required before execution.",
            "ExecutionMode": "Advisory",
        }

    if action_id in {"COLLECT_EVIDENCE", "INCREASE_MONITORING"}:
        return {
            "ActionID": action_id,
            "Target": target,
            "Permitted": True,
            "RequiresApproval": False,
            "HumanApproved": human_approved,
            "DecisionReason": "Evidence collection and monitoring are allowed in guarded mode.",
            "ExecutionMode": "Guarded",
        }

    if is_critical_device and not human_approved:
        return {
            "ActionID": action_id,
            "Target": target,
            "Permitted": False,
            "RequiresApproval": True,
            "HumanApproved": human_approved,
            "DecisionReason": "Protected critical-device automation requires human approval.",
            "ExecutionMode": "Advisory",
        }

    if action_id == "NO_ACTION":
        return {
            "ActionID": action_id,
            "Target": target,
            "Permitted": True,
            "RequiresApproval": False,
            "HumanApproved": human_approved,
            "DecisionReason": "No action is required.",
            "ExecutionMode": "No Action",
        }

    return {
        "ActionID": action_id,
        "Target": target,
        "Permitted": True,
        "RequiresApproval": requires_approval,
        "HumanApproved": human_approved,
        "DecisionReason": "The requested action satisfies policy and approval requirements.",
        "ExecutionMode": "Advisory",
    }
