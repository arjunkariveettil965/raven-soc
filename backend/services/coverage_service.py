from __future__ import annotations

from core.coverage import CORRELATION_COVERAGE, DETECTION_COVERAGE


def get_coverage() -> dict[str, list[dict[str, object]]]:
    detection_rules = [
        {
            "RuleID": rule_id,
            "Name": name,
            "MITRETechnique": mitre,
            "DataSource": data_source,
            "RecommendedActionID": action_id,
            "RequiresApproval": requires_approval,
            "ImplementationStatus": "Implemented",
        }
        for rule_id, name, mitre, data_source, action_id, requires_approval in DETECTION_COVERAGE
    ]
    correlation_patterns = [
        {
            "PatternID": pattern_id,
            "Name": name,
            "MITRETechniques": mitre,
            "DataSource": data_source,
            "RecommendedActionID": action_id,
            "RequiresApproval": requires_approval,
            "ImplementationStatus": "Implemented",
        }
        for pattern_id, name, mitre, data_source, action_id, requires_approval in CORRELATION_COVERAGE
    ]
    return {
        "DetectionRules": detection_rules,
        "CorrelationPatterns": correlation_patterns,
    }
