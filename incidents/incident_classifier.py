from __future__ import annotations

import pandas as pd


CLASSIFICATION_COLUMNS = [
    "IncidentType",
    "IncidentSeverity",
    "IncidentConfidence",
    "AttackStages",
    "ClassificationReason",
]


def _empty_classification_frame() -> pd.DataFrame:
    """Return an empty classified incident DataFrame."""

    return pd.DataFrame(columns=CLASSIFICATION_COLUMNS)


def _normalize_text(value: object) -> str:
    """Normalize string-like values for deterministic output."""

    if value is None:
        return ""

    if isinstance(value, str):
        normalized_value = value.strip()
        return normalized_value or ""

    if pd.isna(value):
        return ""

    return str(value)


def classify_incidents(incidents: pd.DataFrame) -> pd.DataFrame:
    """
    Classify correlated incidents into high-level incident types based on the
    alert sequence and attack-stage coverage.
    """

    if not isinstance(incidents, pd.DataFrame):
        raise TypeError("classify_incidents expects a pandas DataFrame.")

    if incidents.empty:
        return _empty_classification_frame()

    classified_rows: list[dict[str, object]] = []

    for _, incident in incidents.iterrows():
        existing_incident_type = _normalize_text(incident.get("CorrelationPattern"))
        alert_types = {
            _normalize_text(alert_type)
            for alert_type in incident.get("RelatedAlertTypes", [])
        }
        attack_stages = []
        for tactic in incident.get("MITRETactics", []):
            tactic_name = _normalize_text(tactic)
            if tactic_name and tactic_name not in attack_stages:
                attack_stages.append(tactic_name)

        if existing_incident_type in {
            "Password Spray Attempt",
            "Malware Download and Execution",
            "Command-and-Control Beaconing",
            "Multi-Stage Intrusion",
        }:
            incident_type = existing_incident_type
            classification_reason = f"Matched correlation pattern: {existing_incident_type}."
        elif (
            len(alert_types) >= 4
            and "Credential Access" in attack_stages
            and "Execution" in attack_stages
            and "Command and Control" in attack_stages
        ):
            incident_type = "Multi-Stage Intrusion"
            classification_reason = (
                "The incident combines authentication, execution and network "
                "activity across multiple attack stages."
            )
        elif (
            "Failed Login Burst" in alert_types
            and "Successful Login After Failures" in alert_types
            and "Suspicious PowerShell" in alert_types
        ):
            incident_type = "Account Compromise with Malicious Execution"
            classification_reason = (
                "Repeated authentication failures were followed by a successful "
                "login and malicious PowerShell execution."
            )
        elif (
            "Successful Login After Failures" in alert_types
            and "Suspicious PowerShell" in alert_types
        ):
            incident_type = "Account Compromise with Suspicious Execution"
            classification_reason = (
                "A successful login was followed by suspicious PowerShell activity."
            )
        elif (
            "Suspicious PowerShell" in alert_types
            and "Suspicious Outbound Connection" in alert_types
        ):
            incident_type = "Possible Malware Execution and Command and Control"
            classification_reason = (
                "PowerShell execution was followed by suspicious outbound network activity."
            )
        elif (
            "Failed Login Burst" in alert_types
            and "Successful Login After Failures" in alert_types
        ):
            incident_type = "Possible Account Compromise"
            classification_reason = (
                "A burst of failed logins was followed by a successful login."
            )
        elif "Failed Login Burst" in alert_types:
            incident_type = "Brute-Force Attempt"
            classification_reason = (
                "Repeated failed authentication attempts indicate a brute-force attempt."
            )
        else:
            incident_type = "Unknown"
            classification_reason = "The incident did not match a known classification pattern."

        highest_severity = _normalize_text(incident.get("HighestAlertSeverity")) or "Low"
        alert_count = int(incident.get("AlertCount", 0))
        if highest_severity == "Critical" and (len(attack_stages) >= 2 or alert_count >= 2):
            incident_severity = "Critical"
        elif highest_severity == "High" and len(attack_stages) >= 3:
            incident_severity = "Critical"
        elif highest_severity in {"Critical", "High"}:
            incident_severity = "High"
        elif highest_severity == "Medium":
            incident_severity = "Medium"
        else:
            incident_severity = "Low"

        maximum_confidence = float(incident.get("MaximumConfidenceScore", 0))
        incident_confidence = min(100.0, maximum_confidence + (5 if alert_count >= 3 else 0) + (5 if len(attack_stages) >= 3 else 0))

        classified_rows.append(
            {
                "IncidentType": incident_type,
                "IncidentSeverity": incident_severity,
                "IncidentConfidence": incident_confidence,
                "AttackStages": attack_stages,
                "ClassificationReason": classification_reason,
            }
        )

    return pd.DataFrame(classified_rows, columns=CLASSIFICATION_COLUMNS)
