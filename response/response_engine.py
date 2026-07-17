import pandas as pd


def generate_response_recommendations(
    machine_ranking: pd.DataFrame,
) -> pd.DataFrame:
    """
    Generate response recommendations for every device using:

    - overall risk
    - device criticality
    - high-severity alerts
    - medium-severity alerts
    - warning and error activity

    Isolation remains simulated.
    """

    required_columns = {
        "DeviceName",
        "DeviceRole",
        "DeviceOwner",
        "DeviceCriticality",
        "OverallRisk",
        "HighSeverityAlerts",
        "MediumSeverityAlerts",
        "ErrorEvents",
        "WarningEvents",
    }

    missing_columns = (
        required_columns - set(machine_ranking.columns)
    )

    if missing_columns:
        raise ValueError(
            "Device ranking is missing response columns: "
            f"{sorted(missing_columns)}"
        )

    responses = machine_ranking.copy()

    def recommend_action(row: pd.Series) -> str:
        overall_risk = str(row["OverallRisk"]).lower()
        criticality = str(
            row["DeviceCriticality"]
        ).lower()

        high_alerts = int(row["HighSeverityAlerts"])
        medium_alerts = int(row["MediumSeverityAlerts"])

        if overall_risk == "critical" and high_alerts >= 1:
            return (
                "Isolate the endpoint, notify the SOC analyst, "
                "collect forensic evidence, review related alerts "
                "and begin incident response."
            )

        if overall_risk == "critical":
            return (
                "Begin immediate investigation, run an endpoint scan, "
                "review recent activity and prepare the device for "
                "isolation if stronger evidence appears."
            )

        if overall_risk == "high" and high_alerts >= 1:
            return (
                "Run an endpoint scan, inspect the responsible event "
                "sources and request analyst approval for isolation."
            )

        if overall_risk == "high":
            return (
                "Start an immediate investigation and apply enhanced "
                "monitoring to the device."
            )

        if overall_risk == "medium" or medium_alerts >= 1:
            return (
                "Review warning and error sources, inspect recent "
                "activity and continue enhanced monitoring."
            )

        if criticality == "critical":
            return (
                "Continue monitoring and regularly review activity "
                "because this is a business-critical device."
            )

        return "Continue normal monitoring."

    def determine_response_mode(row: pd.Series) -> str:
        overall_risk = str(row["OverallRisk"]).lower()
        criticality = str(
            row["DeviceCriticality"]
        ).lower()

        high_alerts = int(row["HighSeverityAlerts"])

        if (
            overall_risk == "critical"
            and high_alerts >= 1
            and criticality in {"high", "critical"}
        ):
            return "Automatic Isolation"

        if overall_risk in {"high", "critical"}:
            return "Analyst Approval Required"

        if overall_risk == "medium":
            return "Recommendation Only"

        return "Monitor"

    def determine_isolation_status(row: pd.Series) -> str:
        response_mode = row["ResponseMode"]

        if response_mode == "Automatic Isolation":
            return "Simulated Isolated"

        if response_mode == "Analyst Approval Required":
            return "Pending Approval"

        return "Not Isolated"

    responses["RecommendedAction"] = responses.apply(
        recommend_action,
        axis=1,
    )

    responses["ResponseMode"] = responses.apply(
        determine_response_mode,
        axis=1,
    )

    responses["IsolationStatus"] = responses.apply(
        determine_isolation_status,
        axis=1,
    )

    return responses