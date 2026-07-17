import pandas as pd


CRITICALITY_WEIGHTS = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}


def add_machine_inventory(
    machine_overview: pd.DataFrame,
    inventory: pd.DataFrame,
) -> pd.DataFrame:
    """
    Add machine role, owner and business criticality information
    to the machine overview table.
    """

    required_inventory_columns = {
        "MachineName",
        "Role",
        "Owner",
        "Criticality",
    }

    missing_columns = (
        required_inventory_columns - set(inventory.columns)
    )

    if missing_columns:
        raise ValueError(
            "Machine inventory is missing required columns: "
            f"{sorted(missing_columns)}"
        )

    enriched_overview = machine_overview.merge(
        inventory[
            [
                "MachineName",
                "Role",
                "Owner",
                "Criticality",
            ]
        ],
        on="MachineName",
        how="left",
    )

    enriched_overview["Role"] = (
        enriched_overview["Role"]
        .fillna("Employee Workstation")
    )

    enriched_overview["Owner"] = (
        enriched_overview["Owner"]
        .fillna("Unknown")
    )

    enriched_overview["Criticality"] = (
        enriched_overview["Criticality"]
        .fillna("Medium")
    )

    return enriched_overview


def calculate_machine_risk(
    machine_overview: pd.DataFrame,
) -> pd.DataFrame:
    """
    Calculate a simple machine risk score using:

    - warning events
    - error events
    - total alerts
    - high-severity alerts
    - medium-severity alerts
    - business criticality
    """

    ranked = machine_overview.copy()

    ranked["CriticalityWeight"] = (
        ranked["Criticality"]
        .map(CRITICALITY_WEIGHTS)
        .fillna(2)
        .astype(int)
    )

    ranked["RiskScore"] = (
        ranked["WarningEvents"] * 1
        + ranked["ErrorEvents"] * 2
        + ranked["MediumSeverityAlerts"] * 10
        + ranked["HighSeverityAlerts"] * 25
        + ranked["CriticalityWeight"] * 20
    )

    def assign_risk_level(score: int) -> str:
        if score >= 500:
            return "Critical"

        if score >= 250:
            return "High"

        if score >= 100:
            return "Medium"

        return "Low"

    ranked["OverallRisk"] = (
        ranked["RiskScore"]
        .apply(assign_risk_level)
    )

    ranked = ranked.sort_values(
        by=[
            "RiskScore",
            "HighSeverityAlerts",
            "ErrorEvents",
            "WarningEvents",
        ],
        ascending=False,
    ).reset_index(drop=True)

    ranked.insert(
        0,
        "Rank",
        range(1, len(ranked) + 1),
    )

    return ranked


def add_most_common_event_type(
    machine_ranking: pd.DataFrame,
) -> pd.DataFrame:
    """
    Determine whether Information, Warning or Error is the most
    common event type for each machine.
    """

    ranked = machine_ranking.copy()

    event_columns = {
        "Information": "InformationEvents",
        "Warning": "WarningEvents",
        "Error": "ErrorEvents",
    }

    ranked["MostCommonEventType"] = ranked.apply(
        lambda row: max(
            event_columns,
            key=lambda event_type: row[
                event_columns[event_type]
            ],
        ),
        axis=1,
    )

    return ranked