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
    Add normalized device role, owner and business criticality
    information to the device overview.
    """

    required_overview_columns = {
        "DeviceName",
    }

    missing_overview_columns = (
        required_overview_columns
        - set(machine_overview.columns)
    )

    if missing_overview_columns:
        raise ValueError(
            "Device overview is missing required columns: "
            f"{sorted(missing_overview_columns)}"
        )

    required_inventory_columns = {
        "DeviceName",
        "DeviceRole",
        "DeviceOwner",
        "DeviceCriticality",
    }

    missing_inventory_columns = (
        required_inventory_columns
        - set(inventory.columns)
    )

    if missing_inventory_columns:
        raise ValueError(
            "Device inventory is missing required columns: "
            f"{sorted(missing_inventory_columns)}"
        )

    cleaned_inventory = inventory[
        [
            "DeviceName",
            "DeviceRole",
            "DeviceOwner",
            "DeviceCriticality",
        ]
    ].copy()

    cleaned_inventory["DeviceName"] = (
        cleaned_inventory["DeviceName"]
        .astype(str)
        .str.strip()
    )

    enriched_overview = machine_overview.merge(
        cleaned_inventory,
        on="DeviceName",
        how="left",
    )

    enriched_overview["DeviceRole"] = (
        enriched_overview["DeviceRole"]
        .fillna("Employee Workstation")
    )

    enriched_overview["DeviceOwner"] = (
        enriched_overview["DeviceOwner"]
        .fillna("Unknown")
    )

    enriched_overview["DeviceCriticality"] = (
        enriched_overview["DeviceCriticality"]
        .fillna("Medium")
    )

    return enriched_overview


def calculate_machine_risk(
    machine_overview: pd.DataFrame,
) -> pd.DataFrame:
    """
    Calculate a device risk score using:

    - warning events
    - error events
    - medium-severity alerts
    - high-severity alerts
    - business criticality
    """

    required_columns = {
        "DeviceName",
        "WarningEvents",
        "ErrorEvents",
        "MediumSeverityAlerts",
        "HighSeverityAlerts",
        "DeviceCriticality",
    }

    missing_columns = (
        required_columns - set(machine_overview.columns)
    )

    if missing_columns:
        raise ValueError(
            "Device overview is missing risk columns: "
            f"{sorted(missing_columns)}"
        )

    ranked = machine_overview.copy()

    ranked["CriticalityWeight"] = (
        ranked["DeviceCriticality"]
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

    ranked["OverallRisk"] = ranked["RiskScore"].apply(
        assign_risk_level
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
    Determine the most common normalized event severity
    for each device.
    """

    required_columns = {
        "InformationEvents",
        "WarningEvents",
        "ErrorEvents",
    }

    missing_columns = (
        required_columns - set(machine_ranking.columns)
    )

    if missing_columns:
        raise ValueError(
            "Device ranking is missing event-count columns: "
            f"{sorted(missing_columns)}"
        )

    ranked = machine_ranking.copy()

    event_columns = {
        "Informational": "InformationEvents",
        "Medium": "WarningEvents",
        "High": "ErrorEvents",
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