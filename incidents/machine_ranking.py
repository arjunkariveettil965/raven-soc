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


def summarize_ueba_anomalies(
    ueba_anomalies: pd.DataFrame,
) -> pd.DataFrame:
    """
    Convert the UEBA anomaly table into one summary row per device.

    The summary contains:
    - total anomalies
    - critical anomalies
    - maximum anomaly score
    - UEBA risk contribution
    """

    summary_columns = [
        "DeviceName",
        "TotalUEBAAnomalies",
        "CriticalUEBAAnomalies",
        "MaximumAnomalyScore",
        "UEBARiskContribution",
    ]

    if ueba_anomalies.empty:
        return pd.DataFrame(
            columns=summary_columns
        )

    required_columns = {
        "DeviceName",
        "AnomalyScore",
        "AnomalySeverity",
    }

    missing_columns = (
        required_columns
        - set(ueba_anomalies.columns)
    )

    if missing_columns:
        raise ValueError(
            "UEBA anomalies are missing required columns: "
            f"{sorted(missing_columns)}"
        )

    working_anomalies = ueba_anomalies.copy()

    working_anomalies["IsCriticalAnomaly"] = (
        working_anomalies["AnomalySeverity"]
        .astype(str)
        .str.strip()
        .str.lower()
        .eq("critical")
        .astype(int)
    )

    ueba_summary = (
        working_anomalies.groupby("DeviceName")
        .agg(
            TotalUEBAAnomalies=(
                "AnomalyScore",
                "count",
            ),
            CriticalUEBAAnomalies=(
                "IsCriticalAnomaly",
                "sum",
            ),
            MaximumAnomalyScore=(
                "AnomalyScore",
                "max",
            ),
        )
        .reset_index()
    )

    ueba_summary["UEBARiskContribution"] = (
        ueba_summary["MaximumAnomalyScore"]
        + (
            ueba_summary["CriticalUEBAAnomalies"]
            * 20
        )
    ).clip(upper=150)

    integer_columns = [
        "TotalUEBAAnomalies",
        "CriticalUEBAAnomalies",
        "MaximumAnomalyScore",
        "UEBARiskContribution",
    ]

    ueba_summary[integer_columns] = (
        ueba_summary[integer_columns]
        .fillna(0)
        .astype(int)
    )

    return ueba_summary


def add_ueba_summary(
    machine_overview: pd.DataFrame,
    ueba_summary: pd.DataFrame,
) -> pd.DataFrame:
    """
    Merge device-level UEBA summary values into the device overview.
    """

    if "DeviceName" not in machine_overview.columns:
        raise ValueError(
            "Device overview is missing DeviceName."
        )

    ueba_columns = [
        "TotalUEBAAnomalies",
        "CriticalUEBAAnomalies",
        "MaximumAnomalyScore",
        "UEBARiskContribution",
    ]

    if ueba_summary.empty:
        enriched_overview = machine_overview.copy()

        for column in ueba_columns:
            enriched_overview[column] = 0

        return enriched_overview

    required_summary_columns = {
        "DeviceName",
        *ueba_columns,
    }

    missing_columns = (
        required_summary_columns
        - set(ueba_summary.columns)
    )

    if missing_columns:
        raise ValueError(
            "UEBA summary is missing required columns: "
            f"{sorted(missing_columns)}"
        )

    enriched_overview = machine_overview.merge(
        ueba_summary[
            [
                "DeviceName",
                *ueba_columns,
            ]
        ],
        on="DeviceName",
        how="left",
    )

    enriched_overview[ueba_columns] = (
        enriched_overview[ueba_columns]
        .fillna(0)
        .astype(int)
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
    - UEBA risk contribution
    """

    required_columns = {
        "DeviceName",
        "WarningEvents",
        "ErrorEvents",
        "MediumSeverityAlerts",
        "HighSeverityAlerts",
        "DeviceCriticality",
        "UEBARiskContribution",
    }

    missing_columns = (
        required_columns
        - set(machine_overview.columns)
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
        + ranked["UEBARiskContribution"]
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
            "CriticalUEBAAnomalies",
            "MaximumAnomalyScore",
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
        required_columns
        - set(machine_ranking.columns)
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