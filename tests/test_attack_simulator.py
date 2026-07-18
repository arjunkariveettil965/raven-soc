import pandas as pd
import pytest

from data_generation.attack_simulator import (
    NORMALIZED_EVENT_COLUMNS,
    generate_account_compromise_scenario,
    generate_multistage_attack_scenario,
    generate_suspicious_network_scenario,
    generate_suspicious_powershell_scenario,
)


def test_account_compromise_scenario() -> None:
    """
    Verify repeated failures followed by a successful login.
    """

    events = generate_account_compromise_scenario()

    assert len(events) == 6

    assert list(events.columns) == (
        NORMALIZED_EVENT_COLUMNS
    )

    failed_events = events[
        events["EventResult"] == "Failure"
    ]

    successful_events = events[
        events["EventResult"] == "Success"
    ]

    assert len(failed_events) == 5
    assert len(successful_events) == 1

    assert set(
        failed_events["WindowsEventID"]
    ) == {4625}

    assert set(
        successful_events["WindowsEventID"]
    ) == {4624}

    assert events["DeviceName"].nunique() == 1
    assert events["UserName"].nunique() == 1
    assert events["SourceIP"].nunique() == 1


def test_invalid_failed_login_count() -> None:
    """
    Reject invalid authentication scenario configuration.
    """

    with pytest.raises(
        ValueError,
        match="at least 1",
    ):
        generate_account_compromise_scenario(
            failed_login_count=0,
        )


def test_suspicious_powershell_scenario() -> None:
    """
    Verify that PowerShell simulation contains process evidence.
    """

    events = generate_suspicious_powershell_scenario()

    assert len(events) == 2

    assert "powershell.exe" in set(
        events["ProcessName"]
    )

    assert events[
        "CommandLine"
    ].str.contains(
        "EncodedCommand",
        case=False,
        na=False,
    ).any()

    assert set(
        events["WindowsEventID"]
    ) == {
        1,
        4104,
    }


def test_suspicious_network_scenario() -> None:
    """
    Verify the simulated network event.
    """

    events = generate_suspicious_network_scenario()

    assert len(events) == 1

    assert (
        events.iloc[0]["EventType"]
        == "Network Connection"
    )

    assert (
        events.iloc[0]["DestinationIP"]
        == "198.51.100.25"
    )

    assert events.iloc[0]["WindowsEventID"] == 3


def test_multistage_attack_scenario() -> None:
    """
    Verify the complete synthetic attack chain.
    """

    events = generate_multistage_attack_scenario()

    assert len(events) == 9

    assert list(events.columns) == (
        NORMALIZED_EVENT_COLUMNS
    )

    assert events["EventTime"].is_monotonic_increasing

    assert set(
        events["WindowsEventID"]
    ) == {
        4625,
        4624,
        1,
        4104,
        3,
    }

    assert (
        events["DeviceName"].nunique()
        == 1
    )

    assert (
        events["UserName"].nunique()
        == 1
    )

    assert (
        events["EventType"]
        == "Authentication"
    ).sum() == 6

    assert (
        events["EventType"]
        == "Process Creation"
    ).sum() == 1

    assert (
        events["EventType"]
        == "PowerShell Script Block"
    ).sum() == 1

    assert (
        events["EventType"]
        == "Network Connection"
    ).sum() == 1

    assert isinstance(
        events,
        pd.DataFrame,
    )