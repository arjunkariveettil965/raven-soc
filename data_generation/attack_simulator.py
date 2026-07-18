from datetime import datetime, timedelta

import pandas as pd


NORMALIZED_EVENT_COLUMNS = [
    "EventTime",
    "DeviceName",
    "UserName",
    "WindowsEventID",
    "EventSource",
    "EventType",
    "EventResult",
    "EventSeverity",
    "SourceIP",
    "DestinationIP",
    "ProcessName",
    "ParentProcessName",
    "CommandLine",
    "Country",
    "RawMessage",
    "RawPayload",
]


def _create_event(
    *,
    event_time: datetime,
    device_name: str,
    user_name: str,
    windows_event_id: int,
    event_source: str,
    event_type: str,
    event_result: str,
    event_severity: str,
    source_ip: str = "",
    destination_ip: str = "",
    process_name: str = "",
    parent_process_name: str = "",
    command_line: str = "",
    country: str = "India",
    raw_message: str = "",
    raw_payload: str = "",
) -> dict[str, object]:
    """
    Create one normalized synthetic security event.

    These events are data-only simulations. They do not execute
    commands or modify the host system.
    """

    return {
        "EventTime": event_time,
        "DeviceName": device_name,
        "UserName": user_name,
        "WindowsEventID": windows_event_id,
        "EventSource": event_source,
        "EventType": event_type,
        "EventResult": event_result,
        "EventSeverity": event_severity,
        "SourceIP": source_ip,
        "DestinationIP": destination_ip,
        "ProcessName": process_name,
        "ParentProcessName": parent_process_name,
        "CommandLine": command_line,
        "Country": country,
        "RawMessage": raw_message,
        "RawPayload": raw_payload,
    }


def generate_account_compromise_scenario(
    *,
    start_time: datetime | None = None,
    device_name: str = "CFO-PC",
    user_name: str = "cfo.user",
    source_ip: str = "203.0.113.50",
    country: str = "Unknown",
    failed_login_count: int = 5,
) -> pd.DataFrame:
    """
    Generate a simulated account-compromise sequence.

    Sequence:
    - repeated failed logins
    - successful login from the same source
    - unusual login context

    No real authentication attempt is performed.
    """

    if failed_login_count < 1:
        raise ValueError(
            "failed_login_count must be at least 1."
        )

    if start_time is None:
        start_time = datetime(
            2026,
            7,
            18,
            2,
            0,
            0,
        )

    events: list[dict[str, object]] = []

    for attempt_number in range(
        failed_login_count
    ):
        event_time = (
            start_time
            + timedelta(minutes=attempt_number)
        )

        events.append(
            _create_event(
                event_time=event_time,
                device_name=device_name,
                user_name=user_name,
                windows_event_id=4625,
                event_source=(
                    "Microsoft-Windows-"
                    "Security-Auditing"
                ),
                event_type="Authentication",
                event_result="Failure",
                event_severity="High",
                source_ip=source_ip,
                destination_ip=device_name,
                country=country,
                raw_message=(
                    "Simulated failed Windows logon "
                    f"attempt {attempt_number + 1}."
                ),
                raw_payload=(
                    '{"simulation": true, '
                    '"event_id": 4625, '
                    '"logon_result": "failure"}'
                ),
            )
        )

    successful_login_time = (
        start_time
        + timedelta(
            minutes=failed_login_count
        )
    )

    events.append(
        _create_event(
            event_time=successful_login_time,
            device_name=device_name,
            user_name=user_name,
            windows_event_id=4624,
            event_source=(
                "Microsoft-Windows-"
                "Security-Auditing"
            ),
            event_type="Authentication",
            event_result="Success",
            event_severity="High",
            source_ip=source_ip,
            destination_ip=device_name,
            country=country,
            raw_message=(
                "Simulated successful Windows logon "
                "after repeated failures."
            ),
            raw_payload=(
                '{"simulation": true, '
                '"event_id": 4624, '
                '"logon_result": "success"}'
            ),
        )
    )

    return pd.DataFrame(
        events,
        columns=NORMALIZED_EVENT_COLUMNS,
    )


def generate_suspicious_powershell_scenario(
    *,
    start_time: datetime | None = None,
    device_name: str = "CFO-PC",
    user_name: str = "cfo.user",
    source_ip: str = "203.0.113.50",
) -> pd.DataFrame:
    """
    Generate simulated suspicious PowerShell activity.

    The command line is a harmless placeholder string and is never
    executed by this module.
    """

    if start_time is None:
        start_time = datetime(
            2026,
            7,
            18,
            2,
            7,
            0,
        )

    events = [
        _create_event(
            event_time=start_time,
            device_name=device_name,
            user_name=user_name,
            windows_event_id=1,
            event_source=(
                "Microsoft-Windows-Sysmon"
            ),
            event_type="Process Creation",
            event_result="Success",
            event_severity="High",
            source_ip=source_ip,
            process_name="powershell.exe",
            parent_process_name="explorer.exe",
            command_line=(
                "powershell.exe "
                "-EncodedCommand "
                "SIMULATED_SAFE_PAYLOAD"
            ),
            country="Unknown",
            raw_message=(
                "Simulated encoded PowerShell "
                "process creation."
            ),
            raw_payload=(
                '{"simulation": true, '
                '"event_id": 1, '
                '"process": "powershell.exe"}'
            ),
        ),
        _create_event(
            event_time=(
                start_time
                + timedelta(minutes=1)
            ),
            device_name=device_name,
            user_name=user_name,
            windows_event_id=4104,
            event_source=(
                "Microsoft-Windows-"
                "PowerShell"
            ),
            event_type="PowerShell Script Block",
            event_result="Success",
            event_severity="High",
            source_ip=source_ip,
            process_name="powershell.exe",
            parent_process_name="explorer.exe",
            command_line=(
                "Write-Output "
                "'RAVEN-SOC simulation only'"
            ),
            country="Unknown",
            raw_message=(
                "Simulated PowerShell script-block "
                "logging event."
            ),
            raw_payload=(
                '{"simulation": true, '
                '"event_id": 4104}'
            ),
        ),
    ]

    return pd.DataFrame(
        events,
        columns=NORMALIZED_EVENT_COLUMNS,
    )


def generate_suspicious_network_scenario(
    *,
    start_time: datetime | None = None,
    device_name: str = "CFO-PC",
    user_name: str = "cfo.user",
    source_ip: str = "192.168.1.50",
    destination_ip: str = "198.51.100.25",
) -> pd.DataFrame:
    """
    Generate a simulated suspicious outbound connection.

    The destination uses a documentation-only IP range.
    No network connection is made.
    """

    if start_time is None:
        start_time = datetime(
            2026,
            7,
            18,
            2,
            9,
            0,
        )

    events = [
        _create_event(
            event_time=start_time,
            device_name=device_name,
            user_name=user_name,
            windows_event_id=3,
            event_source=(
                "Microsoft-Windows-Sysmon"
            ),
            event_type="Network Connection",
            event_result="Success",
            event_severity="High",
            source_ip=source_ip,
            destination_ip=destination_ip,
            process_name="powershell.exe",
            parent_process_name="explorer.exe",
            command_line="",
            country="Unknown",
            raw_message=(
                "Simulated outbound connection "
                "from PowerShell to an unusual "
                "destination."
            ),
            raw_payload=(
                '{"simulation": true, '
                '"event_id": 3, '
                '"protocol": "tcp"}'
            ),
        )
    ]

    return pd.DataFrame(
        events,
        columns=NORMALIZED_EVENT_COLUMNS,
    )


def generate_multistage_attack_scenario(
    *,
    start_time: datetime | None = None,
    device_name: str = "CFO-PC",
    user_name: str = "cfo.user",
    attacker_ip: str = "203.0.113.50",
) -> pd.DataFrame:
    """
    Generate one complete simulated multi-stage attack.

    Sequence:
    1. Repeated failed logins
    2. Successful login
    3. Encoded PowerShell process
    4. PowerShell script-block activity
    5. Suspicious outbound network connection

    This function only creates DataFrame records.
    """

    if start_time is None:
        start_time = datetime(
            2026,
            7,
            18,
            2,
            0,
            0,
        )

    authentication_events = (
        generate_account_compromise_scenario(
            start_time=start_time,
            device_name=device_name,
            user_name=user_name,
            source_ip=attacker_ip,
            country="Unknown",
            failed_login_count=5,
        )
    )

    powershell_events = (
        generate_suspicious_powershell_scenario(
            start_time=(
                start_time
                + timedelta(minutes=7)
            ),
            device_name=device_name,
            user_name=user_name,
            source_ip=attacker_ip,
        )
    )

    network_events = (
        generate_suspicious_network_scenario(
            start_time=(
                start_time
                + timedelta(minutes=9)
            ),
            device_name=device_name,
            user_name=user_name,
            source_ip="192.168.1.50",
            destination_ip="198.51.100.25",
        )
    )

    complete_scenario = pd.concat(
        [
            authentication_events,
            powershell_events,
            network_events,
        ],
        ignore_index=True,
    )

    complete_scenario["EventTime"] = (
        pd.to_datetime(
            complete_scenario["EventTime"],
            errors="coerce",
        )
    )

    complete_scenario = (
        complete_scenario
        .sort_values("EventTime")
        .reset_index(drop=True)
    )

    return complete_scenario[
        NORMALIZED_EVENT_COLUMNS
    ]