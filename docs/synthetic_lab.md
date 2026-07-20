# RAVEN-SOC Synthetic Attack Lab

The synthetic lab generates data-only security events. It never executes commands,
downloads files, opens sockets, changes Windows Event Logs, isolates devices,
disables accounts, or blocks IPs.

## Scenarios

- Multi-Stage Intrusion
- Password Spray Attempt
- Malware Download and Execution
- Command-and-Control Beaconing

The scenario registry lives in `data_generation/scenario_lab.py`. New scenarios
are added by defining a generator function and registering it in the explicit
`SCENARIOS` allowlist.

## Controls

- Scenario Mode: select a named scenario or choose a random allowed scenario.
- Difficulty: Easy, Medium, or Hard.
- Noise level: None, Low, Medium, or High.
- Random seed: reproduces the same generated event content and ordering.
- Reveal Scenario Answer: shows hidden expected-result metadata for demos/tests.

Random mode stores the generated result in Streamlit session state until reset or
explicit regeneration, so reruns do not silently change the scenario.

## Difficulty

- Easy: obvious indicators, minimal jitter, all required stages present.
- Medium: moderate noise and randomized delays.
- Hard: higher noise, larger bounded delays/jitter, still enough evidence for
  deterministic detection unless a future scenario is intentionally incomplete.

## Noise

Benign noise includes normal logons, browser/internal traffic, service starts,
and ordinary PowerShell administration. The answer key marks benign event IDs,
but those fields are never included in the event stream passed to detection.

## Evaluation

`dashboard/scenario_evaluation.py` compares deterministic outputs with hidden
scenario metadata:

- detected alerts
- incident type match
- severity threshold
- MITRE coverage
- expected/missing alert types
- unexpected incident types
- target match
- approved recommended action

AI wording is not the primary correctness signal; deterministic alerts,
correlation, trusted incident fields, and action policy are.
