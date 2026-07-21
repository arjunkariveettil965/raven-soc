from __future__ import annotations


DETECTION_COVERAGE = [
    ("AUTH_FAILED_LOGIN_BURST", "Failed Login Burst", "T1110 - Brute Force", "Authentication logs", "COLLECT_EVIDENCE", True),
    ("AUTH_SUCCESS_AFTER_FAILURES", "Success After Failures", "T1078 - Valid Accounts", "Authentication logs", "DISABLE_USER", True),
    ("PROC_SUSPICIOUS_POWERSHELL", "Suspicious PowerShell", "T1059.001 - PowerShell", "Process events", "ISOLATE_DEVICE", True),
    ("NET_SUSPICIOUS_OUTBOUND", "Suspicious Outbound Connection", "T1071 - Application Layer Protocol", "Network events", "ISOLATE_DEVICE", True),
    ("AUTH_PASSWORD_SPRAY", "Password Spray", "T1110.003 - Password Spraying", "Authentication logs", "BLOCK_DESTINATION_IP", False),
    ("PROC_DOWNLOAD_CAPABLE", "Suspicious Download Command", "T1105 - Ingress Tool Transfer", "Process events", "ISOLATE_DEVICE", True),
    ("PROC_SUSPICIOUS_EXECUTION", "Suspicious Execution", "T1218 - System Binary Proxy Execution", "Process events", "ISOLATE_DEVICE", True),
    ("NETWORK_BEACONING", "Command-and-Control Beaconing", "T1071 - Application Layer Protocol", "Network events", "ISOLATE_DEVICE", True),
]


CORRELATION_COVERAGE = [
    ("MULTI_STAGE_INTRUSION", "Multi-Stage Intrusion", "T1110, T1078, T1059.001, T1071", "Standard alerts", "ISOLATE_DEVICE", True),
    ("PASSWORD_SPRAY_ATTEMPT", "Password Spray Attempt", "T1110.003", "Authentication alerts", "BLOCK_DESTINATION_IP", False),
    ("MALWARE_DOWNLOAD_EXECUTION", "Malware Download and Execution", "T1105, T1059.001, T1218, T1204", "Process alerts", "ISOLATE_DEVICE", True),
    ("COMMAND_CONTROL_BEACONING", "Command-and-Control Beaconing", "T1071", "Network alerts", "ISOLATE_DEVICE", True),
]
