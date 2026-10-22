# Sentinel SIEM Detection Rules

The Sentinel detection engine evaluates incoming Windows host telemetry against six core security detection families implemented in `backend/sentinel/monitoring/detections.py` and validated by positive/negative synthetic test suites in `tests/test_detections.py`.

## Core Detection Families

1. **Repeated Failed Logins** (`win_failed_logins`):
   - **Event ID**: Security 4625 (An account failed to log on).
   - **MITRE ATT&CK**: [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/).
   - **Prerequisites**: Windows Advanced Audit Policy -> *Audit Logon* enabled.
   - **Correlation**: Correlates multiple logon failures for the same target domain/user/IP within a sliding time window (default 5 attempts in 300 seconds).

2. **Local Administrator Group Changes** (`win_admin_group_change`):
   - **Event IDs**: Security 4732 (A member was added to a security-enabled local group) & 4733 (A member was removed).
   - **MITRE ATT&CK**: [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) & [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/).
   - **Prerequisites**: Windows Advanced Audit Policy -> *Audit User Account Management*.
   - **Target**: Detects privilege escalation or rogue administrative account provisioning targeting the Administrators group (`S-1-5-32-544`).

3. **New Service Installation** (`win_service_install`):
   - **Event IDs**: Security 4697 & System 7045 (A service was installed in the system).
   - **MITRE ATT&CK**: [T1543.003 - Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/).
   - **Details**: Captures service name, service binary path, startup type, and executing user account.

4. **Scheduled Task Creation** (`win_task_create`):
   - **Event IDs**: Security 4698 & TaskScheduler/Operational 106 (A scheduled task was created).
   - **MITRE ATT&CK**: [T1053.005 - Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/).
   - **Prerequisites**: Audit Other Object Access Events or TaskScheduler Operational channel enabled.

5. **Security Audit Log Clearing** (`win_security_log_cleared`):
   - **Event ID**: Security 1102 (The audit log was cleared).
   - **MITRE ATT&CK**: [T1070.001 - Indicator Removal: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/).
   - **Severity**: High. Alerts immediately upon intentional clearing of the Windows Security event log.

6. **Microsoft Defender Threat Detection** (`win_defender_detection`):
   - **Event ID**: Microsoft-Windows-Windows Defender/Operational 1116 (Malware or unwanted software was detected).
   - **MITRE ATT&CK**: [T1204 - User Execution](https://attack.mitre.org/techniques/T1204/).
   - **Details**: Extracts threat name, severity, infected file path, remediation state, and detection origin.

