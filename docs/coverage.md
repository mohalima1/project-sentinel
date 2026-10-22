# Coverage and Current Implementation Scope

## Implemented and Verified

- **Authenticated Local Access & Dashboard**:
  - Direct launcher (`Start-Sentinel.cmd`) using short-lived one-use token exchange (`@local`).
  - Compatibility password accounts with scrypt (N=16384, r=8, p=5) and login throttling.
  - Multi-tab navigation: Overview, Changes, Events, Alerts, Collection health, Settings & audit.
  - Responsive desktop and mobile layouts with error, empty, offline, and stale states.

- **Real Host Monitoring & Durable Collection**:
  - Native Windows collection via `sentinel.collector` and `sentinel.collector.windows`.
  - Windows Event Logs: System, Security, Microsoft-Windows-TaskScheduler/Operational, Microsoft-Windows-Windows Defender/Operational, and Sysmon.
  - Snapshot inventories: Running processes, Windows services, scheduled tasks, startup commands, local administrator group members, and installed software.
  - Durable SQLite spool (`queue.db`) preserving cursors, baseline state, and delivery acknowledgement.
  - Bounded storage and queue limits; explicit permission denial and unavailable source reporting.

- **SIEM Detection Engine & Evidence-Backed Alerts**:
  - Six core Windows rule families: Repeated failed logins (Security 4625), Local admin group membership changes (4732/4733), New service installation (4697/System 7045), Scheduled task creation (4698/4702), Security log clearing (1102), and Defender threat detections (1116).
  - Explicit MITRE ATT&CK technique mapping, official Microsoft documentation links, prerequisites, and investigation steps for each rule.
  - Alert deduplication, threshold grouping, suppression, and investigation lifecycle states (`new`, `investigating`, `resolved`, `false_positive`).

- **Packaging and Service Host**:
  - Reproducible Windows installer builder (`installer/build.ps1`) bundling pinned Python 3.12.13 runtime, hash-verified dependencies, and SHA-256 manifest.
  - Native 64-bit Windows Service host (`SentinelService.exe` / `SentinelService.cs`) supervising the background collector.
  - Elevated installer (`installer/install.ps1`) with strict Windows ACLs, automatic SQLite pre-upgrade backup, and Alembic migrations.
  - Safe uninstaller (`installer/uninstall.ps1`) with explicit `-Data Retain` or `-Data Remove` choices.

## Deferred / Future Work

- External NVD/CISA/vendor vulnerability feed synchronization and automated CVE matching against inventory.
- Host-changing remediation actions (monitoring is enabled; host-modifying controls remain disabled).
- Whole-network monitoring beyond the installed host (requires network taps, sensor appliances, or firewall/DNS log forwarders).
- Caldera adversary emulation VM integration.
