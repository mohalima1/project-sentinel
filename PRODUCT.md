# Project Sentinel Product Scope

Project Sentinel is an installable, private personal SIEM and security monitoring system built for Windows 11 x64.

## Product Goals & Capabilities

1. **Local Real Host Collection**: Collects actual Windows Event Logs and system inventory snapshots (processes, services, tasks, startup programs, local administrator accounts, and installed software) without cloud uploads.
2. **Crash-Resilient Durability**: Buffers telemetry locally in a bounded SQLite spool (`queue.db`), maintaining cursor positions and baseline state across restarts.
3. **Evidence-Backed Detections**: Evaluates incoming telemetry against six Windows security rule families mapped to MITRE ATT&CK techniques, providing full original XML event evidence and clear investigation workflows.
4. **Accessible Local Dashboard**: Responsive, authenticated React dashboard with zero registration or default passwords required, launched seamlessly via an ephemeral one-use launcher token (`@local`).
5. **Reproducible Windows Packaging**: Bundles a pinned Python 3.12 runtime with hash-verified dependencies and a native 64-bit Windows Service host (`SentinelService.exe`).

