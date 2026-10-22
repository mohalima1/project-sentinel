# Architecture and Data Flow

## 1. Local Authentication and Session Lifecycle
`Start-Sentinel.cmd` launches `sentinel.launch`, which reserves a free loopback port and opens the default browser with a private two-minute, one-use token in the URL fragment (`/#local=<token>`). React removes the fragment from the URL and exchanges it at `POST /api/auth/local` for an ordinary session cookie (`sentinel_session`). The launch token is never printed to terminal or written to disk. The reserved `@local` identity has no password. Traditional password accounts remain available for development compatibility.

Authentication queries obtain a SQLite writer reservation before checking throttling counters, release the transaction during CPU-bound password hashing, and re-verify users in a short write transaction to prevent database lock contention. Scrypt hashes use parameters N=16384, r=8, p=5; older hashes upgrade automatically on successful login.

## 2. Ingestion and Durable Collection
Host telemetry is gathered by a decoupled process (`sentinel.collector`) orchestrated as a native Windows Service (`ProjectSentinelCollector`).
- **Telemetry Sources**: Queries read-only Windows PowerShell/API sources: Windows Event Logs (`System`, `Security`, `Microsoft-Windows-TaskScheduler/Operational`, `Microsoft-Windows-Windows Defender/Operational`, `Sysmon`) and snapshot inventories (processes, services, tasks, startup, local administrators, installed software, audit policy).
- **Durable Spool**: Events and baseline snapshots are staged atomically in a local SQLite spool (`queue.db`). Log cursors advance ONLY after positive delivery acknowledgement from the backend ingestion API (`POST /api/ingest`).
- **Ingestion Authentication**: Authenticated independently of web browser sessions using a dedicated, cryptographically generated token file (`ingestion.json`).
- **Backpressure & Hard Limits**: The collector enforces bounded queue limits (10 MB default) and maximum spool disk limits (50 MB default). When limits are exceeded, collection pauses safely rather than silently dropping evidence.

## 3. SIEM Detection Engine
During event ingestion, newly committed events are evaluated inside the ingestion transaction against six Windows rule families:
- Repeated failed logins (Security 4625)
- Local administrator group membership additions/removals (4732/4733)
- New service installations (4697 / System 7045)
- Scheduled task creation and registration (4698 / 4702)
- Security audit log clearing (1102)
- Microsoft Defender threat detections (1116)

Alerts group correlated events within configurable time windows, link to original event evidence, map to MITRE ATT&CK techniques, provide investigation guidance, and support workflow states (`new`, `investigating`, `resolved`, `false_positive`).

## 4. Web Application and Presentation
- FastAPI serves API endpoints under `/api/` and Vite's compiled production assets under `/` and `/assets/`.
- Keyset-paginated search (`/api/events`) supports source, category, severity, and text filters.
- React/TypeScript frontend presents six core sections:
  1. **Overview**: Host posture, recent activity, and system status.
  2. **Changes**: Registry and inventory baseline diffs.
  3. **Events**: Raw and parsed event log explorer with full XML evidence.
  4. **Alerts**: Detection timeline, severity, MITRE ATT&CK mappings, and status triage.
  5. **Collection health**: Status, permissions, and health across all telemetry sources.
  6. **Settings & audit**: Administrative configuration, retention policies, and audit logs.

## 5. Service & Packaging
- `installer/SentinelService.cs` compiles via C# to `SentinelService.exe`, hosting the background collector as a resilient Windows service with automatic restart recovery.
- `installer/build.ps1` builds a standalone, reproducible zip package containing a pinned Python 3.12.13 runtime, hash-verified dependencies (`requirements.lock`), and a SHA-256 integrity manifest.
- `installer/install.ps1` installs with strict Windows ACLs and automatic pre-upgrade database backups.
- `installer/uninstall.ps1` cleanly removes binaries and services with explicit user data retention choice (`-Data Retain` or `-Data Remove`).
