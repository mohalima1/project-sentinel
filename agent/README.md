# Sentinel Agent / Collector Boundary

The Sentinel background agent is implemented as a dedicated, decoupled Python process (`sentinel.collector`) orchestrated as a native Windows Service (`ProjectSentinelCollector` via `installer/SentinelService.exe`).

## Key Principles & Design

1. **Decoupled Architecture**:
   - The collector is strictly decoupled from the web application and dashboard. It does not import dashboard session state or open listening ports.
   - It connects only to the local ingestion endpoint (`/api/ingest`) using a dedicated, cryptographically generated ingestion token (`ingestion.json`).

2. **Durable SQLite Spool (`sentinel.collector.spool`)**:
   - Telemetry events, baseline diffs, and log cursors are stored atomically in a local SQLite spool (`queue.db`).
   - Cursors advance ONLY after positive delivery acknowledgement (`HTTP 200` with event IDs) from the backend.
   - If the dashboard or backend is offline, events accumulate safely up to configured disk and queue limits without dropping progress.
   - If storage limits are reached, collection pauses gracefully with explicit warning status rather than silently dropping logs.

3. **Read-Only Telemetry Collection (`sentinel.collector.windows`)**:
   - Queries Windows Event Logs (System, Security, TaskScheduler/Operational, Defender/Operational, Sysmon).
   - Reads inventory snapshots for running processes, services, tasks, startup commands, local administrator group members, and installed software.
   - Explicitly records source availability, disabled states, or permission denials (`denied`, `unavailable`, `disabled`) without breaking other functional sources.

4. **Service Lifecycle**:
   - The Windows Service executable (`installer/SentinelService.exe`) launches and supervises `python.exe -m sentinel.collector`.
   - Supports clean service stop signals (`stop.request` cooperative shutdown) and SCM control.
