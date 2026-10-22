# Project Sentinel

A local personal SIEM and security monitoring system for Windows 11 x64.
Project Sentinel collects real host telemetry, detects suspicious activity with evidence-backed rules, and explains findings through an authenticated local dashboard. No AI model, subscription, cloud account, or external telemetry upload is required.

## Key Features

- **Real Windows Host Monitoring**:
  - Live collection of Windows Event Logs (`System`, `Security`, `Microsoft-Windows-TaskScheduler/Operational`, `Microsoft-Windows-Windows Defender/Operational`, `Sysmon`).
  - Periodic diff snapshots of running processes, Windows services, scheduled tasks, startup commands, local administrator group members, and installed software.
  - Transparent reporting of permission denials (e.g. non-elevated Security log access) and disabled sources.
- **Durable Local Collection & Spooling**:
  - Decoupled collector process (`sentinel.collector`) with a crash-resilient SQLite spool (`queue.db`).
  - Bounded buffering, cursor tracking, and backpressure safeguards.
  - Safe replay and deduplication: restarts never lose queued logs or create duplicate events.
- **Evidence-Backed SIEM Detection Rules**:
  - Six core Windows detection rule families: Repeated failed logins (4625), Local administrator group changes (4732/4733), New service installation (4697/7045), Scheduled task creation (4698/4702), Security log clearing (1102), and Defender threat detections (1116).
  - Explicit MITRE ATT&CK technique mapping, official Microsoft prerequisites, and actionable investigation guidance.
  - Alert deduplication, threshold grouping, suppression, and triage workflows (`new`, `investigating`, `resolved`, `false_positive`).
- **Authenticated Local Web Dashboard**:
  - Responsive React 19 + TypeScript + Vite UI with dark-mode aesthetic.
  - Six main tabs: Overview, Changes, Events, Alerts, Collection health, and Settings & audit.
  - Seamless launch via `Start-Sentinel.cmd` using short-lived one-use local tokens (`@local`), with optional password accounts for development.
- **Reproducible Packaging & Windows Service**:
  - Pinned standalone Python 3.12.13 runtime with strict SHA-256 dependency lock (`requirements.lock`).
  - Native 64-bit Windows Service host (`SentinelService.exe`).
  - Scripted installer (`installer/install.ps1`) and uninstaller (`installer/uninstall.ps1`) with strict Windows ACLs and automatic pre-upgrade database backups.

## Windows Development Startup

Prerequisites: Windows 11 x64, `uv`, Python 3.12 (uv can download it automatically), and Node.js 22.12+ (tested with 24.22.0 and npm 11.19.1).

**Double-click `Start-Sentinel.cmd` in this folder.** It runs setup if the Python environment or dashboard build is missing, starts a local server on a free port, and opens your browser directly into Sentinel. No registration or typed password is needed. Keep its terminal open while using Sentinel; press **Ctrl+C** to stop it.

The launcher grants access with a one-use link valid for two minutes. It opens automatically and is removed from the address bar. Don't share the link. Sessions expire after eight hours. A bare dashboard URL does not grant access.

For manual first setup or to rebuild after source updates:

```powershell
.\scripts\setup.cmd
.\Start-Sentinel.cmd
```

The terminal equivalent is `uv run --locked python -m sentinel.launch`.
The launcher binds only to `127.0.0.1`; each launch chooses a free port. Existing password accounts remain available under **Use an existing password account**.

`setup.cmd` installs locked dependencies, builds the dashboard, restricts `data/` to the current user, SYSTEM, and Administrators, then upgrades the database schema. Python dependencies are locked in `uv.lock`, and frontend dependencies in `frontend/package-lock.json`.

Equivalent individual build/migration commands:

```powershell
uv sync --locked --python 3.12
npm.cmd --prefix frontend ci
npm.cmd --prefix frontend run build
uv run alembic upgrade head
```

Optional developer/password mode:

```powershell
uv run python -m sentinel.cli create-user admin
uv run uvicorn sentinel.app:app --host 127.0.0.1 --port 8000 --reload
```

For frontend hot reload, keep the backend running and open a second terminal:

```powershell
npm.cmd --prefix frontend run dev
```

Open **http://127.0.0.1:5173**. Vite proxies API calls to port 8000; requests keep their original Host so same-origin validation works in development.

## Data and Upgrades

The default database is `data/sentinel.db`. Set `$env:SENTINEL_DATABASE_PATH = 'C:\private\Sentinel\sentinel.db'` before **both** migrations and startup to use a different location.

Apply schema changes with `uv run alembic upgrade head` while the server is stopped.
Check the revision with `uv run alembic current`, and check model consistency with `uv run alembic check`. The server refuses an unmigrated or incorrect schema.

## Packaging and Installer Build

To build the standalone, unsigned Windows x64 package:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File installer/build.ps1
```

This compiles `SentinelService.exe`, bundles the standalone runtime and frontend assets, hashes all files into `manifest.json`, and outputs `artifacts\packages\Sentinel-<timestamp>.zip`.

To install on a Windows system (run from an elevated PowerShell inside the extracted zip directory):

```powershell
.\install.ps1
```

To uninstall:

```powershell
.\uninstall.ps1 -Data Retain    # Keeps database and collector logs
# OR
.\uninstall.ps1 -Data Remove    # Cleans up all data and binaries
```

## Verification Suite

Run the full automated verification suite:

```powershell
# 1. Full Python unit and integration regression suite (63 tests)
uv run pytest -q

# 2. Ruff linter and formatting checks
uv run ruff check backend migrations tests
uv run ruff format --check backend migrations tests

# 3. TypeScript and Vite frontend production build
npm.cmd --prefix frontend run build

# 4. Concurrent login transaction check
uv run python tests/concurrent_login_check.py

# 5. Browser smoke tests (Chromium headless desktop & mobile)
uv run python tests/browser_smoke.py
uv run python tests/local_browser_smoke.py

# 6. Live Windows collection, durable spooling & Chromium acceptance
uv run python tests/live_windows_acceptance.py --inventory-change
```

All pytest account/event data is labeled synthetic test data; live Windows acceptance tests execute actual read-only Windows event queries and temporary, reversible registry inventory changes in an isolated test database.

## Architecture & Security Docs

- [Architecture & Data Flow](docs/architecture.md)
- [Security Model & Threat Boundaries](docs/security-model.md)
- [Coverage and Scope](docs/coverage.md)
- [Dependency Compatibility & Locks](docs/dependencies.md)
- [Readiness Review](docs/READINESS_REVIEW.md)
- [Installer & Windows Service Tooling](installer/README.md)
- [Collector & Agent Boundary](agent/README.md)

