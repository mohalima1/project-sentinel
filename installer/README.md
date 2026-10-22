# Project Sentinel Windows Installer & Service Tooling

This directory provides the packaging, installation, Windows service host, and uninstallation tooling for Project Sentinel on Windows 11 / Windows Server x64.

## Overview

- **Package Builder (`build.ps1`)**:
  - Compiles frontend assets (`tsc --noEmit && vite build`).
  - Bundles a pinned, standalone Python 3.12.13 runtime with strict hash-verified dependencies (`requirements.lock`).
  - Packages the Sentinel backend application, database migrations, and web assets.
  - Compiles the native 64-bit Windows Service executable (`SentinelService.exe`) from `SentinelService.cs`.
  - Generates a SHA-256 integrity manifest (`manifest.json`) covering every packaged file.
  - Produces a distributable zip archive under `artifacts\packages\Sentinel-<timestamp>.zip`.

- **Windows Service Host (`SentinelService.exe` / `SentinelService.cs`)**:
  - Hosted as Windows Service `ProjectSentinelCollector`.
  - Runs in the background as a dedicated, read-only telemetry collector with no arbitrary command execution or network listening ports.
  - Communicates directly with the local Sentinel backend ingestion endpoint (`http://127.0.0.1:8765/api/ingest`).
  - Buffers telemetry securely in a bounded SQLite spool (`%ProgramData%\Project Sentinel\collector\queue.db`) when the dashboard/backend is closed.
  - Automatically handles graceful shutdown via cooperative file signals (`stop.request`) and SCM stop requests.

- **Installer (`install.ps1`)**:
  - Run from an elevated PowerShell prompt on the target system.
  - Verifies package SHA-256 integrity against `manifest.json`.
  - Installs binaries to `%ProgramFiles%\Project Sentinel`.
  - Restricts access using explicit Windows ACLs:
    - Binaries: FullControl for SYSTEM and Administrators; ReadAndExecute for Users.
    - Backend Data (`%LOCALAPPDATA%\Project Sentinel\data`): FullControl only for the owner and Administrators.
    - Collector State (`%ProgramData%\Project Sentinel\collector`): FullControl for SYSTEM/Administrators, ReadAndExecute for owner.
  - Automatically initializes or upgrades the database schema using Alembic migrations (with automatic pre-upgrade SQLite backup).
  - Registers and configures the `ProjectSentinelCollector` Windows Service with automatic restart recovery.

- **Launcher (`Start-Sentinel.cmd` / `installed_launch.py`)**:
  - Launched by the regular, unelevated user.
  - Starts the Sentinel backend application on a reserved loopback port and opens the authenticated local dashboard in the default browser.

- **Uninstaller (`uninstall.ps1`)**:
  - Run from an elevated PowerShell prompt.
  - Stops and unregisters the `ProjectSentinelCollector` service.
  - Removes installed files under `%ProgramFiles%\Project Sentinel`.
  - Requires explicit parameter `-Data Retain` or `-Data Remove` to decide whether user databases and telemetry history should be preserved.
