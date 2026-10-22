# Security Policy

## Reporting a Vulnerability

Do not report vulnerabilities with credentials, real host logs, or database files in public GitHub issues.
When hosted on GitHub, use GitHub's **Private Vulnerability Reporting** feature on this repository, or contact the maintainers privately before disclosing sensitive vulnerability details publicly.

Security fixes should include an isolated, reproducing synthetic fixture and verified test results.

## Security Architecture & Boundaries

Project Sentinel is designed as a local personal SIEM:
- **Loopback Binding**: The web backend and dashboard bind strictly to `127.0.0.1` by default.
- **Local Access Authentication**: The local launcher (`Start-Sentinel.cmd`) exchanges an ephemeral, single-use launch token for an authenticated, HTTP-only session cookie. Bare URLs without a valid token or session are rejected (`HTTP 401`).
- **Collector Separation**: Telemetry collection runs in a separate process/service (`ProjectSentinelCollector`) and authenticates to `/api/ingest` using a private token file (`ingestion.json`) completely independent of browser sessions.
- **Data Protection**: Local databases (`sentinel.db`) and spool queues (`queue.db`) are restricted using strict Windows Access Control Lists (ACLs) to SYSTEM, Administrators, and the active user.
- **Privacy by Design**: No telemetry, event logs, or credentials are uploaded to external cloud endpoints.

See [docs/security-model.md](docs/security-model.md) for the complete threat model and security specifications.

