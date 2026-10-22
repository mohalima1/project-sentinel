Act as a senior software engineer and security engineer. Build an
installable project called “Project Sentinel.”

PRODUCT GOAL

Create a personal SIEM and security management application that runs
locally on my computer. It must collect real host telemetry, detect
suspicious activity, identify potentially applicable vulnerabilities,
and explain findings through an authenticated web dashboard.

Deliver working software, installation tooling, tests, documentation,
and a repository ready to share on GitHub.

AI is helping develop this project. An embedded AI model or paid AI
subscription must not be required to run it.

INITIAL SCOPE

- Support one Windows 11 x64 computer first.
- Run a native background agent, local backend, and browser dashboard.
- Keep security data on the computer by default.
- Design clear interfaces for future Linux and multi-host support.
- Monitor the installed host and the network activity visible to it.
- Explain that whole-network visibility requires additional agents
  or integrations with network sensors, DNS, or firewall logs.
- Keep Caldera as an optional future VM testing integration.

TECHNOLOGY

Preferred starting stack:
- Python and FastAPI for the backend.
- React, TypeScript, and Vite for the dashboard.
- SQLite with migrations and indexed search for local storage.
- A native Windows service for background collection.
- A reproducible Windows installer.

Verify dependency compatibility against official documentation and
pin versions. Explain necessary deviations from this stack.

Keep collection, ingestion, detection, vulnerability matching, host
actions, and presentation in separate modules.

1. REAL HOST MONITORING

Collect:
- OS version, build, and available patch information.
- Installed software with vendor and version where available.
- Running processes, services, and listening ports.
- Active host network connections.
- CPU, memory, disk usage, and agent health.
- Relevant Windows Event Logs.
- Microsoft Defender and Sysmon events when those sources exist.

Document required permissions and logging settings. Show unavailable
sources and permission errors explicitly.

Use incremental collection, persisted cursors, bounded buffering,
retries, and duplicate prevention. Restarting the application must
not reset collection progress or silently lose queued events.

Normalize events with host ID, source, source event identifier, UTC
timestamp, event category, and original supporting evidence.

Provide configurable retention and disk limits.

2. SIEM AND DETECTION ENGINE

Implement:
- Searchable events with time, host, source, and severity filters.
- Configurable rules with thresholds and time windows.
- Alert deduplication and suppression.
- Alert states: new, investigating, resolved, and false positive.
- Evidence linking each alert to the events that triggered it.

Start with a small, tested Windows rule set covering:
- Repeated failed logins.
- Local administrator group membership changes.
- New service installation.
- Scheduled task creation.
- Security log clearing.
- Defender threat detections.

Verify each rule’s event sources and prerequisites. Explain normal
activities that can also trigger it.

Map rules to ATT&CK techniques only when justified. Distinguish
suspicious activity from a confirmed security incident.

3. VULNERABILITY AND THREAT KNOWLEDGE BASE

Integrate:
- NVD/CVE information.
- CISA Known Exploited Vulnerabilities.
- Relevant vendor advisories.
- MITRE ATT&CK technique and mitigation information.

Build a searchable knowledge base explaining:
- What each vulnerability or attack technique means.
- Affected products and conditions.
- Potential impact.
- Available detection evidence.
- Recommended mitigations and vendor references.

Cover concepts such as phishing, credential attacks, malware,
ransomware, persistence, privilege escalation, lateral movement,
and data exfiltration. Clearly distinguish educational coverage
from techniques Sentinel can actually detect.

Synchronize feeds using documented interfaces, pagination, rate
limits, retries, and local caching. Display source, last successful
update, and stale-data warnings. Retain usable cached data when a
feed is unavailable.

Match inventory against vendor/product identifiers, version ranges,
OS builds, and applicable patch information. Start with documented
supported matchers and expand through tests.

Do not treat a product-name keyword match as proof of vulnerability.
Handle ambiguous identity, missing versions, and patch exceptions.

Every finding must show:
- CVE identifier and description.
- Observed product/version.
- Match evidence and confidence.
- Severity, including score source and version when available.
- Known exploitation status.
- Relevant exposure information, or “unknown.”
- Remediation guidance and authoritative references.

Separate “potentially affected,” “affected based on available
evidence,” and “insufficient information.”

A vulnerability match must never be presented as proof of compromise.
Do not invent CVEs, affected versions, exploits, or remediation steps.

4. DASHBOARD

Create a clear, accessible dashboard with:
- Overview: recent alerts, findings, and collection health.
- Host inventory: software, processes, services, and connections.
- Events: searchable event explorer.
- Alerts: evidence, timeline, investigation state, and guidance.
- Vulnerabilities: prioritized findings and matching explanations.
- Knowledge base: searchable vulnerabilities and attack techniques.
- Controls: permitted host actions and their results.
- Settings: collection, retention, feeds, and authentication.
- Audit log: administrative actions and configuration changes.

Use real backend data. Any demo mode must be explicitly labeled,
opt-in, and stored separately.

Include loading, empty, offline, stale-data, and error states.
Missing telemetry must not appear as “everything is secure.”

5. HOST CONTROLS AND APPLICATION SECURITY

Begin with monitoring enabled and host-changing controls disabled.

Support inventory refresh, collection settings, and diagnostic
export. Add start/stop/restart only for explicitly allowlisted,
noncritical services.

For host-changing actions:
- Authenticate and authorize the user.
- Show the exact target and requested change.
- Require confirmation.
- Enforce the allowlist in the privileged component.
- Record request, actor, timestamp, outcome, and errors.

Keep privileged operations separate from the web dashboard.
Do not implement an unrestricted command shell.

Bind the dashboard to localhost by default. Require secure initial
account setup without default passwords. Protect sessions, validate
requests, enforce authorization server-side, and protect against
CSRF and injection.

Local-use update approved 2026-10-22: the normal Windows launcher opens
the dashboard without registration or a typed password, using a private,
short-lived, one-use launch token exchanged for a protected session.
Keep existing password accounts as optional compatibility access. A bare
localhost URL must not bypass authentication. The launcher stays on loopback.

Authenticate agent ingestion separately from dashboard access.
Protect secrets and local data with appropriate Windows permissions.
Treat collected logs and external feed content as untrusted input.

Document any telemetry fields that could contain sensitive data.
Do not upload host telemetry to external services by default.

6. INSTALLATION AND GITHUB DELIVERY

Provide:
- A development setup command.
- A reproducible installer build and installable package.
- Background service installation and startup.
- Start, stop, status, and troubleshooting commands.
- Database migration and upgrade handling.
- Uninstall with an explicit choice to retain or remove user data.
- Dependency lockfiles and example configuration.

Organize the repository into agent, backend, frontend, rules,
tests, installer, and documentation directories.

Include:
- README with prerequisites and verified setup instructions.
- Architecture and data-flow documentation.
- Permissions and security model.
- Supported telemetry and detection coverage.
- Vulnerability matching limitations.
- CONTRIBUTING.md, SECURITY.md, and a suitable LICENSE.
- .gitignore and sanitized example data.
- GitHub Actions for relevant tests, linting, builds, dependency
  checks, and secret scanning.

Keep credentials, real host logs, private inventory, databases,
and VM images out of Git.

Prepare the repository locally. Publish it only when a GitHub
destination and publication authorization are provided.

7. VERIFICATION AND IMPLEMENTATION PROCESS

Inspect the workspace first and preserve existing work.
Record assumptions and a concise implementation plan, then build
in working milestones:

1. Authenticated dashboard and backend with persistent storage.
2. Real host collection and event search.
3. Detection rules and evidence-backed alerts.
4. Knowledge feeds and tested vulnerability matching.
5. Restricted controls, installer, and documentation.

Complete each milestone end to end before expanding it.

Verify:
- A real host event reaches the searchable dashboard.
- Benign test fixtures trigger the expected detection rules.
- Negative fixtures do not trigger those same rules.
- Vulnerability matching handles affected, unaffected, ambiguous,
  and patched cases.
- Unauthorized ingestion and host actions are rejected.
- Restarts, feed outages, and collection failures are handled.
- Retention limits work.
- Installation, reboot startup, upgrade, and uninstall work in a
  disposable Windows VM when that environment is available.

Tests using synthetic data must be identified as fixture tests,
not evidence that live collection works.

Never claim a test passed unless it was actually executed.
If an environment or credential is unavailable, identify the exact
unverified requirement and continue independent work.

Finish with the implemented features, actual test results,
installation instructions, known limitations, and remaining work.
Do not claim the system detects every attack or is “perfect.”
