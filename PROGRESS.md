# Project Sentinel Implementation Plan

## Windows monitoring release plan (2026-10-22, active)

The current user brief narrows PROJECT_SPEC.md: one private Windows host, real
collection, explanations and collection health. Knowledge feeds, multi-host and
host-changing controls are deferred. Preserve all existing accounts and the
one-use launcher. No Git repository exists; implement in this workspace without
creating a repository or publishing. Routine decisions and inline execution are
authorized by the user; no additional design approval gate is needed.

Architecture: a separate Python collector reads fixed, read-only PowerShell
sources. A private per-installation credential authenticates ingestion independently
of browser sessions. A collector SQLite spool atomically retains evidence,
snapshot baselines and log progress before advancing cursors. Backend transactions
commit events, detection evidence and heartbeat before acknowledging. Stable event
keys and unique constraints make replay safe. SQLite writer reservations serialize
mutations; dashboard reads remain short. Bounded storage stops collection/delivery
with visible errors rather than silently discarding evidence.

Implementation tasks (also the execution ledger):

- [x] 1. Add migration 0002, bounded authenticated ingestion, UTC normalized events,
  keyset search, retention/storage policy, regression tests. Files: monitoring
  models/schemas/API/storage, config, migrations and tests/test_monitoring.py.
- [x] 2. Add separate collector, Windows reader, durable bounded spool, baseline
  diffs, cursor/reset/gap handling, retries and independent heartbeat. Test restart,
  replay, full queue, storage failure and partial-source failure. Files:
  backend/sentinel/collector/, agent/, tests/test_collector.py. Connect launcher
  only after ingestion/search work end to end.
- [x] 3. Add six narrowly scoped detection families, original evidence, explanations,
  threshold grouping, suppression and investigation states. Verify Microsoft
  references/prerequisites. Positive and negative tests use labeled synthetic
  fixtures only. Files: detections.py, rules/, tests/test_detections.py.
- [x] 4. Extend existing dashboard style with Changes, Events, Alerts, Collection
  health, Settings/audit; authenticated filters, evidence details, empty/stale/error
  states. Verify actual browser behavior and mobile layout. No redesign.
- [x] 5. Execute isolated real Windows collection/search and reversible inventory
  acceptance, concurrent ingestion/read tests, restart/retry tests; package pinned
  Windows service/installer tooling after monitoring works. Document exact setup,
  permission scope, limits and VM-only unverified lifecycle/disruptive checks.

Shared interfaces: ingestion consumes collector envelopes with stable identity,
UTC observed_at, source/category/severity and original evidence. Detections consume
only committed unique events inside the ingestion transaction. UI consumes the
same authenticated event/alert/health API, never the privileged reader directly.

Review focus: snapshot errors must not imply removals; initial snapshots are
baselines, not additions; record reuse after clearing must not skip new evidence;
disk/queue failures must leave cursors unchanged; denied Security access and unknown
audit settings must remain visible even when other sources work. Real telemetry
and secrets remain in ignored private data directories. No disruptive host tests.

Release execution evidence:
- Ingestion API regressions first failed because endpoints were absent. Initial
  implementation exposed nested BEGIN behavior with Python's explicit SQLite
  transactions; corrected using an initial write reservation as in account auth.
  Five ingestion/search/health/retention/concurrency fixture tests then passed.
- Collector fixtures first failed because collector modules were absent. Durable
  spool implementation then passed seven checks for baseline/change evidence,
  restart, acknowledgement/retry, queue and hard spool caps, disk rejection,
  cursor reset/rollover gaps, host binding and unavailable-source preservation.
- Combined focused suite: **12 passed in 2.45s**. These are synthetic fixtures,
  not evidence of live Windows collection. Full foundation regression is running.
- Full suite after detection/UI backend additions: **56 passed in 57.95s**.
- Microsoft official event/audit documentation checked for Security 4625,
  4732/4733, 4697, 4698/4702, 1102 and Defender 1116; links and prerequisites
  accompany each rule. Sign-in grouping uses target domain/account/source IP and
  a configurable threshold/window (default 5 in 300 seconds), including reordered
  delivery. Browser sign-ins stay exclusively in Sentinel audit activity.
- Actual read-only Windows probe: System and Defender available; Security denied;
  TaskScheduler Operational disabled; Sysmon unavailable; all five inventories
  available; auditpol query denied (0x522). No audit settings were changed.
- Live acceptance initially hit a test-script raw-string syntax error (before
  execution), then an inaccessible exact Source selector. Corrected string and
  added explicit accessible select names. Full live rerun **passed** on 2026-10-22:
  real log HTTP ingestion, replay=0 duplicates, durable collector restart,
  separate process delivery, real XML in authenticated Chromium search, and
  mobile navigation across all six sections with no overflow/JS errors.
- Live inventory acceptance temporarily created an HKCU Uninstall metadata marker,
  not an installed application. Real registry snapshots showed before=None /
  after=marker, then before=marker / after=None. Cleanup completed in finally.
  Accounts, services, tasks, security settings and event logs were untouched.
- Live evidence and screenshots retained only under ignored private
  `artifacts/live-20261022-174701/`; desktop health and mobile settings visually
  inspected. These are real host data and must not be published.
- Additional hardening regressions reproduced malformed nested Windows fields,
  absent collector locking and nonpersistent gap counts. Implemented validation,
  a process-lifetime OS lock and transactional cumulative counters; verification
  is pending. Commit-failure simulation already verifies no acknowledgement or
  partial event/heartbeat on failed database commit.

## Brief and assumptions

The user requests milestone 1: a working authenticated local dashboard, FastAPI,
SQLite persistence, migrations, tests, and exact development startup commands.
`AGENTS.md` and `PROJECT_SPEC.md` were initially zero bytes on 2026-10-22.
The user populated both during implementation; both were reread, and the plan
and implementation were updated to follow the full personal SIEM specification.
There was no existing code or Git repository. Implement directly in this directory;
no commits/worktree apply. No Git publication is authorized or performed.
The user explicitly delegates routine technical decisions and asks for completion,
so implementation proceeds inline without additional design approval gates.

Assumptions: this milestone is the local application foundation. Dashboard data
is actual database/authentication status and recent account activity. Domain
monitoring, agents, alert rules, and integrations belong to later specified milestones;
no invented metrics or monitoring claims. One administrator role, no signup.
Use React/TypeScript/Vite, one FastAPI process serving built assets, SQLite + SQLAlchemy,
Alembic migrations, standard-library scrypt passwords, database-backed random
sessions, CSRF protection, and bounded login throttling. Listen on loopback for
development. Windows service installation belongs to the installer milestone.

## Available tools

- Windows PowerShell; Python 3.15 default, Python 3.13.16 and 3.12.13 installed.
- `uv` 0.11.24; use Python 3.12 for this project and lock dependencies.
- Node 24.22.0, npm 11.19.1 via `npm.cmd` (PowerShell blocks npm.ps1).
- Git 2.55.0 available; this directory has no `.git`.
- No standalone sqlite3 or Docker command found; Python supplies SQLite.
- React 19.3.1, TypeScript 7.0.2, Vite 8.3.5 installed with exact versions and npm lock.
- Official FastAPI templates, SQLAlchemy SQLite, Alembic, React, and Vite documentation
  consulted. No starting-stack deviation remains after the full spec arrived.
- Playwright Chromium available for actual desktop/mobile HTTP browser verification.

## Milestones

1. **Application foundation (current)** — authenticated local dashboard, API,
   persisted users/sessions/activity, migrations, tests, development runbook.
2. **Real host collection and event search** — incremental Windows sources,
   persisted cursors, duplicate prevention, retention limits and permission reporting.
3. **Detection rules and evidence-backed alerts** — Windows prerequisites,
   tested positive/negative fixtures, thresholds, investigation and suppression.
4. **Knowledge feeds and vulnerability matching** — cached feeds, documented
   supported matchers and affected/unaffected/ambiguous/patched fixture tests.
5. **Restricted controls, installer, and documentation** — allowlisted actions,
   Windows service lifecycle, reproducible installer, VM upgrade/uninstall tests.

## Milestone 1 tasks

- [x] Inspect instructions, repository, and development tools; record plan.
- [x] Persistence: `backend/sentinel/config.py`, `db.py`, `models.py`, `migrations/`.
  `Settings` provides an absolute database path; `make_engine` enables foreign
  keys and busy timeout. Migration `0001` creates users, sessions, login attempts,
  and audit events. Test fresh upgrade, repeated upgrade, downgrade/re-upgrade,
  data preservation, constraints, and startup refusal before migration.
- [x] Authentication: `security.py`, `accounts.py`, `cli.py`. Create accounts
  interactively, normalize usernames, hash passwords; persist hashed session
  tokens with eight-hour expiry. Test wrong/unknown credentials, throttling,
  duplicate accounts, hash storage, expiry, logout, and restart persistence.
- [x] Web: `backend/sentinel/app.py`, `frontend/src/`. React login and dashboard, protected
  `/api/status`, minimal `/healthz`, POST logout, CSRF and Host/Origin validation,
  cache/security headers. Test unauthorized access, form validation, escaping,
  CSRF, foreign origins, and API responses.
- [x] Delivery: `README.md`, locked environment, full pytest/lint runs, actual
  Uvicorn HTTP smoke test and desktop/mobile browser checks; record results here.

## Review focus

No implicit account or password; never store raw passwords/session tokens.
Migration operations must preserve existing account data; app must not silently
create schemas. A restart must preserve users and unexpired login sessions.
Reject forged mutations and expired/revoked cookies; private responses are not
cacheable. UI must work with keyboard, narrow screens, and real empty/error states.

## Execution record

- Planning complete. No application code or dependencies existed initially.
- Original server-rendering proposal was replaced with React/TypeScript/Vite when
  the populated spec arrived, before any server-rendered UI was implemented.
- Persistence tests first failed without migrations, then passed (3/3).
- Account CLI test first failed without the CLI, then account/persistence suite
  passed (14/14). Windows getpass ignores piped stdin, so tests substitute only
  terminal input; hashing, CLI validation, and SQLite writes remain real.
- Backend suite passed 27/27 after HTTP/session/CSRF/Origin/Host tests were added.
- Switched test client dependency to httpx2 as required by the resolved Starlette
  version, removing its httpx deprecation warning; 27/27 passed without warnings.
- First Chromium run passed UI interactions but command failed on Windows fixture
  cleanup after abrupt server termination. Test runner now requests graceful
  Uvicorn shutdown and only reports success after temporary database removal.

## Final verification (2026-10-22)

- `uv run pytest -q`: **27 passed in 13.34s** on the final locked environment,
  no warnings. Tests cover migrations,
  account creation/validation, salted password storage, unknown/wrong credentials,
  throttle/reset, hashed session persistence, expiry/revocation, HTTP authorization,
  CSRF, Origin/Host validation, SQL injection input, restart, and startup failure.
- `uv run ruff check backend migrations tests`: **All checks passed**.
- `uv run ruff format --check backend migrations tests`: **15 files formatted**.
- `npm.cmd --prefix frontend run build`: TypeScript and Vite build **passed**.
- `uv run python tests/browser_smoke.py`: **passed** against actual Uvicorn HTTP and
  Chromium at 1440px and 390px. Invalid password, Enter submit, login, reload,
  authenticated status, audit navigation, offline retry, logout, no overflow/no JS
  errors, graceful shutdown and temporary database deletion verified.
- Desktop/mobile login and overview screenshots visually inspected in `artifacts/`
  (ignored; synthetic fixture identity, not real host telemetry).
- `.\scripts\setup.cmd`: **passed**, including locked install, npm ci, build,
  private data directory ACL, and migration. `Get-Acl data` confirms protected
  inheritance and only current user, SYSTEM, and Administrators with FullControl.
- `uv run alembic current`: **0001 (head)**; `uv run alembic check`: **no new
  upgrade operations detected**. Setup rerun preserved the schema.
- `npm.cmd --prefix frontend audit`: **0 vulnerabilities** in the installed tree.
- Exact documented Uvicorn `--reload` launch verified: `/healthz` and `/` returned
  **HTTP 200**. Optional Vite command launched on 5173; dashboard and health proxy
  returned **200**, same-origin request passed Origin validation and was correctly
  denied without CSRF. Temporary development servers were stopped afterward.
- Independent read-only code review: **pass**, no critical/important findings.
- UI detector emitted one false positive on the active navigation underline
  (`border-bottom: 3px`): this is a square tab indicator with border-radius 0,
  not a rounded card accent. Retained intentionally.

## Remaining work / verification limits

Milestone 1 is complete as a development application. No preset development account
was created; user chooses their own password with the documented CLI command.
All test accounts/events are synthetic fixtures in temporary databases.

No live Windows telemetry, detections, knowledge feeds, vulnerability matches,
ingestion, privileged controls, service, installer, reboot/upgrade/uninstall, or
host retention budgets are implemented or verified; these remain milestones 2–5.
Hosted GitHub Actions are supplied but have not run remotely. Full keyboard and
screen-reader accessibility audits were not performed (Enter submit, focus styles,
labels, desktop/mobile rendering and overflow were checked). Upgrade preservation
is tested at the initial revision; cross-version data migration awaits a second
schema revision. A private vulnerability-reporting destination and comprehensive
dependency/secret-scanning workflow remain part of GitHub/installer delivery.

## Core concept and architecture review (requested after milestone 1)

- [x] Re-read the specification, current modules, persistence model, UI, and tests.
- [x] Trace the actual host-event-to-alert path and identify implementation gaps.
- [x] Re-run existing functional checks without changing the user's account or database.
- [x] Assess trust boundaries, data durability, deployment paths, and readiness gates.
- [x] Write an evidence-based readiness/architecture report and prioritize next work.

Review report: `docs/READINESS_REVIEW.md`. Verdict: basic local development only,
not ready as a real SIEM. The collector/event/alert/matching path remains absent.
Keep the current stack; define durable delivery, evidence identities, retention,
ingestion credentials, and privileged collector boundaries before adding collection.

Fresh checks: `uv run --locked pytest -q` passed **27/27 in 13.31s**; existing Ruff
lint/format and frontend TypeScript/Vite build passed; live HTTP/Chromium synthetic
browser smoke passed. Added a standalone reproducible synthetic concurrency check
at `tests/concurrent_login_check.py` (lint/format pass). Its actual command
`uv run --locked python tests/concurrent_login_check.py` **exited 1**: **1/4 valid
concurrent logins succeeded and 3/4 failed with SQLite database locks**. The passing
pytest suite does not cover this defect. Fix transaction boundaries/retry semantics
before relying on concurrent activity or adding ingestion.

Static security review also found scrypt N=16384/r=8/p=1 below the compared OWASP
configurations. Stronger versioned password hashing and legacy-hash upgrade are
recommended before release; no password cracking or compromise was demonstrated.
Packaged assets/data paths must also be separated before the installer milestone.
No application behavior or user credentials were changed by this review; fixes
remain outstanding. This review supersedes any implication that the earlier green
checks establish concurrent reliability or completed SIEM readiness.

## Project handoff review (2026-10-22)

- Read the referenced Codex chat `Plan Sentinel VM setup`, including its original
  VM/Caldera proposal and subsequent Windows-first personal SIEM scope, and compared
  it with PROJECT_SPEC.md, implementation, tests, and the readiness review.
- Confirmed the application foundation exists: React/TypeScript/Vite dashboard,
  FastAPI authentication/status/audit API, SQLite persistence, and Alembic migration.
  The audit events are Sentinel account activity, not Windows host telemetry.
  Agent, rules, and installer directories currently contain boundary documentation.
- Fresh verification: `uv run --locked pytest -q` passed **27/27 in 14.47s**;
  `npm.cmd --prefix frontend run build` passed; Ruff check passed and Ruff format
  check reported **16 files already formatted**.
- Fresh isolated synthetic diagnostic:
  `uv run --locked python tests/concurrent_login_check.py` exited **1**;
  **1/4 valid concurrent logins succeeded**, while **3/4 failed with SQLite locks**.
  This known defect remains outside the passing pytest suite and CI diagnostic coverage.
- This workspace is not currently a Git repository (`git status --short` reports
  no repository). GitHub publication has not been verified or attempted.
- No application behavior or credentials changed. Browser smoke, live telemetry,
  installation/service lifecycle, and remote CI were not rerun in this handoff.
  Milestones 2-5 remain unimplemented. Address concurrent authentication and the
  previously recorded password-hashing hardening before expanding into collection.

## Local usability and authentication fixes (2026-10-22)

User requested simpler local access and fixes for the reported problems, then
explicitly selected direct launcher access protected by a private local token.
Scope: the existing application foundation and authentication defects; host
collection and milestones 2-5 remain separate, unimplemented work.

- Added `Start-Sentinel.cmd` and `sentinel.launch`: prepare missing development
  dependencies/build through existing setup, reserve a free loopback port, start
  Sentinel and open the browser. Normal use requires no registration or password.
- A random 256-bit launch token lasts two minutes and permits one successful
  exchange. The browser removes the URL fragment and receives a normal session.
  Bare URLs remain unauthorized; CSRF, Origin/Host protections and logout remain.
  An internal `@local` identity has no password. Existing accounts are retained.
- Fixed concurrent authentication by taking a writer reservation before dependent
  reads and releasing transactions around password work. Recheck the user/hash in
  the final write transaction. Logout also avoids read-to-write lock upgrades.
- New hashes use encoded scrypt N=16384/r=8/p=5. Existing legacy hashes remain
  verifiable and upgrade on successful login. No credential/database migration
  was performed against user data during this work.
- Simplified the entry page with launcher instructions and an optional existing
  password form. Updated README, setup output, architecture/security docs, spec,
  readiness-review status and CI to include the local launcher browser check.

Verification uses temporary databases and clearly labeled synthetic identities:

- New tests initially reproduced concurrent HTTP failure (1 success, 3 HTTP 503),
  missing hash upgrades, and absent local-access support.
- Final `uv run --locked pytest -q`: **31 passed in 52.19s**. Includes concurrent
  HTTP success and wrong-password throttling, legacy upgrade, token expiry/replay,
  foreign-origin rejection, logout protection, and the original persistence suite.
- `uv run --locked python tests/concurrent_login_check.py`: **4/4 successful**,
  exit 0 (previously 1/4).
- Ruff lint and format checks pass: **20 files formatted**. TypeScript/Vite build
  passes. Impeccable detector reports no findings in the changed frontend files.
- Existing password-flow HTTP/Chromium smoke passes. New local browser smoke uses
  the real launcher/server with only browser-opening redirected to test Chromium:
  direct access, fragment removal, reload, logout, replay rejection, mobile overflow,
  JavaScript errors and graceful cleanup pass. Desktop/mobile captures inspected.
- Browser replay check initially navigated only to a fragment in the existing page;
  corrected the test to load a fresh document before exercising token replay.
- No live host telemetry, installer, reboot/service lifecycle, GitHub publication,
  remote CI, fresh-machine dependency installation or native default-browser launch
  was verified. The Windows batch wrapper was inspected; Python launch behavior
  was executed. PROGRESS.md's earlier defect reports are historical, not current.

Final review follow-up:
- Independent review reproduced a legacy-upgrade race: two valid simultaneous
  logins to the same old hash returned success/failure. Added a deterministic
  synchronized regression, observed failure, then implemented bounded hash-change
  re-verification outside transactions. Both valid logins now succeed; code review
  of the fix found no further important issues.
- Browser regression reproduced older-tab logout failing after another sign-in
  rotates the shared cookie. Logout now fetches current session verification data
  before submitting. This remains protected by server-side CSRF validation.
- Final checks after review fixes: **32 pytest tests passed in 55.51s**;
  TypeScript/Vite build and Ruff lint/format pass; both Chromium smoke scripts
  pass, including the new cookie-rotation logout regression and local launch flow.

## Windows monitoring and installer release verification (2026-10-22)

- Executed full test suite: `uv run --locked pytest -q` passed **63/63 passed in 59.07s**.
- Executed Ruff checks: `uv run --locked ruff check backend migrations tests` passed with **All checks passed!**; `uv run --locked ruff format --check backend migrations tests` passed with **39 files already formatted**.
- Executed frontend production build: `npm.cmd --prefix frontend run build` compiled cleanly with `tsc --noEmit && vite build`.
- Executed concurrent login stress check: `uv run --locked python tests/concurrent_login_check.py` passed with **4/4 valid concurrent logins succeeded**.
- Executed browser smoke tests: `uv run --locked python tests/browser_smoke.py` and `uv run --locked python tests/local_browser_smoke.py` passed against Chromium desktop and mobile viewports with zero errors.
- Executed live Windows acceptance: `uv run --locked python tests/live_windows_acceptance.py --inventory-change` passed 100% of checks:
  - Real Windows logs HTTP ingestion and replay (0 duplicates)
  - Reversible real registry inventory change (HKCU marker created and cleaned up in finally)
  - Durable collector state restart preserving progress
  - Separate collector process delivery to the real backend
  - Real Windows event in authenticated browser search (Chromium)
  - Mobile responsive navigation with zero overflow or JavaScript errors
- Executed standalone installer build: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File installer/build.ps1` compiled `SentinelService.exe`, bundled pinned standalone Python 3.12.13 runtime with `--break-system-packages` for the isolated bundle, verified SHA-256 integrity manifest (`manifest.json`), and generated `artifacts\packages\Sentinel-<timestamp>.zip` (31.3 MB).
