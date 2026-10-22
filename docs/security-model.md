# Milestone 1 security model

Local launcher access: the Windows user who can run Sentinel can open its dashboard
without a password. This trusts that user's OS session and private data directory;
it does not protect against processes already running as that user. The launcher
binds only to loopback and creates a random 256-bit token, valid for two minutes
and one successful exchange. The fragment is removed from browser history at page
startup. Sessions retain HttpOnly, SameSite=Strict cookies and CSRF checks.
Foreign origins and unapproved Hosts are rejected. Bare URLs remain unauthorized.
Tokens are not printed or saved. The reserved local identity has no usable password.

Run as your normal Windows user and bind to `127.0.0.1`. The dashboard is a local
HTTP development app. Do not expose it to the LAN or the internet. Installer/service
privilege boundaries and HTTPS deployment are not part of this milestone.

Optional password account creation requires local CLI access and a 12–128 character password.
There are no default credentials, registration endpoints, embedded secrets, or
required AI services. Usernames are normalized and limited to a constrained ASCII
alphabet. New passwords use salted scrypt (N=16384, r=8, p=5); comparisons are constant
time. Database statements are parameterized. All accounts currently have the one
administrator role; there is no multi-role permission model yet.

Hashes record their parameters. Legacy p=1 hashes upgrade after successful login,
preserving existing accounts. The new configuration is listed in the
[OWASP guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

Sessions use random 256-bit tokens; only SHA-256 token digests are stored in SQLite.
The session cookie is HttpOnly, SameSite=Strict, has an eight-hour maximum age, and
is revoked on logout. Session validity is checked server-side on every private
request. The Secure flag is false for loopback HTTP development. Cookies never go
into browser local storage. Authenticated sessions survive backend restarts.

Login and logout require CSRF tokens. Login uses a cookie-bound nonce; logout uses
a per-session nonce. Mutations with foreign Origin headers are rejected. Host
validation accepts only loopback names to reduce DNS rebinding exposure. Responses
set no-store, CSP, anti-framing, no-referrer, and nosniff headers. No permissive
CORS is enabled. React renders event/user strings as text, not HTML.

Five failed attempts per normalized username in a rolling five-minute window
trigger a temporary throttle (including nonexistent accounts). Subsequent attempts
extend the wait. This limits basic guessing; it is not a distributed abuse defense.
Events record account creation, successful/failed sign-in, and sign-out, without
passwords or raw session tokens. Audit events are local administrative activity,
not Windows host telemetry. They are not tamper-proof against someone with local
database access. Retention and a disk budget are planned with host ingestion.

Setup restricts the default data directory to the current user, SYSTEM, and local
Administrators. Custom database locations require equivalent ACLs. SQLite is not
encrypted at rest; use Windows device encryption/BitLocker for disk protection.
An administrator or process already running as your user can read/modify local data.
Keep `.env`, databases, logs, private inventory, credentials, exports, and VM images
out of Git. Future event evidence can contain usernames, paths, command lines, IP
addresses, URLs, and other sensitive material; no such collection exists yet.

Host-changing controls and agent ingestion are absent. No shell, arbitrary command
execution, service control, or telemetry upload endpoint is available. Collection
permissions and privileged action allowlists will be documented with those modules.
