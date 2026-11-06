# TrustVault Python application

This directory is an additive Python/Flask foundation. The existing project at
the repository root is not modified or replaced. Authentication and
server-side session management are implemented, along with private document
management routes, file validation, and centralized authorization.

## Database foundation

- `schema.sql` defines users, documents, document permissions, and append-only
  audit logs.
- `database.py` opens caller-owned SQLite connections, enables foreign keys for
  each connection, sets a bounded busy timeout, supports nested-safe
  transactions, and initializes schema without dropping data.
- `audit.py` appends canonical UTC-timestamped SHA-256 chained events and
  provides a structured, read-only integrity report.
- `permissions.py` provides centralized `authorize`, `check_permission`,
  `require_authentication`, and `require_permission` checks. It reloads account
  status, role, and grants from SQLite for every authorization decision.
- `documents.py` provides private upload, listing, view, download, metadata
  edit, and soft-delete routes. Each operation uses centralized authorization;
  mutations reauthorize inside their SQLite transaction.
- `auth.py` provides invite-controlled registration, Werkzeug password hashes,
  generic login errors, SQLite-backed sessions, CSRF validation, account-status
  checks, and IP/normalized-email login throttling.
- `mfa.py` provides Administrator-only TOTP login challenges and encrypts
  authenticator secrets with a key derived from the stable session hash key.
- `security.py` provides allowlists, normalization, opaque IDs, and token
  hashing.

### Tables and constraints

- **users** stores opaque IDs, normalized unique emails, names, Werkzeug hash
  slots, constrained roles/status, encrypted optional TOTP secrets, a replay
  counter, an auth-version counter, and UTC timestamps.
  `status` is the authoritative account state; authentication derives
  `is_active` from it to avoid duplicate state.
- **registration_invites** stores only a SHA-256 digest of a single-use,
  expiring invite. The invite text is displayed once by the seed command.
- **login_attempts** stores hashed normalized identifiers, source IP, UTC
  attempt time, and outcome to enforce rolling-window limits.
- **server_sessions** stores only a digest of a random opaque session ID and
  server-side session data. The browser cookie contains no identity, role, or
  permissions. Sessions reference users and include their auth-version.
- **documents** references its owner, has a unique random server-generated storage key,
  bounded display metadata, nonnegative size, a lowercase SHA-256 digest, a
  constrained scan state, UTC timestamps, and a soft-delete timestamp. The
  schema intentionally has no public file path.
- **document_permissions** references the document, recipient, and grantor;
  accepts only `read`/`edit`; stores grant/expiry/revocation UTC times; and
  prevents more than one unrevoked grant for a document/user pair. Service code
  must revoke an expired grant before creating a replacement.
- **audit_logs** stores sequence, ID, UTC timestamp, user ID and username,
  action, document ID, IP address, success/failure/denied status, canonical
  JSON details, previous digest, current digest, and user agent. The hash
  covers every field (including sequence) using sorted, compact UTF-8 JSON.
  Sensitive-key names and non-finite numbers are rejected by the writer.
- Foreign keys use `RESTRICT` so referenced identity/document rows cannot be
  silently deleted or rewritten. Role, status, permission, result, digest,
  lengths, file sizes, timestamps, and required fields are constrained at the
  database boundary.

### Indexes and transaction decisions

- `idx_users_status_role` supports active-account and role checks.
- Invite, login-attempt, and session indexes support expiry and lookup paths.
- `idx_documents_owner_created` supports listing non-deleted owner documents
  newest-first.
- `idx_permissions_user_document` and `idx_permissions_document` support ACL
  checks by recipient and resource. The partial unique
  `idx_permissions_one_unrevoked_grant` prevents duplicate current grants while
  preserving revoked history.
- The three audit indexes support actor-, document-, and action/time-filtered
  read-only investigation. Audit sequence is the chain order.
- Audit append writes use `BEGIN IMMEDIATE` so concurrent requests serialize
  the read-head/hash-and-insert sequence. `audit_logs_validate_insert`
  enforces contiguous sequence numbers and the previous-hash link;
  `audit_logs_prevent_update` and `audit_logs_prevent_delete` reject ordinary
  SQL mutations.
- Schema creation runs inside `BEGIN IMMEDIATE` and only uses
  `CREATE ... IF NOT EXISTS`, so rerunning initialization does not erase data.
  The optional Administrator MFA fields are added with non-destructive
  `ALTER TABLE` statements for existing databases.
  Each connection enables foreign keys and a bounded busy timeout. Nested
  transactions use savepoints.
- Timestamps are ISO-8601 UTC strings ending in `Z`; the database enforces the
  UTC marker and Python supplies canonical timestamps.

### Audit integrity limits

The chain is **tamper-evident, not tamper-proof**. It detects ordinary row
modification, internal deletion, insertion, and reordering when checked by
`verify_audit_integrity()`. The SQLite triggers protect against application
mistakes and low-privilege SQL access, but a privileged attacker who can edit
the database file can drop triggers, rewrite rows, or recompute the unkeyed
SHA-256 chain. A local chain also cannot prove that its newest rows were
deleted. For that, periodically store the latest `head_hash` and
`events_checked` in an independently protected system (for example, a remote
append-only service or signed operational checkpoint) and pass those values as
`expected_head_hash` and `expected_event_count`. Verification reports
corruption; it never silently repairs or rehashes damaged history.

When startup encounters the prior audit schema, migration first validates its
entire legacy chain and creates a SQLite online-backup copy beside the database
before changing the table. Corrupted legacy history aborts without migration.

### Administrator two-step verification

Administrators must sign in with their password and a six-digit code from an
authenticator app. Codes expire on a 30-second time step, allow one adjacent
time step for clock drift, are rate limited with password failures, and cannot
be reused. MFA secrets are encrypted in SQLite. Keep
`TRUSTVAULT_SESSION_HASH_KEY` stable across restarts and backups; changing it
requires reprovisioning MFA secrets as well as invalidating sessions.

When an account is promoted to Administrator from the trusted console, the
provisioning command displays the authenticator setup URI and setup key once.
Save them in an authenticator app before closing the terminal. An
Administrator registration invite similarly displays the setup key once after
successful registration. If setup is lost, the trusted operator can demote and
reprovision the account, which invalidates existing sessions and rotates the
MFA secret.

```sh
python provision_role.py --email "existing-account@example.com" --role administrator
```

## Tests

Install the requirements and run:

```sh
python -m pip install -r requirements-dev.txt
python -m pytest -q tests
```

For coverage, run:

```sh
python -m pytest -q tests --cov=app --cov=auth --cov=audit --cov=database \
  --cov=documents --cov=permissions --cov=security --cov=web --cov=config \
  --cov=backup --cov=observability --cov=provision_role --cov=verify_audit \
  --cov-report=term-missing
```

Tests create disposable databases in pytest temporary directories. Do not use
production data or credentials in tests.

### Security regression test map

`tests/test_security.py` adds independent Flask-client tests. Each uses the
temporary database fixtures in `tests/conftest.py`; records and files are
created under pytest's temporary directory.

- **Authentication:** `test_invalid_password_is_rejected` checks credential
  verification; `test_inactive_user_cannot_login` checks account-state gating;
  `test_logout_invalidates_server_side_session` checks server-side session
  deletion; `test_session_fixation_rotates_pre_authentication_identifier`
  checks ID rotation; `test_login_rate_limit_blocks_sixth_bad_attempt` checks
  the attempt threshold; `test_username_enumeration_uses_same_login_error`
  checks generic failure responses.
- **Authorization and IDOR:** the `test_user_a_cannot_*_user_b_document`
  tests check view, download, edit, and delete isolation;
  `test_viewer_cannot_edit_documents` and
  `test_viewer_cannot_delete_documents` check read-only roles;
  `test_unauthorized_user_cannot_share_document` and
  `test_permission_escalation_fields_are_rejected` check owner-only sharing
  and forged grant fields; `test_revocation_immediately_blocks_document_access_and_download`
  checks live ACL revocation; `test_positive_explicit_read_grant_allows_view_and_download`
  confirms a valid grant works; `test_administrator_does_not_get_implicit_private_document_access`
  checks least privilege; `test_idor_alternate_routes_do_not_expose_document_permissions`
  checks ACL endpoints.
- **File safety:** `test_executable_svg_and_html_uploads_are_rejected` covers
  executable, SVG, and HTML payloads; the oversized and MIME-spoofing tests
  check size/signature validation; `test_path_traversal_upload_filename_is_rejected`
  checks that unsafe names cause no database/file write;
  `test_arbitrary_document_download_identifier_is_not_a_file_path` checks
  path-like identifiers; `test_unauthorized_document_file_access_does_not_read_or_expose_content`
  checks private-content confidentiality.
- **Database and audit:** `test_search_sql_injection_payload_is_treated_as_literal`
  checks parameter binding; separate trigger tests check UPDATE and DELETE
  rejection; integrity tests check modified rows, deleted middle rows, broken
  previous-hash links, and the genesis hash; the concurrent-write test checks
  a valid serialized chain.
- **Search, browser, and request tampering:** the metadata-leakage test checks
  private titles and totals; the stored-XSS test checks Jinja escaping;
  `test_csrf_protection_blocks_document_permission_mutation` checks missing
  CSRF tokens; `test_http_parameter_tampering_cannot_change_document_owner_or_role`
  checks forged principal and permission fields.

## Local initialization

```sh
python seed.py --create-invite
```

This initializes the schema without deleting records and prints a one-time
Viewer registration invite. No default user or password is created. Use that
invite to create the initial account at `/register`. To bootstrap the first
administrator, use `provision_role.py` from trusted console access. Afterward,
administrators can generate single-use registration links for Viewer, Document
Owner, or Administrator from the role-invite popup on the admin dashboard.
Opening a link supplies its invite automatically; the role is assigned during
registration, while client-supplied roles and user IDs are ignored. Share
links securely and do not put them in logs. Existing users should use the email
and password they set during registration; the application intentionally has
no default credentials. User and audit activity remains restricted to the
authenticated administrator dashboard.
Authenticated users can view their account details at `/profile` and sign out
using the CSRF-protected navigation control.

## Administrator control dashboard

Administrators sign in through `/login` and are sent to `/admin`. The dashboard
provides live, paginated views for users, document metadata, document access,
permissions, shares, audit activity, and SQLite-backed summary reports. User
role/status changes require CSRF-protected administrator APIs, are recorded in
the append-only audit chain, and increment the target's authentication version
so role changes and account disabling take effect on the next request.

The JSON endpoints are under `/api/admin`: `dashboard`, `users`,
`users/<id>`, `users/<id>/documents`, `users/<id>/activity`, `documents`,
`documents/<id>/access`, `documents/<id>/permissions`,
`documents/<id>/permission-history`, `permissions`, `shares`, `activity`,
`audit-logs`, and `reports`. `PATCH /api/admin/users/<id>/role` and
`PATCH /api/admin/users/<id>/status` manage accounts. Every endpoint requires
an active administrator; changes also require the normal CSRF header.

The dashboard only exposes document metadata and access-control history. It
does not grant administrators access to private file contents. The existing
schema has no document-version table or version-replacement service, so file
version replacement is not offered. Reports use accessible native bar charts
and do not load a third-party chart script.

For local HTTP development in PowerShell, turn off the Secure-cookie flag only
for that local process, then start Flask on port 5003 (the workspace task uses
this port to avoid stale app processes already occupying earlier local ports):

```powershell
$env:TRUSTVAULT_COOKIE_SECURE = "false"
python -m flask --app "app:create_app()" run --host 127.0.0.1 --port 5003
```

For the first local account, use a Viewer invite from a second terminal in the
same `TrustVault` folder:

```powershell
$env:TRUSTVAULT_COOKIE_SECURE = "false"
python seed.py --create-invite
```

The browser/API client first obtains a CSRF token from `GET /api/auth/csrf`.
Send it in the `X-CSRF-Token` header for registration, login, and logout.
Successful login returns a rotated CSRF token. `GET /api/auth/me` validates
the current account state on every request.

## Document authorization policy

`authorize(user, document_id, required_permission)` treats `user` only as a
candidate server-side identity. It looks up the current account and active
status from SQLite, then checks document ownership or an unrevoked, unexpired
explicit grant directly from SQLite. It does not cache decisions.

- A `document_owner` can read and edit their own documents.
- A `viewer` can read only documents they own or those explicitly shared with
  them for read/edit; viewers cannot edit or delete even if a stale or overly
  broad edit grant exists. Deletion routes must use the fixed `edit` policy.
- Only an active `document_owner` who owns the document may list, grant, or
  revoke its permissions. Grants accept a normalized recipient email and a
  server-validated `read` or `edit` value; recipient identity and `granted_by`
  are resolved from SQLite. Viewers cannot receive an effective edit grant.
- Permission changes run in a SQLite write transaction and append audit events.
  Revocation marks the grant revoked; subsequent listing/search and download
  requests query the current ACL and deny access immediately.
- An `administrator` has no implicit access to private document content.
  Ownership or an explicit document grant is still required.
- Missing, deleted, and inaccessible documents all return the same concealed
  404 response. Anonymous requests are rejected as 401.
- Every authorization denial appends a denied event to the tamper-evident audit
  chain. Route policy is fixed in server code; request-supplied `user_id`,
  `role`, or `permission_level` fields are never authorization inputs.

## Private document handling

The upload allowlist is PDF, PNG, JPG/JPEG, and UTF-8 TXT, with a strict
5 MiB-per-file maximum. Extension, declared MIME type, and parsed file content
must agree. PDF structure is checked with pypdf; raster images are decoded
with Pillow; plain text is strictly decoded and checked for active markup,
executable signatures, and binary control characters. Active PDF actions and
embedded content are rejected.

Files are stored outside `static/` under random UUID filenames, with
owner-only directory/file permissions on POSIX. Files are opened relative to
a no-follow directory descriptor where supported; client filenames are only
stored as sanitized display metadata. View/download responses use safe
Content-Disposition, `X-Content-Type-Options: nosniff`, restrictive CSP, and
private no-store caching. Document deletion revokes access in SQLite before
unlinking the private file.

These checks are strict format and active-content screening; they are not a
substitute for a dedicated antivirus/malware scanning service.

## Document search and web dashboard

- `GET /api/documents?q=...&page=1&page_size=20` and the `/documents` and
  `/search` pages use the same search implementation. Results and totals are
  restricted in SQL to non-deleted documents owned by the active user or
  covered by a currently active read/edit grant. Search terms are escaped as
  literal `LIKE` patterns and bound as SQL parameters; page size is limited to
  50. Access is checked again for each result and refreshed on every request.
- `/login`, `/documents`, `/search`, `/upload`, and per-document `/sharing`
  pages are minimal responsive Jinja templates. Jinja autoescaping remains on;
  user-controlled values are never marked safe. The local stylesheet and script
  are served under a restrictive Content Security Policy.
- `/admin` requires an active `administrator` account. Each allowed dashboard
  view and denied access attempt is recorded in the audit chain. The page shows
  active and disabled accounts, document ownership, sharing grants, success
  and denied events, and the current audit-chain integrity report. It does not
  grant administrators access to private document content.
- Browser upload and sharing forms call the existing CSRF-protected JSON APIs.
  State-changing API calls continue to require the session CSRF token; search
  and dashboard reads are non-mutating except for their required audit events.

For production, retain the default Secure, HttpOnly, SameSite=Lax cookie
settings and serve only over HTTPS. Set `TRUSTVAULT_DATA_DIR` and
`TRUSTVAULT_UPLOAD_DIR` to private persistent directories. On Render, attach a
persistent disk before deploying. Gunicorn is configured in `Procfile`.

## Render production deployment

The Python service has its own Render blueprint at [`render.yaml`](./render.yaml).
The repository root already has a separate `render.yaml` for the existing
deployment, so do not replace it. In Render, create a Blueprint from this
repository and set the Blueprint file path to `TrustVault/render.yaml`.

Deployment-related project layout:

```text
TrustVault/
  app.py
  auth.py
  audit.py
  backup.py
  config.py
  database.py
  documents.py
  gunicorn.conf.py
  observability.py
  permissions.py
  provision_role.py
  render.yaml
  seed.py
  schema.sql
  security.py
  verify_audit.py
  web.py
  Procfile
  requirements.txt
  requirements-dev.txt
  .python-version
  templates/
  static/
  tests/
  instance/       # local-only database; ignored by Git
  uploads/        # local-only private files; ignored by Git
```

The blueprint sets the service root to `TrustVault/`, uses the Gunicorn
`gthread` worker with one process and four threads, mounts a persistent disk at
`/var/data`, configures `/healthz`, and keeps exactly one instance. The SQLite
database, uploads, and local backup snapshots are under
`/var/data/trustvault`. Do not scale this service horizontally or add worker
processes without first migrating SQLite and session persistence to shared
production services.

Deployment steps:

1. Attach the Render persistent disk defined by the blueprint and confirm the
   service keeps one instance.
2. Deploy with the blueprint-generated `TRUSTVAULT_SESSION_HASH_KEY`. Keep it
   secret and back it up in a secure secret manager.
3. Confirm `/healthz` reports `{"status":"ok"}` after deployment.
4. Create an invitation from the Render Shell:

   ```sh
   python seed.py --create-invite
   ```

   Deliver the one-time invite out of band. Registration only creates a
   `viewer`; it never accepts a client role.
5. After the intended first administrator registers, promote that account from
   the trusted Render Shell (not through an HTTP endpoint):

   ```sh
   python provision_role.py --email admin@example.com --role administrator
   ```

   The command updates the role transactionally, appends an audit event, and
   prints a one-time authenticator setup URI and manual key. Add the account to
   an authenticator app and store the setup key securely before closing the
   Render Shell; it cannot be retrieved from the database later. Administrator
   login requires this authenticator code. Restrict Render Shell and blueprint
   access to authorized operators. The dashboard is read-only; user role
   changes are currently performed using this audited operational command.
6. Run the security tests before release:

   ```sh
   python -m pip install -r requirements-dev.txt
   python -m pytest -q tests
   ```

The default app debug setting is false; production startup fails closed if the
session hash key is missing/weak, Secure cookies are disabled, or any of the
database, backup, or upload paths lie outside `TRUSTVAULT_DATA_DIR`. Flask is
run behind Render's TLS-terminating proxy; production enables a one-hop
`ProxyFix` for forwarded client, scheme, and host headers. Configure
`TRUSTVAULT_ALLOWED_HOSTS` if you need an explicit comma-separated host
allowlist; Render's `RENDER_EXTERNAL_HOSTNAME` is used when available.

### Environment variables

| Variable | Required / default | Purpose |
|---|---|---|
| `TRUSTVAULT_ENV` | Render: `production`; otherwise `development` | Enables production validation, trusted-proxy handling, and safe exception responses. |
| `TRUSTVAULT_SESSION_HASH_KEY` | Required in production; generate a random secret of at least 32 bytes | HMAC key for database session-token digests. Never commit or log it. Changing it invalidates existing sessions. |
| `TRUSTVAULT_DATA_DIR` | Render: `/var/data/trustvault` | Root of persistent database, upload, and backup directories. |
| `TRUSTVAULT_DATABASE_PATH` | Optional; defaults to `<DATA_DIR>/trustvault.sqlite3` | SQLite database path; must remain on the mounted persistent disk. |
| `TRUSTVAULT_UPLOAD_DIR` | Optional; defaults to `<DATA_DIR>/uploads` | Private document storage outside Flask's `static/` web root. |
| `TRUSTVAULT_BACKUP_DIR` | Optional; defaults to `<DATA_DIR>/backups` | Private local snapshot output. Copy completed backups off the Render disk. |
| `TRUSTVAULT_COOKIE_SECURE` | `true` in production | Secure cookies are mandatory in production. HttpOnly and SameSite=Lax are always enabled. |
| `TRUSTVAULT_ALLOWED_HOSTS` | Optional; defaults to Render external hostname | Comma-separated Flask trusted-host allowlist for custom domains. |
| `TRUSTVAULT_SQLITE_BUSY_TIMEOUT_MS` | `10000` in Render blueprint; otherwise `5000` | How long SQLite waits for a competing writer before returning a busy error. |
| `TRUSTVAULT_LOGIN_WINDOW_SECONDS` | `900` | Failed-login rolling-window duration. The attempt maximum remains five. |
| `PORT` | Supplied by Render; local Gunicorn fallback `10000` | Listener port used by Gunicorn. |
| `RENDER_EXTERNAL_HOSTNAME` | Supplied by Render | Default trusted host when no explicit host list is provided. |

`requirements.txt` contains runtime dependencies only. `requirements-dev.txt`
adds pytest and coverage tooling for development and CI. The Gunicorn
configuration is [gunicorn.conf.py](./gunicorn.conf.py); the Render start
command and [`Procfile`](./Procfile) use the same factory entry point.

### Persistence, backups, and recovery

Container filesystems are ephemeral. Only the mounted Render disk is treated
as persistent by this configuration. `database.py` enables SQLite WAL mode,
foreign keys, a bounded busy timeout, and `synchronous=FULL`; the database
directory is private and the database file is restricted to owner access on
POSIX systems. The upload directory is private, not served by Flask static
routes, and stores UUID-named files.

Create a paired SQLite online snapshot and archive of all live referenced
uploads during a maintenance window with writes stopped:

```sh
python backup.py
```

The resulting `.sqlite3` and `.tar.gz` files are written with restrictive
permissions under `TRUSTVAULT_BACKUP_DIR`. Keep them encrypted and copy them to
an independent off-site location; a backup on the same Render disk does not
survive disk loss or a privileged account compromise. Schedule this command
from an external operator/automation system, alert on failures, and regularly
perform a restore drill into a separate test environment. Stop application
writes during paired file/database backup so the two snapshots describe the
same set of documents.

For recovery, stop writes, restore the database snapshot and its corresponding
upload archive to private paths, verify the audit chain, and call `/healthz`
before reopening traffic. Never extract an archive into `static/`. Do not
overwrite production data during a restore without a separately approved
recovery plan.

### Secret rotation

- Rotate `TRUSTVAULT_SESSION_HASH_KEY` in Render's secret settings, then restart
  the service. Existing browser sessions will no longer match their HMAC
  digests and users must sign in again. Do not reuse the previous value.
- Keep a separately access-controlled copy of the active key in a secret
  manager. Restrict who can view or change Render environment variables.
- Rotate Render account/API credentials and any external backup credentials
  using their provider's process; no application passwords or database
  credentials are embedded in the code.
- If an administrator account may be compromised, disable it using the
  authorized operational/database incident procedure, rotate sessions as
  above, inspect audit history, and issue new invitations only after
  containment.

### Audit verification and external anchoring

Run local integrity verification from the service root:

```sh
python verify_audit.py
```

This verifies the complete local chain but cannot detect a valid-looking
trailing suffix that a privileged attacker removed. Independently retain the
last verified head hash and event count outside Render/database control, then
compare them during verification:

```sh
python verify_audit.py --expected-head-hash "<externally-stored-sha256>" \
  --expected-event-count 12345
```

The report's `anchored` field indicates whether external values were supplied.
For resistance to a database administrator, have an independent scheduled
collector export the chain head/count to a separately administered append-only
or WORM log service (or sign checkpoints with a key stored outside Render).
Alert on verification failures and retain checkpoint history; do not store the
only checkpoint beside the SQLite database.

### Incident response

1. **Contain:** restrict or suspend the Render service and revoke compromised
   Render/operator credentials. Preserve the persistent disk; do not delete or
   redeploy over evidence.
2. **Preserve:** take a protected database and upload backup, copy relevant
   platform logs and the last external audit checkpoint, and record incident
   times/handlers. Restrict evidence access.
3. **Assess:** run `verify_audit.py` against the latest independent anchor,
   inspect failed/denied events and provider logs, identify affected users and
   documents, and check recent backups.
4. **Recover:** rotate session hash key and operator credentials, disable
   affected accounts or invitations, patch the cause, restore only from a
   verified backup if required, and validate health and permissions before
   reopening traffic.
5. **Notify and learn:** follow legal/customer notification obligations,
   document scope and actions, preserve the incident timeline, and add
   regression tests before closing the incident.

## Final security review and threat model

| Area | Controls present and verified | Residual risk / required operations |
|---|---|---|
| OWASP A01 Broken Access Control / IDOR | SQLite-backed per-request document ownership/grant checks; role-protected admin page; concealed 404s; tests for cross-user view/download/edit/delete, permission endpoints, search leakage, and revoked grants. | Admin dashboard can inspect metadata, not content. Role provisioning requires trusted console access; no web role-management API. |
| A02 Cryptographic Failures / session hijacking | Random server-side session tokens; only HMAC digests stored in SQLite; key rotation invalidates sessions; Secure/HttpOnly/SameSite=Lax cookies; HTTPS HSTS when secure proxy scheme is present. | Session tokens remain bearer credentials; TLS and Render account security remain critical. |
| A03 Injection / SQL injection | Raw SQL uses bound parameters for untrusted values; dynamic update field names come from a strict allowlist; search LIKE metacharacters are escaped; SQL injection regression tests. | Continue reviewing new SQL and keeping database libraries current. |
| A05 Security Misconfiguration | Production validation disables debug, requires a strong session hash key and Secure cookies, applies host/proxy settings, and returns generic exceptions; health and security-header tests. | Trusted proxy count assumes Render's one-hop proxy topology. Revalidate if hosting topology changes. |
| A07 Identification and Authentication Failures / brute force | Werkzeug hashes, generic errors, active-account checks, server-side sessions, CSRF, five-attempt rolling rate limit, and auth tests. | IP-based rate limiting can be affected by proxy/IP configuration; consider a managed edge/WAF for broader abuse controls. |
| A08 Software and Data Integrity Failures / audit tampering | Transaction-serialized SHA-256 chain, append-only triggers, integrity tests, backup-before-legacy-migration, and external anchor verifier. | SQLite triggers and an unkeyed local hash chain are not tamper-proof against privileged file/database access. External independent anchors are required for trailing-deletion detection. |
| A10 SSRF / file and path attacks | Upload allowlist, signature/parser validation, UUID storage names, path-component rejection, private file serving, no-follow storage opens where supported, safe headers, and malicious upload/ID tests. | Format screening is not antivirus; run an isolated malware-scanning service before accepting high-risk files. |
| XSS / CSRF | Jinja autoescaping, local scripts/styles with CSP, nosniff/referrer headers, and CSRF tokens on state-changing API routes; stored-XSS and CSRF tests. | Keep untrusted HTML out of templates and do not add unsafe inline scripts or `|safe`. |
| Privilege escalation | Registration ignores submitted roles; role assignment uses constrained roles and trusted console command with an audit event; admin access checks current SQLite role. | Shell/Render operators are highly privileged and must be tightly controlled and audited by the provider. |

### Known deployment limitations

- **SQLite concurrency:** SQLite allows multiple readers but serializes writers.
  Busy timeout reduces transient failures; it does not make SQLite a
  high-write-concurrency database. The blueprint uses one Gunicorn process, one
  Render instance, and a persistent local disk. Do not run multiple instances
  against separate local disks and do not place a WAL database on a network
  filesystem.
- **Scale-out:** SQLite database and server-side sessions are local files. A
  second instance would have a different database/session state. For multiple
  instances, migrate to PostgreSQL for users, sessions, permissions, and audit
  metadata, and private object storage for document bytes. Use shared
  transaction semantics and preserve the centralized authorization interface.
- **Persistence and backup:** a Render persistent disk is not a backup.
  External encrypted backup storage, scheduled backup verification, and
  restore drills are operational requirements.
- **Audit anchoring:** local SHA-256 chaining detects interior changes but is
  not proof against an attacker able to replace the database. Independently
  anchor hashes/counts outside the application account.
- **Moderation/scanning:** MIME/parser checks reject many risky files but do
  not replace malware scanning.
- **Availability controls:** rate limits are stored in SQLite and the app has
  no distributed queue/WAF. A managed edge layer is recommended before
  internet-wide high-volume use.

This configuration is deployment hardening, not a claim of unconditional
production readiness. A real production launch still requires verified Render
environment/disk settings, off-site backup automation and restore testing,
independent audit anchoring, operator access controls, and monitoring.
