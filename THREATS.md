# TrustVault Threat Model

## Purpose and scope

This document describes the application-level security boundaries and material
residual risks for the TrustVault Flask application in this directory. It is
based on the current code, schema, tests, and documented Render deployment
configuration. It is not a penetration test, compliance certification, or
guarantee that every deployment is secure.

The model covers account registration and login, Administrator MFA, server-side
sessions, document uploads and access grants, the Administrator metadata
dashboard, SQLite and audit records, and the single-instance Render deployment.
It assumes supported dependencies are installed and production settings are
configured as documented.

## Assets

- Private document bytes and document metadata.
- User identities, password hashes, roles, account status, and MFA secrets.
- Registration invitations, session credentials, and authorization grants.
- Permission history and audit events.
- SQLite database, uploaded files, backups, session-hash key, and deployment
  configuration.
- Availability and integrity of the application and its records.

## Actors and trust boundaries

- **Viewer, Document Owner, and Administrator:** authenticated users with
  different application permissions. Administrator access to dashboard
  metadata does not grant access to private document bytes.
- **Unauthenticated visitor:** can reach public registration and login routes,
  but registration requires a valid single-use invitation.
- **Trusted operator:** can access the host shell, provision roles, inspect
  deployment secrets, and access persistent storage. This is a highly
  privileged boundary outside ordinary application authorization.
- **Application host and dependencies:** execute application code and handle
  plaintext requests and authorized document bytes.
- **Browser-to-service boundary:** credentials and session cookies cross this
  boundary. Production depends on HTTPS and correctly configured proxy/header
  handling.
- **Persistent-storage boundary:** SQLite, uploaded content, and local backups
  reside on a private disk. Anyone who can read or replace these files can
  bypass application-level controls.

## Threats and mitigations

| Threat | Abuse path and impact | Existing controls | Residual risk and recommended action |
|---|---|---|---|
| Account takeover | Password guessing, credential reuse, or intercepted credentials could expose an account and its authorized documents. | Werkzeug password hashing, generic login errors, active-account checks, rolling failed-login limits, HTTPS-only production cookies, server-side sessions, and Administrator TOTP. | Rate limits are local SQLite controls, not a distributed abuse defense. Use unique passwords, protect operator accounts, monitor failed logins, and add an edge rate limiter/WAF for public high-volume deployments. |
| MFA setup secret theft or key loss | A stolen Administrator setup key can enable OTP generation; losing the encryption key prevents decrypting enrolled secrets. | TOTP secrets are encrypted using a key derived from the stable session-hash key; setup material is displayed once during trusted provisioning; OTP challenges expire and codes cannot be reused. | Protect the Render shell, terminal output, and secret manager. Keep the key stable and backed up securely. Reprovision MFA after suspected disclosure or key loss. |
| Session theft or fixation | A stolen bearer cookie can impersonate its account until expiry or invalidation. | Random server-side session identifiers, only HMAC digests stored in SQLite, session regeneration on authentication, account/auth-version checks, Secure/HttpOnly/SameSite cookies, and logout invalidation. | XSS, compromised endpoints, browser extensions, or host access can still expose a live session. Enforce HTTPS, maintain dependencies, and revoke/rotate sessions during incidents. |
| CSRF | A malicious site could try to trigger state changes using a victim's browser session. | State-changing API calls require a session CSRF token; SameSite=Lax cookies provide an additional browser control. | Keep every mutating route behind the shared CSRF validation and test new routes. SameSite is not a substitute for CSRF validation. |
| Unauthorized document access / IDOR | A user could alter document or grant identifiers to read, download, change, delete, share, or revoke another user's document. | Central authorization checks reload account and grant state from SQLite; owner-only sharing operations; mutations reauthorize transactionally; opaque identifiers; tests cover IDOR and revoked grants. | Preserve centralized checks in every new endpoint and background workflow. Admin metadata access must not be used as a content-access bypass. |
| Privilege escalation | A user could submit an Administrator role or invoke administrative APIs without authorization. | Registration derives role only from a server-side invite; administrative APIs check active role; trusted-console provisioning is audited and increments auth version; Administrator login requires TOTP. | Shell and deployment-control access are equivalent to privileged administrative access. Restrict operator access and review provisioning/audit activity. |
| Invite theft or abuse | A leaked invitation can be used to create an account with the role bound to that invitation. | Invites are single-use, expiring, stored as hashes, and created through the Administrator API or operator workflow. | Deliver invites out of band, limit their lifetime and distribution, and revoke or expire any suspected leaked invite. |
| Malicious or oversized uploads | Crafted file content, parser edge cases, or large requests could exploit a parser or consume resources. | Size limits, allowlists/signature and parser validation, UUID storage names, private upload storage, and safe document-serving headers. | File validation is not antivirus. Use isolated malware scanning for higher-risk deployments, review parser updates, and monitor disk usage. |
| Metadata disclosure | A dashboard or API flaw could reveal user identities, document names, sharing relationships, or audit details. | Admin APIs and dashboard require Administrator role; paginated/filterable endpoints; documented metadata/content boundary; access and denial auditing. | Metadata is sensitive even when content remains private. Restrict Administrator accounts, avoid unnecessary response fields, and test every endpoint for role enforcement and pagination bounds. |
| SQL injection or unsafe input handling | Crafted query/filter values could alter database operations or expose records. | Parameterized SQL for values, allowlisted dynamic fields, normalized inputs, bounded pagination, and injection regression tests. | Continue using bound parameters; do not interpolate untrusted values into SQL or filesystem paths. |
| Audit manipulation or repudiation | An attacker with database-file access could alter events or erase history. | Append-only triggers and a transaction-serialized SHA-256 chain detect many ordinary edits and internal deletions; a verifier supports external head/count anchors. | The chain is not tamper-proof against a privileged database attacker and cannot alone detect removal of a valid trailing suffix. Export anchors to an independently controlled append-only/WORM service and alert on verification failures. |
| Database, upload, or backup loss | Disk failure, accidental deletion, ransomware, or operator error could destroy records or uploaded content. | Render blueprint uses a persistent private disk; paired database/upload backup command and restore procedures are documented. | A same-disk snapshot is not disaster recovery. Automate encrypted off-site backups, monitor failures, and regularly test restore into an isolated environment. |
| Multi-instance inconsistency | Requests routed to another instance could see a different local database, session store, or file set. | Render blueprint pins one instance and one Gunicorn worker process with threads. | Do not scale horizontally or use multiple local disks. Migrate to shared database/session/object storage before multi-instance operation. |
| Host or dependency compromise | A compromised runtime, dependency, or operator account could access application data and secrets. | Production debug mode is disabled; configuration validates secure cookies, a strong session key, private storage paths, and host/proxy behavior; dependencies are declared and tests cover deployment assumptions. | Keep dependencies and host patched, restrict shell/secret access, monitor the provider account, and use managed scanning/monitoring. These controls do not protect against a fully privileged host compromise. |
| Availability abuse | Request floods, expensive parsing, or disk exhaustion could interrupt service. | Bounded upload size, SQLite busy timeout, login throttling, and configured Gunicorn limits/timeouts. | The app has no distributed rate limiter or queue. Add managed edge controls, quotas, monitoring, and operational disk alerts for internet-facing use. |

## Deployment assumptions and operational requirements

- Serve production traffic only over HTTPS and keep the Secure cookie setting
  enabled.
- Keep `TRUSTVAULT_SESSION_HASH_KEY` in a secret manager, at least 32 bytes, and
  stable across restarts. Do not commit it or print its value.
- Use a private persistent disk for the database, uploaded documents, and
  local backup staging. Do not expose these paths through static hosting.
- Keep one Render instance and the documented single-process Gunicorn
  configuration while SQLite and sessions are local.
- Restrict Render Shell, environment-variable, and disk access to trusted
  operators. Provision Administrator roles only through the audited
  operational command and securely retain the one-time TOTP setup material.
- Create encrypted off-site backups, verify them, and conduct restore drills.
- Send audit-chain checkpoints to an independently administered store; local
  database chaining alone cannot prove that the tail was not removed.
- Monitor health, failed logins, authorization denials, storage capacity,
  backups, dependency advisories, and audit-integrity failures.

## Change-review checklist

For changes that touch authentication, documents, roles, permissions, uploads,
auditing, or deployment:

1. Identify assets, caller identity, and trust boundaries.
2. Trace the complete route and data flow; enforce authorization on the server
   for every request.
3. Preserve the rule that Administrator metadata access does not imply
   document-content access.
4. Validate inputs, parameterize SQL, and avoid logging credentials, tokens,
   MFA secrets, or document bytes.
5. Add regression tests for both allowed and denied behavior.
6. Reassess backup, audit, privacy, and deployment assumptions when changing
   persistence or adding instances.
