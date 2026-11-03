# TrustVault Threat Model

## Scope

TrustVault is a secure document-sharing application for confidential documents. The primary security objectives are:

- enforce explicit authorization for every document operation
- protect private file storage from abuse or disclosure
- keep an auditable, tamper-evident activity trail
- prevent privilege escalation and unauthorized access to private data

## Assets

- user accounts and password hashes
- document files and metadata
- permission grants and revocation history
- audit logs and integrity hashes
- system configuration and allowed file policies

## Threats and Mitigations

### 1. Unauthorized document access
Threat: Users without a valid grant may attempt to read, download, or edit protected documents.

Mitigations:
- default-deny authorization at the server layer
- ACL checks on every access path
- deny access for inactive or disabled users
- reject expired permissions and revoked grants
- never trust client-provided document IDs or user IDs

### 2. Privilege escalation
Threat: A user attempts to alter roles or change permissions beyond policy.

Mitigations:
- server-side role enforcement
- admin-only role and status changes
- self-protection rules for admins
- no client-side trust in UI visibility

### 3. File upload abuse
Threat: Malicious or malformed files are uploaded to the system.

Mitigations:
- enforce file-size limits
- allowlist supported extensions
- validate MIME type and magic-byte signature where possible
- reject empty or malformed content
- sanitize display names
- store files in private storage, not the public web root
- generate unpredictable server-controlled storage keys

### 4. Path traversal and filesystem attacks
Threat: Uploads or downloads may be manipulated to read or overwrite unintended server files.

Mitigations:
- sanitize filenames
- use server-generated storage names
- store files in a private directory
- validate file paths before responding with downloads
- avoid exposing permanent public URLs

### 5. Audit tampering
Threat: An attacker attempts to alter or forge audit records.

Mitigations:
- append-only audit log model
- previous-hash linkage in each record
- integrity verification endpoint
- store canonical JSON payloads for hashing

### 6. Broken access control through UI assumptions
Threat: Hidden buttons, frontend filtering, or route guards create a false sense of security.

Mitigations:
- enforce authorization on every backend endpoint
- treat UI state as non-authoritative
- return 401/403/404 consistently according to policy

### 7. Session fixation and hijacking
Threat: A previously known or reused session token gives unauthorized access.

Mitigations:
- use secure, HttpOnly cookies
- rotate or regenerate session IDs on login
- restrict cookie scope and same-site policy
- invalidate sessions on logout

### 8. Brute-force or credential stuffing
Threat: Attackers repeatedly try to guess passwords or email combinations.

Mitigations:
- rate limiting on login attempts
- generic authentication errors
- account disablement support for repeated abuse patterns
- strong minimum password policy

### 9. Insecure metadata leakage
Threat: Document metadata or access information is exposed to unauthorized users.

Mitigations:
- filter search and dashboard results to visible data only
- avoid returning file paths, storage keys, or private metadata before authorization
- enforce minimum information disclosure policies

### 10. Malware and untrusted content
Threat: Users upload files that are malicious or need security review before opening.

Mitigations:
- explicit scan-status workflow
- block download until a required scan is approved
- integration point for antivirus or malware scanning
- keep unapproved files out of the downloadable path

## Security Requirements to Keep

- no hardcoded production credentials
- no default public file URLs
- no claims of secure access without validated authorization
- any emergency break-glass workflow must be explicitly audited and time-limited
- role changes and status changes must be server-verified

## Priorities

1. enforce authorization at every protected operation
2. protect uploaded files and storage paths
3. preserve an integrity-checked audit record
4. prevent privilege escalation and session abuse
5. ensure admin actions remain separate from document ownership
