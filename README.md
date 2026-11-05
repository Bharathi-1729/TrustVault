# TrustVault

TrustVault is a secure document-sharing application designed around explicit access control, audit logging, and private file storage. It uses Express.js with SQLite persistence for document management and sharing.

## Features

- Secure authentication and session management
- Role-based access: administrator, document owner, and viewer
- Server-side authorization checks for documents and permissions
- Private uploads stored outside the public web root
- File validation by extension, MIME, and signature checks
- Document sharing with read/edit permissions and optional expiry
- Append-only audit records with SHA-256 chaining and HMAC signatures
- Admin statistics, account controls, recent uploads, and audit filters
- Search, category/file-type/date filters, and pagination over authorized documents
- Owner-managed document categories

## Setup

1. Install dependencies:
   `npm install`
2. Set stable secrets (PowerShell example):
   `$env:TRUSTVAULT_SESSION_SECRET = '<random value with at least 32 characters>'`
   `$env:TRUSTVAULT_AUDIT_SECRET = '<different random value with at least 32 characters>'`
3. Start the server:
   `npm start`
4. Open `http://localhost:3000`

Run verification with `npm run check` and `npm test`. Tests use temporary SQLite databases and upload directories.

## First user

The first registered user becomes the administrator automatically. There is no default production password or hard-coded secret.

## Roles and sessions

- The **Owner** role is the administrator role. Owners can manage users, access the audit trail, and manage sharing permissions for documents.
- **Document owner** users can upload documents and manage sharing for documents they own.
- **Viewer** users can only access documents explicitly shared with them.
- Public registration requires a matching confirmation and a password of at least 8 characters containing uppercase and lowercase letters, a number, and a symbol. Existing accounts can continue to log in with their existing passwords.
- Set distinct, stable `TRUSTVAULT_SESSION_SECRET` and `TRUSTVAULT_AUDIT_SECRET` values of at least 32 characters in production. Startup is rejected if either production secret is missing or too short. Set the audit secret consistently across restarts or audit signatures will not verify.
- State-changing requests with an `Origin` or `Referer` header are restricted to the same origin. Session cookies are HttpOnly, SameSite=Lax, and Secure in production.
- Users whose role or status changes are checked against SQLite on each protected request, so disabling an account or removing its role takes effect immediately.
- Older user tables are migrated additively: missing role/status columns are added without deleting records, and the earliest existing account becomes Owner if no role column existed.
- Active duplicate document permissions are reconciled during startup by keeping the newest grant, recording the migration, and installing a unique partial index. No user, document, or audit rows are removed by these migrations.

## Notes

- Documents are stored in `private_uploads/`.
- Database state is stored in `data/trustvault.db`.
- For persistent hosting, set `TRUSTVAULT_DATA_DIR` to the mounted persistent disk directory. For example, on a Render disk mounted at `/var/data`, set `TRUSTVAULT_DATA_DIR=/var/data`.
- To persist uploaded documents on Render too, set `TRUSTVAULT_UPLOAD_DIR` to a directory on that disk, such as `/var/data/private_uploads`.
- Render service start command: `npm start`. Attach a persistent disk at `/var/data` and configure `TRUSTVAULT_DATA_DIR=/var/data`, `TRUSTVAULT_UPLOAD_DIR=/var/data/private_uploads`, `TRUSTVAULT_SESSION_SECRET`, and `TRUSTVAULT_AUDIT_SECRET` in the service environment. Back up the existing database and private upload directory before deploying schema migrations.
- File extensions can be restricted with `TRUSTVAULT_ALLOWED_EXTENSIONS`, a comma-separated subset of `.pdf,.png,.jpg,.jpeg,.txt,.docx,.xlsx`. The server validates signatures and Office ZIP contents; browser MIME headers are not trusted.
- The project deliberately does not expose public file URLs.

## Security model

- Default deny authorization is enforced on every protected operation.
- Users without an active permission cannot view or download protected documents.
- Only the application HTML and required frontend assets are served publicly; database files, server source, and private uploads are not exposed by static-file serving.
- Audit events are insert-only at the SQLite layer and include hash-chain linkage and HMAC signatures. Legacy events remain verifiable with the original hash-chain format; only newly signed events get HMAC protection.
- The application intentionally does not trust client-supplied user IDs, document IDs, or permission values.
- Document approval is a manual administrator release gate; this project does not include an antivirus engine or automated malware scanning. Do not treat approval as a malware-clean verdict.
- Revoking access prevents future application requests and downloads; it cannot erase files a recipient already downloaded.
