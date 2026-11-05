# TrustVault

TrustVault is a secure document-sharing application designed around explicit access control, audit logging, and private file storage. It uses Express.js with SQLite persistence to provide a working MVP for document management and sharing.

## Features

- Secure authentication and session management
- Role-based access: administrator, document owner, and viewer
- Server-side authorization checks for documents and permissions
- Private uploads stored outside the public web root
- File validation by extension, MIME, and signature checks
- Document sharing with read/edit permissions and optional expiry
- Audit trail with a simple tamper-evident hash chain
- Admin dashboard for users and security events
- Search, filter, and pagination for visible documents

## Setup

1. Install dependencies:
   `npm install`
2. Start the server:
   `npm start`
3. Open `http://localhost:3000`

## First user

The first registered user becomes the administrator automatically. There is no default production password or hard-coded secret.

## Roles and sessions

- The **Owner** role is the administrator role. Owners can manage users, access the audit trail, and manage sharing permissions for documents.
- **Document owner** users can upload documents and manage sharing for documents they own.
- **Viewer** users can only access documents explicitly shared with them.
- Set `TRUSTVAULT_SESSION_SECRET` to a stable, random value of at least 32 characters in production. The application rejects production startup without it. Development uses an ephemeral secret unless you set the variable.
- Users whose role or status changes are checked against SQLite on each protected request, so disabling an account or removing its role takes effect immediately.
- Older user tables are migrated additively: missing role/status columns are added without deleting records, and the earliest existing account becomes Owner if no role column existed.

## Notes

- Documents are stored in `private_uploads/`.
- Database state is stored in `data/trustvault.db`.
- For persistent hosting, set `TRUSTVAULT_DATA_DIR` to the mounted persistent disk directory. For example, on a Render disk mounted at `/var/data`, set `TRUSTVAULT_DATA_DIR=/var/data`.
- To persist uploaded documents on Render too, set `TRUSTVAULT_UPLOAD_DIR` to a directory on that disk, such as `/var/data/private_uploads`.
- The project deliberately does not expose public file URLs.

## Security model

- Default deny authorization is enforced on every protected operation.
- Users without an active permission cannot view or download protected documents.
- Only the application HTML and required frontend assets are served publicly; database files, server source, and private uploads are not exposed by static-file serving.
- Audit records include a previous-hash linkage to help detect tampering.
- The application intentionally does not trust client-supplied user IDs, document IDs, or permission values.
