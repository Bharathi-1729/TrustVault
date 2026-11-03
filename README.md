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

## Notes

- Documents are stored in `private_uploads/`.
- Database state is stored in `data/trustvault.db`.
- The project deliberately does not expose public file URLs.

## Security model

- Default deny authorization is enforced on every protected operation.
- Users without an active permission cannot view or download protected documents.
- Audit records include a previous-hash linkage to help detect tampering.
- The application intentionally does not trust client-supplied user IDs, document IDs, or permission values.
