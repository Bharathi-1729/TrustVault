# TrustVault Prompt Pack

This file contains reusable prompts for reviewing, testing, and extending the TrustVault application safely.

## 1. Security Review Prompt

"Review the TrustVault codebase for authentication, authorization, file upload, and audit trail risks. Focus on default-deny access control, bypass paths, privilege escalation, path traversal, insecure storage, and tampering of audit data. Provide ranked findings with file references, impact, and actionable fixes."

## 2. Authorization Audit Prompt

"Trace every protected API route in TrustVault and verify that each one enforces authorization server-side. Check for missing checks on owner-only actions, permission grants, document downloads, admin endpoints, and update/delete operations. Report any route that trusts client input or UI-only restrictions."

## 3. File Upload Security Prompt

"Assess TrustVault upload handling for unsafe file validation, path traversal, extension spoofing, MIME mismatch, file size abuse, storage key generation, and malicious content. Suggest a secure upload policy and confirm whether files remain private and inaccessible from the public web root."

## 4. Audit Integrity Prompt

"Inspect the audit log implementation for tamper-evidence. Verify the hash chaining, record ordering, integrity validation, and whether the system can detect modifications or deletions. Suggest improvements that make the log harder to tamper with."

## 5. Role and Access Testing Prompt

"Create a test matrix for TrustVault covering administrator, document owner, and viewer roles. Include tests for permission granting, revocation, deactivation, self-protection, document access denial, and unauthorized access attempts. Validate that default-deny rules hold even when a user tampers with identifiers in requests."

## 6. QA Regression Prompt

"Run through the TrustVault user flows: registration, login, logout, document upload, metadata editing, search, sharing, permission changes, download restrictions, audit review, and admin role management. Check for broken buttons, missing validation, stale UI state, and authorization mismatches between frontend and backend."

## 7. Bug Fix Prompt

"Investigate the TrustVault runtime issue, isolate the root cause, and fix it without deleting working features or broad unrelated changes. Preserve the current security model, keep the app functional, and validate the start-up path and critical user flows."

## 8. Threat Modeling Prompt

"Prepare a concise threat model for TrustVault covering assets, attack surfaces, trust boundaries, key risks, mitigations, and residual risk. Include access control, auth, file validation, session security, and tamper-evident logging."

## 9. Deployment Hardening Prompt

"Review TrustVault for production deployment hardening. Check session security, HTTPS usage assumptions, file storage security, server configuration, secret management, rate limiting, and dependency hygiene. Recommend the minimal changes needed before deployment."

## 10. Security Acceptance Prompt

"Review TrustVault against the core requirements: no unauthorized access, no UI-only authorization, no public file exposure, proper audit logging, proper role boundaries, and secure document lifecycle control. State whether the system meets the acceptance criteria and identify any remaining blockers."
