import { sql } from 'drizzle-orm';
import { pgTable, text, integer, bigint, index, uniqueIndex, check } from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: text().primaryKey(), email: text().notNull().unique(), name: text().notNull(),
  password_hash: text().notNull(), role: text().notNull().default('viewer'),
  status: text().notNull().default('active'), auth_version: integer().notNull().default(1),
  created_at: text().notNull(), updated_at: text().notNull(),
}, t => [
  check('users_role', sql`${t.role} in ('administrator','document_owner','viewer')`),
  check('users_status', sql`${t.status} in ('active','disabled')`),
  check('users_email', sql`${t.email} = lower(trim(${t.email})) and length(${t.email}) between 3 and 254`),
  check('users_name', sql`length(trim(${t.name})) between 1 and 120`),
  check('users_auth_version', sql`${t.auth_version} > 0`),
  index('users_status_role').on(t.status, t.role),
]);
export const registration_invites = pgTable('registration_invites', {
  id: text().primaryKey(), token_hash: text().notNull().unique(),
  role: text().notNull().default('viewer'), created_at: text().notNull(),
  expires_at: text().notNull(), consumed_at: text(),
  created_by: text().references(() => users.id, { onDelete: 'restrict' }),
}, t => [
  check('invites_role', sql`${t.role} in ('administrator','document_owner','viewer')`),
  check('invites_expiry', sql`${t.expires_at} > ${t.created_at}`),
  index('invites_expiry').on(t.expires_at, t.consumed_at),
]);
export const login_attempts = pgTable('login_attempts', {
  id: text().primaryKey(), username_key: text().notNull(), source_ip: text().notNull(),
  attempted_at: text().notNull(), outcome: text().notNull(),
}, t => [
  check('attempts_outcome', sql`${t.outcome} in ('failed','success','blocked')`),
  index('attempts_username_time').on(t.username_key, t.attempted_at),
  index('attempts_ip_time').on(t.source_ip, t.attempted_at),
]);
// Only a digest of the opaque browser cookie is persisted. CSRF derives from the cookie.
export const server_sessions = pgTable('server_sessions', {
  sid_hash: text().primaryKey(), user_id: text().notNull().references(() => users.id, { onDelete: 'cascade' }),
  auth_version: integer().notNull(), expires_at: text().notNull(), created_at: text().notNull(),
}, t => [index('sessions_expiry').on(t.expires_at)]);
export const documents = pgTable('documents', {
  id: text().primaryKey(), owner_id: text().notNull().references(() => users.id, { onDelete: 'restrict' }),
  storage_key: text().notNull().unique(), name: text().notNull(), description: text().notNull().default(''),
  category: text().notNull().default('general'), mime_type: text().notNull(),
  size_bytes: bigint({ mode: 'number' }).notNull(), sha256: text().notNull(),
  scan_status: text().notNull().default('pending'), created_at: text().notNull(),
  updated_at: text().notNull(), deleted_at: text(),
}, t => [
  check('documents_name', sql`length(trim(${t.name})) between 1 and 255`),
  check('documents_description', sql`length(${t.description}) <= 2000`),
  check('documents_category', sql`length(trim(${t.category})) between 1 and 64`),
  check('documents_size', sql`${t.size_bytes} >= 0`),
  check('documents_scan', sql`${t.scan_status} in ('pending','approved','rejected')`),
  index('documents_owner_created').on(t.owner_id, t.created_at),
]);
export const document_permissions = pgTable('document_permissions', {
  id: text().primaryKey(), document_id: text().notNull().references(() => documents.id, { onDelete: 'restrict' }),
  user_id: text().notNull().references(() => users.id, { onDelete: 'restrict' }),
  granted_by: text().notNull().references(() => users.id, { onDelete: 'restrict' }),
  permission: text().notNull(), granted_at: text().notNull(), expires_at: text(), revoked_at: text(),
}, t => [
  check('permissions_type', sql`${t.permission} in ('read','edit')`),
  check('permissions_expiry', sql`${t.expires_at} is null or ${t.expires_at} > ${t.granted_at}`),
  uniqueIndex('permissions_one_unrevoked').on(t.document_id, t.user_id).where(sql`${t.revoked_at} is null`),
  index('permissions_user_document').on(t.user_id, t.document_id),
]);
export const audit_logs = pgTable('audit_logs', {
  sequence: bigint({ mode: 'number' }).primaryKey(), id: text().notNull().unique(), timestamp: text().notNull(),
  user_id: text().references(() => users.id, { onDelete: 'restrict' }), username: text(),
  action: text().notNull(), document_id: text().references(() => documents.id, { onDelete: 'restrict' }),
  ip_address: text(), status: text().notNull(), details: text().notNull(),
  prev_hash: text().notNull(), current_hash: text().notNull().unique(), user_agent: text(),
}, t => [
  check('audit_status', sql`${t.status} in ('success','failure','denied')`),
  check('audit_details', sql`jsonb_typeof(${t.details}::jsonb) = 'object'`),
  index('audit_actor_time').on(t.user_id, t.timestamp),
  index('audit_document_time').on(t.document_id, t.timestamp),
]);
