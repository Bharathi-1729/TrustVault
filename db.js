const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const dataDir = process.env.TRUSTVAULT_DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });

const dbPath = path.join(dataDir, 'trustvault.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function nowIso() {
  return new Date().toISOString();
}

function initializeDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('administrator','document_owner','viewer')),
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS documents (
      id TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL,
      name TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'general',
      description TEXT,
      storage_key TEXT NOT NULL,
      original_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      sha256 TEXT NOT NULL,
      scan_status TEXT NOT NULL DEFAULT 'pending',
      is_deleted INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY(owner_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS document_permissions (
      id TEXT PRIMARY KEY,
      document_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      permission TEXT NOT NULL CHECK(permission IN ('read','edit')),
      active INTEGER NOT NULL DEFAULT 1,
      expires_at TEXT,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      revoked_at TEXT,
      FOREIGN KEY(document_id) REFERENCES documents(id),
      FOREIGN KEY(user_id) REFERENCES users(id),
      FOREIGN KEY(created_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS audit_events (
      id TEXT PRIMARY KEY,
      actor_id TEXT,
      actor_name TEXT,
      action TEXT NOT NULL,
      resource_type TEXT,
      resource_id TEXT,
      details TEXT,
      ip TEXT,
      created_at TEXT NOT NULL,
      prev_hash TEXT NOT NULL,
      hash TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS settings (
      name TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      sid TEXT PRIMARY KEY NOT NULL,
      sess TEXT NOT NULL,
      expires INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions(expires);
  `);

  const rows = db.prepare('SELECT COUNT(*) AS count FROM users').get();
  if (!rows || Number(rows.count) === 0) {
    db.prepare('INSERT OR IGNORE INTO settings(name, value, updated_at) VALUES(?, ?, ?)')
      .run('first_run_completed', 'false', nowIso());
  }
}

function getSetting(name, fallback = null) {
  const row = db.prepare('SELECT value FROM settings WHERE name = ?').get(name);
  return row ? row.value : fallback;
}

function setSetting(name, value) {
  db.prepare(`INSERT INTO settings(name, value, updated_at) VALUES(?, ?, ?) 
    ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`)
    .run(name, String(value), nowIso());
}

function recordAuditEvent({ actorId, actorName, action, resourceType, resourceId, details, ip }) {
  const latestHash = db.prepare('SELECT hash FROM audit_events ORDER BY created_at DESC, id DESC LIMIT 1').get();
  const prevHash = latestHash ? latestHash.hash : 'GENESIS';
  const createdAt = nowIso();
  const payload = JSON.stringify({
    actorId,
    actorName,
    action,
    resourceType,
    resourceId,
    details,
    ip,
    createdAt,
    prevHash
  });
  const digest = crypto.createHash('sha256').update(payload).digest('hex');
  const id = crypto.randomUUID();

  db.prepare(`
    INSERT INTO audit_events(id, actor_id, actor_name, action, resource_type, resource_id, details, ip, created_at, prev_hash, hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, actorId || null, actorName || null, action, resourceType || null, resourceId || null, details ? JSON.stringify(details) : null, ip || null, createdAt, prevHash, digest);

  return digest;
}

function verifyAuditChain() {
  const rows = db.prepare('SELECT * FROM audit_events ORDER BY created_at ASC, id ASC').all();
  let previous = 'GENESIS';
  let issues = [];

  for (const row of rows) {
    const payload = JSON.stringify({
      actorId: row.actor_id,
      actorName: row.actor_name,
      action: row.action,
      resourceType: row.resource_type,
      resourceId: row.resource_id,
      details: row.details ? JSON.parse(row.details) : null,
      ip: row.ip,
      createdAt: row.created_at,
      prevHash: previous
    });

    const digest = crypto.createHash('sha256').update(payload).digest('hex');
    if (row.prev_hash !== previous || row.hash !== digest) {
      issues.push({ id: row.id, expected: digest, actual: row.hash, previousHash: previous, actualPreviousHash: row.prev_hash });
    }
    previous = row.hash;
  }

  return { valid: issues.length === 0, issues };
}

function getUserById(id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}

function getUserByEmail(email) {
  return db.prepare('SELECT * FROM users WHERE lower(email) = ?').get(email.trim().toLowerCase());
}

function createUser({ id, name, email, passwordHash, role, status = 'active' }) {
  const now = nowIso();
  db.prepare(`
    INSERT INTO users(id, name, email, password_hash, role, status, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, name, email.toLowerCase(), passwordHash, role, status, now, now);

  return getUserById(id);
}

function updateUser(id, fields) {
  const existing = getUserById(id);
  if (!existing) return null;

  const merged = { ...existing, ...fields, updated_at: nowIso() };
  db.prepare(`
    UPDATE users
    SET name = ?, email = ?, password_hash = ?, role = ?, status = ?, updated_at = ?
    WHERE id = ?
  `).run(merged.name, merged.email, merged.password_hash, merged.role, merged.status, merged.updated_at, id);

  return getUserById(id);
}

function getAllUsers() {
  return db.prepare('SELECT * FROM users ORDER BY created_at DESC').all();
}

function getDocumentById(id) {
  return db.prepare('SELECT * FROM documents WHERE id = ? AND is_deleted = 0').get(id);
}

function listDocumentsForUser(user) {
  if (!user) return [];

  const rows = db.prepare(`
    SELECT d.*
    FROM documents d
    WHERE d.is_deleted = 0
      AND (
        d.owner_id = ?
        OR EXISTS (
          SELECT 1 FROM document_permissions dp
          WHERE dp.document_id = d.id
            AND dp.user_id = ?
            AND dp.active = 1
            AND (dp.expires_at IS NULL OR datetime(dp.expires_at) > datetime('now'))
        )
      )
    ORDER BY d.created_at DESC
  `).all(user.id, user.id);

  return rows;
}

function getDocumentPermissions(documentId) {
  return db.prepare(`
    SELECT dp.*, u.name AS user_name, u.email AS user_email
    FROM document_permissions dp
    JOIN users u ON u.id = dp.user_id
    WHERE dp.document_id = ? AND dp.active = 1
    ORDER BY dp.created_at DESC
  `).all(documentId);
}

function upsertPermission({ documentId, userId, permission, createdBy, expiresAt }) {
  const now = nowIso();
  const existing = db.prepare(`
    SELECT * FROM document_permissions WHERE document_id = ? AND user_id = ? AND active = 1
  `).get(documentId, userId);

  if (existing) {
    db.prepare(`
      UPDATE document_permissions
      SET permission = ?, expires_at = ?, updated_at = ?, revoked_at = NULL
      WHERE id = ?
    `).run(permission, expiresAt || null, now, existing.id);
    return db.prepare('SELECT * FROM document_permissions WHERE id = ?').get(existing.id);
  }

  const id = crypto.randomUUID();
  db.prepare(`
    INSERT INTO document_permissions(id, document_id, user_id, permission, active, expires_at, created_by, created_at, updated_at, revoked_at)
    VALUES(?, ?, ?, ?, 1, ?, ?, ?, ?, NULL)
  `).run(id, documentId, userId, permission, expiresAt || null, createdBy, now, now);

  return db.prepare('SELECT * FROM document_permissions WHERE id = ?').get(id);
}

function revokePermission(documentId, userId) {
  const row = db.prepare(`
    SELECT * FROM document_permissions WHERE document_id = ? AND user_id = ? AND active = 1 ORDER BY created_at DESC LIMIT 1
  `).get(documentId, userId);

  if (!row) return null;

  db.prepare(`
    UPDATE document_permissions
    SET active = 0, revoked_at = ?, updated_at = ?
    WHERE id = ?
  `).run(nowIso(), nowIso(), row.id);

  return row;
}

function insertDocument(document) {
  db.prepare(`
    INSERT INTO documents(id, owner_id, name, category, description, storage_key, original_name, mime_type, size_bytes, sha256, scan_status, is_deleted, created_at, updated_at)
    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
  `).run(
    document.id,
    document.ownerId,
    document.name,
    document.category,
    document.description || '',
    document.storageKey,
    document.originalName,
    document.mimeType,
    document.sizeBytes,
    document.sha256,
    document.scanStatus || 'pending',
    document.createdAt || nowIso(),
    document.createdAt || nowIso()
  );

  return getDocumentById(document.id);
}

function updateDocument(id, fields) {
  const existing = getDocumentById(id);
  if (!existing) return null;

  const merged = { ...existing, ...fields, updated_at: nowIso() };
  db.prepare(`
    UPDATE documents
    SET name = ?, category = ?, description = ?, updated_at = ?
    WHERE id = ?
  `).run(merged.name, merged.category, merged.description || '', merged.updated_at, id);

  return getDocumentById(id);
}

function deleteDocument(id) {
  db.prepare(`UPDATE documents SET is_deleted = 1, updated_at = ? WHERE id = ?`).run(nowIso(), id);
  return true;
}

function getAuditEvents(limit = 100) {
  return db.prepare(`
    SELECT * FROM audit_events ORDER BY created_at DESC LIMIT ?
  `).all(limit);
}

module.exports = {
  db,
  initializeDatabase,
  nowIso,
  getSetting,
  setSetting,
  recordAuditEvent,
  verifyAuditChain,
  getUserById,
  getUserByEmail,
  createUser,
  updateUser,
  getAllUsers,
  getDocumentById,
  listDocumentsForUser,
  getDocumentPermissions,
  upsertPermission,
  revokePermission,
  insertDocument,
  updateDocument,
  deleteDocument,
  getAuditEvents
};
