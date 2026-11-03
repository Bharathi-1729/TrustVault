const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const { fileTypeFromBuffer } = require('file-type');
const { v4: uuidv4 } = require('uuid');

const {
  db,
  initializeDatabase,
  getUserByEmail,
  getUserById,
  getAllUsers,
  createUser,
  updateUser,
  getDocumentById,
  listDocumentsForUser,
  getDocumentPermissions,
  upsertPermission,
  revokePermission,
  insertDocument,
  updateDocument,
  deleteDocument,
  getAuditEvents,
  recordAuditEvent,
  verifyAuditChain
} = require('./db');

const {
  MAX_FILE_SIZE_BYTES,
  ALLOWED_EXTENSIONS,
  sanitizeFilename,
  normalizePermission,
  isAllowedRole,
  computeSha256
} = require('./policy');

const app = express();
const port = Number(process.env.PORT || 3000);
const privateUploadDir = path.join(__dirname, 'private_uploads');
fs.mkdirSync(privateUploadDir, { recursive: true });
const staticDir = __dirname;

initializeDatabase();

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

app.use(session({
  secret: process.env.TRUSTVAULT_SESSION_SECRET || 'trustvault-dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: 1000 * 60 * 60 * 8
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please wait and try again.' }
});

app.use(express.static(staticDir, { index: false }));

function serializeUser(user) {
  if (!user) return null;
  const { password_hash, ...safeUser } = user;
  return safeUser;
}

function getSessionUser(req) {
  const userId = req.session && req.session.userId;
  if (!userId) return null;
  return getUserById(userId);
}

function requireAuth(req, res, next) {
  const user = getSessionUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  if (user.status !== 'active') {
    return res.status(403).json({ error: 'User account is disabled.' });
  }
  req.user = user;
  next();
}

function requireAdministrator(req, res, next) {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required.' });
  if (user.role !== 'administrator') return res.status(403).json({ error: 'Administrative access required.' });
  req.user = user;
  next();
}

function getEffectiveDocumentPermission(user, documentId) {
  if (!user || !documentId) return null;

  if (documentId && documentId.owner_id && documentId.owner_id === user.id) {
    return 'owner';
  }

  const doc = typeof documentId === 'string' ? getDocumentById(documentId) : documentId;
  if (!doc) return null;

  if (doc.owner_id === user.id) return 'owner';

  const row = db.prepare(`
    SELECT permission, expires_at
    FROM document_permissions
    WHERE document_id = ? AND user_id = ? AND active = 1
      AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
    ORDER BY created_at DESC
    LIMIT 1
  `).get(doc.id, user.id);

  return row ? row.permission : null;
}

function canAccessDocument(user, document, requiredLevel = 'read') {
  if (!user || !document) return false;
  if (user.status !== 'active') return false;
  if (document.owner_id === user.id) return true;
  if (user.role === 'administrator') return false;

  const activeLevel = getEffectiveDocumentPermission(user, document);
  if (!activeLevel) return false;
  if (requiredLevel === 'read') return activeLevel === 'read' || activeLevel === 'edit' || activeLevel === 'owner';
  if (requiredLevel === 'edit') return activeLevel === 'edit' || activeLevel === 'owner';
  return false;
}

function addAudit(action, req, details, resourceType = null, resourceId = null) {
  const user = getSessionUser(req);
  return recordAuditEvent({
    actorId: user ? user.id : null,
    actorName: user ? user.name : null,
    action,
    resourceType,
    resourceId,
    details,
    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
  });
}

function buildDocumentSummary(document, user) {
  const summary = {
    ...document,
    ownerName: user && user.id === document.owner_id ? user.name : null,
    accessLevel: getEffectiveDocumentPermission(user, document)
  };

  if (summary.ownerName === null) {
    const owner = getUserById(document.owner_id);
    summary.ownerName = owner ? owner.name : 'Unknown';
  }

  return summary;
}

function getUserDocumentAccessLevel(user, document) {
  if (!user || !document) return null;
  if (document.owner_id === user.id) return 'owner';
  const row = db.prepare(`
    SELECT permission FROM document_permissions
    WHERE document_id = ? AND user_id = ? AND active = 1
      AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
    ORDER BY created_at DESC LIMIT 1
  `).get(document.id, user.id);
  return row ? row.permission : null;
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, privateUploadDir),
  filename: (_req, file, cb) => {
    const extension = path.extname(file.originalname || 'document').toLowerCase();
    cb(null, `${uuidv4()}${extension}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE_BYTES },
  fileFilter: (_req, file, cb) => {
    const extension = path.extname(file.originalname || '').toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(extension)) {
      return cb(new Error('Unsupported file extension. Allowed: .pdf, .png, .jpg, .jpeg, .txt, .docx'));
    }
    cb(null, true);
  }
});

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, name: 'TrustVault' });
});

app.post('/api/auth/register', loginLimiter, (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required.' });
    }
    if (String(name).trim().length < 2) {
      return res.status(400).json({ error: 'Name must be at least 2 characters.' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email))) {
      return res.status(400).json({ error: 'Provide a valid email address.' });
    }
    if (String(password).length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }

    const existingUser = getUserByEmail(String(email));
    if (existingUser) {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }

    const allUsers = getAllUsers();
    const role = allUsers.length === 0 ? 'administrator' : 'viewer';
    const id = uuidv4();
    const passwordHash = bcrypt.hashSync(String(password), 12);
    const created = createUser({
      id,
      name: String(name).trim(),
      email: String(email).trim().toLowerCase(),
      passwordHash,
      role
    });

    req.session.userId = created.id;
    recordAuditEvent({
      actorId: created.id,
      actorName: created.name,
      action: 'user_registered',
      resourceType: 'user',
      resourceId: created.id,
      details: { email: created.email, role: created.role },
      ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
    });

    return res.status(201).json({ user: serializeUser(created) });
  } catch (error) {
    return res.status(500).json({ error: 'Unable to register user.' });
  }
});

app.post('/api/auth/login', loginLimiter, (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = getUserByEmail(String(email).trim().toLowerCase());
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    if (user.status !== 'active') {
      return res.status(403).json({ error: 'This account is disabled.' });
    }

    const passwordMatches = bcrypt.compareSync(String(password), user.password_hash);
    if (!passwordMatches) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    req.session.userId = user.id;
    recordAuditEvent({
      actorId: user.id,
      actorName: user.name,
      action: 'user_login',
      resourceType: 'user',
      resourceId: user.id,
      details: { email: user.email },
      ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
    });

    return res.json({ user: serializeUser(user) });
  } catch (error) {
    return res.status(500).json({ error: 'Unable to log in.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  const user = getSessionUser(req);
  if (user) {
    recordAuditEvent({
      actorId: user.id,
      actorName: user.name,
      action: 'user_logout',
      resourceType: 'user',
      resourceId: user.id,
      details: { email: user.email },
      ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
    });
  }

  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: serializeUser(req.user) });
});

app.put('/api/profile', requireAuth, (req, res) => {
  const { name, password } = req.body || {};
  const user = req.user;
  const nextName = name ? String(name).trim() : user.name;

  if (nextName.length < 2) {
    return res.status(400).json({ error: 'Name must be at least 2 characters.' });
  }

  let nextPasswordHash = user.password_hash;
  if (password) {
    if (String(password).length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    nextPasswordHash = bcrypt.hashSync(String(password), 12);
  }

  const updated = updateUser(user.id, {
    name: nextName,
    password_hash: nextPasswordHash
  });

  recordAuditEvent({
    actorId: updated.id,
    actorName: updated.name,
    action: 'profile_updated',
    resourceType: 'user',
    resourceId: updated.id,
    details: { changedPassword: !!password },
    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
  });

  res.json({ user: serializeUser(updated) });
});

app.get('/api/users', requireAuth, (req, res) => {
  const all = getAllUsers().map((user) => serializeUser(user));
  res.json({ users: all });
});

app.get('/api/documents', requireAuth, (req, res) => {
  const docs = listDocumentsForUser(req.user).map((doc) => buildDocumentSummary(doc, req.user));
  let filtered = docs;
  const search = String(req.query.search || '').trim().toLowerCase();
  if (search) {
    filtered = filtered.filter((doc) => {
      const hay = `${doc.name} ${doc.ownerName} ${doc.category} ${doc.created_at}`.toLowerCase();
      return hay.includes(search);
    });
  }

  const category = String(req.query.category || '').trim();
  if (category) {
    filtered = filtered.filter((doc) => doc.category.toLowerCase() === category.toLowerCase());
  }

  const sortKey = String(req.query.sort || 'created_at').toLowerCase();
  const dir = String(req.query.dir || 'desc').toLowerCase() === 'asc' ? 1 : -1;

  filtered.sort((a, b) => {
    const left = a[sortKey] ?? '';
    const right = b[sortKey] ?? '';
    if (typeof left === 'number' && typeof right === 'number') return (left - right) * dir;
    return String(left).localeCompare(String(right)) * dir;
  });

  const page = Math.max(1, Number(req.query.page || 1));
  const limit = Math.min(Math.max(1, Number(req.query.limit || 10)), 50);
  const total = filtered.length;
  const paged = filtered.slice((page - 1) * limit, page * limit);

  res.json({
    documents: paged,
    page,
    limit,
    total,
    totalPages: Math.ceil(total / limit) || 1
  });
});

app.get('/api/documents/:id', requireAuth, (req, res) => {
  const document = getDocumentById(req.params.id);
  if (!document) {
    return res.status(404).json({ error: 'Document not found.' });
  }

  if (!canAccessDocument(req.user, document, 'read')) {
    recordAuditEvent({
      actorId: req.user.id,
      actorName: req.user.name,
      action: 'document_access_denied',
      resourceType: 'document',
      resourceId: document.id,
      details: { reason: 'No active read permission.', documentName: document.name },
      ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
    });
    return res.status(403).json({ error: 'Document access denied.' });
  }

  const userAccess = getUserDocumentAccessLevel(req.user, document);
  const permissions = getDocumentPermissions(document.id);
  res.json({
    document: {
      ...document,
      ownerName: getUserById(document.owner_id)?.name || 'Unknown',
      permissions,
      accessLevel: userAccess || 'owner'
    }
  });
});

app.get('/api/documents/:id/download', requireAuth, (req, res) => {
  const document = getDocumentById(req.params.id);
  if (!document) {
    return res.status(404).json({ error: 'Document not found.' });
  }

  if (!canAccessDocument(req.user, document, 'read')) {
    recordAuditEvent({
      actorId: req.user.id,
      actorName: req.user.name,
      action: 'document_download_denied',
      resourceType: 'document',
      resourceId: document.id,
      details: { reason: 'No active read permission for download.' },
      ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
    });
    return res.status(403).json({ error: 'Document access denied.' });
  }

  if (document.scan_status !== 'approved') {
    recordAuditEvent({
      actorId: req.user.id,
      actorName: req.user.name,
      action: 'document_download_blocked',
      resourceType: 'document',
      resourceId: document.id,
      details: { reason: 'Security scan pending or failed.', scanStatus: document.scan_status },
      ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
    });
    return res.status(403).json({ error: 'This document is awaiting security review.' });
  }

  const extension = path.extname(document.original_name || '');
  const filePath = path.join(privateUploadDir, `${document.storage_key}${extension}`);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Document file is not available.' });
  }

  res.download(filePath, sanitizeFilename(document.name) || 'document');
});

app.post('/api/documents', requireAuth, upload.single('file'), async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Authentication required.' });
  if (req.user.role !== 'document_owner' && req.user.role !== 'administrator') {
    return res.status(403).json({ error: 'Only document owners can upload files.' });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'A file is required for upload.' });
  }

  const fileBuffer = fs.readFileSync(req.file.path);
  const fileType = await fileTypeFromBuffer(fileBuffer);
  const extension = path.extname(req.file.originalname || '').toLowerCase();

  if (fileBuffer.length === 0) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'The uploaded file is empty.' });
  }

  if (extension === '.txt') {
    const text = fileBuffer.toString('utf8');
    const looksText = [...text].every((char) => char.charCodeAt(0) === 9 || char.charCodeAt(0) === 10 || char.charCodeAt(0) === 13 || (char.charCodeAt(0) >= 32 && char.charCodeAt(0) <= 126));
    if (!looksText) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'Text files must be valid UTF-8 content.' });
    }
  }

  const detectedMime = fileType ? fileType.mime : null;
  if (detectedMime && !['application/pdf', 'image/png', 'image/jpeg', 'text/plain', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'].includes(detectedMime)) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'The file content type is not allowed.' });
  }

  const finalName = sanitizeFilename(req.file.originalname || 'document');
  const storageKey = uuidv4();
  const finalFileName = `${storageKey}${extension}`;
  const destinationPath = path.join(privateUploadDir, finalFileName);
  fs.renameSync(req.file.path, destinationPath);

  const doc = {
    id: uuidv4(),
    ownerId: req.user.id,
    name: finalName,
    category: String(req.body.category || 'general').trim() || 'general',
    description: String(req.body.description || '').trim(),
    storageKey,
    originalName: finalName,
    mimeType: detectedMime || 'application/octet-stream',
    sizeBytes: fileBuffer.length,
    sha256: computeSha256(fileBuffer),
    scanStatus: 'pending',
    createdAt: new Date().toISOString()
  };

  insertDocument(doc);

  recordAuditEvent({
    actorId: req.user.id,
    actorName: req.user.name,
    action: 'document_uploaded',
    resourceType: 'document',
    resourceId: doc.id,
    details: { documentName: doc.name, category: doc.category, sizeBytes: doc.sizeBytes },
    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
  });

  return res.status(201).json({ document: { ...doc, ownerName: req.user.name, accessLevel: 'owner' } });
});

app.put('/api/documents/:id', requireAuth, (req, res) => {
  const document = getDocumentById(req.params.id);
  if (!document) return res.status(404).json({ error: 'Document not found.' });

  if (document.owner_id !== req.user.id && !canAccessDocument(req.user, document, 'edit')) {
    recordAuditEvent({
      actorId: req.user.id,
      actorName: req.user.name,
      action: 'document_update_denied',
      resourceType: 'document',
      resourceId: document.id,
      details: { reason: 'Insufficient permission for metadata edit.' },
      ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
    });
    return res.status(403).json({ error: 'You are not allowed to edit this document.' });
  }

  const nextName = sanitizeFilename(String(req.body.name || document.name));
  const nextCategory = String(req.body.category || document.category).trim() || 'general';
  const description = String(req.body.description || document.description || '').trim();

  const updated = updateDocument(document.id, {
    name: nextName,
    category: nextCategory,
    description
  });

  recordAuditEvent({
    actorId: req.user.id,
    actorName: req.user.name,
    action: 'document_updated',
    resourceType: 'document',
    resourceId: updated.id,
    details: { documentName: updated.name, category: updated.category },
    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
  });

  return res.json({ document: { ...updated, ownerName: getUserById(document.owner_id)?.name || 'Unknown' } });
});

app.delete('/api/documents/:id', requireAuth, (req, res) => {
  const document = getDocumentById(req.params.id);
  if (!document) return res.status(404).json({ error: 'Document not found.' });
  if (document.owner_id !== req.user.id) {
    return res.status(403).json({ error: 'Only the document owner can delete it.' });
  }

  const extension = path.extname(document.original_name || '');
  const diskPath = path.join(privateUploadDir, `${document.storage_key}${extension}`);
  if (fs.existsSync(diskPath)) fs.unlinkSync(diskPath);

  deleteDocument(document.id);
  recordAuditEvent({
    actorId: req.user.id,
    actorName: req.user.name,
    action: 'document_deleted',
    resourceType: 'document',
    resourceId: document.id,
    details: { documentName: document.name },
    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
  });

  res.json({ ok: true });
});

app.post('/api/documents/:id/share', requireAuth, (req, res) => {
  const document = getDocumentById(req.params.id);
  if (!document) return res.status(404).json({ error: 'Document not found.' });
  if (document.owner_id !== req.user.id) return res.status(403).json({ error: 'Only the owner can change permissions.' });

  const email = String(req.body.email || '').trim().toLowerCase();
  const permission = normalizePermission(req.body.permission || 'read');
  const target = getUserByEmail(email);

  if (!target || target.status !== 'active') {
    return res.status(400).json({ error: 'The target user must already exist and be active.' });
  }

  if (target.id === req.user.id) {
    return res.status(400).json({ error: 'The document owner is already authorized.' });
  }

  let expiresAt = req.body.expiresAt || null;
  if (expiresAt) {
    const date = new Date(expiresAt);
    if (Number.isNaN(date.getTime())) {
      return res.status(400).json({ error: 'Permission expiration must be a valid date.' });
    }
    expiresAt = date.toISOString();
  }

  const granted = upsertPermission({
    documentId: document.id,
    userId: target.id,
    permission,
    createdBy: req.user.id,
    expiresAt
  });

  recordAuditEvent({
    actorId: req.user.id,
    actorName: req.user.name,
    action: 'document_permission_granted',
    resourceType: 'document_permission',
    resourceId: granted.id,
    details: { documentId: document.id, targetEmail: email, permission, expiresAt },
    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
  });

  res.status(201).json({ permission: granted, user: serializeUser(target) });
});

app.delete('/api/documents/:id/share/:userId', requireAuth, (req, res) => {
  const document = getDocumentById(req.params.id);
  if (!document) return res.status(404).json({ error: 'Document not found.' });
  if (document.owner_id !== req.user.id) return res.status(403).json({ error: 'Only the owner can revoke permissions.' });

  const revoked = revokePermission(document.id, req.params.userId);
  if (!revoked) {
    return res.status(404).json({ error: 'No active permission was found for that user.' });
  }

  recordAuditEvent({
    actorId: req.user.id,
    actorName: req.user.name,
    action: 'document_permission_revoked',
    resourceType: 'document_permission',
    resourceId: revoked.id,
    details: { documentId: document.id, targetUserId: req.params.userId },
    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
  });

  res.json({ ok: true });
});

app.get('/api/admin/dashboard', requireAdministrator, (req, res) => {
  const users = getAllUsers();
  const docs = listDocumentsForUser(req.user);
  const audit = getAuditEvents(10);

  res.json({
    counts: {
      users: users.length,
      documents: docs.length,
      administrators: users.filter((user) => user.role === 'administrator').length,
      viewers: users.filter((user) => user.role === 'viewer').length,
      ownerUsers: users.filter((user) => user.role === 'document_owner').length
    },
    recentAudit: audit
  });
});

app.post('/api/admin/documents/:id/scan', requireAdministrator, (req, res) => {
  const document = getDocumentById(req.params.id);
  if (!document) return res.status(404).json({ error: 'Document not found.' });

  const nextStatus = String(req.body.status || 'approved').toLowerCase();
  if (!['approved', 'failed', 'pending'].includes(nextStatus)) {
    return res.status(400).json({ error: 'Invalid scan status.' });
  }

  db.prepare('UPDATE documents SET scan_status = ?, updated_at = ? WHERE id = ?').run(nextStatus, new Date().toISOString(), document.id);
  recordAuditEvent({
    actorId: req.user.id,
    actorName: req.user.name,
    action: 'document_scan_status_updated',
    resourceType: 'document',
    resourceId: document.id,
    details: { scanStatus: nextStatus },
    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
  });

  res.json({ ok: true, scanStatus: nextStatus });
});

app.get('/api/admin/users', requireAdministrator, (req, res) => {
  res.json({ users: getAllUsers().map((user) => serializeUser(user)) });
});

app.put('/api/admin/users/:id/role', requireAdministrator, (req, res) => {
  const target = getUserById(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found.' });

  const nextRole = String(req.body.role || '').toLowerCase();
  if (!isAllowedRole(nextRole)) return res.status(400).json({ error: 'Unsupported role assignment.' });

  if (target.id === req.user.id && nextRole !== 'administrator') {
    return res.status(400).json({ error: 'Administrators cannot demote themselves.' });
  }

  const updated = updateUser(target.id, { role: nextRole });
  recordAuditEvent({
    actorId: req.user.id,
    actorName: req.user.name,
    action: 'user_role_updated',
    resourceType: 'user',
    resourceId: updated.id,
    details: { targetUser: updated.email, previousRole: target.role, newRole: nextRole },
    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
  });

  res.json({ user: serializeUser(updated) });
});

app.put('/api/admin/users/:id/status', requireAdministrator, (req, res) => {
  const target = getUserById(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found.' });
  const nextStatus = String(req.body.status || '').toLowerCase();
  if (!['active', 'disabled'].includes(nextStatus)) return res.status(400).json({ error: 'Unsupported status value.' });
  if (target.id === req.user.id && nextStatus === 'disabled') {
    return res.status(400).json({ error: 'An administrator cannot disable their own account.' });
  }

  const updated = updateUser(target.id, { status: nextStatus });
  recordAuditEvent({
    actorId: req.user.id,
    actorName: req.user.name,
    action: 'user_status_updated',
    resourceType: 'user',
    resourceId: updated.id,
    details: { targetUser: updated.email, previousStatus: target.status, newStatus: nextStatus },
    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
  });

  res.json({ user: serializeUser(updated) });
});

app.get('/api/admin/audit', requireAdministrator, (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit || 100), 1), 500);
  const audit = getAuditEvents(limit);
  res.json({ audit, integrity: verifyAuditChain() });
});

app.get('/', (_req, res) => {
  res.sendFile(path.join(staticDir, 'index.html'));
});

app.get('/app.html', requireAuth, (_req, res) => {
  res.sendFile(path.join(staticDir, 'app.html'));
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: err.message });
  }

  if (err && err.message) {
    return res.status(400).json({ error: err.message });
  }

  return res.status(500).json({ error: 'An unexpected server error occurred.' });
});

app.listen(port, () => {
  console.log(`TrustVault listening on http://localhost:${port}`);
});
