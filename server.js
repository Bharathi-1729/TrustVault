const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const {
  db,
  initializeDatabase,
  getUserByEmail,
  getUserById,
  getAllUsers,
  listAllDocuments,
  createRegisteredUser,
  updateUser,
  getDocumentById,
  listDocumentsForUser,
  getDocumentPermissions,
  getDocumentAuditEvents,
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
  ALLOWED_MIME_TYPES,
  sanitizeFilename,
  normalizePermission,
  isAllowedRole,
  computeSha256
} = require('./policy');

const app = express();
const port = Number(process.env.PORT || 3000);
const sessionSecret = process.env.TRUSTVAULT_SESSION_SECRET;
if (process.env.NODE_ENV === 'production' && (!sessionSecret || sessionSecret.length < 32)) {
  throw new Error('TRUSTVAULT_SESSION_SECRET must be set to at least 32 characters in production.');
}
const privateUploadDir = process.env.TRUSTVAULT_UPLOAD_DIR || path.join(__dirname, 'private_uploads');
fs.mkdirSync(privateUploadDir, { recursive: true });
const staticDir = __dirname;

initializeDatabase();

app.set('trust proxy', 1);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

class SQLiteSessionStore extends session.Store {
  constructor(database) {
    super();
    this.database = database;
  }

  get(sessionId, callback) {
    try {
      const row = this.database.prepare(
        'SELECT sess, expires FROM sessions WHERE sid = ?'
      ).get(sessionId);
      if (!row) return callback(null, null);
      if (row.expires <= Date.now()) {
        this.database.prepare('DELETE FROM sessions WHERE sid = ?').run(sessionId);
        return callback(null, null);
      }
      return callback(null, JSON.parse(row.sess));
    } catch (error) {
      return callback(error);
    }
  }

  set(sessionId, sessionData, callback) {
    try {
      const cookie = sessionData.cookie || {};
      const expiresAt = cookie.expires
        ? new Date(cookie.expires).getTime()
        : Date.now() + (Number(cookie.maxAge) || 24 * 60 * 60 * 1000);

      this.database.prepare(`
        INSERT INTO sessions(sid, sess, expires) VALUES(?, ?, ?)
        ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expires = excluded.expires
      `).run(sessionId, JSON.stringify(sessionData), expiresAt);
      this.database.prepare('DELETE FROM sessions WHERE expires <= ?').run(Date.now());
      if (callback) callback(null);
    } catch (error) {
      if (callback) callback(error);
    }
  }

  touch(sessionId, sessionData, callback) {
    try {
      const cookie = sessionData.cookie || {};
      const expiresAt = cookie.expires
        ? new Date(cookie.expires).getTime()
        : Date.now() + (Number(cookie.maxAge) || 24 * 60 * 60 * 1000);
      this.database.prepare('UPDATE sessions SET expires = ? WHERE sid = ?')
        .run(expiresAt, sessionId);
      if (callback) callback(null);
    } catch (error) {
      if (callback) callback(error);
    }
  }

  destroy(sessionId, callback) {
    try {
      this.database.prepare('DELETE FROM sessions WHERE sid = ?').run(sessionId);
      if (callback) callback(null);
    } catch (error) {
      if (callback) callback(error);
    }
  }
}

app.use(session({
  secret: sessionSecret || crypto.randomBytes(32).toString('hex'),
  store: new SQLiteSessionStore(db),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
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

app.get('/styles.css', (_req, res) => {
  res.sendFile(path.join(staticDir, 'styles.css'));
});

app.get('/app.js', (_req, res) => {
  res.sendFile(path.join(staticDir, 'app.js'));
});

app.get('/index.html', (_req, res) => {
  res.sendFile(path.join(staticDir, 'index.html'));
});

app.get('/motion.html', (_req, res) => {
  res.sendFile(path.join(staticDir, 'motion.html'));
});

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

function recordAuthorizationDenial(req, user, action, resourceId = null) {
  recordAuditEvent({
    actorId: user ? user.id : null,
    actorName: user ? user.name : null,
    action: 'authorization_denied',
    resourceType: resourceId ? 'document' : 'route',
    resourceId,
    details: { attemptedAction: action },
    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
  });
}

function startUserSession(req, userId, callback) {
  req.session.regenerate((error) => {
    if (error) return callback(error);
    req.session.userId = userId;
    req.session.save(callback);
  });
}

function requireAuth(req, res, next) {
  const user = getSessionUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  if (user.status !== 'active') {
    recordAuthorizationDenial(req, user, 'protected_api_access');
    return res.status(403).json({ error: 'User account is disabled.' });
  }
  req.user = user;
  next();
}

function requireAdministrator(req, res, next) {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required.' });
  if (user.status !== 'active') {
    recordAuthorizationDenial(req, user, 'administrative_access');
    return res.status(403).json({ error: 'User account is disabled.' });
  }
  if (user.role !== 'administrator') {
    recordAuthorizationDenial(req, user, 'administrative_access');
    return res.status(403).json({ error: 'Administrative access required.' });
  }
  req.user = user;
  next();
}

function canManageDocumentPermissions(user, document) {
  return Boolean(user && document && (
    user.role === 'administrator'
    || (user.role === 'document_owner' && document.owner_id === user.id)
  ));
}

function requireDocumentUploader(req, res, next) {
  if (req.user.role !== 'document_owner' && req.user.role !== 'administrator') {
    recordAuthorizationDenial(req, req.user, 'document_upload');
    return res.status(403).json({ error: 'Only document owners can upload files.' });
  }
  return next();
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
  if (requiredLevel === 'edit' && user.role === 'viewer') return false;
  if (document.owner_id === user.id) return true;

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

function getStoredDocumentPath(document) {
  const root = path.resolve(privateUploadDir);
  if (typeof document.storage_key !== 'string' || path.basename(document.storage_key) !== document.storage_key) {
    return null;
  }
  const extension = path.extname(document.original_name || '').toLowerCase();
  const filePath = path.resolve(root, `${document.storage_key}${extension}`);
  return filePath.startsWith(`${root}${path.sep}`) ? filePath : null;
}

function buildDocumentSummary(document, user) {
  const owner = user && user.id === document.owner_id ? user : getUserById(document.owner_id);
  return {
    id: document.id,
    owner_id: document.owner_id,
    name: document.name,
    category: document.category,
    description: document.description,
    mime_type: document.mime_type,
    size_bytes: document.size_bytes,
    scan_status: document.scan_status,
    created_at: document.created_at,
    updated_at: document.updated_at,
    ownerName: owner ? owner.name : 'Unknown',
    accessLevel: getEffectiveDocumentPermission(user, document)
  };
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

function zipContainsEntries(buffer, requiredEntries) {
  const directoryEndMin = Math.max(0, buffer.length - 22 - 0xffff);
  let endOffset = -1;

  for (let offset = buffer.length - 22; offset >= directoryEndMin; offset -= 1) {
    if (buffer.readUInt32LE(offset) === 0x06054b50) {
      endOffset = offset;
      break;
    }
  }
  if (endOffset < 0) return false;

  const entryCount = buffer.readUInt16LE(endOffset + 10);
  const directoryOffset = buffer.readUInt32LE(endOffset + 16);
  if (entryCount === 0xffff || directoryOffset === 0xffffffff) return false;

  const names = new Set();
  let offset = directoryOffset;
  for (let index = 0; index < entryCount; index += 1) {
    if (offset + 46 > buffer.length || buffer.readUInt32LE(offset) !== 0x02014b50) return false;
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const entryEnd = offset + 46 + nameLength + extraLength + commentLength;
    if (entryEnd > buffer.length) return false;

    names.add(buffer.toString('utf8', offset + 46, offset + 46 + nameLength));
    offset = entryEnd;
  }

  return requiredEntries.every((name) => names.has(name));
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, name: 'TrustVault' });
});

app.post('/api/auth/register', loginLimiter, (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (typeof name !== 'string' || typeof email !== 'string' || typeof password !== 'string'
      || !name.trim() || !email.trim() || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required.' });
    }
    if (String(name).trim().length < 2) {
      return res.status(400).json({ error: 'Name must be at least 2 characters.' });
    }
    const normalizedEmail = email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      return res.status(400).json({ error: 'Provide a valid email address.' });
    }
    if (String(password).length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    if (Buffer.byteLength(password, 'utf8') > 72) {
      return res.status(400).json({ error: 'Password must not exceed 72 UTF-8 bytes.' });
    }

    const existingUser = getUserByEmail(normalizedEmail);
    if (existingUser) {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }

    const id = uuidv4();
    const passwordHash = bcrypt.hashSync(String(password), 12);
    const created = createRegisteredUser({
      id,
      name: String(name).trim(),
      email: normalizedEmail,
      passwordHash
    });

    startUserSession(req, created.id, (sessionError) => {
      if (sessionError) {
        console.error('Unable to establish registration session:', sessionError);
        return res.status(500).json({ error: 'Unable to establish a session.' });
      }

      try {
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
        console.error('Unable to register user:', error);
        return res.status(500).json({ error: 'Unable to register user.' });
      }
    });
  } catch (error) {
    if (error && error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }
    console.error('Unable to register user:', error);
    return res.status(500).json({ error: 'Unable to register user.' });
  }
});

app.post('/api/auth/login', loginLimiter, (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string' || !email.trim() || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }
    if (Buffer.byteLength(password, 'utf8') > 72) {
      return res.status(401).json({ error: 'Invalid email or password.' });
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

    startUserSession(req, user.id, (sessionError) => {
      if (sessionError) {
        console.error('Unable to establish login session:', sessionError);
        return res.status(500).json({ error: 'Unable to establish a session.' });
      }

      try {
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
        console.error('Unable to log in:', error);
        return res.status(500).json({ error: 'Unable to log in.' });
      }
    });
  } catch (error) {
    return res.status(500).json({ error: 'Unable to log in.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  const user = getSessionUser(req);
  req.session.destroy((error) => {
    if (error) {
      console.error('Unable to destroy login session:', error);
      return res.status(500).json({ error: 'Unable to log out.' });
    }

    if (user) {
      try {
        recordAuditEvent({
          actorId: user.id,
          actorName: user.name,
          action: 'user_logout',
          resourceType: 'user',
          resourceId: user.id,
          details: { email: user.email },
          ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
        });
      } catch (auditError) {
        console.error('Unable to record logout audit event:', auditError);
        return res.status(500).json({ error: 'You have been logged out, but the logout could not be audited.' });
      }
    }

    return res.json({ ok: true });
  });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: serializeUser(req.user) });
});

app.put('/api/profile', requireAuth, (req, res) => {
  const body = req.body || {};
  const { name, password } = body;
  const user = req.user;
  const hasName = Object.hasOwn(body, 'name');
  const hasPassword = Object.hasOwn(body, 'password');

  if (hasName && typeof name !== 'string') {
    return res.status(400).json({ error: 'Name must be a string.' });
  }
  if (hasPassword && password !== '' && typeof password !== 'string') {
    return res.status(400).json({ error: 'Password must be a string.' });
  }

  const nextName = hasName ? name.trim() : user.name;

  if (nextName.length < 2) {
    return res.status(400).json({ error: 'Name must be at least 2 characters.' });
  }

  let nextPasswordHash = user.password_hash;
  if (hasPassword && password !== '') {
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    if (Buffer.byteLength(password, 'utf8') > 72) {
      return res.status(400).json({ error: 'Password must not exceed 72 UTF-8 bytes.' });
    }
    nextPasswordHash = bcrypt.hashSync(password, 12);
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
    details: { changedPassword: hasPassword && password !== '' },
    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
  });

  res.json({ user: serializeUser(updated) });
});

app.get('/api/users', requireAuth, (req, res) => {
  if (!['administrator', 'document_owner'].includes(req.user.role)) {
    return res.status(403).json({ error: 'Only owners can access the user directory.' });
  }
  const all = getAllUsers()
    .filter((user) => user.status === 'active' && user.id !== req.user.id)
    .map((user) => serializeUser(user));
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
    recordAuthorizationDenial(req, req.user, 'document_read', document.id);
    return res.status(403).json({ error: 'Document access denied.' });
  }

  const userAccess = getUserDocumentAccessLevel(req.user, document);
  const permissions = canManageDocumentPermissions(req.user, document)
    ? getDocumentPermissions(document.id)
    : [];
  const summary = buildDocumentSummary(document, req.user);
  res.json({
    document: {
      ...summary,
      permissions,
      accessLevel: userAccess || 'owner'
    }
  });
});

app.get('/api/documents/:id/activity', requireAuth, (req, res) => {
  const document = getDocumentById(req.params.id);
  if (!document) return res.status(404).json({ error: 'Document not found.' });
  if (!canAccessDocument(req.user, document, 'read')) {
    recordAuthorizationDenial(req, req.user, 'document_activity', document.id);
    return res.status(403).json({ error: 'Document access denied.' });
  }

  const limit = Math.min(Math.max(Number(req.query.limit || 50), 1), 200);
  const activity = getDocumentAuditEvents(document.id, limit).map((entry) => ({
    action: entry.action,
    actor_name: entry.actor_name,
    created_at: entry.created_at,
    details: entry.details
  }));
  res.json({ activity });
});

app.get('/api/documents/:id/download', requireAuth, (req, res) => {
  const document = getDocumentById(req.params.id);
  if (!document) {
    return res.status(404).json({ error: 'Document not found.' });
  }

  if (!canAccessDocument(req.user, document, 'read')) {
    recordAuthorizationDenial(req, req.user, 'document_download', document.id);
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

  const filePath = getStoredDocumentPath(document);
  if (!filePath || !fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Document file is not available.' });
  }

  res.download(filePath, sanitizeFilename(document.name) || 'document', (error) => {
    if (error) {
      recordAuditEvent({
        actorId: req.user.id,
        actorName: req.user.name,
        action: 'document_download_failed',
        resourceType: 'document',
        resourceId: document.id,
        details: { error: error.code || 'transfer_failed' },
        ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
      });
      if (!res.headersSent) {
        res.status(500).json({ error: 'Unable to download the document.' });
      }
      return;
    }

    recordAuditEvent({
      actorId: req.user.id,
      actorName: req.user.name,
      action: 'document_downloaded',
      resourceType: 'document',
      resourceId: document.id,
      details: { documentName: document.name },
      ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
    });
  });
});

app.post('/api/documents', requireAuth, requireDocumentUploader, upload.single('file'), async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Authentication required.' });

  if (!req.file) {
    return res.status(400).json({ error: 'A file is required for upload.' });
  }

  let fileBuffer;
  let fileType;
  const extension = path.extname(req.file.originalname || '').toLowerCase();
  try {
    fileBuffer = fs.readFileSync(req.file.path);
    const { fileTypeFromBuffer } = await import('file-type');
    fileType = await fileTypeFromBuffer(fileBuffer);
  } catch (error) {
    if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    throw error;
  }

  if (fileBuffer.length === 0) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'The uploaded file is empty.' });
  }

  if (extension === '.txt') {
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(fileBuffer);
    } catch (_error) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'Text files must be valid UTF-8 content.' });
    }
    if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(text)) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'Text files cannot contain binary control characters.' });
    }
  }

  const docxMime = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
  let detectedMime = fileType ? fileType.mime : null;

  if (extension === '.txt') {
    detectedMime = 'text/plain';
  } else if (extension === '.docx' && detectedMime === 'application/zip'
    && zipContainsEntries(fileBuffer, ['[Content_Types].xml', 'word/document.xml'])) {
    detectedMime = docxMime;
  }

  const expectedMimeByExtension = {
    '.pdf': 'application/pdf',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.txt': 'text/plain',
    '.docx': docxMime
  };
  if (!ALLOWED_MIME_TYPES.has(detectedMime) || expectedMimeByExtension[extension] !== detectedMime) {
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

  return res.status(201).json({ document: buildDocumentSummary(getDocumentById(doc.id), req.user) });
});

app.put('/api/documents/:id', requireAuth, (req, res) => {
  const document = getDocumentById(req.params.id);
  if (!document) return res.status(404).json({ error: 'Document not found.' });

  if (!canAccessDocument(req.user, document, 'edit')) {
    recordAuthorizationDenial(req, req.user, 'document_edit', document.id);
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

  return res.json({ document: buildDocumentSummary(updated, req.user) });
});

app.delete('/api/documents/:id', requireAuth, (req, res) => {
  const document = getDocumentById(req.params.id);
  if (!document) return res.status(404).json({ error: 'Document not found.' });
  if (document.owner_id !== req.user.id || req.user.role === 'viewer') {
    recordAuthorizationDenial(req, req.user, 'document_delete', document.id);
    return res.status(403).json({ error: 'Only the document owner can delete it.' });
  }

  const diskPath = getStoredDocumentPath(document);
  if (!diskPath) {
    return res.status(404).json({ error: 'Document file is not available.' });
  }
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
  if (!canManageDocumentPermissions(req.user, document)) {
    recordAuthorizationDenial(req, req.user, 'document_share', document.id);
    return res.status(403).json({ error: 'Only the document owner or an administrator can change permissions.' });
  }

  const email = String(req.body.email || '').trim().toLowerCase();
  const requestedPermission = String(req.body.permission || 'read').toLowerCase();
  if (!['read', 'edit'].includes(requestedPermission)) {
    return res.status(400).json({ error: 'Permission must be read or edit.' });
  }
  const permission = normalizePermission(requestedPermission);
  const target = getUserByEmail(email);

  if (!target || target.status !== 'active') {
    return res.status(400).json({ error: 'The target user must already exist and be active.' });
  }

  if (target.id === req.user.id) {
    return res.status(400).json({ error: 'The document owner is already authorized.' });
  }
  if (permission === 'edit' && target.role === 'viewer') {
    return res.status(400).json({ error: 'Viewers have read-only access. Assign the document owner role to grant edit access.' });
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

app.get('/api/documents/:id/shares', requireAuth, (req, res) => {
  const document = getDocumentById(req.params.id);
  if (!document) return res.status(404).json({ error: 'Document not found.' });
  if (!canManageDocumentPermissions(req.user, document)) {
    recordAuthorizationDenial(req, req.user, 'document_share_list', document.id);
    return res.status(403).json({ error: 'Only the document owner or an administrator can view sharing permissions.' });
  }

  const shares = getDocumentPermissions(document.id).map((permission) => ({
    id: permission.id,
    user_id: permission.user_id,
    user_name: permission.user_name,
    user_email: permission.user_email,
    permission: permission.permission,
    expires_at: permission.expires_at
  }));
  res.json({ shares });
});

app.delete('/api/documents/:id/share/:userId', requireAuth, (req, res) => {
  const document = getDocumentById(req.params.id);
  if (!document) return res.status(404).json({ error: 'Document not found.' });
  if (!canManageDocumentPermissions(req.user, document)) {
    recordAuthorizationDenial(req, req.user, 'document_permission_revoke', document.id);
    return res.status(403).json({ error: 'Only the document owner or an administrator can revoke permissions.' });
  }

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

app.get('/api/admin/dashboard', requireAdministrator, (_req, res) => {
  const users = getAllUsers();
  const docs = listAllDocuments();
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

app.get('/api/admin/documents', requireAdministrator, (_req, res) => {
  const documents = listAllDocuments().map((document) => ({
    id: document.id,
    name: document.name,
    category: document.category,
    ownerName: getUserById(document.owner_id)?.name || 'Unknown',
    created_at: document.created_at
  }));
  res.json({ documents });
});

app.put('/api/admin/users/:id/role', requireAdministrator, (req, res) => {
  const target = getUserById(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found.' });

  const nextRole = String(req.body.role || '').toLowerCase();
  if (!isAllowedRole(nextRole)) return res.status(400).json({ error: 'Unsupported role assignment.' });

  if (target.id === req.user.id && nextRole !== 'administrator') {
    return res.status(400).json({ error: 'Administrators cannot demote themselves.' });
  }
  if (target.status === 'active' && target.role === 'administrator' && nextRole !== 'administrator') {
    const activeAdministrators = getAllUsers().filter(
      (user) => user.status === 'active' && user.role === 'administrator'
    ).length;
    if (activeAdministrators <= 1) {
      return res.status(409).json({ error: 'The last active administrator cannot be demoted.' });
    }
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
  if (nextStatus === 'disabled' && target.status === 'active' && target.role === 'administrator') {
    const activeAdministrators = getAllUsers().filter(
      (user) => user.status === 'active' && user.role === 'administrator'
    ).length;
    if (activeAdministrators <= 1) {
      return res.status(409).json({ error: 'The last active administrator cannot be disabled.' });
    }
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
