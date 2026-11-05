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

const sessionSecret = process.env.TRUSTVAULT_SESSION_SECRET;
const auditSecret = process.env.TRUSTVAULT_AUDIT_SECRET;
if (process.env.NODE_ENV === 'production' && (!sessionSecret || sessionSecret.length < 32)) {
  throw new Error('TRUSTVAULT_SESSION_SECRET must be set to at least 32 characters in production.');
}
if (process.env.NODE_ENV === 'production' && (!auditSecret || auditSecret.length < 32)) {
  throw new Error('TRUSTVAULT_AUDIT_SECRET must be set to at least 32 characters in production.');
}

const {
  db,
  initializeDatabase,
  getUserByEmail,
  getUserById,
  getAllUsers,
  listAllDocuments,
  getCategoriesForUser,
  createCategory,
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
  MIME_TYPES_BY_EXTENSION,
  sanitizeFilename,
  normalizePermission,
  isAllowedRole,
  isStrongPassword,
  computeSha256
} = require('./policy');

const app = express();
const port = Number(process.env.PORT || 3000);
const privateUploadDir = process.env.TRUSTVAULT_UPLOAD_DIR || path.join(__dirname, 'private_uploads');
fs.mkdirSync(privateUploadDir, { recursive: true });
const staticDir = __dirname;

initializeDatabase();

app.set('trust proxy', 1);
app.disable('x-powered-by');
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

function recordRequestAuditEvent(req, event) {
  return recordAuditEvent({
    ...event,
    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown',
    userAgent: req.get('user-agent') || null,
    eventResult: event.eventResult || 'success'
  });
}

function asyncHandler(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

app.use((req, res, next) => {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();

  const source = req.get('origin') || req.get('referer');
  if (!source) return next();

  try {
    const sourceUrl = new URL(source);
    const requestOrigin = `${req.protocol}://${req.get('host')}`;
    if (sourceUrl.origin === requestOrigin) return next();
  } catch (_error) {
    // Invalid Origin and Referer values are treated as cross-origin requests.
  }

  recordRequestAuditEvent(req, {
    actorId: getSessionUser(req)?.id || null,
    actorName: getSessionUser(req)?.name || null,
    action: 'csrf_request_blocked',
    resourceType: 'route',
    resourceId: req.path,
    details: { method: req.method },
    eventResult: 'denied'
  });
  return res.status(403).json({ error: 'Cross-origin state-changing requests are not allowed.' });
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    recordRequestAuditEvent(req, {
      actorId: null,
      actorName: null,
      action: 'login_rate_limited',
      resourceType: 'route',
      resourceId: req.path,
      details: null,
      eventResult: 'denied'
    });
    res.status(429).json({ error: 'Too many login attempts. Please wait and try again.' });
  }
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
  recordRequestAuditEvent(req, {
    actorId: user ? user.id : null,
    actorName: user ? user.name : null,
    action: 'authorization_denied',
    resourceType: resourceId ? 'document' : 'route',
    resourceId,
    details: { attemptedAction: action },
    eventResult: 'denied'
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
    recordAuthorizationDenial(req, null, 'unauthenticated_access');
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
  if (!user) {
    recordAuthorizationDenial(req, null, 'unauthenticated_administrative_access');
    return res.status(401).json({ error: 'Authentication required.' });
  }
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
  return recordRequestAuditEvent(req, {
    actorId: user ? user.id : null,
    actorName: user ? user.name : null,
    action,
    resourceType,
    resourceId,
    details
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
      const error = new Error(`Unsupported file extension. Allowed: ${[...ALLOWED_EXTENSIONS].join(', ')}`);
      error.status = 400;
      return cb(error);
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

function rejectDocumentUpload(req, res, uploadedFile, message, result = 'failure') {
  try {
    if (uploadedFile && fs.existsSync(uploadedFile.path)) fs.unlinkSync(uploadedFile.path);
  } catch (error) {
    console.error('Unable to remove rejected upload from private storage:', error);
    return res.status(500).json({ error: 'The rejected upload could not be removed from private storage.' });
  }

  try {
    const user = getSessionUser(req);
    recordRequestAuditEvent(req, {
      actorId: user ? user.id : null,
      actorName: user ? user.name : null,
      action: 'document_upload_rejected',
      resourceType: 'route',
      resourceId: req.path,
      details: { reason: message },
      eventResult: result
    });
  } catch (error) {
    console.error('Unable to audit rejected document upload:', error);
    return res.status(500).json({ error: 'The upload was rejected but the security event could not be recorded.' });
  }

  return res.status(400).json({ error: message });
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, name: 'TrustVault' });
});

function recordFailedLogin(req, user, email, reason) {
  recordRequestAuditEvent(req, {
    actorId: user ? user.id : null,
    actorName: user ? user.name : null,
    action: 'user_login_failed',
    resourceType: 'user',
    resourceId: user ? user.id : null,
    details: { email, reason },
    eventResult: 'failure'
  });
}

app.post('/api/auth/register', loginLimiter, (req, res) => {
  try {
    const { name, email, password, confirmPassword } = req.body || {};
    if (typeof name !== 'string' || typeof email !== 'string' || typeof password !== 'string'
      || typeof confirmPassword !== 'string' || !name.trim() || !email.trim() || !password) {
      return res.status(400).json({ error: 'Name, email, password, and password confirmation are required.' });
    }
    if (String(name).trim().length < 2) {
      return res.status(400).json({ error: 'Name must be at least 2 characters.' });
    }
    const normalizedEmail = email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      return res.status(400).json({ error: 'Provide a valid email address.' });
    }
    if (!isStrongPassword(password)) {
      return res.status(400).json({
        error: 'Password must be at least 8 characters and include uppercase, lowercase, a number, and a symbol.'
      });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Password confirmation does not match.' });
    }

    const existingUser = getUserByEmail(normalizedEmail);
    if (existingUser) {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }

    const created = db.transaction(() => {
      const user = createRegisteredUser({
        id: uuidv4(),
        name: name.trim(),
        email: normalizedEmail,
        passwordHash: bcrypt.hashSync(password, 12)
      });
      recordRequestAuditEvent(req, {
        actorId: user.id,
        actorName: user.name,
        action: 'user_registered',
        resourceType: 'user',
        resourceId: user.id,
        details: { email: user.email, role: user.role }
      });
      return user;
    }).immediate();

    startUserSession(req, created.id, (sessionError) => {
      if (sessionError) {
        console.error('Unable to establish registration session:', sessionError);
        return res.status(500).json({ error: 'Unable to establish a session.' });
      }

      return res.status(201).json({ user: serializeUser(created) });
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
      recordFailedLogin(req, null, email.trim().toLowerCase(), 'invalid_credentials');
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const user = getUserByEmail(String(email).trim().toLowerCase());
    if (!user) {
      recordFailedLogin(req, null, email.trim().toLowerCase(), 'invalid_credentials');
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    if (user.status !== 'active') {
      recordFailedLogin(req, user, user.email, 'disabled_account');
      return res.status(403).json({ error: 'This account is disabled.' });
    }

    const passwordMatches = bcrypt.compareSync(String(password), user.password_hash);
    if (!passwordMatches) {
      recordFailedLogin(req, user, user.email, 'invalid_credentials');
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    startUserSession(req, user.id, (sessionError) => {
      if (sessionError) {
        console.error('Unable to establish login session:', sessionError);
        return res.status(500).json({ error: 'Unable to establish a session.' });
      }

      try {
        recordRequestAuditEvent(req, {
          actorId: user.id,
          actorName: user.name,
          action: 'user_login',
          resourceType: 'user',
          resourceId: user.id,
          details: { email: user.email }
        });

        return res.json({ user: serializeUser(user) });
      } catch (error) {
        console.error('Unable to log in:', error);
        req.session.destroy((destroyError) => {
          if (destroyError) console.error('Unable to invalidate unaudited login session:', destroyError);
          return res.status(500).json({ error: 'Unable to log in.' });
        });
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
        recordRequestAuditEvent(req, {
          actorId: user.id,
          actorName: user.name,
          action: 'user_logout',
          resourceType: 'user',
          resourceId: user.id,
          details: { email: user.email }
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
    if (!isStrongPassword(password)) {
      return res.status(400).json({
        error: 'Password must be at least 8 characters and include uppercase, lowercase, a number, and a symbol.'
      });
    }
    nextPasswordHash = bcrypt.hashSync(password, 12);
  }

  const updated = db.transaction(() => {
    const changed = updateUser(user.id, {
      name: nextName,
      password_hash: nextPasswordHash
    });
    recordRequestAuditEvent(req, {
      actorId: changed.id,
      actorName: changed.name,
      action: 'profile_updated',
      resourceType: 'user',
      resourceId: changed.id,
      details: { changedPassword: hasPassword && password !== '' }
    });
    return changed;
  })();

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

app.get('/api/categories', requireAuth, (req, res) => {
  res.json({ categories: getCategoriesForUser(req.user) });
});

app.post('/api/categories', requireAuth, (req, res) => {
  if (!['administrator', 'document_owner'].includes(req.user.role)) {
    recordAuthorizationDenial(req, req.user, 'category_create');
    return res.status(403).json({ error: 'Only document owners can create categories.' });
  }

  const name = req.body && req.body.name;
  if (typeof name !== 'string' || name.trim().length < 1 || name.trim().length > 64) {
    return res.status(400).json({ error: 'Category name must be between 1 and 64 characters.' });
  }

  try {
    const category = db.transaction(() => {
      const created = createCategory({ id: uuidv4(), ownerId: req.user.id, name: name.trim() });
      recordRequestAuditEvent(req, {
        actorId: req.user.id,
        actorName: req.user.name,
        action: 'category_created',
        resourceType: 'category',
        resourceId: created.id,
        details: { name: created.name }
      });
      return created;
    })();
    return res.status(201).json({ category });
  } catch (error) {
    if (error && error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'You already have a category with that name.' });
    }
    throw error;
  }
});

app.get('/api/documents', requireAuth, (req, res) => {
  const docs = listDocumentsForUser(req.user).map((doc) => buildDocumentSummary(doc, req.user));
  let filtered = docs;
  const search = String(req.query.search || '').trim().toLowerCase();
  if (search) {
    filtered = filtered.filter((doc) => {
      const hay = `${doc.name} ${doc.ownerName} ${doc.category} ${doc.created_at} ${doc.mime_type}`.toLowerCase();
      return hay.includes(search);
    });
  }

  const fileType = String(req.query.fileType || '').trim().toLowerCase();
  if (fileType) {
    filtered = filtered.filter((doc) => doc.mime_type.toLowerCase() === fileType);
  }

  const ownerId = String(req.query.ownerId || '').trim();
  if (ownerId) {
    filtered = filtered.filter((doc) => doc.owner_id === ownerId);
  }

  const dateFrom = req.query.dateFrom ? new Date(String(req.query.dateFrom)) : null;
  const dateTo = req.query.dateTo ? new Date(String(req.query.dateTo)) : null;
  if (dateTo && /^\d{4}-\d{2}-\d{2}$/.test(String(req.query.dateTo))) {
    dateTo.setHours(23, 59, 59, 999);
  }
  if ((dateFrom && Number.isNaN(dateFrom.getTime())) || (dateTo && Number.isNaN(dateTo.getTime()))) {
    return res.status(400).json({ error: 'Date filters must contain valid dates.' });
  }
  if (dateFrom) filtered = filtered.filter((doc) => new Date(doc.created_at) >= dateFrom);
  if (dateTo) filtered = filtered.filter((doc) => new Date(doc.created_at) <= dateTo);

  const category = String(req.query.category || '').trim();
  if (category) {
    filtered = filtered.filter((doc) => doc.category.toLowerCase() === category.toLowerCase());
  }

  const allowedSortKeys = new Set(['name', 'ownerName', 'category', 'mime_type', 'size_bytes', 'created_at']);
  const requestedSortKey = String(req.query.sort || 'created_at');
  const sortKey = allowedSortKeys.has(requestedSortKey) ? requestedSortKey : 'created_at';
  const dir = String(req.query.dir || 'desc').toLowerCase() === 'asc' ? 1 : -1;

  filtered.sort((a, b) => {
    const left = a[sortKey] ?? '';
    const right = b[sortKey] ?? '';
    if (typeof left === 'number' && typeof right === 'number') return (left - right) * dir;
    return String(left).localeCompare(String(right)) * dir;
  });

  const requestedPage = Number(req.query.page || 1);
  const requestedLimit = Number(req.query.limit || 10);
  if (!Number.isInteger(requestedPage) || !Number.isInteger(requestedLimit)) {
    return res.status(400).json({ error: 'Page and limit must be whole numbers.' });
  }
  const page = Math.max(1, requestedPage);
  const limit = Math.min(Math.max(1, requestedLimit), 50);
  const total = filtered.length;
  const paged = filtered.slice((page - 1) * limit, page * limit);
  const owners = [...new Map(docs.map((document) => [
    document.owner_id,
    { id: document.owner_id, name: document.ownerName }
  ])).values()];

  res.json({
    documents: paged,
    owners,
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

  recordRequestAuditEvent(req, {
    actorId: req.user.id,
    actorName: req.user.name,
    action: 'document_viewed',
    resourceType: 'document',
    resourceId: document.id,
    details: { documentName: document.name }
  });

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

  recordRequestAuditEvent(req, {
    actorId: req.user.id,
    actorName: req.user.name,
    action: 'document_activity_viewed',
    resourceType: 'document',
    resourceId: document.id,
    details: null
  });

  const limit = Math.min(Math.max(Number(req.query.limit || 50), 1), 200);
  const events = getDocumentAuditEvents(document.id, limit)
    .filter((entry) => document.owner_id === req.user.id || entry.actor_id === req.user.id);
  const activity = events.map((entry) => ({
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
    recordRequestAuditEvent(req, {
      actorId: req.user.id,
      actorName: req.user.name,
      action: 'document_download_blocked',
      resourceType: 'document',
      resourceId: document.id,
      details: { reason: 'Security scan pending or failed.', scanStatus: document.scan_status },
      eventResult: 'denied'
    });
    return res.status(403).json({ error: 'This document is awaiting security review.' });
  }

  const filePath = getStoredDocumentPath(document);
  if (!filePath || !fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Document file is not available.' });
  }

  res.download(filePath, sanitizeFilename(document.name) || 'document', (error) => {
    if (error) {
      recordRequestAuditEvent(req, {
        actorId: req.user.id,
        actorName: req.user.name,
        action: 'document_download_failed',
        resourceType: 'document',
        resourceId: document.id,
        details: { error: error.code || 'transfer_failed' },
        eventResult: 'failure'
      });
      if (!res.headersSent) {
        res.status(500).json({ error: 'Unable to download the document.' });
      }
      return;
    }

    recordRequestAuditEvent(req, {
      actorId: req.user.id,
      actorName: req.user.name,
      action: 'document_downloaded',
      resourceType: 'document',
      resourceId: document.id,
      details: { documentName: document.name }
    });
  });
});

app.post('/api/documents', requireAuth, requireDocumentUploader, upload.single('file'), asyncHandler(async (req, res) => {
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
    const response = rejectDocumentUpload(req, res, req.file, 'The uploaded file could not be inspected.');
    console.error('Unable to inspect uploaded file:', error);
    return response;
  }

  if (fileBuffer.length === 0) {
    return rejectDocumentUpload(req, res, req.file, 'The uploaded file is empty.');
  }

  if (extension === '.txt') {
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(fileBuffer);
    } catch (_error) {
      return rejectDocumentUpload(req, res, req.file, 'Text files must be valid UTF-8 content.');
    }
    if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(text)) {
      return rejectDocumentUpload(req, res, req.file, 'Text files cannot contain binary control characters.');
    }
  }

  const docxMime = MIME_TYPES_BY_EXTENSION['.docx'];
  const xlsxMime = MIME_TYPES_BY_EXTENSION['.xlsx'];
  let detectedMime = fileType ? fileType.mime : null;

  if (extension === '.txt') {
    detectedMime = 'text/plain';
  } else if (detectedMime === 'application/zip') {
    if (extension === '.docx' && zipContainsEntries(fileBuffer, ['[Content_Types].xml', 'word/document.xml'])) {
      detectedMime = docxMime;
    } else if (extension === '.xlsx' && zipContainsEntries(fileBuffer, ['[Content_Types].xml', 'xl/workbook.xml'])) {
      detectedMime = xlsxMime;
    }
  }

  if (!ALLOWED_MIME_TYPES.has(detectedMime) || MIME_TYPES_BY_EXTENSION[extension] !== detectedMime) {
    return rejectDocumentUpload(req, res, req.file, 'The file content type is not allowed.');
  }

  const category = req.body.category === undefined ? 'general' : req.body.category;
  const description = req.body.description === undefined ? '' : req.body.description;
  if (typeof category !== 'string' || category.trim().length > 64
    || typeof description !== 'string' || description.trim().length > 2000) {
    return rejectDocumentUpload(req, res, req.file, 'Category or description is invalid.');
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
    category: category.trim() || 'general',
    description: description.trim(),
    storageKey,
    originalName: finalName,
    mimeType: detectedMime || 'application/octet-stream',
    sizeBytes: fileBuffer.length,
    sha256: computeSha256(fileBuffer),
    scanStatus: 'pending',
    createdAt: new Date().toISOString()
  };

  try {
    db.transaction(() => {
      insertDocument(doc);
      recordRequestAuditEvent(req, {
        actorId: req.user.id,
        actorName: req.user.name,
        action: 'document_uploaded',
        resourceType: 'document',
        resourceId: doc.id,
        details: { documentName: doc.name, category: doc.category, sizeBytes: doc.sizeBytes }
      });
    })();
  } catch (error) {
    if (fs.existsSync(destinationPath)) fs.unlinkSync(destinationPath);
    console.error('Unable to persist uploaded document:', error);
    return res.status(500).json({ error: 'Unable to save the uploaded document.' });
  }

  return res.status(201).json({ document: buildDocumentSummary(getDocumentById(doc.id), req.user) });
}));

app.put('/api/documents/:id', requireAuth, (req, res) => {
  const document = getDocumentById(req.params.id);
  if (!document) return res.status(404).json({ error: 'Document not found.' });

  if (!canAccessDocument(req.user, document, 'edit')) {
    recordAuthorizationDenial(req, req.user, 'document_edit', document.id);
    return res.status(403).json({ error: 'You are not allowed to edit this document.' });
  }

  const body = req.body || {};
  for (const field of ['name', 'category', 'description']) {
    if (Object.hasOwn(body, field) && typeof body[field] !== 'string') {
      return res.status(400).json({ error: `${field} must be a string.` });
    }
  }
  const nextName = sanitizeFilename(Object.hasOwn(body, 'name') ? body.name : document.name);
  const nextCategory = (Object.hasOwn(body, 'category') ? body.category : document.category).trim() || 'general';
  const description = (Object.hasOwn(body, 'description') ? body.description : document.description || '').trim();

  if (!nextName || nextName.length > 255 || nextCategory.length > 64 || description.length > 2000) {
    return res.status(400).json({ error: 'Document name, category, or description is invalid.' });
  }

  const updated = db.transaction(() => {
    const changed = updateDocument(document.id, {
      name: nextName,
      category: nextCategory,
      description
    });
    recordRequestAuditEvent(req, {
      actorId: req.user.id,
      actorName: req.user.name,
      action: 'document_updated',
      resourceType: 'document',
      resourceId: changed.id,
      details: { documentName: changed.name, category: changed.category }
    });
    return changed;
  })();

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
  db.transaction(() => {
    deleteDocument(document.id);
    recordRequestAuditEvent(req, {
      actorId: req.user.id,
      actorName: req.user.name,
      action: 'document_deleted',
      resourceType: 'document',
      resourceId: document.id,
      details: { documentName: document.name }
    });
  })();

  if (fs.existsSync(diskPath)) {
    try {
      fs.unlinkSync(diskPath);
    } catch (error) {
      console.error('Unable to remove deleted document from private storage:', error);
      return res.status(500).json({ error: 'Document access was revoked, but private-file cleanup failed.' });
    }
  }

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
    if (date.getTime() <= Date.now()) {
      return res.status(400).json({ error: 'Permission expiration must be in the future.' });
    }
    expiresAt = date.toISOString();
  }

  const granted = db.transaction(() => {
    const permissionRecord = upsertPermission({
      documentId: document.id,
      userId: target.id,
      permission,
      createdBy: req.user.id,
      expiresAt
    });
    recordRequestAuditEvent(req, {
      actorId: req.user.id,
      actorName: req.user.name,
      action: 'document_permission_granted',
      resourceType: 'document_permission',
      resourceId: permissionRecord.id,
      details: { documentId: document.id, targetEmail: email, permission, expiresAt }
    });
    return permissionRecord;
  })();

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

  const revoked = db.transaction(() => {
    const permissionRecord = revokePermission(document.id, req.params.userId);
    if (!permissionRecord) return null;
    recordRequestAuditEvent(req, {
      actorId: req.user.id,
      actorName: req.user.name,
      action: 'document_permission_revoked',
      resourceType: 'document_permission',
      resourceId: permissionRecord.id,
      details: { documentId: document.id, targetUserId: req.params.userId }
    });
    return permissionRecord;
  })();
  if (!revoked) {
    return res.status(404).json({ error: 'No active permission was found for that user.' });
  }

  res.json({ ok: true });
});

app.get('/api/admin/dashboard', requireAdministrator, (_req, res) => {
  const users = getAllUsers();
  const docs = listAllDocuments();
  const audit = getAuditEvents(10);
  const countEvents = (action) => db.prepare('SELECT COUNT(*) AS count FROM audit_events WHERE action = ?').get(action).count;
  const sharedDocuments = db.prepare(`
    SELECT COUNT(DISTINCT document_id) AS count FROM document_permissions
    WHERE active = 1 AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
  `).get().count;
  const recentUploads = db.prepare(`
    SELECT d.id, d.name, d.category, d.scan_status, d.created_at, u.name AS owner_name
    FROM documents d JOIN users u ON u.id = d.owner_id
    WHERE d.is_deleted = 0 ORDER BY d.created_at DESC LIMIT 5
  `).all();

  res.json({
    counts: {
      users: users.length,
      activeUsers: users.filter((user) => user.status === 'active').length,
      disabledUsers: users.filter((user) => user.status !== 'active').length,
      documents: docs.length,
      sharedDocuments,
      administrators: users.filter((user) => user.role === 'administrator').length,
      viewers: users.filter((user) => user.role === 'viewer').length,
      ownerUsers: users.filter((user) => user.role === 'document_owner').length,
      totalDownloads: countEvents('document_downloaded'),
      permissionChanges: countEvents('document_permission_granted') + countEvents('document_permission_revoked'),
      failedLogins: countEvents('user_login_failed'),
      deniedAccessAttempts: countEvents('authorization_denied') + countEvents('csrf_request_blocked')
    },
    recentUploads,
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

  db.transaction(() => {
    db.prepare('UPDATE documents SET scan_status = ?, updated_at = ? WHERE id = ?')
      .run(nextStatus, new Date().toISOString(), document.id);
    recordRequestAuditEvent(req, {
      actorId: req.user.id,
      actorName: req.user.name,
      action: 'document_scan_status_updated',
      resourceType: 'document',
      resourceId: document.id,
      details: { scanStatus: nextStatus }
    });
  })();

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

  const updated = db.transaction(() => {
    const changed = updateUser(target.id, { role: nextRole });
    recordRequestAuditEvent(req, {
      actorId: req.user.id,
      actorName: req.user.name,
      action: 'user_role_updated',
      resourceType: 'user',
      resourceId: changed.id,
      details: { targetUser: changed.email, previousRole: target.role, newRole: nextRole }
    });
    return changed;
  })();

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

  const updated = db.transaction(() => {
    const changed = updateUser(target.id, { status: nextStatus });
    recordRequestAuditEvent(req, {
      actorId: req.user.id,
      actorName: req.user.name,
      action: 'user_status_updated',
      resourceType: 'user',
      resourceId: changed.id,
      details: { targetUser: changed.email, previousStatus: target.status, newStatus: nextStatus }
    });
    return changed;
  })();

  res.json({ user: serializeUser(updated) });
});

app.get('/api/admin/audit', requireAdministrator, (req, res) => {
  const requestedLimit = Number(req.query.limit || 100);
  if (!Number.isInteger(requestedLimit)) {
    return res.status(400).json({ error: 'Audit limit must be a whole number.' });
  }
  const limit = Math.min(Math.max(requestedLimit, 1), 500);
  let audit = getAuditEvents(500);
  const action = String(req.query.action || '').trim().toLowerCase();
  const user = String(req.query.user || '').trim().toLowerCase();
  const document = String(req.query.document || '').trim().toLowerCase();
  const result = String(req.query.result || '').trim().toLowerCase();
  const dateFrom = req.query.dateFrom ? new Date(String(req.query.dateFrom)) : null;
  const dateTo = req.query.dateTo ? new Date(String(req.query.dateTo)) : null;
  if ((dateFrom && Number.isNaN(dateFrom.getTime())) || (dateTo && Number.isNaN(dateTo.getTime()))) {
    return res.status(400).json({ error: 'Date filters must contain valid dates.' });
  }
  if (dateTo && /^\d{4}-\d{2}-\d{2}$/.test(String(req.query.dateTo))) dateTo.setHours(23, 59, 59, 999);

  audit = audit.filter((entry) => {
    if (action && !entry.action.toLowerCase().includes(action)) return false;
    if (user && !`${entry.actor_id || ''} ${entry.actor_name || ''} ${entry.details || ''}`.toLowerCase().includes(user)) return false;
    if (document && !`${entry.resource_id || ''} ${entry.details || ''}`.toLowerCase().includes(document)) return false;
    if (result && String(entry.event_result || '').toLowerCase() !== result) return false;
    const createdAt = new Date(entry.created_at);
    if (dateFrom && createdAt < dateFrom) return false;
    if (dateTo && createdAt > dateTo) return false;
    return true;
  }).slice(0, limit);
  res.json({ audit, integrity: verifyAuditChain() });
});

app.get('/', (_req, res) => {
  res.sendFile(path.join(staticDir, 'index.html'));
});

app.get('/app.html', requireAuth, (_req, res) => {
  res.sendFile(path.join(staticDir, 'app.html'));
});

app.use((err, req, res, _next) => {
  if (req.method === 'POST' && req.path === '/api/documents') {
    try {
      const user = getSessionUser(req);
      recordRequestAuditEvent(req, {
        actorId: user ? user.id : null,
        actorName: user ? user.name : null,
        action: 'document_upload_failed',
        resourceType: 'route',
        resourceId: req.path,
        details: { reason: err.code || (err.status === 400 ? 'invalid_upload' : 'upload_error') },
        eventResult: 'failure'
      });
    } catch (auditError) {
      console.error('Unable to audit failed document upload:', auditError);
    }
  }

  if (err instanceof multer.MulterError) {
    const message = err.code === 'LIMIT_FILE_SIZE'
      ? 'The uploaded file exceeds the maximum allowed size.'
      : 'The uploaded file could not be accepted.';
    return res.status(400).json({ error: message });
  }

  if (err && err.status === 400) {
    return res.status(400).json({ error: err.message });
  }

  console.error('Unexpected request error:', err);
  return res.status(500).json({ error: 'An unexpected server error occurred.' });
});

app.listen(port, () => {
  console.log(`TrustVault listening on http://localhost:${port}`);
});
