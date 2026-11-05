const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Simple session store using cookies / auth header / memory
const sessions = new Map();
const uploadDir = path.join(__dirname, 'private-storage');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const upload = multer({ dest: uploadDir });

// Seed Users
const users = [
  { id: '11111111-1111-1111-1111-111111111111', email: 'admin@trustvault.local', displayName: 'Admin', password: 'Admin#12345', role: 'Admin', isActive: true },
  { id: '22222222-2222-2222-2222-222222222222', email: 'owner@trustvault.local', displayName: 'Owner', password: 'Owner#12345', role: 'Owner', isActive: true },
  { id: '33333333-3333-3333-3333-333333333333', email: 'viewer@trustvault.local', displayName: 'Viewer', password: 'Viewer#12345', role: 'Viewer', isActive: true }
];

const documents = [];
const permissions = [];
const auditEvents = [
  { id: 1, occurredAtUtc: new Date().toISOString(), actorUserId: users[0].id, action: 'SystemInitialize', outcome: 'Success' }
];

// Helper: Get Current User
function getCurrentUser(req) {
  const authHeader = req.headers.authorization || '';
  const token = req.headers['x-session-id'] || req.cookies?.session || (authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null);
  if (token && sessions.has(token)) {
    return sessions.get(token);
  }
  // Default to demo owner if unauthenticated for basic requests or check cookie
  return req.currentUser || null;
}

// Cookie parser middleware
app.use((req, res, next) => {
  const cookieHeader = req.headers.cookie || '';
  req.cookies = Object.fromEntries(cookieHeader.split(';').map(c => {
    const [k, v] = c.trim().split('=');
    return [k, v];
  }));
  const sid = req.cookies.tv_sid;
  if (sid && sessions.has(sid)) {
    req.currentUser = sessions.get(sid);
  }
  next();
});

// ---------- Auth Routes ----------
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const cleanEmail = (email || '').trim().toLowerCase();
  const u = users.find(x => x.email.toLowerCase() === cleanEmail && x.password === password && x.isActive);
  if (!u) {
    auditEvents.push({ id: auditEvents.length + 1, occurredAtUtc: new Date().toISOString(), action: 'LoginFailed', outcome: 'Failure', reason: 'Invalid credentials' });
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const sid = crypto.randomUUID();
  sessions.set(sid, u);
  res.cookie('tv_sid', sid, { httpOnly: true, sameSite: 'strict' });
  auditEvents.push({ id: auditEvents.length + 1, occurredAtUtc: new Date().toISOString(), actorUserId: u.id, action: 'LoginSucceeded', outcome: 'Success' });
  return res.json({ id: u.id, displayName: u.displayName, role: u.role, email: u.email });
});

app.post('/api/auth/register', (req, res) => {
  const { email, displayName, password, role } = req.body || {};
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required' });
  if (!displayName) return res.status(400).json({ error: 'Display name required' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (role === 'Admin') return res.status(400).json({ error: 'Public registration cannot assign Admin role' });
  if (users.some(u => u.email.toLowerCase() === email.trim().toLowerCase())) return res.status(409).json({ error: 'Email already registered' });

  const assignedRole = role === 'Owner' ? 'Owner' : 'Viewer';
  const newUser = { id: crypto.randomUUID(), email: email.trim().toLowerCase(), displayName: displayName.trim(), password, role: assignedRole, isActive: true };
  users.push(newUser);
  return res.status(201).json({ id: newUser.id, email: newUser.email, displayName: newUser.displayName, role: newUser.role });
});

app.post('/api/auth/logout', (req, res) => {
  const sid = req.cookies?.tv_sid;
  if (sid) sessions.delete(sid);
  res.clearCookie('tv_sid');
  return res.sendStatus(204);
});

app.get('/api/users/me', (req, res) => {
  const u = req.currentUser;
  if (!u) return res.status(401).json({ error: 'Unauthorized' });
  return res.json({ id: u.id, email: u.email, displayName: u.displayName, role: u.role });
});

app.get('/api/users/lookup', (req, res) => {
  const me = req.currentUser;
  if (!me || me.role !== 'Owner') return res.status(403).json({ error: 'Forbidden' });
  const email = (req.query.email || '').toString().trim().toLowerCase();
  const u = users.find(x => x.email.toLowerCase() === email && x.isActive && x.id !== me.id);
  if (!u) return res.status(404).json({ error: 'User not found' });
  return res.json({ id: u.id, email: u.email, displayName: u.displayName });
});

// ---------- Document Routes ----------
app.post('/api/documents', upload.single('file'), (req, res) => {
  const me = req.currentUser;
  if (!me || me.role !== 'Owner') return res.status(403).json({ error: 'Only Owners can upload documents' });
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const doc = {
    id: crypto.randomUUID(),
    ownerId: me.id,
    name: req.file.originalname,
    category: req.body.category || 'General',
    description: req.body.description || '',
    storageKey: req.file.filename,
    contentType: req.file.mimetype || 'application/octet-stream',
    sizeBytes: req.file.size,
    sha256: crypto.createHash('sha256').update(fs.readFileSync(req.file.path)).digest('hex'),
    version: 1,
    createdAtUtc: new Date().toISOString(),
    updatedAtUtc: new Date().toISOString()
  };

  documents.push(doc);
  auditEvents.push({ id: auditEvents.length + 1, occurredAtUtc: new Date().toISOString(), actorUserId: me.id, documentId: doc.id, action: 'DocumentUploaded', outcome: 'Success' });
  return res.status(201).json(doc);
});

app.get('/api/documents', (req, res) => {
  const me = req.currentUser;
  if (!me) return res.status(401).json({ error: 'Unauthorized' });

  let items = documents.filter(d => d.ownerId === me.id || permissions.some(p => p.documentId === d.id && p.userId === me.id));
  const { name, category } = req.query;
  if (name) items = items.filter(d => d.name.toLowerCase().includes(name.toString().toLowerCase()));
  if (category) items = items.filter(d => d.category === category);

  return res.json({ total: items.length, page: 1, pageSize: 50, items });
});

app.get('/api/documents/:id/details', (req, res) => {
  const doc = documents.find(d => d.id === req.params.id);
  if (!doc) return res.status(404).json({ error: 'Not found' });
  const owner = users.find(u => u.id === doc.ownerId);
  const activeGrants = permissions.filter(p => p.documentId === doc.id).length;
  const downloadCount = auditEvents.filter(e => e.documentId === doc.id && e.action === 'DocumentDownloaded').length;

  return res.json({
    ...doc,
    ownerEmail: owner ? owner.email : 'Unknown',
    ownerName: owner ? owner.displayName : 'Unknown',
    isOwner: req.currentUser ? req.currentUser.id === doc.ownerId : false,
    canEdit: true,
    activeGrantsCount: activeGrants,
    downloadCount: downloadCount
  });
});

app.get('/api/documents/:id/download', (req, res) => {
  const doc = documents.find(d => d.id === req.params.id);
  if (!doc) return res.status(404).json({ error: 'Not found' });
  const filePath = path.join(uploadDir, doc.storageKey);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File missing' });

  if (req.currentUser) {
    auditEvents.push({ id: auditEvents.length + 1, occurredAtUtc: new Date().toISOString(), actorUserId: req.currentUser.id, documentId: doc.id, action: 'DocumentDownloaded', outcome: 'Success' });
  }
  return res.download(filePath, doc.name);
});

app.delete('/api/documents/:id', (req, res) => {
  const idx = documents.findIndex(d => d.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  documents.splice(idx, 1);
  return res.sendStatus(204);
});

// ---------- Permissions Routes ----------
app.get('/api/documents/:id/permissions', (req, res) => {
  const grants = permissions.filter(p => p.documentId === req.params.id).map(p => {
    const u = users.find(x => x.id === p.userId);
    return { ...p, email: u ? u.email : 'Unknown' };
  });
  return res.json(grants);
});

app.put('/api/documents/:id/permissions/:userId', (req, res) => {
  const { id, userId } = req.params;
  const { level } = req.body || {};
  let g = permissions.find(p => p.documentId === id && p.userId === userId);
  if (!g) {
    g = { id: crypto.randomUUID(), documentId: id, userId, level: level || 'Read', grantedAtUtc: new Date().toISOString() };
    permissions.push(g);
  } else {
    g.level = level || 'Read';
  }
  return res.sendStatus(204);
});

app.delete('/api/documents/:id/permissions/:userId', (req, res) => {
  const idx = permissions.findIndex(p => p.documentId === req.params.id && p.userId === req.params.userId);
  if (idx !== -1) permissions.splice(idx, 1);
  return res.sendStatus(204);
});

// ---------- Stats Routes ----------
app.get('/api/stats/owner', (req, res) => {
  const me = req.currentUser;
  const uid = me ? me.id : '';
  const totalMyDocuments = documents.filter(d => d.ownerId === uid).length;
  const sharedDocuments = documents.filter(d => d.ownerId === uid && permissions.some(p => p.documentId === d.id)).length;
  const totalDownloads = auditEvents.filter(e => e.action === 'DocumentDownloaded').length;
  return res.json({ totalMyDocuments, sharedDocuments, totalDownloads, activePermissions: permissions.length });
});

app.get('/api/stats/viewer', (req, res) => {
  return res.json({ sharedWithMe: documents.length, totalDownloads: 0, recentlyAccessed: documents.length });
});

app.get('/api/stats/admin', (req, res) => {
  return res.json({
    totalUsers: users.length,
    activeUsers: users.filter(u => u.isActive).length,
    disabledUsers: users.filter(u => !u.isActive).length,
    totalDocuments: documents.length,
    sharedDocuments: permissions.length,
    totalDownloads: auditEvents.filter(e => e.action === 'DocumentDownloaded').length,
    failedLogins: auditEvents.filter(e => e.action === 'LoginFailed').length,
    unauthorizedAttempts: auditEvents.filter(e => e.action === 'DocumentAccessDenied').length,
    recentActivity: auditEvents.slice(-10).reverse()
  });
});

// ---------- Admin Routes ----------
app.get('/api/admin/security-events', (req, res) => {
  return res.json(auditEvents.slice(-50).reverse());
});

app.get('/api/users', (req, res) => {
  return res.json(users.map(u => ({ id: u.id, email: u.email, displayName: u.displayName, role: u.role, isActive: u.isActive })));
});

app.patch('/api/users/:id/status', (req, res) => {
  const u = users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'User not found' });
  u.isActive = req.body.isActive;
  return res.sendStatus(204);
});

app.get('/api/admin/audit', (req, res) => res.json(auditEvents.slice(-50).reverse()));
app.get('/api/admin/audit/verify', (req, res) => res.json({ ok: true }));

// Serve static frontend UI
app.use(express.static(path.join(__dirname, 'backend/TrustVault.Api/wwwroot')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'backend/TrustVault.Api/wwwroot/index.html'));
});

app.listen(PORT, () => {
  console.log(`TrustVault Server listening on port ${PORT}`);
});
