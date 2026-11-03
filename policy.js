const crypto = require('crypto');

const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024;
const ALLOWED_EXTENSIONS = new Set(['.pdf', '.png', '.jpg', '.jpeg', '.txt', '.docx']);
const ALLOWED_MIME_TYPES = new Set(['application/pdf', 'image/png', 'image/jpeg', 'text/plain', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']);

function sanitizeFilename(name) {
  if (!name || typeof name !== 'string') {
    return 'document';
  }

  const trimmed = name.replace(/[\\/]+/g, '').trim();
  const cleaned = trimmed.replace(/[^a-zA-Z0-9._-]+/g, '_').replace(/_+/g, '_');
  return cleaned || 'document';
}

function normalizePermission(value) {
  const permission = String(value || '').toLowerCase();
  if (permission === 'edit') return 'edit';
  if (permission === 'read') return 'read';
  return 'read';
}

function isAllowedRole(value) {
  const role = String(value || '').toLowerCase();
  return ['administrator', 'document_owner', 'viewer'].includes(role);
}

function computeSha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function sha256OfText(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

module.exports = {
  ALLOWED_EXTENSIONS,
  ALLOWED_MIME_TYPES,
  MAX_FILE_SIZE_BYTES,
  sanitizeFilename,
  normalizePermission,
  isAllowedRole,
  computeSha256,
  sha256OfText
};
