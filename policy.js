const crypto = require('crypto');

const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024;
const MIME_TYPES_BY_EXTENSION = {
  '.pdf': 'application/pdf',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.txt': 'text/plain',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
};
const defaultExtensions = Object.keys(MIME_TYPES_BY_EXTENSION);
const configuredExtensions = process.env.TRUSTVAULT_ALLOWED_EXTENSIONS
  ? process.env.TRUSTVAULT_ALLOWED_EXTENSIONS.split(',').map((extension) => extension.trim().toLowerCase())
  : defaultExtensions;
const ALLOWED_EXTENSIONS = new Set(configuredExtensions.filter((extension) => Object.hasOwn(MIME_TYPES_BY_EXTENSION, extension)));
if (!ALLOWED_EXTENSIONS.size || ALLOWED_EXTENSIONS.size !== new Set(configuredExtensions).size) {
  throw new Error('TRUSTVAULT_ALLOWED_EXTENSIONS contains no supported file types or an unsupported extension.');
}
const ALLOWED_MIME_TYPES = new Set([...ALLOWED_EXTENSIONS].map((extension) => MIME_TYPES_BY_EXTENSION[extension]));

function sanitizeFilename(name) {
  if (!name || typeof name !== 'string') {
    return 'document';
  }

  const trimmed = name
    .split(/[\\/]+/)
    .filter((segment) => segment && segment !== '.' && segment !== '..')
    .join('_')
    .trim();
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

function isStrongPassword(value) {
  return typeof value === 'string'
    && value.length >= 8
    && Buffer.byteLength(value, 'utf8') <= 72
    && /[a-z]/.test(value)
    && /[A-Z]/.test(value)
    && /\d/.test(value)
    && /[^A-Za-z0-9]/.test(value);
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
  MIME_TYPES_BY_EXTENSION,
  MAX_FILE_SIZE_BYTES,
  sanitizeFilename,
  normalizePermission,
  isAllowedRole,
  isStrongPassword,
  computeSha256,
  sha256OfText
};
