const test = require('node:test');
const assert = require('node:assert/strict');
const { sanitizeFilename, isAllowedRole, normalizePermission } = require('./policy');

test('sanitizeFilename strips unsafe paths and whitespace', () => {
  const value = sanitizeFilename('../../etc/passwd 2024-09-01.pdf');
  assert.equal(value, 'etc_passwd_2024-09-01.pdf');
});

test('role validation accepts the allowed roles only', () => {
  assert.equal(isAllowedRole('administrator'), true);
  assert.equal(isAllowedRole('document_owner'), true);
  assert.equal(isAllowedRole('viewer'), true);
  assert.equal(isAllowedRole('superuser'), false);
});

test('permission normalization keeps only supported document permissions', () => {
  assert.equal(normalizePermission('read'), 'read');
  assert.equal(normalizePermission('edit'), 'edit');
  assert.equal(normalizePermission('admin'), 'read');
});
