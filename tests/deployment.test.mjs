import test from 'node:test';
import bcrypt from 'bcryptjs';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { drizzle } from 'drizzle-orm/node-postgres';
import { createHash, randomBytes } from 'node:crypto';
import { Repository, canonical } from '../db/repository.mjs';
import handler, { createHandler, config } from '../netlify/functions/trustvault.mjs';

function fixture(respond = () => []) {
  const calls = [];
  const client = { async query(query, params) {
    const text = query.text || query;
    calls.push({ text, params });
    return { rows: await respond(text, params, query.rowMode) };
  }};
  return { repository: new Repository(drizzle({ client })), calls };
}
function rowsFor(text, record) {
  const fields = text.slice(7, text.indexOf(' from '));
  return [[...fields.matchAll(/(?:"\w+"\.)?"(\w+)"/g)].map(match => record[match[1]])];
}
function authenticatedFixture({ role = 'document_owner', document, grant, disabled = false, expired = false } = {}) {
  const token = randomBytes(32).toString('base64url');
  const user = { id: 'a'.repeat(32), name: 'Test user', email: 'user@example.test', role,
    status: disabled ? 'disabled' : 'active', auth_version: 1, created_at: '2026-01-01T00:00:00Z' };
  const data = fixture((text) => {
    if (text.startsWith('select') && text.includes('from "server_sessions"')) return rowsFor(text, {
      user_id: user.id, auth_version: 1, expires_at: expired ? '2020-01-01T00:00:00Z' : '2099-01-01T00:00:00Z',
    });
    if (text.startsWith('select') && text.includes('from "users"')) return rowsFor(text, user);
    if (text.startsWith('select') && text.includes('from "documents"')) return document ? rowsFor(text, document) : [];
    if (text.startsWith('select') && text.includes('from "document_permissions"')) return grant ? rowsFor(text, grant) : [];
    return [];
  });
  return { ...data, token, user, csrf: createHash('sha256').update('csrf:' + token).digest('hex') };
}
function request(path, fixture, options = {}) {
  return new Request('https://example.test' + path, {
    ...options, headers: { cookie: `trustvault_session=${fixture.token}`, ...(options.headers || {}) },
  });
}

test('pages, root redirect, static asset references, and missing route', async () => {
  assert.deepEqual(config, { path: ['/*'], preferStatic: true });
  const root = await handler(new Request('https://example.test/'));
  assert.equal(root.status, 302);
  assert.equal(root.headers.get('location'), 'https://example.test/login');
  for (const path of ['/login','/register','/documents','/search','/upload','/profile','/admin']) {
    const response = await handler(new Request('https://example.test' + path));
    assert.equal(response.status, 200);
    assert.ok(response.headers.get('content-security-policy'));
    const html = await response.text();
    for (const asset of ['app.js','style.css']) {
      assert.ok(html.includes('/' + asset));
      assert.ok((await readFile(new URL('../public/' + asset, import.meta.url))).length);
    }
  }
  assert.equal((await handler(new Request('https://example.test/missing'))).status, 404);
});

test('query facade binds user input and preserves pagination counts', async () => {
  const data = fixture(text => text.includes('count(*)') ? [[21]] : [['test-id', 'A name']]);
  const search = "%' OR 1=1 --";
  const result = await data.repository.from('users').select('id,name', { count: 'exact' })
    .eq('status', 'active').ilike('name', search).order('created_at', { ascending: false }).range(20, 39);
  assert.equal(result.error, null);
  assert.equal(result.count, 21);
  assert.deepEqual(result.data, [{ id: 'test-id', name: 'A name' }]);
  assert.equal(data.calls.length, 2);
  assert.ok(!data.calls[0].text.includes('limit'));
  assert.ok(!data.calls[1].text.includes(search));
  assert.ok(data.calls[1].params.includes(search));
  assert.match(data.calls[1].text, /limit \$\d+ offset \$\d+/);
});

test('owner and recipient joins use their respective foreign keys', async () => {
  const data = fixture(() => [['record', 'Test', 'test@example.test']]);
  await data.repository.from('documents').select('id,users(name,email)');
  await data.repository.from('document_permissions').select('id,users(name,email)');
  assert.match(data.calls[0].text, /"documents"\."owner_id" = "users"\."id"/);
  assert.match(data.calls[1].text, /"document_permissions"\."user_id" = "users"\."id"/);
});

test('writes use RETURNING and retain database constraint codes', async () => {
  const data = fixture(text => {
    if (text.startsWith('insert')) throw Object.assign(new Error('Duplicate'), { code: '23505' });
    return [['record']];
  });
  const failed = await data.repository.from('users').insert({ id: 'record' });
  assert.equal(failed.error.code, '23505');
  const updated = await data.repository.from('registration_invites').update({ consumed_at: 'now' })
    .eq('id', 'record').is('consumed_at', null).select('id').maybeSingle();
  assert.deepEqual(updated.data, { id: 'record' });
  assert.match(data.calls[1].text, /is null\)+ returning "id"/);
});

test('missing and expired sessions cannot access private routes', async () => {
  const anonymous = fixture();
  const app = createHandler({ repository: () => anonymous.repository });
  const denied = await app(new Request('https://example.test/api/documents'));
  assert.equal(denied.status, 401);
  const expired = authenticatedFixture({ expired: true });
  const expiredApp = createHandler({ repository: () => expired.repository });
  assert.equal((await expiredApp(request('/api/documents', expired))).status, 401);
  assert.equal(expired.calls.filter(call => call.text.includes('from "users"')).length, 0);
});

test('disabled users lose access and public session responses exclude password hashes', async () => {
  const disabled = authenticatedFixture({ disabled: true });
  let app = createHandler({ repository: () => disabled.repository });
  assert.equal((await app(request('/api/auth/me', disabled))).status, 401);
  const active = authenticatedFixture();
  app = createHandler({ repository: () => active.repository });
  const response = await app(request('/api/auth/me', active));
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.user.role, 'document_owner');
  assert.ok(!('password_hash' in body.user));
  assert.ok(!('auth_version' in body.user));
});

test('non-administrators and missing CSRF cannot mutate accounts', async () => {
  const data = authenticatedFixture({ role: 'viewer' });
  const app = createHandler({ repository: () => data.repository });
  assert.equal((await app(request('/api/admin/users', data))).status, 403);
  assert.equal((await app(request('/api/auth/logout', data, { method: 'POST' }))).status, 403);
});

test('logout deletes the persisted session and expires the cookie', async () => {
  const data = authenticatedFixture();
  const app = createHandler({ repository: () => data.repository });
  // Keep this check focused on revocation; audit transactions are checked separately.
  data.repository.appendAudit = async () => ({});
  const response = await app(request('/api/auth/logout', data, {
    method: 'POST', headers: { 'x-csrf-token': data.csrf },
  }));
  assert.equal(response.status, 200);
  assert.match(response.headers.get('set-cookie'), /Max-Age=0/);
  const deletion = data.calls.find(call => call.text.startsWith('delete from "server_sessions"'));
  assert.ok(deletion);
  assert.ok(!deletion.params.includes(data.token));
});

test('unshared and expired-share downloads never read private storage', async () => {
  for (const grant of [undefined, { permission: 'read', expires_at: '2020-01-01T00:00:00Z' }]) {
    const data = authenticatedFixture({ document: { id: 'b'.repeat(32), owner_id: 'c'.repeat(32) }, grant });
    let storageReads = 0;
    const app = createHandler({ repository: () => data.repository, documentStore: () => {
      storageReads++; throw new Error('Must not read storage');
    }});
    const response = await app(request('/api/documents/' + 'b'.repeat(32) + '/download', data));
    assert.equal(response.status, 404);
    assert.equal(storageReads, 0);
  }
});

test('authorized download uses private storage and no-store headers', async () => {
  const data = authenticatedFixture({ document: {
    id: 'b'.repeat(32), owner_id: 'a'.repeat(32), storage_key: 'private-key',
    name: 'report.txt', mime_type: 'text/plain',
  }});
  data.repository.appendAudit = async () => ({});
  const app = createHandler({ repository: () => data.repository, documentStore: () => ({
    async download(key) { assert.equal(key, 'private-key'); return { data: new Blob(['report']), error: null }; },
  }) });
  const response = await app(request('/api/documents/' + 'b'.repeat(32) + '/download', data));
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'report');
  assert.equal(response.headers.get('cache-control'), 'private, no-store');
  assert.match(response.headers.get('content-disposition'), /^attachment/);
});

test('cross-site mutations are rejected before database initialization', async () => {
  const app = createHandler({ repository: () => { throw new Error('Must not initialize'); } });
  const response = await app(new Request('https://example.test/api/auth/login', {
    method: 'POST', headers: { origin: 'https://different.test' },
  }));
  assert.equal(response.status, 403);
});

test('audit appends serialize, chain, and roll back on failure', async () => {
  const data = fixture(() => []);
  await data.repository.appendAudit({ id: 'event', timestamp: '2026-01-01T00:00:00Z',
    user_id: null, username: null, action: 'test', document_id: null, ip_address: null,
    status: 'success', details: { z: 2, a: 1 }, user_agent: null });
  assert.equal(data.calls[0].text, 'begin');
  assert.match(data.calls[1].text, /pg_advisory_xact_lock/);
  const insertion = data.calls.find(call => call.text.startsWith('insert into "audit_logs"'));
  assert.ok(insertion.params.includes('0'.repeat(64)));
  assert.ok(insertion.params.includes('{"a":1,"z":2}'));
  assert.equal(data.calls.at(-1).text, 'commit');
  const failed = fixture(text => {
    if (text.startsWith('insert into "audit_logs"')) throw new Error('Write failed');
    return [];
  });
  await assert.rejects(failed.repository.appendAudit({ id: 'failed', timestamp: 'now', action: 'test', status: 'success', details: {} }));
  assert.equal(failed.calls.at(-1).text, 'rollback');
  assert.equal(canonical({ z: 2, a: { y: 1, x: 0 } }), '{"a":{"x":0,"y":1},"z":2}');
});

test('login persists a hashed session rather than a raw cookie', async () => {
  const password = randomBytes(24).toString('base64url');
  const user = { id: 'a'.repeat(32), name: 'Test user', email: 'user@example.test', role: 'viewer',
    status: 'active', auth_version: 1, created_at: '2026-01-01T00:00:00Z', password_hash: await bcrypt.hash(password, 4) };
  const data = fixture(text => text.startsWith('select') && text.includes('from "users"') ? rowsFor(text, user) : []);
  data.repository.appendAudit = async () => ({});
  const app = createHandler({ repository: () => data.repository });
  const response = await app(new Request('https://example.test/api/auth/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: user.email, password }),
  }));
  assert.equal(response.status, 200);
  const cookie = response.headers.get('set-cookie');
  assert.match(cookie, /HttpOnly; Secure; SameSite=Lax/);
  const raw = cookie.split(';')[0].split('=')[1];
  const saved = data.calls.find(call => call.text.startsWith('insert into "server_sessions"'));
  assert.ok(saved);
  assert.ok(!saved.params.includes(raw));
  assert.ok(saved.params.includes(createHash('sha256').update(raw).digest('hex')));
});

test('a failed registration rolls back invitation consumption', async () => {
  const password = randomBytes(24).toString('base64url');
  const data = fixture(text => {
    if (text.startsWith('select') && text.includes('from "registration_invites"')) {
      return rowsFor(text, { id: 'invite', role: 'viewer', expires_at: '2099-01-01T00:00:00Z', consumed_at: null });
    }
    if (text.startsWith('update "registration_invites"')) return [['invite']];
    if (text.startsWith('insert into "users"')) throw Object.assign(new Error('Duplicate account'), { code: '23505' });
    return [];
  });
  const app = createHandler({ repository: () => data.repository });
  const response = await app(new Request('https://example.test/api/auth/register', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name: 'Test user', email: 'user@example.test', password, invite_token: randomBytes(32).toString('base64url') }),
  }));
  assert.equal(response.status, 409);
  assert.equal(data.calls.at(-1).text, 'rollback');
  assert.ok(!data.calls.some(call => call.text === 'commit'));
});

test('administrator role changes revoke sessions and viewer edit grants', async () => {
  const actorId = 'a'.repeat(32);
  const targetId = 'b'.repeat(32);
  const actor = { id: actorId, role: 'administrator', status: 'active', auth_version: 1 };
  const target = { id: targetId, role: 'document_owner', status: 'active', auth_version: 1 };
  const data = fixture((text, params) => {
    if (text.startsWith('select') && text.includes('from "users"')) return rowsFor(text, params.includes(actorId) ? actor : target);
    if (text.startsWith('update "users"')) return [[targetId, 'Target', 'target@example.test', 'viewer', 'active']];
    return [];
  });
  const result = await data.repository.adminUpdate({ actorId, targetId, field: 'role', value: 'viewer', timestamp: '2026-01-01T00:00:00Z' });
  assert.equal(result.error, null);
  assert.equal(result.data.user.role, 'viewer');
  assert.ok(data.calls.some(call => call.text.startsWith('delete from "server_sessions"')));
  assert.ok(data.calls.some(call => call.text.startsWith('update "document_permissions"')));
  assert.equal(data.calls.at(-1).text, 'commit');
});
