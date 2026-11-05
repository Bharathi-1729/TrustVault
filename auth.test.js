const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const vm = require('node:vm');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const TEST_PASSWORD = 'Valid-test-Password1!';

async function getAvailablePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const { port } = server.address();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function startServer(port, dataDir, envOverrides = {}) {
  const child = spawn(process.execPath, ['server.js'], {
    cwd: __dirname,
    env: {
      ...process.env,
      NODE_ENV: 'test',
      PORT: String(port),
      TRUSTVAULT_DATA_DIR: dataDir,
      TRUSTVAULT_UPLOAD_DIR: path.join(dataDir, 'private_uploads'),
      TRUSTVAULT_SESSION_SECRET: 'test-only-session-secret-for-integration-tests',
      TRUSTVAULT_AUDIT_SECRET: 'test-only-audit-secret-for-integration-tests',
      ...envOverrides
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { output += chunk; });

  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (child.exitCode !== null) {
      throw new Error(`Test server exited before starting:\n${output}`);
    }

    try {
      const response = await fetch(`http://127.0.0.1:${port}/api/health`);
      if (response.ok) return child;
    } catch (_error) {
      await new Promise((resolve) => setTimeout(resolve, 80));
    }
  }

  child.kill();
  throw new Error(`Test server did not become ready:\n${output}`);
}

async function stopServer(child) {
  if (child.exitCode !== null) return;
  const exited = new Promise((resolve) => child.once('exit', resolve));
  child.kill();
  await exited;
}

function sessionCookie(response) {
  const setCookie = response.headers.get('set-cookie');
  assert.ok(setCookie, 'authentication response should set a session cookie');
  return setCookie.split(';', 1)[0];
}

test('production server starts without a separate audit secret when session secret is configured', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustvault-production-start-'));
  const port = await getAvailablePort();
  let server;

  try {
    server = await startServer(port, dataDir, {
      NODE_ENV: 'production',
      TRUSTVAULT_SESSION_SECRET: 'production-session-secret-used-only-in-this-test',
      TRUSTVAULT_AUDIT_SECRET: ''
    });
    const response = await fetch(`http://127.0.0.1:${port}/api/health`);
    assert.equal(response.status, 200);
  } finally {
    if (server) await stopServer(server);
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('dashboard browser script parses successfully', () => {
  const appScript = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');
  assert.doesNotThrow(() => new vm.Script(appScript, { filename: 'app.js' }));
});

test('registration, bcrypt login, sessions, and SQLite persistence work', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustvault-auth-'));
  const port = await getAvailablePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  let server;

  try {
    server = await startServer(port, dataDir);

    const registration = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'Auth Test User',
        email: '  AUTH-Test@example.invalid  ',
        password: TEST_PASSWORD,
        confirmPassword: TEST_PASSWORD
      })
    });
    assert.equal(registration.status, 201);
    const registrationBody = await registration.json();
    assert.equal(registrationBody.user.email, 'auth-test@example.invalid');
    assert.equal(registrationBody.user.role, 'administrator');
    assert.equal(Object.hasOwn(registrationBody.user, 'password_hash'), false);
    let cookie = sessionCookie(registration);

    const database = new Database(path.join(dataDir, 'trustvault.db'), { readonly: true });
    const user = database.prepare('SELECT password_hash FROM users WHERE email = ?').get('auth-test@example.invalid');
    assert.ok(user);
    assert.notEqual(user.password_hash, TEST_PASSWORD);
    assert.equal(bcrypt.compareSync(TEST_PASSWORD, user.password_hash), true);
    database.close();

    const currentUser = await fetch(`${baseUrl}/api/auth/me`, { headers: { cookie } });
    assert.equal(currentUser.status, 200);
    assert.equal((await currentUser.json()).user.email, 'auth-test@example.invalid');
    const dashboard = await fetch(`${baseUrl}/app.html`, { headers: { cookie } });
    assert.equal(dashboard.status, 200);
    assert.match(await dashboard.text(), /Administrative controls/);

    const invalidProfileName = await fetch(`${baseUrl}/api/profile`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: { value: 'Unexpected object' } })
    });
    assert.equal(invalidProfileName.status, 400);
    const invalidProfilePassword = await fetch(`${baseUrl}/api/profile`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ password: 12345678 })
    });
    assert.equal(invalidProfilePassword.status, 400);
    const weakRegistration = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'Weak Password User',
        email: 'weak-password@example.invalid',
        password: 'all-lowercase',
        confirmPassword: 'all-lowercase'
      })
    });
    assert.equal(weakRegistration.status, 400);
    const mismatchedRegistration = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'Password Mismatch User',
        email: 'mismatch@example.invalid',
        password: TEST_PASSWORD,
        confirmPassword: `${TEST_PASSWORD}different`
      })
    });
    assert.equal(mismatchedRegistration.status, 400);
    const crossOriginUpdate = await fetch(`${baseUrl}/api/profile`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie, origin: 'https://untrusted.example' },
      body: JSON.stringify({ name: 'Cross-site Change' })
    });
    assert.equal(crossOriginUpdate.status, 403);

    const formData = new FormData();
    formData.append('file', new Blob(['TrustVault upload test – café'], { type: 'text/plain' }), 'upload-test.txt');
    formData.append('category', 'test');
    const upload = await fetch(`${baseUrl}/api/documents`, {
      method: 'POST',
      headers: { cookie },
      body: formData
    });
    assert.equal(upload.status, 201);
    const uploadedDocument = (await upload.json()).document;
    assert.equal(Object.hasOwn(uploadedDocument, 'storageKey'), false);
    assert.equal(Object.hasOwn(uploadedDocument, 'storage_key'), false);
    assert.equal(Object.hasOwn(uploadedDocument, 'sha256'), false);
    const pendingDownload = await fetch(`${baseUrl}/api/documents/${uploadedDocument.id}/download`, {
      headers: { cookie }
    });
    assert.equal(pendingDownload.status, 403);

    const approveScan = await fetch(`${baseUrl}/api/admin/documents/${uploadedDocument.id}/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ status: 'approved' })
    });
    assert.equal(approveScan.status, 200);
    const download = await fetch(`${baseUrl}/api/documents/${uploadedDocument.id}/download`, {
      headers: { cookie }
    });
    assert.equal(download.status, 200);
    assert.equal(await download.text(), 'TrustVault upload test – café');
    const preview = await fetch(`${baseUrl}/api/documents/${uploadedDocument.id}/preview`, {
      headers: { cookie }
    });
    assert.equal(preview.status, 200);
    assert.match(preview.headers.get('content-type'), /^text\/plain(?:;|$)/);
    assert.match(preview.headers.get('content-security-policy'), /sandbox/);
    assert.equal(await preview.text(), 'TrustVault upload test – café');
    const ownActivity = await fetch(`${baseUrl}/api/account/activity`, { headers: { cookie } });
    assert.equal(ownActivity.status, 200);
    assert.ok((await ownActivity.json()).activity.some((entry) => entry.action === 'document_previewed'));
    const uploadAudit = await fetch(`${baseUrl}/api/admin/audit`, {
      headers: { cookie }
    });
    const uploadAuditBody = await uploadAudit.json();
    assert.equal(uploadAuditBody.integrity.valid, true);
    assert.ok(uploadAuditBody.audit.some((entry) => entry.action === 'document_uploaded'));
    assert.ok(uploadAuditBody.audit.some((entry) => entry.action === 'document_downloaded'));
    const activityResponse = await fetch(`${baseUrl}/api/documents/${uploadedDocument.id}/activity`, {
      headers: { cookie }
    });
    assert.equal(activityResponse.status, 200);
    const activity = (await activityResponse.json()).activity;
    assert.ok(activity.some((entry) => entry.action === 'document_uploaded'));
    assert.ok(activity.some((entry) => entry.action === 'document_downloaded'));

    const logout = await fetch(`${baseUrl}/api/auth/logout`, { method: 'POST', headers: { cookie } });
    assert.equal(logout.status, 200);
    const afterLogout = await fetch(`${baseUrl}/api/auth/me`, { headers: { cookie } });
    assert.equal(afterLogout.status, 401);

    const invalidLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': 'trustvault-test-agent' },
      body: JSON.stringify({ email: 'AUTH-TEST@example.invalid', password: 'incorrect-password' })
    });
    assert.equal(invalidLogin.status, 401);
    assert.equal((await invalidLogin.json()).error, 'Invalid email or password.');

    const validLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'AUTH-TEST@example.invalid', password: TEST_PASSWORD })
    });
    assert.equal(validLogin.status, 200);
    cookie = sessionCookie(validLogin);
    const failedLoginAudit = await fetch(`${baseUrl}/api/admin/audit?action=user_login_failed&result=failure`, {
      headers: { cookie }
    });
    const failedLoginEvents = (await failedLoginAudit.json()).audit;
    assert.ok(failedLoginEvents.some(
      (entry) => entry.event_result === 'failure' && entry.user_agent === 'trustvault-test-agent'
    ));

    await stopServer(server);
    server = await startServer(port, dataDir);

    const loginAfterRestart = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'auth-test@example.invalid', password: TEST_PASSWORD })
    });
    assert.equal(loginAfterRestart.status, 200);
    assert.equal((await loginAfterRestart.json()).user.email, 'auth-test@example.invalid');
    cookie = sessionCookie(loginAfterRestart);

    await stopServer(server);
    server = await startServer(port, dataDir);

    const restoredSession = await fetch(`${baseUrl}/api/auth/me`, { headers: { cookie } });
    assert.equal(restoredSession.status, 200);
    assert.equal((await restoredSession.json()).user.email, 'auth-test@example.invalid');

    const appendOnlyDb = new Database(path.join(dataDir, 'trustvault.db'));
    assert.throws(() => appendOnlyDb.prepare("UPDATE audit_events SET action = 'rewritten'").run(), /append-only/);
    appendOnlyDb.exec('DROP TRIGGER audit_events_no_update');
    appendOnlyDb.prepare("UPDATE audit_events SET details = ? WHERE action = 'user_login_failed'").run('{"tampered":true}');
    appendOnlyDb.close();
    const tamperedAudit = await fetch(`${baseUrl}/api/admin/audit`, { headers: { cookie } });
    assert.equal((await tamperedAudit.json()).integrity.valid, false);
  } finally {
    if (server) await stopServer(server);
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('Owner and Viewer authorization, document sharing, and disabled sessions are enforced', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustvault-roles-'));
  const port = await getAvailablePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  let server;
  const postJson = (url, cookie, body, method = 'POST') => fetch(`${baseUrl}${url}`, {
    method,
    headers: {
      'content-type': 'application/json',
      ...(cookie ? { cookie } : {})
    },
    body: JSON.stringify(body)
  });
  const register = async (email, name) => {
    const response = await postJson('/api/auth/register', null, {
      name,
      email,
      password: TEST_PASSWORD,
      confirmPassword: TEST_PASSWORD
    });
    assert.equal(response.status, 201);
    return sessionCookie(response);
  };

  try {
    server = await startServer(port, dataDir);

    assert.equal((await fetch(`${baseUrl}/app.html`)).status, 401);
    assert.equal((await fetch(`${baseUrl}/data/trustvault.db`)).status, 404);
    assert.equal((await fetch(`${baseUrl}/server.js`)).status, 404);
    assert.equal((await fetch(`${baseUrl}/styles.css`)).status, 200);
    assert.equal((await fetch(`${baseUrl}/motion.html`)).status, 200);

    const ownerCookie = await register('owner@example.invalid', 'Owner User');
    const viewerCookie = await register('viewer@example.invalid', 'Viewer User');
    const secondViewerCookie = await register('second-viewer@example.invalid', 'Second Viewer');
    const categoryCreated = await postJson('/api/categories', ownerCookie, { name: 'Contracts' });
    assert.equal(categoryCreated.status, 201);
    const duplicateCategory = await postJson('/api/categories', ownerCookie, { name: 'contracts' });
    assert.equal(duplicateCategory.status, 409);
    const viewerCategoryAttempt = await postJson('/api/categories', viewerCookie, { name: 'Private' });
    assert.equal(viewerCategoryAttempt.status, 403);

    const usersResponse = await fetch(`${baseUrl}/api/admin/users`, {
      headers: { cookie: ownerCookie }
    });
    assert.equal(usersResponse.status, 200);
    const users = (await usersResponse.json()).users;
    const owner = users.find((user) => user.email === 'owner@example.invalid');
    const viewer = users.find((user) => user.email === 'viewer@example.invalid');
    const secondViewer = users.find((user) => user.email === 'second-viewer@example.invalid');
    assert.ok(owner);
    assert.ok(viewer);
    assert.ok(secondViewer);
    assert.equal(Object.hasOwn(viewer, 'password_hash'), false);

    const duplicateRegistration = await postJson('/api/auth/register', null, {
      name: 'Duplicate User',
      email: 'VIEWER@example.invalid',
      password: TEST_PASSWORD,
      confirmPassword: TEST_PASSWORD
    });
    assert.equal(duplicateRegistration.status, 409);

    const viewerAdminAttempt = await fetch(`${baseUrl}/api/admin/users`, {
      headers: { cookie: viewerCookie }
    });
    assert.equal(viewerAdminAttempt.status, 403);
    const viewerDirectoryAttempt = await fetch(`${baseUrl}/api/users`, {
      headers: { cookie: viewerCookie }
    });
    assert.equal(viewerDirectoryAttempt.status, 403);

    const promote = await postJson(`/api/admin/users/${viewer.id}/role`, ownerCookie, {
      role: 'administrator'
    }, 'PUT');
    assert.equal(promote.status, 200);
    const promotedAdminAccess = await fetch(`${baseUrl}/api/admin/users`, {
      headers: { cookie: viewerCookie }
    });
    assert.equal(promotedAdminAccess.status, 200);

    const disableAdministrator = await postJson(`/api/admin/users/${viewer.id}/status`, ownerCookie, {
      status: 'disabled'
    }, 'PUT');
    assert.equal(disableAdministrator.status, 200);
    const disabledAdministratorAccess = await fetch(`${baseUrl}/api/admin/users`, {
      headers: { cookie: viewerCookie }
    });
    assert.equal(disabledAdministratorAccess.status, 403);
    const enableAdministrator = await postJson(`/api/admin/users/${viewer.id}/status`, ownerCookie, {
      status: 'active'
    }, 'PUT');
    assert.equal(enableAdministrator.status, 200);

    const demote = await postJson(`/api/admin/users/${viewer.id}/role`, ownerCookie, {
      role: 'viewer'
    }, 'PUT');
    assert.equal(demote.status, 200);
    const selfDemotion = await postJson(`/api/admin/users/${owner.id}/role`, ownerCookie, {
      role: 'viewer'
    }, 'PUT');
    assert.equal(selfDemotion.status, 400);

    const setDocumentOwner = await postJson(`/api/admin/users/${viewer.id}/role`, ownerCookie, {
      role: 'document_owner'
    }, 'PUT');
    assert.equal(setDocumentOwner.status, 200);

    const documentId = 'shared-test-document';
    const database = new Database(path.join(dataDir, 'trustvault.db'));
    database.prepare(`
      INSERT INTO documents(
        id, owner_id, name, category, description, storage_key, original_name,
        mime_type, size_bytes, sha256, scan_status, is_deleted, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
    `).run(
      documentId,
      viewer.id,
      'shared.txt',
      'test',
      '',
      'unused-storage-key',
      'shared.txt',
      'text/plain',
      6,
      'test-digest',
      'approved',
      new Date().toISOString(),
      new Date().toISOString()
    );
    database.close();

    const unauthorizedDocument = await fetch(`${baseUrl}/api/documents/${documentId}`, {
      headers: { cookie: secondViewerCookie }
    });
    assert.equal(unauthorizedDocument.status, 403);
    const adminWithoutShare = await fetch(`${baseUrl}/api/documents/${documentId}`, {
      headers: { cookie: ownerCookie }
    });
    assert.equal(adminWithoutShare.status, 403);
    const adminActivityWithoutShare = await fetch(`${baseUrl}/api/documents/${documentId}/activity`, {
      headers: { cookie: ownerCookie }
    });
    assert.equal(adminActivityWithoutShare.status, 403);

    const editForViewer = await postJson(`/api/documents/${documentId}/share`, viewerCookie, {
      email: 'second-viewer@example.invalid',
      permission: 'edit'
    });
    assert.equal(editForViewer.status, 400);

    const grant = await postJson(`/api/documents/${documentId}/share`, viewerCookie, {
      email: 'second-viewer@example.invalid',
      permission: 'read'
    });
    assert.equal(grant.status, 201);
    const permissionConstraintDb = new Database(path.join(dataDir, 'trustvault.db'));
    assert.throws(() => permissionConstraintDb.prepare(`
      INSERT INTO document_permissions(
        id, document_id, user_id, permission, active, expires_at,
        created_by, created_at, updated_at, revoked_at
      ) VALUES (?, ?, ?, 'read', 1, NULL, ?, ?, ?, NULL)
    `).run(
      'duplicate-active-permission',
      documentId,
      secondViewer.id,
      viewer.id,
      new Date().toISOString(),
      new Date().toISOString()
    ), /UNIQUE constraint failed/);
    permissionConstraintDb.close();
    const expiredGrant = await postJson(`/api/documents/${documentId}/share`, viewerCookie, {
      email: 'second-viewer@example.invalid',
      permission: 'read',
      expiresAt: '2020-01-01T00:00:00.000Z'
    });
    assert.equal(expiredGrant.status, 400);
    const ownerShares = await fetch(`${baseUrl}/api/documents/${documentId}/shares`, {
      headers: { cookie: ownerCookie }
    });
    assert.equal(ownerShares.status, 200);
    assert.equal((await ownerShares.json()).shares[0].user_email, 'second-viewer@example.invalid');
    const viewerSharesAttempt = await fetch(`${baseUrl}/api/documents/${documentId}/shares`, {
      headers: { cookie: secondViewerCookie }
    });
    assert.equal(viewerSharesAttempt.status, 403);

    const sharedDocs = await fetch(`${baseUrl}/api/documents`, {
      headers: { cookie: secondViewerCookie }
    });
    assert.equal(sharedDocs.status, 200);
    assert.equal((await sharedDocs.json()).documents[0].id, documentId);
    const filteredSharedDocs = await fetch(`${baseUrl}/api/documents?fileType=text%2Fplain&category=test`, {
      headers: { cookie: secondViewerCookie }
    });
    assert.equal(filteredSharedDocs.status, 200);
    assert.equal((await filteredSharedDocs.json()).documents[0].id, documentId);
    const viewerActivity = await fetch(`${baseUrl}/api/documents/${documentId}/activity`, {
      headers: { cookie: secondViewerCookie }
    });
    assert.equal(viewerActivity.status, 200);
    const viewerActivityEvents = (await viewerActivity.json()).activity;
    assert.ok(viewerActivityEvents.some(
      (entry) => entry.action === 'document_activity_viewed'
    ));
    assert.equal(viewerActivityEvents.some(
      (entry) => entry.action === 'document_permission_granted'
    ), false);

    const viewerPermissionDetails = await fetch(`${baseUrl}/api/documents/${documentId}`, {
      headers: { cookie: secondViewerCookie }
    });
    assert.equal(viewerPermissionDetails.status, 200);
    assert.deepEqual((await viewerPermissionDetails.json()).document.permissions, []);

    const viewerGrantAttempt = await postJson(`/api/documents/${documentId}/share`, secondViewerCookie, {
      email: 'viewer@example.invalid',
      permission: 'edit'
    });
    assert.equal(viewerGrantAttempt.status, 403);
    const viewerRevokeAttempt = await fetch(`${baseUrl}/api/documents/${documentId}/share/${viewer.id}`, {
      method: 'DELETE',
      headers: { cookie: secondViewerCookie }
    });
    assert.equal(viewerRevokeAttempt.status, 403);
    const viewerUploadForm = new FormData();
    viewerUploadForm.append('file', new Blob(['not permitted'], { type: 'text/plain' }), 'viewer.txt');
    const viewerUpload = await fetch(`${baseUrl}/api/documents`, {
      method: 'POST',
      headers: { cookie: secondViewerCookie },
      body: viewerUploadForm
    });
    assert.equal(viewerUpload.status, 403);
    assert.deepEqual(fs.readdirSync(path.join(dataDir, 'private_uploads')), []);
    const viewerEditAttempt = await postJson(`/api/documents/${documentId}`, secondViewerCookie, {
      name: 'unauthorized.txt'
    }, 'PUT');
    assert.equal(viewerEditAttempt.status, 403);
    const viewerDeleteAttempt = await fetch(`${baseUrl}/api/documents/${documentId}`, {
      method: 'DELETE',
      headers: { cookie: secondViewerCookie }
    });
    assert.equal(viewerDeleteAttempt.status, 403);

    const ownerRevoke = await fetch(`${baseUrl}/api/documents/${documentId}/share/${secondViewer.id}`, {
      method: 'DELETE',
      headers: { cookie: viewerCookie }
    });
    assert.equal(ownerRevoke.status, 200);
    const revokedViewerAccess = await fetch(`${baseUrl}/api/documents/${documentId}`, {
      headers: { cookie: secondViewerCookie }
    });
    assert.equal(revokedViewerAccess.status, 403);
    const revokedViewerPreview = await fetch(`${baseUrl}/api/documents/${documentId}/preview`, {
      headers: { cookie: secondViewerCookie }
    });
    assert.equal(revokedViewerPreview.status, 403);

    const setSecondDocumentOwner = await postJson(`/api/admin/users/${secondViewer.id}/role`, ownerCookie, {
      role: 'document_owner'
    }, 'PUT');
    assert.equal(setSecondDocumentOwner.status, 200);
    const editGrant = await postJson(`/api/documents/${documentId}/share`, viewerCookie, {
      email: 'second-viewer@example.invalid',
      permission: 'edit'
    });
    assert.equal(editGrant.status, 201);
    const editUpdate = await postJson(`/api/documents/${documentId}`, secondViewerCookie, {
      name: 'edited-by-owner.txt'
    }, 'PUT');
    assert.equal(editUpdate.status, 200);

    const demoteSecondOwner = await postJson(`/api/admin/users/${secondViewer.id}/role`, ownerCookie, {
      role: 'viewer'
    }, 'PUT');
    assert.equal(demoteSecondOwner.status, 200);
    const viewerEditDespiteEditShare = await postJson(`/api/documents/${documentId}`, secondViewerCookie, {
      name: 'viewer-must-not-edit.txt'
    }, 'PUT');
    assert.equal(viewerEditDespiteEditShare.status, 403);

    const grantAdminRead = await postJson(`/api/documents/${documentId}/share`, viewerCookie, {
      email: 'owner@example.invalid',
      permission: 'read'
    });
    assert.equal(grantAdminRead.status, 201);
    const explicitlySharedAdminAccess = await fetch(`${baseUrl}/api/documents/${documentId}`, {
      headers: { cookie: ownerCookie }
    });
    assert.equal(explicitlySharedAdminAccess.status, 200);
    const explicitlySharedAdminActivity = await fetch(`${baseUrl}/api/documents/${documentId}/activity`, {
      headers: { cookie: ownerCookie }
    });
    assert.equal(explicitlySharedAdminActivity.status, 200);

    const regrant = await postJson(`/api/documents/${documentId}/share`, viewerCookie, {
      email: 'second-viewer@example.invalid',
      permission: 'read'
    });
    assert.equal(regrant.status, 201);

    const disable = await postJson(`/api/admin/users/${secondViewer.id}/status`, ownerCookie, {
      status: 'disabled'
    }, 'PUT');
    assert.equal(disable.status, 200);
    const disabledSession = await fetch(`${baseUrl}/api/documents`, {
      headers: { cookie: secondViewerCookie }
    });
    assert.equal(disabledSession.status, 403);
    const disabledCurrentUser = await fetch(`${baseUrl}/api/auth/me`, {
      headers: { cookie: secondViewerCookie }
    });
    assert.equal(disabledCurrentUser.status, 403);
    const disabledLogin = await postJson('/api/auth/login', null, {
      email: 'second-viewer@example.invalid',
      password: TEST_PASSWORD,
      confirmPassword: TEST_PASSWORD
    });
    assert.equal(disabledLogin.status, 403);

    const enable = await postJson(`/api/admin/users/${secondViewer.id}/status`, ownerCookie, {
      status: 'active'
    }, 'PUT');
    assert.equal(enable.status, 200);
    const enabledLogin = await postJson('/api/auth/login', null, {
      email: 'SECOND-VIEWER@example.invalid',
      password: TEST_PASSWORD,
      confirmPassword: TEST_PASSWORD
    });
    assert.equal(enabledLogin.status, 200);

    const auditResponse = await fetch(`${baseUrl}/api/admin/audit`, {
      headers: { cookie: ownerCookie }
    });
    assert.equal(auditResponse.status, 200);
    const auditBody = await auditResponse.json();
    assert.equal(auditBody.integrity.valid, true);
    assert.ok(auditBody.audit.some((entry) => entry.action === 'authorization_denied'));
    const dashboardResponse = await fetch(`${baseUrl}/api/admin/dashboard`, {
      headers: { cookie: ownerCookie }
    });
    const dashboard = await dashboardResponse.json();
    assert.equal(dashboard.counts.users, 3);
    assert.equal(dashboard.counts.activeUsers, 3);
    assert.ok(dashboard.counts.permissionChanges >= 2);
  } finally {
    if (server) await stopServer(server);
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('legacy user tables gain missing role and status columns without losing accounts', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustvault-migration-'));
  const database = new Database(path.join(dataDir, 'trustvault.db'));
  database.exec(`
    CREATE TABLE users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `);
  database.prepare(`
    INSERT INTO users(id, name, email, password_hash, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    'legacy-user',
    'Legacy User',
    'legacy@example.invalid',
    bcrypt.hashSync(TEST_PASSWORD, 12),
    new Date().toISOString(),
    new Date().toISOString()
  );
  database.close();

  const port = await getAvailablePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  let server;
  try {
    server = await startServer(port, dataDir);
    const login = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        email: 'LEGACY@example.invalid',
        password: TEST_PASSWORD,
        confirmPassword: TEST_PASSWORD
      })
    });
    assert.equal(login.status, 200);
    const loggedInUser = (await login.json()).user;
    assert.equal(loggedInUser.id, 'legacy-user');
    assert.equal(loggedInUser.role, 'administrator');
    assert.equal(loggedInUser.status, 'active');
    const adminAccess = await fetch(`${baseUrl}/api/admin/users`, {
      headers: { cookie: sessionCookie(login) }
    });
    assert.equal(adminAccess.status, 200);

    const persistedDb = new Database(path.join(dataDir, 'trustvault.db'), { readonly: true });
    const migratedUser = persistedDb.prepare('SELECT id, role, status FROM users WHERE id = ?').get('legacy-user');
    assert.deepEqual(migratedUser, {
      id: 'legacy-user',
      role: 'administrator',
      status: 'active'
    });
    persistedDb.close();
  } finally {
    if (server) await stopServer(server);
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});
