const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

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

async function startServer(port, dataDir) {
  const child = spawn(process.execPath, ['server.js'], {
    cwd: __dirname,
    env: {
      ...process.env,
      NODE_ENV: 'test',
      PORT: String(port),
      TRUSTVAULT_DATA_DIR: dataDir
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
        email: 'auth-test@example.invalid',
        password: 'valid-test-password'
      })
    });
    assert.equal(registration.status, 201);
    const registrationBody = await registration.json();
    assert.equal(registrationBody.user.email, 'auth-test@example.invalid');
    let cookie = sessionCookie(registration);

    const database = new Database(path.join(dataDir, 'trustvault.db'), { readonly: true });
    const user = database.prepare('SELECT password_hash FROM users WHERE email = ?').get('auth-test@example.invalid');
    assert.ok(user);
    assert.notEqual(user.password_hash, 'valid-test-password');
    assert.equal(bcrypt.compareSync('valid-test-password', user.password_hash), true);
    database.close();

    const currentUser = await fetch(`${baseUrl}/api/auth/me`, { headers: { cookie } });
    assert.equal(currentUser.status, 200);
    assert.equal((await currentUser.json()).user.email, 'auth-test@example.invalid');

    const logout = await fetch(`${baseUrl}/api/auth/logout`, { method: 'POST', headers: { cookie } });
    assert.equal(logout.status, 200);
    const afterLogout = await fetch(`${baseUrl}/api/auth/me`, { headers: { cookie } });
    assert.equal(afterLogout.status, 401);

    const invalidLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'AUTH-TEST@example.invalid', password: 'incorrect-password' })
    });
    assert.equal(invalidLogin.status, 401);

    const validLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'AUTH-TEST@example.invalid', password: 'valid-test-password' })
    });
    assert.equal(validLogin.status, 200);
    cookie = sessionCookie(validLogin);

    await stopServer(server);
    server = await startServer(port, dataDir);

    const loginAfterRestart = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'auth-test@example.invalid', password: 'valid-test-password' })
    });
    assert.equal(loginAfterRestart.status, 200);
    assert.equal((await loginAfterRestart.json()).user.email, 'auth-test@example.invalid');
    cookie = sessionCookie(loginAfterRestart);

    await stopServer(server);
    server = await startServer(port, dataDir);

    const restoredSession = await fetch(`${baseUrl}/api/auth/me`, { headers: { cookie } });
    assert.equal(restoredSession.status, 200);
    assert.equal((await restoredSession.json()).user.email, 'auth-test@example.invalid');
  } finally {
    if (server) await stopServer(server);
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});
