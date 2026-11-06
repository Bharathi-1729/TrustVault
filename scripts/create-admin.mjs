import bcrypt from 'bcryptjs';
import { randomUUID } from 'node:crypto';
import { sql } from 'drizzle-orm';
import { createRepository } from '../db/repository.mjs';
import { hiddenInput } from './terminal.mjs';

async function main() {
  const email = (process.argv[2] || '').trim().toLowerCase();
  const name = (process.argv[3] || '').trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || !name || name.length > 120) {
    throw new Error('Usage: npm run create-admin -- <email> <name> (run within netlify dev:exec)');
  }
  const password = await hiddenInput('Administrator password (hidden, at least 12 characters): ');
  if (password.length < 12 || Buffer.byteLength(password) > 72) throw new Error('Password must contain at least 12 characters and at most 72 UTF-8 bytes.');
  if (await hiddenInput('Confirm password (hidden): ') !== password) throw new Error('Passwords do not match.');
  const hash = await bcrypt.hash(password, 12);
  const repository = createRepository();
  await repository.transaction(async tx => {
    await tx.db.execute(sql`select pg_advisory_xact_lock(73510423)`);
    const existing = await tx.from('users').select('id').eq('role', 'administrator').limit(1).throwOnError();
    if (existing.data.length) throw new Error('An administrator already exists. Use its dashboard to invite more users.');
    const id = randomUUID().replaceAll('-', '');
    const timestamp = new Date().toISOString();
    await tx.from('users').insert({ id, email, name, password_hash: hash, role: 'administrator',
      status: 'active', auth_version: 1, created_at: timestamp, updated_at: timestamp }).throwOnError();
    await tx.appendAudit({ id: randomUUID().replaceAll('-', ''), timestamp, user_id: id, username: email,
      action: 'initial_administrator_created', document_id: null, ip_address: null, status: 'success',
      details: {}, user_agent: null });
  });
  console.log('Administrator created. Sign in to invite users from the administrator dashboard.');
}
main().then(() => process.exit(0)).catch(() => {
  console.error('Administrator creation failed. Verify the account details, database context, and that migrations have deployed.');
  process.exit(1);
});
