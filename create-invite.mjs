import { createHash, randomUUID } from 'node:crypto';
import { createRepository } from './db/repository.mjs';
import { hiddenInput } from './scripts/terminal.mjs';

async function main() {
  const role = process.argv[2] || 'viewer';
  const hours = Number(process.argv[3] || 24);
  if (!['administrator', 'document_owner', 'viewer'].includes(role) || !Number.isInteger(hours) || hours < 1 || hours > 720) {
    throw new Error('Invalid role or lifetime.');
  }
  // The dashboard generates invitations automatically. This CLI alternative never echoes an invitation.
  const token = await hiddenInput('Invitation value (hidden, at least 32 random characters): ');
  if (token.length < 32 || token.length > 256) throw new Error('Invalid invitation length.');
  await createRepository().from('registration_invites').insert({
    id: randomUUID().replaceAll('-', ''), token_hash: createHash('sha256').update(token).digest('hex'),
    role, created_at: new Date().toISOString(), expires_at: new Date(Date.now() + hours * 3600000).toISOString(),
  }).throwOnError();
  console.log('Invitation created. Its value was not printed or saved to a file.');
}
main().then(() => process.exit(0)).catch(() => {
  console.error('Invitation creation failed. Verify the role, lifetime, and deployed database context.');
  process.exit(1);
});
