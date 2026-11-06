import { createClient } from "@supabase/supabase-js";
import { createHash, randomBytes, randomUUID } from "node:crypto";

const role = process.argv[2] || "viewer";
const lifetimeHours = Number(process.argv[3] || 24);
if (!["administrator", "document_owner", "viewer"].includes(role)) {
  throw new Error("Role must be administrator, document_owner, or viewer.");
}
if (!Number.isFinite(lifetimeHours) || lifetimeHours <= 0 || lifetimeHours > 720) {
  throw new Error("Invite lifetime must be greater than 0 and no more than 720 hours.");
}

const url = process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
if (!url || !serviceKey) {
  throw new Error("Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in this trusted terminal.");
}

const token = randomBytes(32).toString("base64url");
const tokenHash = createHash("sha256").update(token, "utf8").digest("hex");
const createdAt = new Date().toISOString();
const expiresAt = new Date(Date.now() + lifetimeHours * 60 * 60 * 1000).toISOString();
const client = createClient(url, serviceKey, {
  auth: { persistSession: false, autoRefreshToken: false },
});
const { error } = await client.from("registration_invites").insert({
  id: randomUUID().replaceAll("-", ""),
  token_hash: tokenHash,
  role,
  created_at: createdAt,
  expires_at: expiresAt,
});
if (error) throw error;
console.log(`Invite token (shown once; role ${role}; expires ${expiresAt}):\n${token}`);
