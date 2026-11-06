import { createRepository } from "../../db/repository.mjs";
import { privateDocuments } from "../../db/storage.mjs";
import bcrypt from "bcryptjs";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import jpeg from "jpeg-js";
import { PDFDocument } from "pdf-lib";
import { PNG } from "pngjs";

const SESSION_COOKIE = "trustvault_session";
const SESSION_MAX_AGE = 8 * 60 * 60;
const MAX_FILE_BYTES = 4 * 1024 * 1024;
const ROLES = new Set(["administrator", "document_owner", "viewer"]);
const PERMISSIONS = new Set(["read", "edit"]);
const ALLOWED_EXTENSIONS = new Set(["pdf", "png", "jpg", "jpeg", "txt"]);
const MIME_TYPES = {
  pdf: "application/pdf",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  txt: "text/plain",
};
const ACTIVE_CONTENT_MARKERS = [
  /<\s*script\b/i,
  /<\s*svg\b/i,
  /<\s*html\b/i,
  /<\s*iframe\b/i,
  /<\s*object\b/i,
  /<\s*embed\b/i,
];
const GENESIS_HASH = "0".repeat(64);


function jsonResponse(status, value, headers = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
      ...headers,
    },
  });
}

function cookieValue(request, name) {
  const source = request.headers.get("cookie") || "";
  for (const part of source.split(";")) {
    const index = part.indexOf("=");
    if (index > 0 && part.slice(0, index).trim() === name) {
      try {
        return decodeURIComponent(part.slice(index + 1).trim());
      } catch {
        return null;
      }
    }
  }
  return null;
}

function setSessionCookie(token, maxAge = SESSION_MAX_AGE) {
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

async function createSession(user, store) {
  const token = randomBytes(32).toString("base64url");
  await store.from("server_sessions").insert({
    sid_hash: hashHex(token), user_id: user.id, auth_version: user.auth_version,
    created_at: nowUtc(), expires_at: new Date(Date.now() + SESSION_MAX_AGE * 1000).toISOString(),
  }).throwOnError();
  return { token, csrf: hashHex("csrf:" + token) };
}

async function currentUser(request, store) {
  const token = cookieValue(request, SESSION_COOKIE);
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) return { user: null, csrf: null };
  const session = await store.from("server_sessions").select("user_id,auth_version,expires_at")
    .eq("sid_hash", hashHex(token)).maybeSingle().throwOnError();
  if (!session.data || session.data.expires_at <= new Date().toISOString()) return { user: null, csrf: null };
  const { data } = await store.from("users")
    .select("id,email,name,role,status,auth_version,created_at")
    .eq("id", session.data.user_id).maybeSingle().throwOnError();
  if (!data || data.status !== "active" || data.auth_version !== session.data.auth_version) {
    return { user: null, csrf: null };
  }
  return { user: data, csrf: hashHex("csrf:" + token) };
}

async function requestBody(request) {
  const type = request.headers.get("content-type") || "";
  if (type.includes("application/json")) {
    let data;
    try {
      data = await request.json();
    } catch (error) {
      if (error instanceof SyntaxError) throw new HttpError(400, "The JSON request body is invalid.");
      throw error;
    }
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      throw new HttpError(400, "A JSON object is required.");
    }
    return data;
  }
  if (type.includes("multipart/form-data")) return request.formData();
  throw new HttpError(415, "Unsupported request content type.");
}

function assertCsrf(request, csrf) {
  if (!csrf || request.headers.get("x-csrf-token") !== csrf) {
    throw new HttpError(403, "The request could not be verified.");
  }
}

function safeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    status: user.status,
    created_at: user.created_at,
  };
}

function pagination(url) {
  const page = Number(url.searchParams.get("page") || 1);
  const pageSize = Number(url.searchParams.get("page_size") || 20);
  if (!Number.isInteger(page) || page < 1 || page > 10000 ||
      !Number.isInteger(pageSize) || pageSize < 1 || pageSize > 100) {
    throw new HttpError(400, "Invalid pagination values.");
  }
  return { page, pageSize, from: (page - 1) * pageSize, to: page * pageSize - 1 };
}

function paginated(items, total, page, pageSize) {
  return {
    items,
    total,
    page,
    page_size: pageSize,
    pages: total ? Math.ceil(total / pageSize) : 0,
  };
}

function newId() {
  return randomUUID().replaceAll("-", "");
}

function nowUtc() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function hashHex(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

async function validateDocument(content, extension) {
  if (!content.length || content.length > MAX_FILE_BYTES) {
    throw new HttpError(400, "The file must be between 1 byte and 4 MB.");
  }
  if (
    content.subarray(0, 2).toString() === "MZ" ||
    content.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) ||
    content.subarray(0, 2).toString() === "#!"
  ) {
    throw new HttpError(400, "Executable and archive files are not supported.");
  }
  const contentText = content.toString("latin1");
  if (ACTIVE_CONTENT_MARKERS.some((marker) => marker.test(contentText))) {
    throw new HttpError(400, "HTML, SVG, and active markup are not supported.");
  }
  try {
    if (extension === "txt") {
      new TextDecoder("utf-8", { fatal: true }).decode(content);
      if (/\u0000|[\u0001-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(content.toString("utf8"))) {
        throw new HttpError(400, "Text contains unsupported control characters.");
      }
    } else if (extension === "png") {
      const image = PNG.sync.read(content, { checkCRC: true });
      if (!image.width || !image.height || image.width * image.height > 40_000_000) {
        throw new HttpError(400, "The image format or dimensions are not supported.");
      }
    } else if (extension === "jpg" || extension === "jpeg") {
      const image = jpeg.decode(content, {
        useTArray: true,
        tolerantDecoding: false,
        maxResolutionInMP: 40,
        maxMemoryUsageInMB: 256,
      });
      if (!image.width || !image.height || image.width * image.height > 40_000_000) {
        throw new HttpError(400, "The image format or dimensions are not supported.");
      }
    } else if (extension === "pdf") {
      if (
        !content.subarray(0, 5).equals(Buffer.from("%PDF-")) ||
        !content.subarray(-2048).includes(Buffer.from("%%EOF")) ||
        /\/(?:JavaScript|JS|Launch|OpenAction|EmbeddedFiles|RichMedia)\b/i.test(contentText)
      ) {
        throw new HttpError(400, "The PDF is incomplete or contains unsupported active content.");
      }
      const document = await PDFDocument.load(content, {
        ignoreEncryption: false,
        updateMetadata: false,
      });
      if (!document.getPageCount() || document.getPageCount() > 10_000) {
        throw new HttpError(400, "The PDF document is not supported.");
      }
    }
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(400, "The file is malformed or unsafe.");
  }
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
    ).join(",")}}`;
  }
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new HttpError(400, "Audit details contain an invalid number.");
  }
  return JSON.stringify(value);
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function appendAudit(store, event) {
  const details = event.details || {};
  validateAuditDetails(details);
  return store.appendAudit({
    id: newId(), timestamp: event.timestamp || nowUtc(),
    user_id: event.user_id || null, username: event.username || null,
    action: event.action, document_id: event.document_id || null,
    ip_address: event.ip_address?.slice(0, 64) || null,
    status: event.status || "success", details,
    user_agent: event.user_agent || null,
  });
}

function validateAuditDetails(value, key = "") {
  const forbidden = ["password", "secret", "token", "credential", "sessionid", "documentcontent"];
  if (Array.isArray(value)) {
    for (const child of value) validateAuditDetails(child, key);
    return;
  }
  if (value && typeof value === "object") {
    for (const [childKey, child] of Object.entries(value)) {
      if (typeof childKey !== "string") {
        throw new HttpError(400, "Audit detail keys must be strings.");
      }
      const normalized = childKey.toLowerCase().replace(/[^a-z0-9]/g, "");
      if (forbidden.some((fragment) => normalized.includes(fragment))) {
        throw new HttpError(400, "Sensitive audit detail fields are not allowed.");
      }
      validateAuditDetails(child, normalized);
    }
    return;
  }
  if (
    value !== null &&
    typeof value !== "string" &&
    typeof value !== "number" &&
    typeof value !== "boolean"
  ) {
    throw new HttpError(400, "Audit details contain an unsupported value.");
  }
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new HttpError(400, "Audit details contain an invalid number.");
  }
}

async function authorizeDocument(store, user, documentId, permission, ownerOnly = false) {
  const result = await store
    .from("documents")
    .select("*")
    .eq("id", documentId)
    .is("deleted_at", null)
    .maybeSingle();
  if (result.error) throw result.error;
  const document = result.data;
  if (!document) throw new HttpError(404, "The requested resource is not available.");
  if (document.owner_id === user.id) return document;
  if (ownerOnly) throw new HttpError(404, "The requested resource is not available.");
  const grantResult = await store
    .from("document_permissions")
    .select("permission,expires_at")
    .eq("document_id", documentId)
    .eq("user_id", user.id)
    .is("revoked_at", null)
    .maybeSingle();
  if (grantResult.error) throw grantResult.error;
  const grant = grantResult.data;
  const grantActive =
    grant && (!grant.expires_at || grant.expires_at > nowUtc());
  if (
    !grantActive ||
    (permission === "edit" && grant.permission !== "edit")
  ) {
    throw new HttpError(404, "The requested resource is not available.");
  }
  return document;
}

async function requireUser(user) {
  if (!user) throw new HttpError(401, "Authentication is required.");
  return user;
}

async function requireAdmin(user) {
  await requireUser(user);
  if (user.role !== "administrator") {
    throw new HttpError(403, "Administrator access is required.");
  }
}

async function handleApi(request, url, context, services) {
  const store = services.repository();
  const { user, csrf } = await currentUser(request, store);
  const method = request.method.toUpperCase();
  const pathname = url.pathname;
  const ip = context.ip || "unknown";
  const userAgent = (request.headers.get("user-agent") || "").slice(0, 512);

  if (pathname === "/healthz" && method === "GET") {
    const { error } = await store.from("users").select("id").limit(1);
    if (error) throw error;
    return jsonResponse(200, { status: "ok" });
  }

  if (pathname === "/api/auth/csrf" && method === "GET") {
    return jsonResponse(200, { csrf_token: csrf });
  }

  if (pathname === "/api/auth/register" && method === "POST") {
    const data = await requestBody(request);
    const name = typeof data.name === "string" ? data.name.trim() : "";
    const email = typeof data.email === "string" ? data.email.trim().toLowerCase() : "";
    const password = typeof data.password === "string" ? data.password : "";
    const inviteToken = typeof data.invite_token === "string" ? data.invite_token.trim() : "";
    if (
      name.length < 1 ||
      name.length > 120 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      email.length > 254 ||
      password.length < 12 ||
      Buffer.byteLength(password, "utf8") > 72 ||
      inviteToken.length < 32 ||
      inviteToken.length > 256
    ) {
      throw new HttpError(400, "Registration details are invalid.");
    }
    const tokenHash = hashHex(inviteToken);
    const inviteResult = await store
      .from("registration_invites")
      .select("id,role,expires_at,consumed_at")
      .eq("token_hash", tokenHash)
      .maybeSingle();
    if (inviteResult.error) throw inviteResult.error;
    const invite = inviteResult.data;
    if (
      !invite ||
      invite.consumed_at ||
      invite.expires_at <= nowUtc() ||
      !ROLES.has(invite.role)
    ) {
      throw new HttpError(400, "The invitation is invalid or expired.");
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const createdAt = nowUtc();
    try {
      await store.transaction(async transaction => {
        const consumed = await transaction.from("registration_invites")
          .update({ consumed_at: createdAt }).eq("id", invite.id)
          .is("consumed_at", null).gt("expires_at", createdAt)
          .select("id").maybeSingle().throwOnError();
        if (!consumed.data) throw new HttpError(409, "The invitation was already used.");
        const id = newId();
        await transaction.from("users").insert({
          id, email, name, password_hash: passwordHash, role: invite.role,
          status: "active", auth_version: 1, created_at: createdAt, updated_at: createdAt,
        }).throwOnError();
        await appendAudit(transaction, {
          action: "user_registered", user_id: id, username: email,
          ip_address: ip, user_agent: userAgent, details: { role: invite.role },
        });
      });
    } catch (error) {
      if ((error?.cause?.code || error?.code) === "23505") {
        throw new HttpError(409, "An account with that email already exists.");
      }
      throw error;
    }
    return jsonResponse(201, { message: "Account created. You can now sign in." });
  }

  if (pathname === "/api/auth/login" && method === "POST") {
    const data = await requestBody(request);
    const email = typeof data.email === "string" ? data.email.trim().toLowerCase() : "";
    const password = typeof data.password === "string" ? data.password : "";
    if (email.length > 254 || Buffer.byteLength(password, "utf8") > 72) {
      throw new HttpError(400, "Invalid email or password.");
    }
    const identifierHash = hashHex(email);
    const windowStart = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    const [identifierAttempts, ipAttempts] = await Promise.all([
      store
      .from("login_attempts")
      .select("id")
      .eq("username_key", identifierHash)
      .eq("outcome", "failed")
      .gt("attempted_at", windowStart)
      .limit(100),
      store
        .from("login_attempts")
        .select("id")
        .eq("source_ip", ip.slice(0, 64))
        .eq("outcome", "failed")
        .gt("attempted_at", windowStart)
        .limit(100),
    ]);
    if (identifierAttempts.error) throw identifierAttempts.error;
    if (ipAttempts.error) throw ipAttempts.error;
    const failedAttempts = new Set([
      ...identifierAttempts.data.map((attempt) => attempt.id),
      ...ipAttempts.data.map((attempt) => attempt.id),
    ]).size;
    const userResult = await store
      .from("users")
      .select("id,email,name,role,status,auth_version,created_at,password_hash")
      .eq("email", email)
      .maybeSingle();
    if (userResult.error) throw userResult.error;
    const candidate = userResult.data;
    const matches = candidate
      ? await bcrypt.compare(password, candidate.password_hash)
      : await bcrypt.compare(password, "$2b$12$2b2f6CnaF2vNyWWDg5FYjeI2idrrI.gCwyg2Hv6DgJtY3mxVtjH4K");
    const accepted =
      failedAttempts < 5 &&
      candidate?.status === "active" &&
      matches;
    await store.from("login_attempts").insert({
      id: newId(),
      username_key: identifierHash,
      source_ip: ip.slice(0, 64),
      attempted_at: nowUtc(),
      outcome: accepted ? "success" : failedAttempts >= 5 ? "blocked" : "failed",
    }).throwOnError();
    if (!accepted) {
      await appendAudit(store, {
        action: "login_failed",
        user_id: candidate?.id,
        username: email || null,
        ip_address: ip,
        user_agent: userAgent,
        status: failedAttempts >= 5 ? "denied" : "failure",
        details: { reason: failedAttempts >= 5 ? "rate_limited" : "invalid_credentials" },
      });
      throw new HttpError(401, "Invalid email or password.");
    }
    const session = await createSession(candidate, store);
    await appendAudit(store, {
      action: "login_succeeded",
      user_id: candidate.id,
      username: candidate.email,
      ip_address: ip,
      user_agent: userAgent,
    });
    return jsonResponse(
      200,
      { user: safeUser(candidate), csrf_token: session.csrf },
      { "Set-Cookie": setSessionCookie(session.token) },
    );
  }

  if (pathname === "/api/auth/me" && method === "GET") {
    await requireUser(user);
    return jsonResponse(200, { user: safeUser(user), csrf_token: csrf });
  }

  if (pathname === "/api/auth/logout" && method === "POST") {
    assertCsrf(request, csrf);
    if (user) {
      await appendAudit(store, {
        action: "logout",
        user_id: user.id,
        username: user.email,
        ip_address: ip,
        user_agent: userAgent,
      });
    }
    const logoutCookie = cookieValue(request, SESSION_COOKIE);
    if (logoutCookie) await store.from("server_sessions").delete().eq("sid_hash", hashHex(logoutCookie)).throwOnError();
    return jsonResponse(200, { message: "Signed out." }, { "Set-Cookie": clearSessionCookie() });
  }

  if (pathname === "/api/documents" && method === "GET") {
    await requireUser(user);
    const query = (url.searchParams.get("q") || "").trim().slice(0, 254).toLowerCase();
    const { page, pageSize } = pagination(url);
    const owned = await store
      .from("documents")
      .select("id,owner_id,name,description,category,mime_type,size_bytes,created_at,updated_at", { count: "exact" })
      .eq("owner_id", user.id)
      .is("deleted_at", null)
      .order("created_at", { ascending: false });
    if (owned.error) throw owned.error;
    const grants = await store
      .from("document_permissions")
      .select("document_id,permission,expires_at")
      .eq("user_id", user.id)
      .is("revoked_at", null);
    if (grants.error) throw grants.error;
    const ids = grants.data
      .filter((grant) => !grant.expires_at || grant.expires_at > nowUtc())
      .map((grant) => grant.document_id);
    let shared = { data: [], error: null };
    if (ids.length) {
      shared = await store
        .from("documents")
        .select("id,owner_id,name,description,category,mime_type,size_bytes,created_at,updated_at")
        .in("id", ids)
        .is("deleted_at", null)
        .neq("owner_id", user.id);
      if (shared.error) throw shared.error;
    }
    const docs = [...owned.data, ...(shared.data || [])]
      .filter((doc) =>
        !query ||
        [doc.name, doc.description, doc.category].some((value) =>
          value.toLowerCase().includes(query),
        ),
      )
      .sort((a, b) => b.created_at.localeCompare(a.created_at));
    const start = (page - 1) * pageSize;
    return jsonResponse(200, {
      documents: docs.slice(start, start + pageSize).map((doc) => ({
        ...doc,
        permission: doc.owner_id === user.id
          ? "owner"
          : grants.data.find((grant) => grant.document_id === doc.id)?.permission,
      })),
      total: docs.length,
      page,
      page_size: pageSize,
    });
  }

  if (pathname === "/api/documents" && method === "POST") {
    await requireUser(user);
    assertCsrf(request, csrf);
    if (user.role !== "document_owner") {
      throw new HttpError(403, "Document owner access is required.");
    }
    const data = await requestBody(request);
    if (!(data instanceof FormData)) throw new HttpError(415, "A multipart file upload is required.");
    const file = data.get("file");
    if (!(file instanceof File) || file.size < 1 || file.size > MAX_FILE_BYTES) {
      throw new HttpError(400, "Choose a file up to 4 MB.");
    }
    const originalName = file.name
      .replaceAll("\\", "/")
      .split("/")
      .pop()
      .replace(/[\u0000-\u001f\u007f]/g, "_");
    const extension = originalName.split(".").pop().toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(extension)) {
      throw new HttpError(400, "This file type is not allowed.");
    }
    const content = Buffer.from(await file.arrayBuffer());
    await validateDocument(content, extension);
    const description = String(data.get("description") || "").trim();
    const category = String(data.get("category") || "general").trim();
    if (description.length > 2000 || !category || category.length > 64) {
      throw new HttpError(400, "Document metadata is invalid.");
    }
    const documentId = newId();
    const storageKey = `${newId()}.${extension}`;
    const digest = hashHex(content);
    const blobStore = services.documentStore(context);
    const upload = await blobStore.upload(storageKey, content);
    if (upload.error) throw upload.error;
    const createdAt = nowUtc();
    const created = await store.from("documents").insert({
      id: documentId,
      owner_id: user.id,
      storage_key: storageKey,
      name: originalName.slice(0, 255),
      description,
      category,
      mime_type: MIME_TYPES[extension],
      size_bytes: content.length,
      sha256: digest,
      scan_status: "approved",
      created_at: createdAt,
      updated_at: createdAt,
    }).select("id,name,description,category,mime_type,size_bytes,created_at,updated_at").single();
    if (created.error) {
      await blobStore.remove([storageKey]);
      throw created.error;
    }
    await appendAudit(store, {
      action: "document_uploaded",
      user_id: user.id,
      username: user.email,
      document_id: documentId,
      ip_address: ip,
      user_agent: userAgent,
      details: { name: originalName, size_bytes: content.length, sha256: digest },
    });
    return jsonResponse(201, { document: created.data });
  }

  const documentRoute = pathname.match(/^\/api\/documents\/([a-f0-9]{32})(?:\/(download|permissions)(?:\/([a-f0-9]{32}))?)?$/);
  if (documentRoute) {
    await requireUser(user);
    const [, documentId, action, grantId] = documentRoute;
    if (!action && method === "GET" || action === "download" && method === "GET") {
      const doc = await authorizeDocument(store, user, documentId, "read");
      const download = await services.documentStore(context).download(doc.storage_key);
      if (download.error) throw new HttpError(404, "The requested resource is not available.");
      const bytes = await download.data.arrayBuffer();
      await appendAudit(store, {
        action: action ? "document_downloaded" : "document_viewed",
        user_id: user.id,
        username: user.email,
        document_id: documentId,
        ip_address: ip,
        user_agent: userAgent,
        details: { size_bytes: bytes.byteLength },
      });
      const filename = doc.name.replace(/[^\x20-\x7e]|["\\]/g, "_");
      return new Response(bytes, {
        status: 200,
        headers: {
          "Content-Type": doc.mime_type,
          "Content-Length": String(bytes.byteLength),
          "Content-Disposition": `${action ? "attachment" : "inline"}; filename="${filename}"`,
          "Cache-Control": "private, no-store",
          "X-Content-Type-Options": "nosniff",
        },
      });
    }
    if (!action && method === "PATCH") {
      assertCsrf(request, csrf);
      const doc = await authorizeDocument(store, user, documentId, "edit");
      const body = await requestBody(request);
      const allowed = new Set(["name", "description", "category"]);
      if (!Object.keys(body).length || Object.keys(body).some((key) => !allowed.has(key))) {
        throw new HttpError(400, "Only name, description, and category may be updated.");
      }
      const changes = { updated_at: nowUtc() };
      if ("name" in body) {
        if (typeof body.name !== "string" || !body.name.trim() || body.name.trim().length > 255) {
          throw new HttpError(400, "Document name is invalid.");
        }
        changes.name = body.name.trim();
      }
      if ("description" in body) {
        if (typeof body.description !== "string" || body.description.length > 2000) {
          throw new HttpError(400, "Document description is invalid.");
        }
        changes.description = body.description.trim();
      }
      if ("category" in body) {
        if (typeof body.category !== "string" || !body.category.trim() || body.category.trim().length > 64) {
          throw new HttpError(400, "Document category is invalid.");
        }
        changes.category = body.category.trim();
      }
      const updated = await store.from("documents").update(changes).eq("id", doc.id)
        .select("id,name,description,category,mime_type,size_bytes,created_at,updated_at").single();
      if (updated.error) throw updated.error;
      await appendAudit(store, {
        action: "document_metadata_edited",
        user_id: user.id,
        username: user.email,
        document_id: doc.id,
        ip_address: ip,
        user_agent: userAgent,
        details: { fields: Object.keys(changes).filter((key) => key !== "updated_at").sort() },
      });
      return jsonResponse(200, { document: updated.data });
    }
    if (!action && method === "DELETE") {
      assertCsrf(request, csrf);
      const doc = await authorizeDocument(store, user, documentId, "edit");
      const deletedAt = nowUtc();
      const deleted = await store.from("documents")
        .update({ deleted_at: deletedAt, updated_at: deletedAt })
        .eq("id", doc.id)
        .is("deleted_at", null)
        .select("id")
        .maybeSingle();
      if (deleted.error) throw deleted.error;
      if (!deleted.data) throw new HttpError(404, "The requested resource is not available.");
      await appendAudit(store, {
        action: "document_deleted",
        user_id: user.id,
        username: user.email,
        document_id: doc.id,
        ip_address: ip,
        user_agent: userAgent,
      });
      const removed = await services.documentStore(context).remove([doc.storage_key]);
      if (removed.error) {
        console.error("Deleted document object cleanup failed");
        throw new HttpError(500, "Document access was revoked, but private storage cleanup failed.");
      }
      return jsonResponse(200, { message: "Document deleted." });
    }
    if (action === "permissions" && !grantId && method === "GET") {
      const doc = await authorizeDocument(store, user, documentId, "edit", true);
      const result = await store
        .from("document_permissions")
        .select("id,user_id,permission,granted_at,expires_at,revoked_at,users(email,name)")
        .eq("document_id", doc.id)
        .order("granted_at", { ascending: false });
      if (result.error) throw result.error;
      return jsonResponse(200, { permissions: result.data });
    }
    if (action === "permissions" && !grantId && method === "POST") {
      assertCsrf(request, csrf);
      const doc = await authorizeDocument(store, user, documentId, "edit", true);
      const body = await requestBody(request);
      const recipientEmail = typeof body.recipient_email === "string"
        ? body.recipient_email.trim().toLowerCase()
        : "";
      const permission = body.permission;
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipientEmail) || !PERMISSIONS.has(permission)) {
        throw new HttpError(400, "Permission details are invalid.");
      }
      const recipient = await store.from("users").select("id,status,email,role")
        .eq("email", recipientEmail).maybeSingle();
      if (recipient.error) throw recipient.error;
      if (
        !recipient.data ||
        recipient.data.status !== "active" ||
        recipient.data.id === user.id ||
        (recipient.data.role === "viewer" && permission === "edit")
      ) {
        throw new HttpError(400, "The selected account cannot receive access.");
      }
      const prior = await store.from("document_permissions").select("id,expires_at")
        .eq("document_id", doc.id)
        .eq("user_id", recipient.data.id)
        .is("revoked_at", null)
        .maybeSingle();
      if (prior.error) throw prior.error;
      if (prior.data) {
        if (!prior.data.expires_at || prior.data.expires_at > nowUtc()) {
          throw new HttpError(409, "An active permission already exists for this account.");
        }
        const expiredAt = nowUtc();
        const revoked = await store.from("document_permissions")
          .update({ revoked_at: expiredAt })
          .eq("id", prior.data.id)
          .is("revoked_at", null)
          .select("id")
          .maybeSingle();
        if (revoked.error) throw revoked.error;
        if (revoked.data) {
          await appendAudit(store, {
            action: "document_permission_expired",
            user_id: user.id,
            username: user.email,
            document_id: doc.id,
            ip_address: ip,
            user_agent: userAgent,
            details: { grant_id: prior.data.id, recipient_id: recipient.data.id },
          });
        }
      }
      const createdAt = nowUtc();
      const grant = await store.from("document_permissions").insert({
        id: newId(),
        document_id: doc.id,
        user_id: recipient.data.id,
        granted_by: user.id,
        permission,
        granted_at: createdAt,
      }).select("id,user_id,permission,granted_at").single();
      if (grant.error) {
        if (grant.error.code === "23505") {
          throw new HttpError(409, "An active permission already exists for this account.");
        }
        throw grant.error;
      }
      await appendAudit(store, {
        action: "document_permission_granted",
        user_id: user.id,
        username: user.email,
        document_id: doc.id,
        ip_address: ip,
        user_agent: userAgent,
        details: { grant_id: grant.data.id, recipient_id: recipient.data.id, permission },
      });
      return jsonResponse(201, { permission: grant.data });
    }
    if (action === "permissions" && grantId && method === "DELETE") {
      assertCsrf(request, csrf);
      const doc = await authorizeDocument(store, user, documentId, "edit", true);
      const revokedAt = nowUtc();
      const revoked = await store.from("document_permissions")
        .update({ revoked_at: revokedAt })
        .eq("id", grantId)
        .eq("document_id", doc.id)
        .is("revoked_at", null)
        .select("id,user_id")
        .maybeSingle();
      if (revoked.error) throw revoked.error;
      if (!revoked.data) throw new HttpError(404, "Permission not found.");
      await appendAudit(store, {
        action: "document_permission_revoked",
        user_id: user.id,
        username: user.email,
        document_id: doc.id,
        ip_address: ip,
        user_agent: userAgent,
        details: { grant_id: grantId, recipient_id: revoked.data.user_id },
      });
      return jsonResponse(200, { message: "Permission revoked." });
    }
  }

  if (pathname.startsWith("/api/admin/")) {
    await requireAdmin(user);
    if (method !== "GET") assertCsrf(request, csrf);
    if (pathname === "/api/admin/invites" && method === "POST") {
      const body = await requestBody(request);
      const role = body.role;
      const lifetimeHours = body.expires_in_hours === undefined
        ? 24
        : Number(body.expires_in_hours);
      if (
        Object.keys(body).some((key) => !["role", "expires_in_hours"].includes(key)) ||
        !ROLES.has(role) ||
        !Number.isInteger(lifetimeHours) ||
        lifetimeHours < 1 ||
        lifetimeHours > 720
      ) {
        throw new HttpError(400, "Invitation role or lifetime is invalid.");
      }
      const token = randomBytes(32).toString("base64url");
      const createdAt = nowUtc();
      const expiresAt = new Date(Date.now() + lifetimeHours * 60 * 60 * 1000)
        .toISOString()
        .replace(/\.\d{3}Z$/, "Z");
      const invite = await store.from("registration_invites").insert({
        id: newId(),
        token_hash: hashHex(token),
        role,
        created_at: createdAt,
        expires_at: expiresAt,
        created_by: user.id,
      }).select("id").single();
      if (invite.error) throw invite.error;
      await appendAudit(store, {
        action: "registration_invite_created",
        user_id: user.id,
        username: user.email,
        ip_address: ip,
        user_agent: userAgent,
        details: { role, expires_at: expiresAt },
      });
      return jsonResponse(201, { token, role, expires_at: expiresAt });
    }
    if (pathname === "/api/admin/dashboard" && method === "GET") {
      const count = (table, configure = (query) => query) =>
        configure(store.from(table).select("*", { count: "exact", head: true }));
      const queries = await Promise.all([
        count("users"),
        count("users", (query) => query.eq("role", "administrator")),
        count("users", (query) => query.eq("role", "document_owner")),
        count("users", (query) => query.eq("role", "viewer")),
        count("users", (query) => query.eq("status", "active")),
        count("users", (query) => query.eq("status", "disabled")),
        count("documents"),
        count("document_permissions", (query) =>
          query.is("revoked_at", null).or(`expires_at.is.null,expires_at.gt.${nowUtc()}`)),
        store.from("users").select("id,name,email,role,status,created_at")
          .order("created_at", { ascending: false }).limit(8),
        store.from("documents")
          .select("id,name,mime_type,created_at,owner_id,users(name,email)")
          .order("created_at", { ascending: false }).limit(8),
        store.from("audit_logs")
          .select("id,timestamp,username,action,status,ip_address,document_id")
          .in("status", ["denied", "failure"])
          .order("sequence", { ascending: false }).limit(10),
      ]);
      const failed = queries.find((result) => result.error);
      if (failed) throw failed.error;
      return jsonResponse(200, {
        counts: Object.fromEntries([
          "total_users", "administrators", "document_owners", "viewers",
          "active_users", "disabled_users", "total_documents", "shared_documents",
        ].map((key, index) => [key, queries[index].count || 0])),
        recent_users: queries[8].data,
        recent_documents: queries[9].data,
        recent_security_events: queries[10].data,
      });
    }
    if (pathname === "/api/admin/users" && method === "GET") {
      const { page, pageSize, from, to } = pagination(url);
      let query = store.from("users")
        .select("id,name,email,role,status,created_at", { count: "exact" })
        .order("created_at", { ascending: false })
        .range(from, to);
      const role = url.searchParams.get("role");
      const status = url.searchParams.get("status");
      const search = (url.searchParams.get("q") || "").trim().slice(0, 254);
      if (role) {
        if (!ROLES.has(role)) throw new HttpError(400, "Invalid role.");
        query = query.eq("role", role);
      }
      if (status) {
        if (!["active", "disabled"].includes(status)) throw new HttpError(400, "Invalid status.");
        query = query.eq("status", status);
      }
      let result = await query;
      if (result.error) throw result.error;
      let users = result.data;
      let total = result.count || 0;
      if (search) {
        const pattern = `%${search.replaceAll("\\", "\\\\").replaceAll("%", "\\%").replaceAll("_", "\\_")}%`;
        const [names, emails] = await Promise.all([
          store.from("users")
            .select("id,name,email,role,status,created_at")
            .ilike("name", pattern)
            .order("created_at", { ascending: false }).limit(1000),
          store.from("users")
            .select("id,name,email,role,status,created_at")
            .ilike("email", pattern)
            .order("created_at", { ascending: false }).limit(1000),
        ]);
        if (names.error) throw names.error;
        if (emails.error) throw emails.error;
        const matches = new Map([...names.data, ...emails.data].map((account) => [account.id, account]));
        users = [...matches.values()]
          .filter((account) => (!role || account.role === role) && (!status || account.status === status))
          .sort((left, right) => right.created_at.localeCompare(left.created_at));
        total = users.length;
        users = users.slice(from, to + 1);
      }
      const items = await Promise.all(users.map(async (account) => {
        const [uploads, shares] = await Promise.all([
          store.from("documents").select("id", { count: "exact", head: true })
            .eq("owner_id", account.id),
          store.from("document_permissions").select("id", { count: "exact", head: true })
            .eq("granted_by", account.id),
        ]);
        if (uploads.error) throw uploads.error;
        if (shares.error) throw shares.error;
        return { ...account, uploaded_documents: uploads.count || 0, shared_documents: shares.count || 0 };
      }));
      return jsonResponse(200, paginated(items, total, page, pageSize));
    }
    const userRoute = pathname.match(/^\/api\/admin\/users\/([a-f0-9]{32})(?:\/(role|status|activity|documents))?$/);
    if (userRoute) {
      const [, targetId, action] = userRoute;
      if ((action === "role" || action === "status") && method === "PATCH") {
        const body = await requestBody(request);
        const field = action;
        const value = body?.[field];
        if (
          Object.keys(body).length !== 1 ||
          (field === "role" && !ROLES.has(value)) ||
          (field === "status" && !["active", "disabled"].includes(value))
        ) {
          throw new HttpError(400, field === "role" ? "Provide a valid role." : "Status is invalid.");
        }
        if (targetId === user.id) {
          throw new HttpError(400, field === "role" ? "You cannot change your own role." : "You cannot change your own status.");
        }
        const result = await store.adminUpdate({
          actorId: user.id, targetId, field, value, timestamp: nowUtc(),
        });
        if (result.error) {
          if (result.error.code === "P0002") throw new HttpError(404, "User not found.");
          if (result.error.code === "23514") throw new HttpError(409, "The last active administrator cannot be removed.");
          if (result.error.code === "42501") throw new HttpError(403, "Administrator access is required.");
          throw result.error;
        }
        await appendAudit(store, {
          action: "user_" + field + "_updated", user_id: user.id, username: user.email,
          ip_address: ip, user_agent: userAgent, details: { target_id: targetId, field, value },
        });
        return jsonResponse(200, { message: `${field === "role" ? "Role" : "Account status"} updated.`, ...result.data });
      }
      const target = await store.from("users")
        .select("id,name,email,role,status,created_at,updated_at")
        .eq("id", targetId).maybeSingle();
      if (target.error) throw target.error;
      if (!target.data) throw new HttpError(404, "User not found.");
      if (action === "activity" && method === "GET") {
        const { page, pageSize, from, to } = pagination(url);
        const result = await store.from("audit_logs")
          .select("id,timestamp,username,action,document_id,status,details,ip_address", { count: "exact" })
          .eq("user_id", targetId)
          .order("sequence", { ascending: false }).range(from, to);
        if (result.error) throw result.error;
        return jsonResponse(200, paginated(result.data, result.count || 0, page, pageSize));
      }
      if (action === "documents" && method === "GET") {
        const { page, pageSize, from, to } = pagination(url);
        const result = await store.from("documents")
          .select("id,name,category,mime_type,size_bytes,created_at,updated_at,deleted_at", { count: "exact" })
          .eq("owner_id", targetId).order("created_at", { ascending: false }).range(from, to);
        if (result.error) throw result.error;
        return jsonResponse(200, paginated(result.data, result.count || 0, page, pageSize));
      }
      if (!action && method === "GET") return jsonResponse(200, { user: target.data });
    }
    if (pathname === "/api/admin/documents" && method === "GET") {
      const { page, pageSize, from, to } = pagination(url);
      const result = await store.from("documents")
        .select("id,name,category,mime_type,size_bytes,scan_status,created_at,updated_at,deleted_at,owner_id,users(name,email)", { count: "exact" })
        .order("created_at", { ascending: false }).range(from, to);
      if (result.error) throw result.error;
      return jsonResponse(200, paginated(result.data, result.count || 0, page, pageSize));
    }
    if (["/api/admin/activity", "/api/admin/audit-logs"].includes(pathname) && method === "GET") {
      const { page, pageSize, from, to } = pagination(url);
      let query = store.from("audit_logs")
        .select("id,sequence,timestamp,user_id,username,action,document_id,ip_address,status,details", { count: "exact" })
        .order("sequence", { ascending: false }).range(from, to);
      const status = url.searchParams.get("status");
      if (status) {
        if (!["success", "failure", "denied"].includes(status)) throw new HttpError(400, "Invalid audit status.");
        query = query.eq("status", status);
      }
      const action = url.searchParams.get("action");
      if (action) query = query.eq("action", action.slice(0, 100));
      const result = await query;
      if (result.error) throw result.error;
      return jsonResponse(200, paginated(result.data, result.count || 0, page, pageSize));
    }
    if (pathname === "/api/admin/reports" && method === "GET") {
      const tables = [
        ["users_by_role", "users", "role"],
        ["users_by_status", "users", "status"],
        ["documents_by_type", "documents", "mime_type"],
        ["permissions_by_type", "document_permissions", "permission"],
      ];
      const reports = {};
      for (const [key, table, column] of tables) {
        const result = await store.from(table).select(column).limit(5000);
        if (result.error) throw result.error;
        const counts = new Map();
        for (const row of result.data) counts.set(row[column], (counts.get(row[column]) || 0) + 1);
        reports[key] = [...counts].map(([value, count]) => ({
          [column === "mime_type" ? "mime_type" : column]: value,
          count,
        }));
      }
      return jsonResponse(200, reports);
    }
    throw new HttpError(404, "Administrator API route not found.");
  }

  throw new HttpError(404, "Not found.");
}

function pageResponse(pathname) {
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>TrustVault</title><link rel="stylesheet" href="/style.css"><script src="/app.js" defer></script></head><body><header class="site-header"><a class="brand" href="/">TrustVault</a><nav id="navigation"></nav></header><main class="page" id="app"><p>Loading TrustVault…</p></main><footer class="site-footer">Private document access is checked on every request.</footer></body></html>`,
    {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'",
      },
    },
  );
}

export function createHandler(services = { repository: createRepository, documentStore: privateDocuments }) {
  return async (request, context = {}) => {
    const url = new URL(request.url);
    try {
      if (url.pathname.startsWith("/api/") || url.pathname === "/healthz") {
        if (Number(request.headers.get("content-length") || 0) > 5 * 1024 * 1024) {
          throw new HttpError(413, "The request is too large.");
        }
        if (!["GET", "HEAD", "OPTIONS"].includes(request.method)) {
          const origin = request.headers.get("origin");
          if ((origin && origin !== url.origin) || request.headers.get("sec-fetch-site") === "cross-site") {
            throw new HttpError(403, "The request could not be verified.");
          }
        }
        return await handleApi(request, url, context, services);
      }
      if (url.pathname === "/") {
        return Response.redirect(new URL("/login", url), 302);
      }
      if (
        ["/login", "/register", "/documents", "/search", "/upload", "/profile", "/admin"].includes(url.pathname) ||
        /^\/documents\/[a-f0-9]{32}\/sharing$/.test(url.pathname)
      ) {
        return pageResponse(url.pathname);
      }
      return jsonResponse(404, { error: "Not found." });
    } catch (error) {
      if (error instanceof HttpError) {
        return jsonResponse(error.status, { error: error.message }, error.status === 401
          ? { "Set-Cookie": clearSessionCookie() }
          : {});
      }
      console.error("TrustVault request failed", { code: error?.cause?.code || error?.code || "INTERNAL_ERROR" });
      return jsonResponse(500, { error: "The request could not be completed." });
    }
  };

}

export default createHandler();

export const config = {
  path: ["/*"],
  preferStatic: true,
};
