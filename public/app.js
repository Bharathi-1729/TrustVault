"use strict";

const root = document.querySelector("#app");
const navigation = document.querySelector("#navigation");
let currentUser = null;
let csrfToken = "";

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

async function api(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.method && options.method !== "GET") headers.set("X-CSRF-Token", csrfToken);
  if (options.body && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
    options.body = JSON.stringify(options.body);
  }
  const response = await fetch(url, { ...options, headers, credentials: "same-origin" });
  let payload = {};
  try {
    payload = response.status === 204 ? {} : await response.json();
  } catch {
    payload = { error: "The server returned an unreadable response." };
  }
  if (!response.ok) {
    const error = new Error(payload.error || "The request could not be completed.");
    error.status = response.status;
    throw error;
  }
  return payload;
}

function message(text, isError = false) {
  const target = root.querySelector("[data-message]");
  if (!target) return;
  target.textContent = text;
  target.classList.toggle("error-text", isError);
}

function renderNavigation() {
  if (!currentUser) {
    navigation.innerHTML = "";
    return;
  }
  navigation.innerHTML = `
    <a href="/documents">Documents</a>
    <a href="/search">Search</a>
    ${currentUser.role === "document_owner" ? '<a href="/upload">Upload</a>' : ""}
    ${currentUser.role === "administrator" ? '<a href="/admin">Admin</a>' : ""}
    <a href="/profile">Profile</a>
    <button class="button-secondary" type="button" data-logout>Log out</button>`;
  navigation.querySelector("[data-logout]").addEventListener("click", async () => {
    try {
      await api("/api/auth/logout", { method: "POST" });
      location.assign("/login");
    } catch (error) {
      alert(error.message);
    }
  });
}

function renderLogin() {
  root.innerHTML = `
    <section class="panel narrow">
      <h1>Sign in</h1>
      <p class="muted">Access your TrustVault documents securely.</p>
      <form data-login>
        <label for="email">Email</label>
        <input id="email" name="email" type="email" autocomplete="username" maxlength="254" required>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" maxlength="1024" required>
        <button type="submit">Sign in</button>
        <p class="form-message" data-message role="status" aria-live="polite"></p>
      </form>
      <p class="muted">Have an invitation? <a href="/register">Create an account</a>.</p>
    </section>`;
  root.querySelector("[data-login]").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await api("/api/auth/login", {
        method: "POST",
        body: { email: form.get("email"), password: form.get("password") },
      });
      location.assign("/documents");
    } catch (error) {
      message(error.message, true);
    }
  });
}

function renderRegister() {
  root.innerHTML = `
    <section class="panel narrow">
      <h1>Create an account</h1>
      <p class="muted">Viewer can access documents explicitly shared with the account.
      Document Owner can upload and manage owned documents. Administrator can review
      registered users and audit activity; this role does not grant access to private documents.</p>
      <form data-register>
        <label for="name">Name</label>
        <input id="name" name="name" maxlength="120" required>
        <label for="register-email">Email</label>
        <input id="register-email" name="email" type="email" maxlength="254" required>
        <label for="invite">Invitation token</label>
        <input id="invite" name="invite_token" autocomplete="off" required>
        <label for="register-password">Password</label>
        <input id="register-password" name="password" type="password" minlength="12" maxlength="72" required>
        <label for="confirm-password">Confirm password</label>
        <input id="confirm-password" name="password_confirm" type="password" minlength="12" maxlength="72" required>
        <button type="submit">Register</button>
        <p class="form-message" data-message role="status" aria-live="polite"></p>
      </form>
      <p class="muted"><a href="/login">Back to sign in</a></p>
    </section>`;
  root.querySelector("[data-register]").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    if (form.get("password") !== form.get("password_confirm")) {
      message("Passwords do not match.", true);
      return;
    }
    try {
      await api("/api/auth/register", {
        method: "POST",
        body: {
          name: form.get("name"),
          email: form.get("email"),
          password: form.get("password"),
          invite_token: form.get("invite_token"),
        },
      });
      location.assign("/login?registered=1");
    } catch (error) {
      message(error.message, true);
    }
  });
}

async function renderDocuments() {
  root.innerHTML = `
    <section class="panel">
      <h1>Documents</h1>
      <form data-search class="inline-form">
        <label for="query">Search documents</label>
        <input id="query" name="q" maxlength="254" value="${escapeHtml(new URLSearchParams(location.search).get("q") || "")}">
        <button type="submit">Search</button>
      </form>
      <p class="form-message" data-message role="status" aria-live="polite"></p>
      <div data-documents><p>Loading documents…</p></div>
    </section>`;
  root.querySelector("[data-search]").addEventListener("submit", (event) => {
    event.preventDefault();
    const query = new FormData(event.currentTarget).get("q").trim();
    location.assign(query ? `/search?q=${encodeURIComponent(query)}` : "/documents");
  });
  try {
    const query = new URLSearchParams(location.search);
    const result = await api(`/api/documents?${query}`);
    const list = root.querySelector("[data-documents]");
    if (!result.documents.length) {
      list.innerHTML = '<p class="muted">No documents found.</p>';
      return;
    }
    list.innerHTML = `<div class="document-grid">${result.documents.map((doc) => `
      <article class="panel document-card">
        <h2>${escapeHtml(doc.name)}</h2>
        <p>${escapeHtml(doc.description || "No description")}</p>
        <p class="muted">${escapeHtml(doc.category)} · ${escapeHtml(doc.permission)}</p>
        <p class="muted">${escapeHtml(doc.created_at)}</p>
        <div class="actions">
          <a class="button" href="/api/documents/${encodeURIComponent(doc.id)}" target="_blank" rel="noopener">View</a>
          <a class="button button-secondary" href="/api/documents/${encodeURIComponent(doc.id)}/download">Download</a>
          ${doc.owner_id === currentUser.id ? `<a class="button button-secondary" href="/documents/${encodeURIComponent(doc.id)}/sharing">Sharing</a>` : ""}
        </div>
      </article>`).join("")}</div>`;
  } catch (error) {
    message(error.message, true);
  }
}

function renderUpload() {
  if (currentUser.role !== "document_owner") {
    root.innerHTML = '<section class="panel"><h1>Upload unavailable</h1><p>Document Owner access is required.</p></section>';
    return;
  }
  root.innerHTML = `
    <section class="panel narrow">
      <h1>Upload a document</h1>
      <form data-upload>
        <label for="file">File (PDF, PNG, JPG, or TXT; up to 4 MB)</label>
        <input id="file" name="file" type="file" accept=".pdf,.png,.jpg,.jpeg,.txt" required>
        <label for="category">Category</label>
        <input id="category" name="category" maxlength="64" value="general" required>
        <label for="description">Description</label>
        <textarea id="description" name="description" maxlength="2000"></textarea>
        <button type="submit">Upload document</button>
        <p class="form-message" data-message role="status" aria-live="polite"></p>
      </form>
    </section>`;
  root.querySelector("[data-upload]").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api("/api/documents", { method: "POST", body: new FormData(event.currentTarget) });
      location.assign("/documents");
    } catch (error) {
      message(error.message, true);
    }
  });
}

async function renderSharing() {
  const match = location.pathname.match(/^\/documents\/([a-f0-9]{32})\/sharing$/);
  if (!match) return;
  const documentId = match[1];
  root.innerHTML = `
    <section class="panel">
      <h1>Manage document access</h1>
      <form data-share>
        <label for="recipient">Recipient email</label>
        <input id="recipient" name="recipient_email" type="email" maxlength="254" required>
        <label for="permission">Permission</label>
        <select id="permission" name="permission"><option value="read">Read</option><option value="edit">Edit</option></select>
        <button type="submit">Share document</button>
        <p class="form-message" data-message role="status" aria-live="polite"></p>
      </form>
      <h2>Permissions</h2>
      <div data-permissions>Loading…</div>
      <p><a href="/documents">Back to documents</a></p>
    </section>`;
  root.querySelector("[data-share]").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    try {
      await api(`/api/documents/${documentId}/permissions`, {
        method: "POST",
        body: { recipient_email: data.get("recipient_email"), permission: data.get("permission") },
      });
      event.currentTarget.reset();
      await loadPermissions();
    } catch (error) {
      message(error.message, true);
    }
  });
  async function loadPermissions() {
    const result = await api(`/api/documents/${documentId}/permissions`);
    const list = root.querySelector("[data-permissions]");
    list.innerHTML = result.permissions.length ? `<ul>${result.permissions.map((grant) => `
      <li>${escapeHtml(grant.users?.name || grant.users?.email || "Account")} — ${escapeHtml(grant.permission)}
      (${escapeHtml(grant.revoked_at ? "revoked" : "active")})
      ${grant.revoked_at ? "" : `<button type="button" data-revoke="${escapeHtml(grant.id)}">Revoke</button>`}</li>`).join("")}</ul>` : '<p class="muted">No permissions.</p>';
    list.querySelectorAll("[data-revoke]").forEach((button) => {
      button.addEventListener("click", async () => {
        if (!confirm("Revoke this document permission?")) return;
        try {
          await api(`/api/documents/${documentId}/permissions/${encodeURIComponent(button.dataset.revoke)}`, { method: "DELETE" });
          await loadPermissions();
        } catch (error) {
          message(error.message, true);
        }
      });
    });
  }
  try {
    await loadPermissions();
  } catch (error) {
    message(error.message, true);
  }
}

function renderProfile() {
  root.innerHTML = `
    <section class="panel narrow">
      <h1>Profile</h1>
      <dl>
        <dt>Name</dt><dd>${escapeHtml(currentUser.name)}</dd>
        <dt>Email</dt><dd>${escapeHtml(currentUser.email)}</dd>
        <dt>Role</dt><dd>${escapeHtml(currentUser.role)}</dd>
        <dt>Status</dt><dd>${escapeHtml(currentUser.status)}</dd>
        <dt>Registered</dt><dd>${escapeHtml(currentUser.created_at)}</dd>
      </dl>
    </section>`;
}

async function renderAdmin() {
  if (currentUser.role !== "administrator") {
    root.innerHTML = '<section class="panel"><h1>Administrator access required</h1><p><a href="/documents">Back to documents</a></p></section>';
    return;
  }
  root.innerHTML = `
    <section class="panel">
      <h1>Administrator dashboard</h1>
      <p class="muted">Administrative data and audit activity only. This dashboard does not grant access to private document contents.</p>
      <p class="form-message" data-message role="status" aria-live="polite"></p>
      <div data-admin>Loading account and audit information…</div>
    </section>
    <section class="panel">
      <h2>Create registration invitation</h2>
      <form data-invite class="inline-form">
        <label for="invite-role">Role</label>
        <select id="invite-role" name="role">
          <option value="viewer">Viewer</option>
          <option value="document_owner">Document Owner</option>
          <option value="administrator">Administrator</option>
        </select>
        <label for="invite-lifetime">Expires in (hours)</label>
        <input id="invite-lifetime" name="expires_in_hours" type="number" min="1" max="720" value="24" required>
        <button type="submit">Generate invite token</button>
      </form>
      <dialog data-invite-dialog>
        <h2>Invitation token</h2>
        <p class="muted">Copy and share this token securely. It is shown only once.</p>
        <p><strong>Role:</strong> <span data-invite-role></span></p>
        <p><strong>Expires:</strong> <span data-invite-expiry></span></p>
        <textarea data-invite-token readonly rows="3" aria-label="Invitation token"></textarea>
        <p class="form-message" data-invite-feedback role="status" aria-live="polite"></p>
        <div class="actions">
          <button type="button" data-copy-invite>Copy token</button>
          <button type="button" class="button-secondary" data-close-invite>Close</button>
        </div>
      </dialog>
    </section>
    <section class="panel">
      <h2>Registered users</h2>
      <div data-admin-users>Loading users…</div>
    </section>`;
  const inviteDialog = root.querySelector("[data-invite-dialog]");
  root.querySelector("[data-invite]").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const invite = await api("/api/admin/invites", {
        method: "POST",
        body: {
          role: form.get("role"),
          expires_in_hours: Number(form.get("expires_in_hours")),
        },
      });
      inviteDialog.querySelector("[data-invite-token]").value = invite.token;
      inviteDialog.querySelector("[data-invite-role]").textContent = invite.role;
      inviteDialog.querySelector("[data-invite-expiry]").textContent = invite.expires_at;
      inviteDialog.showModal();
    } catch (error) {
      message(error.message, true);
    }
  });
  inviteDialog.querySelector("[data-close-invite]").addEventListener("click", () => {
    inviteDialog.close();
  });
  inviteDialog.addEventListener("close", () => {
    inviteDialog.querySelector("[data-invite-token]").value = "";
    inviteDialog.querySelector("[data-invite-feedback]").textContent = "";
  });
  inviteDialog.querySelector("[data-copy-invite]").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(inviteDialog.querySelector("[data-invite-token]").value);
      inviteDialog.querySelector("[data-invite-feedback]").textContent = "Invitation token copied.";
    } catch (error) {
      inviteDialog.querySelector("[data-invite-feedback]").textContent =
        `Could not copy the token: ${error.message}`;
    }
  });
  try {
    const result = await api("/api/admin/dashboard");
    root.querySelector("[data-admin]").innerHTML = `
      <h2>Summary</h2>
      <dl>${Object.entries(result.counts).map(([key, value]) => `<dt>${escapeHtml(key.replaceAll("_", " "))}</dt><dd>${escapeHtml(value)}</dd>`).join("")}</dl>
      <h2>Recent activity</h2>
      <ul>${(result.recent_security_events || []).map((event) => `<li>${escapeHtml(event.timestamp)} — ${escapeHtml(event.action)} (${escapeHtml(event.status)})</li>`).join("")}</ul>`;
    const users = await api("/api/admin/users?page_size=100");
    const list = root.querySelector("[data-admin-users]");
    list.innerHTML = `<div class="table-wrap"><table><thead><tr><th>User</th><th>Email</th><th>Role</th><th>Status</th><th>Action</th></tr></thead><tbody>${users.items.map((account) => `
      <tr data-user-row="${escapeHtml(account.id)}" data-original-role="${escapeHtml(account.role)}" data-original-status="${escapeHtml(account.status)}">
        <td>${escapeHtml(account.name)}</td><td>${escapeHtml(account.email)}</td>
        <td><select data-role aria-label="Role for ${escapeHtml(account.email)}" ${account.id === currentUser.id ? "disabled" : ""}>
          ${["viewer", "document_owner", "administrator"].map((role) => `<option value="${role}" ${role === account.role ? "selected" : ""}>${escapeHtml(role)}</option>`).join("")}
        </select></td>
        <td><select data-status aria-label="Status for ${escapeHtml(account.email)}" ${account.id === currentUser.id ? "disabled" : ""}>
          ${["active", "disabled"].map((status) => `<option value="${status}" ${status === account.status ? "selected" : ""}>${escapeHtml(status)}</option>`).join("")}
        </select></td>
        <td><button type="button" data-save-user ${account.id === currentUser.id ? "disabled" : ""}>Save</button></td>
      </tr>`).join("")}</tbody></table></div>`;
    list.querySelectorAll("[data-save-user]").forEach((button) => {
      button.addEventListener("click", async () => {
        const row = button.closest("[data-user-row]");
        const id = row.dataset.userRow;
        try {
          const role = row.querySelector("[data-role]").value;
          const status = row.querySelector("[data-status]").value;
          if (role !== row.dataset.originalRole) {
            await api(`/api/admin/users/${encodeURIComponent(id)}/role`, {
              method: "PATCH",
              body: { role },
            });
          }
          if (status !== row.dataset.originalStatus) {
            await api(`/api/admin/users/${encodeURIComponent(id)}/status`, {
              method: "PATCH",
              body: { status },
            });
          }
          row.dataset.originalRole = role;
          row.dataset.originalStatus = status;
          message("User account updated.");
        } catch (error) {
          message(error.message, true);
        }
      });
    });
  } catch (error) {
    message(error.message, true);
  }
}

async function start() {
  const path = location.pathname;
  let startupNotice = "";
  try {
    const session = await api("/api/auth/me");
    currentUser = session.user;
    csrfToken = session.csrf_token;
  } catch (error) {
    currentUser = null;
    if (error.status !== 401) {
      startupNotice = "Sign-in is temporarily unavailable. Please try again shortly.";
    }
  }
  renderNavigation();
  if (currentUser && ["/", "/login", "/register"].includes(path)) {
    location.replace("/documents");
    return;
  }
  if (!currentUser && !["/login", "/register"].includes(path)) {
    location.replace("/login");
    return;
  }
  if (path === "/register") renderRegister();
  else if (!currentUser) renderLogin();
  else if (path === "/upload") renderUpload();
  else if (path === "/profile") renderProfile();
  else if (path === "/admin") await renderAdmin();
  else if (/^\/documents\/[a-f0-9]{32}\/sharing$/.test(path)) await renderSharing();
  else await renderDocuments();
  if (startupNotice) {
    const notice = document.createElement("p");
    notice.className = "error-text";
    notice.setAttribute("role", "alert");
    notice.textContent = startupNotice;
    root.prepend(notice);
  }
  if (path === "/login" && new URLSearchParams(location.search).get("registered") === "1") {
    const notice = document.createElement("p");
    notice.className = "success-text";
    notice.textContent = "Account created. You can now sign in.";
    root.querySelector("form").before(notice);
  }
}

start().catch((error) => {
  root.innerHTML = `<section class="panel"><h1>TrustVault unavailable</h1><p>${escapeHtml(error.message)}</p></section>`;
});
