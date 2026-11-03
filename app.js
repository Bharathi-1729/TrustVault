const API = {
  async request(path, method = 'GET', body = null, isFormData = false) {
    const headers = {};
    const options = { method, credentials: 'same-origin', headers };

    if (body !== null && !isFormData) {
      headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }

    if (body !== null && isFormData) {
      options.body = body;
    }

    const response = await fetch(path, options);
    const text = await response.text();
    let payload = null;

    try {
      payload = text ? JSON.parse(text) : null;
    } catch (error) {
      payload = { message: text };
    }

    if (!response.ok) {
      throw new Error(payload && payload.error ? payload.error : 'Request failed');
    }

    return payload;
  }
};

function showMessage(el, message, type = 'info') {
  if (!el) return;
  el.textContent = message || '';
  el.className = 'status-message';
  if (type === 'error') el.classList.add('error');
  if (type === 'success') el.classList.add('success');
}

function isoToFriendly(value) {
  if (!value) return 'Unknown';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function bindAuthTabs() {
  const loginForm = document.getElementById('loginForm');
  const registerForm = document.getElementById('registerForm');
  const tabs = document.querySelectorAll('.tab-btn');

  if (!loginForm || !registerForm || !tabs.length) return;

  const setMode = (mode) => {
    const isLogin = mode === 'login';
    loginForm.classList.toggle('hidden', !isLogin);
    registerForm.classList.toggle('hidden', isLogin);
    tabs.forEach((button) => {
      button.classList.toggle('active', button.dataset.mode === mode);
    });
  };

  tabs.forEach((button) => {
    button.addEventListener('click', () => setMode(button.dataset.mode));
  });

  loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const formData = new FormData(loginForm);
    const payload = {
      email: formData.get('email'),
      password: formData.get('password')
    };

    try {
      const result = await API.request('/api/auth/login', 'POST', payload);
      window.location.href = '/app.html';
      console.log(result);
    } catch (error) {
      showMessage(document.getElementById('authMessage'), error.message, 'error');
    }
  });

  registerForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const formData = new FormData(registerForm);
    const payload = {
      name: formData.get('name'),
      email: formData.get('email'),
      password: formData.get('password')
    };

    try {
      await API.request('/api/auth/register', 'POST', payload);
      window.location.href = '/app.html';
    } catch (error) {
      showMessage(document.getElementById('authMessage'), error.message, 'error');
    }
  });
}

async function loadCurrentUser() {
  try {
    const result = await API.request('/api/auth/me');
    return result.user;
  } catch (_error) {
    window.location.href = '/';
    return null;
  }
}

async function loadUsersForShare() {
  try {
    const result = await API.request('/api/users');
    const select = document.getElementById('shareUserSelect');
    if (!select) return;

    select.innerHTML = '';
    result.users
      .filter((user) => user.id !== window.currentUser.id)
      .forEach((user) => {
        const option = document.createElement('option');
        option.value = user.id;
        option.textContent = `${user.name} (${user.email})`;
        select.appendChild(option);
      });
  } catch (error) {
    console.error('Unable to load users', error);
  }
}

async function renderDocuments() {
  const documentList = document.getElementById('documentList');
  if (!documentList) return;

  const page = Number(window.currentPage || 1);
  const search = document.getElementById('searchInput')?.value || '';

  try {
    const result = await API.request(`/api/documents?limit=5&page=${page}&search=${encodeURIComponent(search)}`);
    documentList.innerHTML = '';

    if (!result.documents || !result.documents.length) {
      documentList.innerHTML = '<div class="document-item"><p>No documents are available for your current access.</p></div>';
      return;
    }

    result.documents.forEach((document) => {
      const card = document.createElement('div');
      card.className = 'document-item';
      card.innerHTML = `
        <div class="document-header">
          <div>
            <strong>${document.name}</strong>
            <div class="doc-meta">${document.ownerName} • ${document.category}</div>
          </div>
          <span class="user-badge">${document.accessLevel || 'read'}</span>
        </div>
        <div class="doc-meta">${document.description || 'No description'} • ${isoToFriendly(document.created_at)} • ${document.size_bytes || 0} bytes</div>
        <div class="document-actions">
          <button type="button" data-action="download" data-id="${document.id}">Download</button>
          <button type="button" data-action="metadata" data-id="${document.id}">Details</button>
          <button type="button" data-action="delete" data-id="${document.id}">Delete</button>
        </div>
      `;
      documentList.appendChild(card);
    });

    const pageLabel = document.getElementById('pageLabel');
    if (pageLabel) pageLabel.textContent = `Page ${page} / ${Math.max(result.totalPages || 1, 1)}`;
  } catch (error) {
    showMessage(document.getElementById('uploadMessage'), error.message, 'error');
  }
}

async function renderAdminData() {
  const adminSection = document.getElementById('adminSection');
  if (!adminSection) return;

  if (window.currentUser.role !== 'administrator') {
    adminSection.classList.add('hidden');
    return;
  }

  adminSection.classList.remove('hidden');

  try {
    const [dashboard, audit] = await Promise.all([
      API.request('/api/admin/dashboard'),
      API.request('/api/admin/audit?limit=10')
    ]);

    document.getElementById('userCount').textContent = dashboard.counts.users;
    document.getElementById('documentCount').textContent = dashboard.counts.documents;
    document.getElementById('adminCount').textContent = dashboard.counts.administrators;
    document.getElementById('auditCount').textContent = audit.audit.length;

    const adminUsersList = document.getElementById('adminUsersList');
    adminUsersList.innerHTML = '';
    const userList = dashboard.counts.users ? await API.request('/api/admin/users') : { users: [] };
    userList.users.forEach((user) => {
      const row = document.createElement('div');
      row.className = 'admin-row';
      row.innerHTML = `
        <div>
          <strong>${user.name}</strong><br />
          <small>${user.email} / ${user.role} / ${user.status}</small>
        </div>
        <div class="document-actions">
          <button type="button" data-action="set-role" data-user-id="${user.id}" data-role="document_owner">Owner</button>
          <button type="button" data-action="set-role" data-user-id="${user.id}" data-role="viewer">Viewer</button>
          <button type="button" data-action="toggle-status" data-user-id="${user.id}" data-status="${user.status === 'active' ? 'disabled' : 'active'}">${user.status === 'active' ? 'Disable' : 'Enable'}</button>
        </div>
      `;
      adminUsersList.appendChild(row);
    });

    const auditList = document.getElementById('auditList');
    auditList.innerHTML = '';
    audit.audit.forEach((entry) => {
      const item = document.createElement('div');
      item.className = 'audit-entry';
      item.innerHTML = `<strong>${entry.action}</strong><br /><small>${entry.actor_name || 'system'} • ${isoToFriendly(entry.created_at)}</small><div>${entry.details || ''}</div>`;
      auditList.appendChild(item);
    });

    adminUsersList.querySelectorAll('[data-action="set-role"]').forEach((button) => {
      button.addEventListener('click', async () => {
        const userId = button.dataset.userId;
        const role = button.dataset.role;
        try {
          await API.request(`/api/admin/users/${userId}/role`, 'PUT', { role });
          showMessage(document.getElementById('uploadMessage'), 'Role updated', 'success');
          renderAdminData();
        } catch (error) {
          showMessage(document.getElementById('uploadMessage'), error.message, 'error');
        }
      });
    });

    adminUsersList.querySelectorAll('[data-action="toggle-status"]').forEach((button) => {
      button.addEventListener('click', async () => {
        const userId = button.dataset.userId;
        const status = button.dataset.status;
        try {
          await API.request(`/api/admin/users/${userId}/status`, 'PUT', { status });
          showMessage(document.getElementById('uploadMessage'), 'Status updated', 'success');
          renderAdminData();
        } catch (error) {
          showMessage(document.getElementById('uploadMessage'), error.message, 'error');
        }
      });
    });
  } catch (error) {
    showMessage(document.getElementById('uploadMessage'), error.message, 'error');
  }
}

async function setupDashboard() {
  const user = await loadCurrentUser();
  if (!user) return;
  window.currentUser = user;
  document.getElementById('userBadge').textContent = `${user.name} (${user.role})`;

  await loadUsersForShare();
  await renderDocuments();
  await renderAdminData();

  document.getElementById('searchForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    window.currentPage = 1;
    await renderDocuments();
  });

  document.getElementById('prevPageBtn').addEventListener('click', async () => {
    if ((window.currentPage || 1) > 1) {
      window.currentPage -= 1;
      await renderDocuments();
    }
  });

  document.getElementById('nextPageBtn').addEventListener('click', async () => {
    window.currentPage = (window.currentPage || 1) + 1;
    await renderDocuments();
  });

  document.getElementById('logoutBtn').addEventListener('click', async () => {
    await API.request('/api/auth/logout', 'POST');
    window.location.href = '/';
  });

  document.getElementById('uploadForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    const fileInput = document.getElementById('documentFile');
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('category', document.getElementById('categoryInput').value);
    formData.append('description', document.getElementById('descriptionInput').value);

    try {
      await API.request('/api/documents', 'POST', formData, true);
      showMessage(document.getElementById('uploadMessage'), 'Document uploaded successfully.', 'success');
      document.getElementById('uploadForm').reset();
      await renderDocuments();
      await renderAdminData();
    } catch (error) {
      showMessage(document.getElementById('uploadMessage'), error.message, 'error');
    }
  });

  document.getElementById('shareForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    const targetUserId = document.getElementById('shareUserSelect').value;
    const permission = document.getElementById('sharePermissionSelect').value;
    const expiresAt = document.getElementById('shareExpirationInput').value;
    const docId = document.querySelector('[data-action="metadata"]')?.dataset.id;

    if (!docId) {
      showMessage(document.getElementById('shareMessage'), 'Select a document to share from the list.', 'error');
      return;
    }

    try {
      const user = await API.request('/api/users');
      const chosen = user.users.find((entry) => entry.id === targetUserId);
      await API.request(`/api/documents/${docId}/share`, 'POST', {
        email: chosen ? chosen.email : '',
        permission,
        expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null
      });
      showMessage(document.getElementById('shareMessage'), 'Access granted successfully.', 'success');
    } catch (error) {
      showMessage(document.getElementById('shareMessage'), error.message, 'error');
    }
  });

  document.getElementById('documentList').addEventListener('click', async (event) => {
    const button = event.target.closest('button');
    if (!button) return;

    const id = button.dataset.id;
    const action = button.dataset.action;

    try {
      if (action === 'download') {
        window.open(`/api/documents/${id}/download`, '_blank');
      }

      if (action === 'metadata') {
        const result = await API.request(`/api/documents/${id}`);
        const document = result.document;
        const details = [
          `Name: ${document.name}`,
          `Owner: ${document.ownerName}`,
          `Category: ${document.category}`,
          `Status: ${document.accessLevel}`,
          `Created: ${isoToFriendly(document.created_at)}`
        ].join('\n');
        alert(details);
      }

      if (action === 'delete') {
        await API.request(`/api/documents/${id}`, 'DELETE');
        await renderDocuments();
      }
    } catch (error) {
      showMessage(document.getElementById('uploadMessage'), error.message, 'error');
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  bindAuthTabs();
  if (document.getElementById('app-shell')) {
    setupDashboard();
  }
});
