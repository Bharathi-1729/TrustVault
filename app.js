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
      const error = new Error(payload && (payload.error || payload.message) ? payload.error || payload.message : 'Request failed');
      error.status = response.status;
      throw error;
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
      await API.request('/api/auth/login', 'POST', payload);
      window.location.href = '/app.html';
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
      password: formData.get('password'),
      confirmPassword: formData.get('confirmPassword')
    };

    if (payload.password !== payload.confirmPassword) {
      showMessage(document.getElementById('authMessage'), 'Password confirmation does not match.', 'error');
      return;
    }

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
  } catch (error) {
    if (error.status === 401 || error.status === 403) {
      window.location.href = '/';
    } else {
      showMessage(document.getElementById('uploadMessage'), error.message, 'error');
    }
    return null;
  }
}

async function loadUsersForShare() {
  const sharePanel = document.getElementById('sharePanel');
  if (!['administrator', 'document_owner'].includes(window.currentUser.role)) {
    sharePanel?.classList.add('hidden');
    return;
  }

  try {
    const result = await API.request('/api/users');
    const select = document.getElementById('shareUserSelect');
    if (!select) return;

    select.replaceChildren();
    result.users
      .filter((user) => user.id !== window.currentUser.id)
      .forEach((user) => {
        const option = document.createElement('option');
        option.value = user.id;
        option.textContent = `${user.name} (${user.email})`;
        select.appendChild(option);
      });
    select.disabled = select.options.length === 0;
    if (select.disabled) {
      const option = document.createElement('option');
      option.value = '';
      option.textContent = 'No active users available';
      select.appendChild(option);
    }
  } catch (error) {
    console.error('Unable to load users', error);
    showMessage(document.getElementById('shareMessage'), error.message, 'error');
  }
}

async function loadDocumentsForShare() {
  const select = document.getElementById('shareDocumentSelect');
  if (!select) return;

  const result = window.currentUser.role === 'administrator'
    ? await API.request('/api/admin/documents')
    : await API.request('/api/documents?limit=50');
  const documents = result.documents.filter(
    (document) => window.currentUser.role === 'administrator' || document.owner_id === window.currentUser.id
  );

  select.replaceChildren();
  documents.forEach((document) => {
    const option = document.createElement('option');
    option.value = document.id;
    option.textContent = `${document.name} (${document.ownerName || 'you'})`;
    select.appendChild(option);
  });
  select.disabled = documents.length === 0;
  if (!documents.length) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'No documents available to manage';
    select.appendChild(option);
  }
}

async function renderSharePermissions() {
  const list = document.getElementById('sharedAccessList');
  const documentId = document.getElementById('shareDocumentSelect')?.value;
  if (!list) return;
  list.replaceChildren();

  if (!documentId) {
    const empty = document.createElement('p');
    empty.textContent = 'Select a document to view its current access.';
    list.appendChild(empty);
    return;
  }

  try {
    const result = await API.request(`/api/documents/${documentId}/shares`);
    if (!result.shares.length) {
      const empty = document.createElement('p');
      empty.textContent = 'No active shares for this document.';
      list.appendChild(empty);
      return;
    }

    result.shares.forEach((share) => {
      const row = document.createElement('div');
      row.className = 'shared-access-row';

      const details = document.createElement('span');
      const expiry = share.expires_at ? ` • expires ${isoToFriendly(share.expires_at)}` : '';
      details.textContent = `${share.user_name} (${share.user_email}) • ${share.permission}${expiry}`;

      const revokeButton = document.createElement('button');
      revokeButton.type = 'button';
      revokeButton.className = 'secondary-btn';
      revokeButton.dataset.userId = share.user_id;
      revokeButton.textContent = 'Revoke';

      row.append(details, revokeButton);
      list.appendChild(row);
    });
  } catch (error) {
    showMessage(document.getElementById('shareMessage'), error.message, 'error');
  }
}

async function renderDocuments() {
  const documentList = document.getElementById('documentList');
  if (!documentList) return;

  const page = Math.max(1, Math.floor(Number(window.currentPage) || 1));
  const search = document.getElementById('searchInput')?.value || '';
  const filters = new URLSearchParams({
    limit: '5',
    page: String(page),
    search,
    category: document.getElementById('categoryFilter')?.value || '',
    ownerId: document.getElementById('ownerFilter')?.value || '',
    fileType: document.getElementById('fileTypeFilter')?.value || '',
    dateFrom: document.getElementById('dateFromFilter')?.value || '',
    dateTo: document.getElementById('dateToFilter')?.value || ''
  });

  try {
    const result = await API.request(`/api/documents?${filters}`);
    documentList.innerHTML = '';
    if (window.currentUser.role !== 'administrator') {
      document.getElementById('documentCount').textContent = result.total;
    }
    const ownerFilter = document.getElementById('ownerFilter');
    const selectedOwner = ownerFilter.value;
    ownerFilter.replaceChildren(new Option('All owners', ''));
    result.owners.forEach((owner) => {
      ownerFilter.appendChild(new Option(owner.name, owner.id));
    });
    if (result.owners.some((owner) => owner.id === selectedOwner)) ownerFilter.value = selectedOwner;

    const pageLabel = document.getElementById('pageLabel');
    const totalPages = Math.max(result.totalPages || 1, 1);
    if (page > totalPages) {
      window.currentPage = totalPages;
      return renderDocuments();
    }

    if (pageLabel) pageLabel.textContent = `Page ${page} / ${totalPages}`;
    const previousButton = document.getElementById('prevPageBtn');
    const nextButton = document.getElementById('nextPageBtn');
    if (previousButton) previousButton.disabled = page <= 1;
    if (nextButton) nextButton.disabled = page >= totalPages;

    if (!result.documents || !result.documents.length) {
      const emptyState = document.createElement('div');
      emptyState.className = 'document-item document-empty';
      emptyState.textContent = 'No documents are available for your current access.';
      documentList.appendChild(emptyState);
      return;
    }

    result.documents.forEach((doc) => {
      const card = document.createElement('div');
      card.className = 'document-item';

      const header = document.createElement('div');
      header.className = 'document-header';

      const summary = document.createElement('div');
      const name = document.createElement('strong');
      name.textContent = doc.name || 'Untitled document';

      const ownerCategory = document.createElement('div');
      ownerCategory.className = 'doc-meta';
      ownerCategory.textContent = `${doc.ownerName || 'Unknown owner'} • ${doc.category || 'Uncategorized'}`;
      summary.append(name, ownerCategory);

      const accessBadge = document.createElement('span');
      accessBadge.className = 'user-badge';
      accessBadge.textContent = doc.accessLevel || 'read';
      header.append(summary, accessBadge);

      const metadata = document.createElement('div');
      metadata.className = 'doc-meta';
      metadata.textContent = `${doc.description || 'No description'} • ${doc.mime_type || 'Unknown type'} • ${isoToFriendly(doc.created_at)} • ${doc.size_bytes || 0} bytes`;

      const actions = document.createElement('div');
      actions.className = 'document-actions';
      const availableActions = [
        ['preview', 'Preview'],
        ['download', 'Download'],
        ['metadata', 'Details'],
        ['activity', 'Activity']
      ];
      if (doc.owner_id === window.currentUser.id && window.currentUser.role !== 'viewer') {
        availableActions.push(['edit', 'Edit']);
        availableActions.push(['delete', 'Delete']);
      } else if (['edit', 'owner'].includes(doc.accessLevel)) {
        availableActions.push(['edit', 'Edit']);
      }
      for (const [action, label] of availableActions) {
        const button = document.createElement('button');
        button.type = 'button';
        button.dataset.action = action;
        button.dataset.id = doc.id;
        button.textContent = label;
        actions.appendChild(button);
      }

      card.append(header, metadata, actions);
      documentList.appendChild(card);
    });

  } catch (error) {
    showMessage(document.getElementById('uploadMessage'), error.message, 'error');
  }
}

async function renderAccountActivity() {
  const list = document.getElementById('accountActivityList');
  if (!list) return;
  try {
    const result = await API.request('/api/account/activity?limit=30');
    list.replaceChildren();
    if (!result.activity.length) {
      const empty = document.createElement('p');
      empty.textContent = 'No account activity has been recorded yet.';
      list.appendChild(empty);
      return;
    }

    result.activity.forEach((entry) => {
      const item = document.createElement('div');
      item.className = 'audit-entry';
      const action = document.createElement('strong');
      action.textContent = entry.action;
      const metadata = document.createElement('small');
      metadata.textContent = `${entry.event_result || 'legacy'} • ${isoToFriendly(entry.created_at)}`;
      const details = document.createElement('div');
      details.className = 'audit-details';
      details.textContent = entry.details || 'No additional details';
      item.append(action, metadata, details);
      list.appendChild(item);
    });
  } catch (error) {
    showMessage(list, error.message, 'error');
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
  document.querySelectorAll('.admin-only').forEach((stat) => stat.classList.remove('hidden'));

  try {
    const auditFilters = new URLSearchParams({
      limit: '50',
      action: document.getElementById('auditActionFilter')?.value || '',
      user: document.getElementById('auditUserFilter')?.value || '',
      document: document.getElementById('auditDocumentFilter')?.value || '',
      dateFrom: document.getElementById('auditDateFrom')?.value || '',
      dateTo: document.getElementById('auditDateTo')?.value || '',
      result: document.getElementById('auditResultFilter')?.value || ''
    });
    const [dashboard, audit] = await Promise.all([
      API.request('/api/admin/dashboard'),
      API.request(`/api/admin/audit?${auditFilters}`)
    ]);

    document.getElementById('userCount').textContent = dashboard.counts.users;
    document.getElementById('documentCount').textContent = dashboard.counts.documents;
    document.getElementById('activeUserCount').textContent = dashboard.counts.activeUsers;
    document.getElementById('adminCount').textContent = dashboard.counts.disabledUsers;
    document.getElementById('sharedDocumentCount').textContent = dashboard.counts.sharedDocuments;
    document.getElementById('downloadCount').textContent = dashboard.counts.totalDownloads;
    document.getElementById('permissionChangeCount').textContent = dashboard.counts.permissionChanges;
    document.getElementById('failedLoginCount').textContent = dashboard.counts.failedLogins;
    document.getElementById('deniedAccessCount').textContent = dashboard.counts.deniedAccessAttempts;

    const adminUsersList = document.getElementById('adminUsersList');
    const userList = dashboard.counts.users ? await API.request('/api/admin/users') : { users: [] };
    const tableWrap = document.createElement('div');
    tableWrap.className = 'admin-table-wrap';

    const table = document.createElement('table');
    table.className = 'admin-users-table';
    const tableHead = document.createElement('thead');
    const headerRow = document.createElement('tr');
    ['Name', 'Email', 'Role', 'Status', 'Actions'].forEach((label) => {
      const cell = document.createElement('th');
      cell.scope = 'col';
      cell.textContent = label;
      headerRow.appendChild(cell);
    });
    tableHead.appendChild(headerRow);

    const tableBody = document.createElement('tbody');
    userList.users.forEach((user) => {
      const row = tableBody.insertRow();
      row.insertCell().textContent = user.name;
      row.insertCell().textContent = user.email;
      const roleCell = row.insertCell();
      const roleNames = {
        administrator: 'Owner',
        document_owner: 'Document owner',
        viewer: 'Viewer'
      };
      roleCell.textContent = roleNames[user.role] || user.role;
      row.insertCell().textContent = user.status;

      const actions = document.createElement('div');
      actions.className = 'document-actions';

      const ownerButton = document.createElement('button');
      ownerButton.type = 'button';
      ownerButton.dataset.action = 'set-role';
      ownerButton.dataset.userId = user.id;
      ownerButton.dataset.role = 'administrator';
      ownerButton.textContent = 'Owner';
      ownerButton.disabled = user.role === 'administrator';

      const documentOwnerButton = document.createElement('button');
      documentOwnerButton.type = 'button';
      documentOwnerButton.dataset.action = 'set-role';
      documentOwnerButton.dataset.userId = user.id;
      documentOwnerButton.dataset.role = 'document_owner';
      documentOwnerButton.textContent = 'Document owner';
      documentOwnerButton.disabled = user.role === 'document_owner';

      const viewerButton = document.createElement('button');
      viewerButton.type = 'button';
      viewerButton.dataset.action = 'set-role';
      viewerButton.dataset.userId = user.id;
      viewerButton.dataset.role = 'viewer';
      viewerButton.textContent = 'Viewer';
      viewerButton.disabled = user.role === 'viewer' || user.id === window.currentUser.id;

      const statusButton = document.createElement('button');
      statusButton.type = 'button';
      statusButton.dataset.action = 'toggle-status';
      statusButton.dataset.userId = user.id;
      statusButton.dataset.status = user.status === 'active' ? 'disabled' : 'active';
      statusButton.textContent = user.status === 'active' ? 'Disable' : 'Enable';
      statusButton.disabled = user.id === window.currentUser.id;

      actions.append(ownerButton, documentOwnerButton, viewerButton, statusButton);
      const actionsCell = row.insertCell();
      actionsCell.appendChild(actions);
    });
    table.append(tableHead, tableBody);
    tableWrap.appendChild(table);
    adminUsersList.replaceChildren(tableWrap);

    const uploadsList = document.getElementById('adminRecentUploadsList');
    uploadsList.replaceChildren();
    dashboard.recentUploads.forEach((upload) => {
      const item = document.createElement('div');
      item.className = 'audit-entry';
      const title = document.createElement('strong');
      title.textContent = upload.name;
      const metadata = document.createElement('small');
      metadata.textContent = `${upload.owner_name} • ${upload.category} • ${isoToFriendly(upload.created_at)} • ${upload.scan_status}`;
      item.append(title, metadata);
      if (upload.scan_status === 'pending') {
        const approveButton = document.createElement('button');
        approveButton.type = 'button';
        approveButton.className = 'secondary-btn';
        approveButton.textContent = 'Approve for download';
        approveButton.addEventListener('click', async () => {
          if (!window.confirm('Confirm that this document has been reviewed and may be downloaded?')) return;
          try {
            await API.request(`/api/admin/documents/${upload.id}/scan`, 'POST', { status: 'approved' });
            await renderAdminData();
          } catch (error) {
            showMessage(document.getElementById('uploadMessage'), error.message, 'error');
          }
        });
        item.appendChild(approveButton);
      }
      uploadsList.appendChild(item);
    });

    const auditList = document.getElementById('auditList');
    auditList.innerHTML = '';
    audit.audit.forEach((entry) => {
      const item = document.createElement('div');
      item.className = 'audit-entry';

      const eventName = document.createElement('strong');
      eventName.textContent = entry.action;

      const metadata = document.createElement('small');
      metadata.textContent = `${entry.actor_name || 'system'} • ${isoToFriendly(entry.created_at)} • ${entry.event_result || 'legacy'}`;

      const details = document.createElement('div');
      details.className = 'audit-details';
      details.textContent = entry.details || 'No additional details';

      const requestAgent = document.createElement('small');
      requestAgent.textContent = entry.user_agent || 'Unknown client';

      item.append(eventName, metadata, requestAgent, details);
      auditList.appendChild(item);
    });

    adminUsersList.querySelectorAll('[data-action="set-role"]').forEach((button) => {
      button.addEventListener('click', async () => {
        const userId = button.dataset.userId;
        const role = button.dataset.role;
        try {
          await API.request(`/api/admin/users/${userId}/role`, 'PUT', { role });
          showMessage(document.getElementById('uploadMessage'), 'Role updated', 'success');
          await renderAdminData();
        } catch (error) {
          showMessage(document.getElementById('uploadMessage'), error.message, 'error');
        }
      });
    });

    adminUsersList.querySelectorAll('[data-action="toggle-status"]').forEach((button) => {
      button.addEventListener('click', async () => {
        const userId = button.dataset.userId;
        const status = button.dataset.status;
        if (status === 'disabled' && !window.confirm('Disable this user? They will lose access immediately.')) {
          return;
        }
        try {
          await API.request(`/api/admin/users/${userId}/status`, 'PUT', { status });
          showMessage(document.getElementById('uploadMessage'), 'Status updated', 'success');
          await renderAdminData();
          await loadUsersForShare();
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
  const roleNames = { administrator: 'Owner', document_owner: 'Document owner', viewer: 'Viewer' };
  document.getElementById('userBadge').textContent = `${user.name} (${roleNames[user.role] || user.role})`;
  if (!['administrator', 'document_owner'].includes(user.role)) {
    document.getElementById('uploadPanel').classList.add('hidden');
    document.getElementById('categoryPanel').classList.add('hidden');
  } else {
    document.getElementById('categoryPanel').classList.remove('hidden');
  }

  try {
    const { categories } = await API.request('/api/categories');
    const datalist = document.getElementById('categoryOptions');
    const categoryFilter = document.getElementById('categoryFilter');
    categories.forEach((name) => {
      const option = document.createElement('option');
      option.value = name;
      datalist.appendChild(option);
      const filterOption = document.createElement('option');
      filterOption.value = name;
      filterOption.textContent = name;
      categoryFilter.appendChild(filterOption);
    });
  } catch (error) {
    showMessage(document.getElementById('categoryMessage'), error.message, 'error');
  }

  await loadUsersForShare();
  if (['administrator', 'document_owner'].includes(user.role)) {
    try {
      await loadDocumentsForShare();
      await renderSharePermissions();
    } catch (error) {
      showMessage(document.getElementById('shareMessage'), error.message, 'error');
    }
  }
  await renderDocuments();
  await renderAccountActivity();
  await renderAdminData();

  document.getElementById('searchForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    window.currentPage = 1;
    await renderDocuments();
  });

  document.getElementById('categoryForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      const { category } = await API.request('/api/categories', 'POST', {
        name: document.getElementById('categoryNameInput').value
      });
      document.getElementById('categoryForm').reset();
      const suggestion = document.createElement('option');
      suggestion.value = category.name;
      document.getElementById('categoryOptions').appendChild(suggestion);
      const filterOption = document.createElement('option');
      filterOption.value = category.name;
      filterOption.textContent = category.name;
      document.getElementById('categoryFilter').appendChild(filterOption);
      showMessage(document.getElementById('categoryMessage'), 'Category created.', 'success');
    } catch (error) {
      showMessage(document.getElementById('categoryMessage'), error.message, 'error');
    }
  });

  document.getElementById('adminAuditFilters').addEventListener('submit', async (event) => {
    event.preventDefault();
    await renderAdminData();
  });

  document.getElementById('prevPageBtn').addEventListener('click', async () => {
    if ((window.currentPage || 1) > 1) {
      window.currentPage -= 1;
      await renderDocuments();
    }
  });

  document.getElementById('nextPageBtn').addEventListener('click', async () => {
    if (document.getElementById('nextPageBtn').disabled) return;
    window.currentPage = (window.currentPage || 1) + 1;
    await renderDocuments();
  });

  document.getElementById('shareDocumentSelect').addEventListener('change', renderSharePermissions);

  document.getElementById('logoutBtn').addEventListener('click', async () => {
    try {
      await API.request('/api/auth/logout', 'POST');
      window.location.href = '/';
    } catch (error) {
      showMessage(document.getElementById('uploadMessage'), error.message, 'error');
    }
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
    const docId = document.getElementById('shareDocumentSelect').value;

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
      await renderSharePermissions();
    } catch (error) {
      showMessage(document.getElementById('shareMessage'), error.message, 'error');
    }
  });

  document.getElementById('sharedAccessList').addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-user-id]');
    if (!button) return;

    try {
      await API.request(
        `/api/documents/${document.getElementById('shareDocumentSelect').value}/share/${button.dataset.userId}`,
        'DELETE'
      );
      showMessage(document.getElementById('shareMessage'), 'Access revoked successfully.', 'success');
      await renderSharePermissions();
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

      if (action === 'preview') {
        window.open(`/api/documents/${id}/preview`, '_blank', 'noopener,noreferrer');
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

      if (action === 'activity') {
        const result = await API.request(`/api/documents/${id}/activity`);
        const details = result.activity.map((entry) => {
          let auditDetails = '';
          try {
            auditDetails = entry.details ? JSON.stringify(JSON.parse(entry.details)) : '';
          } catch (_error) {
            auditDetails = entry.details || '';
          }
          return `${entry.action} • ${entry.actor_name || 'system'} • ${isoToFriendly(entry.created_at)}${auditDetails ? ` • ${auditDetails}` : ''}`;
        });
        alert(details.length ? details.join('\n') : 'No activity recorded for this document.');
      }

      if (action === 'delete') {
        if (!window.confirm('Delete this document? This removes future access for all users.')) return;
        await API.request(`/api/documents/${id}`, 'DELETE');
        await renderDocuments();
      }

      if (action === 'edit') {
        const result = await API.request(`/api/documents/${id}`);
        const current = result.document;
        const name = window.prompt('Document name', current.name);
        if (name === null) return;
        const category = window.prompt('Category', current.category);
        if (category === null) return;
        const description = window.prompt('Description', current.description || '');
        if (description === null) return;
        await API.request(`/api/documents/${id}`, 'PUT', { name, category, description });
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
