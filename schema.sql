CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE
        CHECK (length(trim(email)) BETWEEN 3 AND 254)
        CHECK (email = lower(trim(email))),
    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 120),
    password_hash TEXT NOT NULL CHECK (length(password_hash) > 0),
    role TEXT NOT NULL DEFAULT 'viewer'
        CHECK (role IN ('administrator', 'document_owner', 'viewer')),
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled')),
    auth_version INTEGER NOT NULL DEFAULT 1 CHECK (auth_version > 0),
    created_at TEXT NOT NULL CHECK (substr(created_at, -1) = 'Z'),
    updated_at TEXT NOT NULL CHECK (substr(updated_at, -1) = 'Z')
);

CREATE TABLE IF NOT EXISTS registration_invites (
    id TEXT PRIMARY KEY NOT NULL,
    token_hash TEXT NOT NULL UNIQUE
        CHECK (length(token_hash) = 64 AND token_hash NOT GLOB '*[^0-9a-f]*'),
    role TEXT NOT NULL DEFAULT 'viewer'
        CHECK (role IN ('administrator', 'document_owner', 'viewer')),
    created_at TEXT NOT NULL CHECK (substr(created_at, -1) = 'Z'),
    expires_at TEXT NOT NULL CHECK (substr(expires_at, -1) = 'Z'),
    consumed_at TEXT CHECK (consumed_at IS NULL OR substr(consumed_at, -1) = 'Z'),
    created_by TEXT,
    FOREIGN KEY (created_by) REFERENCES users(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_registration_invites_expiry
    ON registration_invites(expires_at, consumed_at);

CREATE TABLE IF NOT EXISTS login_attempts (
    id TEXT PRIMARY KEY NOT NULL,
    username_key TEXT NOT NULL CHECK (length(username_key) = 64),
    source_ip TEXT NOT NULL,
    attempted_at TEXT NOT NULL CHECK (substr(attempted_at, -1) = 'Z'),
    outcome TEXT NOT NULL CHECK (outcome IN ('failed', 'success', 'blocked'))
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_username_time
    ON login_attempts(username_key, attempted_at DESC);

CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
    ON login_attempts(source_ip, attempted_at DESC);

CREATE TABLE IF NOT EXISTS server_sessions (
    sid_hash TEXT PRIMARY KEY NOT NULL
        CHECK (length(sid_hash) = 64 AND sid_hash NOT GLOB '*[^0-9a-f]*'),
    user_id TEXT,
    auth_version INTEGER,
    data_json TEXT NOT NULL CHECK (json_valid(data_json)),
    expires_at TEXT NOT NULL CHECK (substr(expires_at, -1) = 'Z'),
    created_at TEXT NOT NULL CHECK (substr(created_at, -1) = 'Z'),
    updated_at TEXT NOT NULL CHECK (substr(updated_at, -1) = 'Z'),
    FOREIGN KEY (user_id) REFERENCES users(id)
        ON UPDATE RESTRICT ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_server_sessions_user_expiry
    ON server_sessions(user_id, expires_at);

CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY NOT NULL,
    owner_id TEXT NOT NULL,
    storage_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 255),
    description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    category TEXT NOT NULL DEFAULT 'general'
        CHECK (length(trim(category)) BETWEEN 1 AND 64),
    mime_type TEXT NOT NULL CHECK (length(mime_type) BETWEEN 1 AND 127),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    sha256 TEXT NOT NULL
        CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    scan_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (scan_status IN ('pending', 'approved', 'rejected')),
    created_at TEXT NOT NULL CHECK (substr(created_at, -1) = 'Z'),
    updated_at TEXT NOT NULL CHECK (substr(updated_at, -1) = 'Z'),
    deleted_at TEXT CHECK (deleted_at IS NULL OR substr(deleted_at, -1) = 'Z'),
    FOREIGN KEY (owner_id) REFERENCES users(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS document_permissions (
    id TEXT PRIMARY KEY NOT NULL,
    document_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    granted_by TEXT NOT NULL,
    permission TEXT NOT NULL CHECK (permission IN ('read', 'edit')),
    granted_at TEXT NOT NULL CHECK (substr(granted_at, -1) = 'Z'),
    expires_at TEXT CHECK (expires_at IS NULL OR substr(expires_at, -1) = 'Z'),
    revoked_at TEXT CHECK (revoked_at IS NULL OR substr(revoked_at, -1) = 'Z'),
    CHECK (expires_at IS NULL OR expires_at > granted_at),
    FOREIGN KEY (document_id) REFERENCES documents(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (user_id) REFERENCES users(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (granted_by) REFERENCES users(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS audit_logs (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL CHECK (substr(timestamp, -1) = 'Z'),
    user_id TEXT,
    username TEXT CHECK (username IS NULL OR length(username) <= 254),
    action TEXT NOT NULL CHECK (length(trim(action)) BETWEEN 1 AND 100),
    document_id TEXT,
    ip_address TEXT CHECK (ip_address IS NULL OR length(ip_address) <= 64),
    status TEXT NOT NULL CHECK (status IN ('success', 'failure', 'denied')),
    details TEXT NOT NULL CHECK (json_valid(details)),
    prev_hash TEXT NOT NULL
        CHECK (length(prev_hash) = 64 AND prev_hash NOT GLOB '*[^0-9a-f]*'),
    current_hash TEXT NOT NULL UNIQUE
        CHECK (length(current_hash) = 64 AND current_hash NOT GLOB '*[^0-9a-f]*'),
    user_agent TEXT CHECK (user_agent IS NULL OR length(user_agent) <= 512),
    actor_id TEXT GENERATED ALWAYS AS (user_id) STORED,
    result TEXT GENERATED ALWAYS AS (status) STORED,
    occurred_at TEXT GENERATED ALWAYS AS (timestamp) STORED,
    metadata_json TEXT GENERATED ALWAYS AS (details) STORED,
    previous_hash TEXT GENERATED ALWAYS AS (prev_hash) STORED,
    event_hash TEXT GENERATED ALWAYS AS (current_hash) STORED,
    FOREIGN KEY (user_id) REFERENCES users(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (document_id) REFERENCES documents(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_users_status_role
    ON users(status, role);

CREATE INDEX IF NOT EXISTS idx_documents_owner_created
    ON documents(owner_id, created_at DESC)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_permissions_user_document
    ON document_permissions(user_id, document_id, revoked_at, expires_at);

CREATE INDEX IF NOT EXISTS idx_permissions_document
    ON document_permissions(document_id, revoked_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_permissions_one_unrevoked_grant
    ON document_permissions(document_id, user_id)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_time
    ON audit_logs(user_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_document_time
    ON audit_logs(document_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_action_time
    ON audit_logs(action, timestamp DESC);

CREATE TRIGGER IF NOT EXISTS audit_logs_validate_insert
BEFORE INSERT ON audit_logs
WHEN NEW.sequence != COALESCE((SELECT MAX(sequence) + 1 FROM audit_logs), 1)
  OR NEW.prev_hash != COALESCE(
      (SELECT current_hash FROM audit_logs ORDER BY sequence DESC LIMIT 1),
      '0000000000000000000000000000000000000000000000000000000000000000'
  )
BEGIN
    SELECT RAISE(ABORT, 'audit chain append is invalid');
END;

CREATE TRIGGER IF NOT EXISTS audit_logs_prevent_update
BEFORE UPDATE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'audit logs are append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_logs_prevent_delete
BEFORE DELETE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'audit logs are append-only');
END;
