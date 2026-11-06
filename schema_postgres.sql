CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    email TEXT NOT NULL UNIQUE CHECK (length(trim(email)) BETWEEN 3 AND 254),
    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 120),
    password_hash TEXT NOT NULL CHECK (length(password_hash) > 0),
    role TEXT NOT NULL DEFAULT 'viewer'
        CHECK (role IN ('administrator', 'document_owner', 'viewer')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    auth_version INTEGER NOT NULL DEFAULT 1 CHECK (auth_version > 0),
    created_at TEXT NOT NULL CHECK (right(created_at, 1) = 'Z'),
    updated_at TEXT NOT NULL CHECK (right(updated_at, 1) = 'Z'),
    CHECK (email = lower(trim(email)))
);

CREATE TABLE IF NOT EXISTS registration_invites (
    id TEXT PRIMARY KEY NOT NULL,
    token_hash TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    role TEXT NOT NULL DEFAULT 'viewer'
        CHECK (role IN ('administrator', 'document_owner', 'viewer')),
    created_at TEXT NOT NULL CHECK (right(created_at, 1) = 'Z'),
    expires_at TEXT NOT NULL CHECK (right(expires_at, 1) = 'Z'),
    consumed_at TEXT CHECK (consumed_at IS NULL OR right(consumed_at, 1) = 'Z'),
    created_by TEXT REFERENCES users(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_registration_invites_expiry
    ON registration_invites(expires_at, consumed_at);

CREATE TABLE IF NOT EXISTS login_attempts (
    id TEXT PRIMARY KEY NOT NULL,
    username_key TEXT NOT NULL CHECK (length(username_key) = 64),
    source_ip TEXT NOT NULL,
    attempted_at TEXT NOT NULL CHECK (right(attempted_at, 1) = 'Z'),
    outcome TEXT NOT NULL CHECK (outcome IN ('failed', 'success', 'blocked'))
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_username_time
    ON login_attempts(username_key, attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
    ON login_attempts(source_ip, attempted_at DESC);

CREATE TABLE IF NOT EXISTS server_sessions (
    sid_hash TEXT PRIMARY KEY NOT NULL CHECK (sid_hash ~ '^[0-9a-f]{64}$'),
    user_id TEXT REFERENCES users(id) ON UPDATE RESTRICT ON DELETE CASCADE,
    auth_version INTEGER,
    data_json TEXT NOT NULL CHECK (jsonb_typeof(data_json::jsonb) = 'object'),
    expires_at TEXT NOT NULL CHECK (right(expires_at, 1) = 'Z'),
    created_at TEXT NOT NULL CHECK (right(created_at, 1) = 'Z'),
    updated_at TEXT NOT NULL CHECK (right(updated_at, 1) = 'Z')
);

CREATE INDEX IF NOT EXISTS idx_server_sessions_user_expiry
    ON server_sessions(user_id, expires_at);

CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY NOT NULL,
    owner_id TEXT NOT NULL REFERENCES users(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    storage_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 255),
    description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    category TEXT NOT NULL DEFAULT 'general'
        CHECK (length(trim(category)) BETWEEN 1 AND 64),
    mime_type TEXT NOT NULL CHECK (length(mime_type) BETWEEN 1 AND 127),
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    scan_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (scan_status IN ('pending', 'approved', 'rejected')),
    created_at TEXT NOT NULL CHECK (right(created_at, 1) = 'Z'),
    updated_at TEXT NOT NULL CHECK (right(updated_at, 1) = 'Z'),
    deleted_at TEXT CHECK (deleted_at IS NULL OR right(deleted_at, 1) = 'Z')
);

CREATE TABLE IF NOT EXISTS document_permissions (
    id TEXT PRIMARY KEY NOT NULL,
    document_id TEXT NOT NULL REFERENCES documents(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    user_id TEXT NOT NULL REFERENCES users(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    granted_by TEXT NOT NULL REFERENCES users(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    permission TEXT NOT NULL CHECK (permission IN ('read', 'edit')),
    granted_at TEXT NOT NULL CHECK (right(granted_at, 1) = 'Z'),
    expires_at TEXT CHECK (expires_at IS NULL OR right(expires_at, 1) = 'Z'),
    revoked_at TEXT CHECK (revoked_at IS NULL OR right(revoked_at, 1) = 'Z'),
    CHECK (expires_at IS NULL OR expires_at > granted_at)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    sequence BIGINT PRIMARY KEY NOT NULL,
    id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL CHECK (right(timestamp, 1) = 'Z'),
    user_id TEXT REFERENCES users(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    username TEXT CHECK (username IS NULL OR length(username) <= 254),
    action TEXT NOT NULL CHECK (length(trim(action)) BETWEEN 1 AND 100),
    document_id TEXT REFERENCES documents(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    ip_address TEXT CHECK (ip_address IS NULL OR length(ip_address) <= 64),
    status TEXT NOT NULL CHECK (status IN ('success', 'failure', 'denied')),
    details TEXT NOT NULL CHECK (jsonb_typeof(details::jsonb) = 'object'),
    prev_hash TEXT NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
    current_hash TEXT NOT NULL UNIQUE CHECK (current_hash ~ '^[0-9a-f]{64}$'),
    user_agent TEXT CHECK (user_agent IS NULL OR length(user_agent) <= 512),
    actor_id TEXT GENERATED ALWAYS AS (user_id) STORED,
    result TEXT GENERATED ALWAYS AS (status) STORED,
    occurred_at TEXT GENERATED ALWAYS AS (timestamp) STORED,
    metadata_json TEXT GENERATED ALWAYS AS (details) STORED,
    previous_hash TEXT GENERATED ALWAYS AS (prev_hash) STORED,
    event_hash TEXT GENERATED ALWAYS AS (current_hash) STORED
);

CREATE INDEX IF NOT EXISTS idx_users_status_role ON users(status, role);
CREATE INDEX IF NOT EXISTS idx_documents_owner_created
    ON documents(owner_id, created_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_permissions_user_document
    ON document_permissions(user_id, document_id, revoked_at, expires_at);
CREATE INDEX IF NOT EXISTS idx_permissions_document
    ON document_permissions(document_id, revoked_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_permissions_one_unrevoked_grant
    ON document_permissions(document_id, user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_time
    ON audit_logs(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_document_time
    ON audit_logs(document_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action_time
    ON audit_logs(action, timestamp DESC);

CREATE OR REPLACE FUNCTION trustvault_validate_audit_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    last_sequence BIGINT;
    last_hash TEXT;
BEGIN
    PERFORM pg_advisory_xact_lock(73510422);
    SELECT sequence, current_hash INTO last_sequence, last_hash
    FROM audit_logs ORDER BY sequence DESC LIMIT 1;
    IF NEW.sequence != COALESCE(last_sequence + 1, 1)
       OR NEW.prev_hash != COALESCE(last_hash, repeat('0', 64)) THEN
        RAISE EXCEPTION 'audit chain append is invalid';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION trustvault_reject_audit_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit logs are append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_logs_validate_insert ON audit_logs;
CREATE TRIGGER audit_logs_validate_insert
BEFORE INSERT ON audit_logs
FOR EACH ROW EXECUTE FUNCTION trustvault_validate_audit_insert();

DROP TRIGGER IF EXISTS audit_logs_prevent_update ON audit_logs;
CREATE TRIGGER audit_logs_prevent_update
BEFORE UPDATE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION trustvault_reject_audit_mutation();

DROP TRIGGER IF EXISTS audit_logs_prevent_delete ON audit_logs;
CREATE TRIGGER audit_logs_prevent_delete
BEFORE DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION trustvault_reject_audit_mutation();
