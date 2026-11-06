"""Canonical SHA-256 hash-chained audit records."""

import hashlib
import json
import math
import os
import sqlite3
from datetime import datetime
from pathlib import Path

from database import transaction, utc_now
from security import new_id


GENESIS_HASH = "0" * 64
FORBIDDEN_DETAILS_FRAGMENTS = (
    "password",
    "secret",
    "token",
    "credential",
    "sessionid",
    "documentcontent",
)


def _validate_details(value, parent_key=""):
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise TypeError("Audit detail object keys must be strings.")
            normalized_key = "".join(
                character for character in key.lower() if character.isalnum()
            )
            if any(fragment in normalized_key for fragment in FORBIDDEN_DETAILS_FRAGMENTS):
                raise ValueError(f"Sensitive audit detail key is not allowed: {key}")
            _validate_details(child, normalized_key)
    elif isinstance(value, list):
        for child in value:
            _validate_details(child, parent_key)
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Audit details cannot contain non-finite numbers.")
    elif value is not None and not isinstance(value, (str, int, bool)):
        raise TypeError("Audit details must contain only JSON-compatible values.")


def _canonical_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _event_hash(payload):
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _validate_timestamp(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("Audit timestamps must use UTC ISO-8601 format ending in Z.")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError("Audit timestamp must be valid UTC ISO-8601.") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError("Audit timestamps must be UTC.")


def _canonical_payload(
    *,
    sequence,
    event_id,
    timestamp,
    user_id,
    username,
    action,
    document_id,
    ip_address,
    status,
    details,
    prev_hash,
    user_agent,
):
    return {
        "sequence": sequence,
        "id": event_id,
        "timestamp": timestamp,
        "user_id": user_id,
        "username": username,
        "action": action,
        "document_id": document_id,
        "ip_address": ip_address,
        "status": status,
        "details": details,
        "prev_hash": prev_hash,
        "user_agent": user_agent,
    }


def record_audit(
    connection,
    *,
    action,
    user_id=None,
    username=None,
    document_id=None,
    ip_address=None,
    status="success",
    details=None,
    timestamp=None,
    user_agent=None,
    _event_id=None,
):
    """Atomically append an immutable event and return its opaque ID.

    A write transaction obtains SQLite's reserved writer lock before reading
    the previous hash, so concurrent writers serialize the chain extension.
    """
    if not isinstance(action, str) or not action.strip() or len(action.strip()) > 100:
        raise ValueError("Audit action must be between 1 and 100 characters.")
    if status not in {"success", "failure", "denied"}:
        raise ValueError("Audit status must be success, failure, or denied.")
    if user_id is not None and (
        not isinstance(user_id, str) or not user_id or len(user_id) > 128
    ):
        raise ValueError("Audit user ID is invalid.")
    if username is not None and (
        not isinstance(username, str) or len(username) > 254
    ):
        raise ValueError("Audit username is invalid.")
    if document_id is not None and (
        not isinstance(document_id, str) or not document_id or len(document_id) > 128
    ):
        raise ValueError("Audit document ID is invalid.")
    if ip_address is not None and (
        not isinstance(ip_address, str) or len(ip_address) > 64
    ):
        raise ValueError("Audit IP address is invalid.")
    if user_agent is not None and (
        not isinstance(user_agent, str) or len(user_agent) > 512
    ):
        raise ValueError("Audit user agent is invalid.")
    if _event_id is not None and (
        not isinstance(_event_id, str) or not _event_id or len(_event_id) > 128
    ):
        raise ValueError("Audit event ID is invalid.")

    if details is None:
        details = {}
    if not isinstance(details, dict):
        raise TypeError("Audit details must be an object.")
    _validate_details(details)
    details_json = _canonical_json(details)

    event_time = timestamp or utc_now()
    _validate_timestamp(event_time)
    if username is not None:
        username = username.strip() or None
    normalized_action = action.strip()
    event_id = _event_id or new_id()

    with transaction(connection):
        if user_id is not None and username is None:
            actor = connection.execute(
                "SELECT email FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            username = actor["email"] if actor is not None else None

        last = connection.execute(
            "SELECT sequence, current_hash FROM audit_logs ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = last["sequence"] + 1 if last else 1
        previous_hash = last["current_hash"] if last else GENESIS_HASH
        payload = _canonical_payload(
            sequence=sequence,
            event_id=event_id,
            timestamp=event_time,
            user_id=user_id,
            username=username,
            action=normalized_action,
            document_id=document_id,
            ip_address=ip_address,
            status=status,
            details=details_json,
            prev_hash=previous_hash,
            user_agent=user_agent,
        )
        current_hash = _event_hash(payload)
        connection.execute(
            """
            INSERT INTO audit_logs (
                sequence, id, timestamp, user_id, username, action, document_id,
                ip_address, status, details, prev_hash, current_hash, user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sequence,
                event_id,
                event_time,
                user_id,
                username,
                normalized_action,
                document_id,
                ip_address,
                status,
                details_json,
                previous_hash,
                current_hash,
                user_agent,
            ),
        )
    return event_id


def append_event(
    connection,
    *,
    action,
    result="success",
    actor_id=None,
    document_id=None,
    ip_address=None,
    user_agent=None,
    metadata=None,
    occurred_at=None,
    username=None,
):
    """Backward-compatible event wrapper; new code should call record_audit."""
    return record_audit(
        connection,
        action=action,
        user_id=actor_id,
        username=username,
        document_id=document_id,
        ip_address=ip_address,
        status=result,
        details=metadata,
        timestamp=occurred_at,
        user_agent=user_agent,
    )


def verify_audit_integrity(connection, *, expected_head_hash=None, expected_event_count=None):
    """Return a read-only integrity report without attempting to repair records.

    A supplied head/count must come from an independently protected checkpoint.
    Without it, a valid local chain cannot prove that its newest rows were not
    removed by an attacker who could also alter the database file.
    """
    issues = []
    rows = connection.execute(
        "SELECT * FROM audit_logs ORDER BY sequence ASC"
    ).fetchall()
    previous_hash = GENESIS_HASH

    for expected_sequence, row in enumerate(rows, start=1):
        expected_payload = _canonical_payload(
            sequence=row["sequence"],
            event_id=row["id"],
            timestamp=row["timestamp"],
            user_id=row["user_id"],
            username=row["username"],
            action=row["action"],
            document_id=row["document_id"],
            ip_address=row["ip_address"],
            status=row["status"],
            details=row["details"],
            prev_hash=previous_hash,
            user_agent=row["user_agent"],
        )
        expected_hash = _event_hash(expected_payload)
        if row["sequence"] != expected_sequence:
            issues.append(
                {
                    "type": "sequence_gap_or_reordering",
                    "sequence": row["sequence"],
                    "expected_sequence": expected_sequence,
                }
            )
        if row["prev_hash"] != previous_hash:
            issues.append(
                {
                    "type": "previous_hash_mismatch",
                    "sequence": row["sequence"],
                    "expected": previous_hash,
                    "actual": row["prev_hash"],
                }
            )
        if row["current_hash"] != expected_hash:
            issues.append(
                {
                    "type": "event_hash_mismatch",
                    "sequence": row["sequence"],
                    "expected": expected_hash,
                    "actual": row["current_hash"],
                }
            )
        try:
            parsed_details = json.loads(row["details"])
            if not isinstance(parsed_details, dict) or _canonical_json(parsed_details) != row["details"]:
                issues.append(
                    {"type": "noncanonical_details", "sequence": row["sequence"]}
                )
        except (json.JSONDecodeError, TypeError, ValueError):
            issues.append({"type": "invalid_details", "sequence": row["sequence"]})
        previous_hash = row["current_hash"]

    head_hash = rows[-1]["current_hash"] if rows else GENESIS_HASH
    if expected_head_hash is not None and head_hash != expected_head_hash:
        issues.append(
            {
                "type": "external_head_mismatch",
                "expected": expected_head_hash,
                "actual": head_hash,
            }
        )
    if expected_event_count is not None and len(rows) != expected_event_count:
        issues.append(
            {
                "type": "external_event_count_mismatch",
                "expected": expected_event_count,
                "actual": len(rows),
            }
        )
    return {
        "valid": not issues,
        "events_checked": len(rows),
        "head_hash": head_hash,
        "anchored": expected_head_hash is not None or expected_event_count is not None,
        "issues": issues,
    }


def verify_chain(connection):
    """Compatibility alias for callers of the foundation phase API."""
    report = verify_audit_integrity(connection)
    return {
        "valid": report["valid"],
        "issues": report["issues"],
        "events_checked": report["events_checked"],
    }


def _backup_database_before_migration(connection):
    database_path = next(
        (
            row["file"]
            for row in connection.execute("PRAGMA database_list")
            if row["name"] == "main"
        ),
        "",
    )
    if not database_path:
        raise RuntimeError("Cannot migrate audit history without a file-backed database.")

    source_path = Path(database_path)
    backup_path = source_path.with_name(
        f"{source_path.name}.pre-audit-migration-{new_id()}.bak"
    )
    backup = sqlite3.connect(str(backup_path))
    try:
        connection.backup(backup)
    finally:
        backup.close()
    if os.name == "posix":
        os.chmod(backup_path, 0o600)
    return backup_path


_LEGACY_CREATE_TABLE = """
CREATE TABLE audit_logs (
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
)
"""

_AUDIT_INDEXES_AND_TRIGGERS = (
    "CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_time ON audit_logs(user_id, timestamp DESC)",
    "CREATE INDEX IF NOT EXISTS idx_audit_logs_document_time ON audit_logs(document_id, timestamp DESC)",
    "CREATE INDEX IF NOT EXISTS idx_audit_logs_action_time ON audit_logs(action, timestamp DESC)",
    """
    CREATE TRIGGER IF NOT EXISTS audit_logs_validate_insert
    BEFORE INSERT ON audit_logs
    WHEN NEW.sequence != COALESCE((SELECT MAX(sequence) + 1 FROM audit_logs), 1)
      OR NEW.prev_hash != COALESCE(
          (SELECT current_hash FROM audit_logs ORDER BY sequence DESC LIMIT 1),
          '0000000000000000000000000000000000000000000000000000000000000000'
      )
    BEGIN
        SELECT RAISE(ABORT, 'audit chain append is invalid');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_logs_prevent_update
    BEFORE UPDATE ON audit_logs
    BEGIN
        SELECT RAISE(ABORT, 'audit logs are append-only');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_logs_prevent_delete
    BEFORE DELETE ON audit_logs
    BEGIN
        SELECT RAISE(ABORT, 'audit logs are append-only');
    END
    """,
)


def migrate_legacy_audit_table(connection):
    """Transactionally migrate the foundation audit schema after validating it."""
    columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(audit_logs)")
    }
    if not columns or "current_hash" in columns:
        return False
    required_legacy = {
        "sequence",
        "id",
        "actor_id",
        "document_id",
        "action",
        "result",
        "occurred_at",
        "ip_address",
        "user_agent",
        "metadata_json",
        "previous_hash",
        "event_hash",
    }
    if not required_legacy <= columns:
        raise RuntimeError("Unrecognized audit schema; refusing to alter audit history.")

    rows = connection.execute(
        "SELECT * FROM audit_logs ORDER BY sequence ASC"
    ).fetchall()
    old_previous = GENESIS_HASH
    for expected_sequence, row in enumerate(rows, start=1):
        legacy_payload = {
            "id": row["id"],
            "actor_id": row["actor_id"],
            "document_id": row["document_id"],
            "action": row["action"],
            "result": row["result"],
            "occurred_at": row["occurred_at"],
            "ip_address": row["ip_address"],
            "user_agent": row["user_agent"],
            "metadata_json": row["metadata_json"],
            "previous_hash": old_previous,
        }
        if (
            row["sequence"] != expected_sequence
            or row["previous_hash"] != old_previous
            or row["event_hash"] != _event_hash(legacy_payload)
        ):
            raise RuntimeError(
                "Legacy audit integrity check failed; refusing migration without repair."
            )
        old_previous = row["event_hash"]

    _backup_database_before_migration(connection)

    with transaction(connection):
        for trigger in (
            "audit_logs_prevent_update",
            "audit_logs_prevent_delete",
            "audit_logs_validate_insert",
        ):
            connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        for index in (
            "idx_audit_logs_actor_time",
            "idx_audit_logs_document_time",
            "idx_audit_logs_action_time",
        ):
            connection.execute(f"DROP INDEX IF EXISTS {index}")
        connection.execute("ALTER TABLE audit_logs RENAME TO audit_logs_legacy_v1")
        connection.execute(_LEGACY_CREATE_TABLE)

        for row in rows:
            try:
                details = json.loads(row["metadata_json"])
            except json.JSONDecodeError as error:
                raise RuntimeError(
                    "Legacy audit details are invalid; refusing migration."
                ) from error
            actor = None
            if row["actor_id"] is not None:
                actor = connection.execute(
                    "SELECT email FROM users WHERE id = ?", (row["actor_id"],)
                ).fetchone()
            record_audit(
                connection,
                action=row["action"],
                user_id=row["actor_id"],
                username=actor["email"] if actor is not None else None,
                document_id=row["document_id"],
                ip_address=row["ip_address"],
                status=row["result"],
                details=details,
                timestamp=row["occurred_at"],
                user_agent=row["user_agent"],
                _event_id=row["id"],
            )
        connection.execute("DROP TABLE audit_logs_legacy_v1")
        for statement in _AUDIT_INDEXES_AND_TRIGGERS:
            connection.execute(statement)

    report = verify_audit_integrity(connection)
    if not report["valid"]:
        raise RuntimeError("Migrated audit history failed integrity verification.")
    return True
