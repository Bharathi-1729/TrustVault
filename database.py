import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from flask import current_app, g


SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def connect(database_path, busy_timeout_ms=5000):
    """Open a caller-owned SQLite connection with security constraints enabled."""
    connection = sqlite3.connect(
        str(database_path),
        timeout=max(busy_timeout_ms, 1) / 1000,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(f"PRAGMA busy_timeout = {max(int(busy_timeout_ms), 1)}")
    connection.execute("PRAGMA synchronous = FULL")
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        connection.close()
        raise RuntimeError("SQLite foreign key enforcement could not be enabled.")
    return connection


@contextmanager
def transaction(connection, immediate=True):
    """Run an atomic transaction, using a savepoint when nested."""
    if connection.in_transaction:
        savepoint = f"sp_{uuid4().hex}"
        connection.execute(f"SAVEPOINT {savepoint}")
        try:
            yield connection
        except Exception:
            connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            raise
        else:
            connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        return

    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield connection
    except Exception:
        connection.rollback()
        raise
    else:
        connection.commit()


def initialize_database(database_path, busy_timeout_ms=5000):
    """Create the schema atomically without deleting existing records."""
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    connection = connect(database_path, busy_timeout_ms)
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        from audit import migrate_legacy_audit_table

        migrate_legacy_audit_table(connection)
        try:
            connection.executescript(f"BEGIN IMMEDIATE;\n{schema}\nCOMMIT;")
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        invite_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(registration_invites)")
        }
        if "role" not in invite_columns:
            connection.execute(
                """
                ALTER TABLE registration_invites
                ADD COLUMN role TEXT NOT NULL DEFAULT 'viewer'
                CHECK (role IN ('administrator', 'document_owner', 'viewer'))
                """
            )
    finally:
        connection.close()
    if os.name == "posix" and Path(database_path).exists():
        os.chmod(database_path, 0o600)


def get_db():
    if "database" not in g:
        g.database = connect(
            current_app.config["DATABASE_PATH"],
            current_app.config["SQLITE_BUSY_TIMEOUT_MS"],
        )
    return g.database


def close_db(_error=None):
    connection = g.pop("database", None)
    if connection is not None:
        connection.close()


def init_app(app):
    app.teardown_appcontext(close_db)
