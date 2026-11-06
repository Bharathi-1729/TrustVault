import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from flask import current_app, g


SCHEMA_PATH = Path(__file__).with_name("schema.sql")
POSTGRES_SCHEMA_PATH = Path(__file__).with_name("schema_postgres.sql")


class _PostgresRow(dict):
    def __init__(self, names, values):
        super().__init__(zip(names, values))
        self._values = values

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)


def _postgres_row_factory(cursor):
    names = [column.name for column in cursor.description]
    return lambda values: _PostgresRow(names, values)


class _PostgresConnection:
    is_postgres = True

    def __init__(self, connection):
        self._connection = connection

    @property
    def in_transaction(self):
        return self._connection.info.transaction_status.name != "IDLE"

    def execute(self, statement, parameters=None):
        statement = re.sub(r"(?<!\?)\?(?!\?)", "%s", statement)
        statement = statement.replace("BEGIN IMMEDIATE", "BEGIN")
        return self._connection.execute(statement, parameters)

    def commit(self):
        self._connection.commit()

    def rollback(self):
        self._connection.rollback()

    def close(self):
        self._connection.close()


def is_postgres(database_path):
    return str(database_path).startswith(("postgres://", "postgresql://"))


def database_errors():
    if is_postgres(current_app.config["DATABASE_PATH"]):
        import psycopg

        return (psycopg.Error,)
    return (sqlite3.Error,)


def integrity_errors():
    if is_postgres(current_app.config["DATABASE_PATH"]):
        from psycopg import IntegrityError

        return (IntegrityError,)
    return (sqlite3.IntegrityError,)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def connect(database_path, busy_timeout_ms=5000):
    """Open a caller-owned SQLite or PostgreSQL connection."""
    if is_postgres(database_path):
        import psycopg

        connection = psycopg.connect(
            str(database_path),
            autocommit=True,
            row_factory=_postgres_row_factory,
            prepare_threshold=None,
        )
        return _PostgresConnection(connection)
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
    if is_postgres(database_path):
        _initialize_postgres_database(database_path)
        return
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


def _split_postgres_script(script):
    statements = []
    start = 0
    quote = None
    dollar_quote = None
    index = 0
    while index < len(script):
        if dollar_quote:
            if script.startswith(dollar_quote, index):
                index += len(dollar_quote)
                dollar_quote = None
                continue
        elif quote:
            if script[index] == quote:
                if quote == "'" and script[index:index + 2] == "''":
                    index += 2
                    continue
                quote = None
        elif script[index] in ("'", '"'):
            quote = script[index]
        elif script[index] == "$":
            match = re.match(r"\$[A-Za-z_0-9]*\$", script[index:])
            if match:
                dollar_quote = match.group(0)
                index += len(dollar_quote)
                continue
        elif script[index] == ";":
            statement = script[start:index].strip()
            if statement:
                statements.append(statement)
            start = index + 1
        index += 1
    trailing = script[start:].strip()
    if trailing:
        statements.append(trailing)
    return statements


def _initialize_postgres_database(database_url):
    connection = connect(database_url)
    try:
        with transaction(connection):
            connection.execute("SELECT pg_advisory_xact_lock(73510421)")
            schema = POSTGRES_SCHEMA_PATH.read_text(encoding="utf-8")
            for statement in _split_postgres_script(schema):
                connection.execute(statement)
    finally:
        connection.close()


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
