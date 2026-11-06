"""Copy a local SQLite TrustVault database and uploads into Supabase."""

import argparse
import hashlib
import os
import re
import sqlite3
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

from audit import verify_audit_integrity
from config import Config
from database import connect, transaction


TABLES = (
    "users",
    "registration_invites",
    "login_attempts",
    "documents",
    "document_permissions",
    "audit_logs",
)
STORAGE_KEY_PATTERN = re.compile(r"[0-9a-f]{32}\.(?:pdf|png|jpg|jpeg|txt)\Z")
MAX_DOCUMENT_SIZE = 5 * 1024 * 1024
BUCKET = "trustvault-private"


def _storage_request(method, object_key, body=None):
    base_url = os.environ.get("SUPABASE_URL", "").strip()
    service_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    if not base_url or not service_key:
        raise RuntimeError("Supabase Storage environment variables are not configured.")
    url = f"{base_url.rstrip('/')}/storage/v1/object/{BUCKET}/{quote(object_key, safe='')}"
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {service_key}",
            "apikey": service_key,
            "Content-Type": "application/octet-stream",
            "x-upsert": "false",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        response_body = error.read()
        if error.code == 404:
            return 404, response_body
        if error.code in {409, 400} and method == "POST":
            status, current = _storage_request("GET", object_key)
            if status == 200 and body is not None and hashlib.sha256(current).digest() == hashlib.sha256(body).digest():
                return status, current
        raise RuntimeError(
            f"Supabase Storage request failed with HTTP {error.code}."
        ) from error
    except urllib.error.URLError as error:
        raise RuntimeError("Supabase Storage could not be reached.") from error


def migrate(sqlite_path, upload_path):
    if not Config.DATABASE_URL.startswith(("postgres://", "postgresql://")):
        raise RuntimeError("Set DATABASE_URL to the Supabase PostgreSQL connection string.")
    if not all(
        (
            os.environ.get("SUPABASE_URL"),
            os.environ.get("SUPABASE_SERVICE_ROLE_KEY"),
        )
    ):
        raise RuntimeError("Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY for storage migration.")

    sqlite_path = Path(sqlite_path).resolve(strict=True)
    upload_path = Path(upload_path).resolve(strict=True)
    source = sqlite3.connect(f"file:{sqlite_path.as_posix()}?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    destination = connect(Config.DATABASE_URL)
    files_copied = 0
    try:
        source.execute("BEGIN")
        if source.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("SQLite integrity check failed; migration stopped.")
        source_audit = verify_audit_integrity(source)
        if not source_audit["valid"]:
            raise RuntimeError("Source audit chain verification failed; migration stopped.")

        with transaction(destination):
            destination.execute("SELECT pg_advisory_xact_lock(73510423)")
            for table in TABLES:
                count = destination.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                if count:
                    raise RuntimeError(
                        f"Supabase table {table} is not empty; migration will not overwrite data."
                    )

            for document in source.execute(
                "SELECT storage_key,size_bytes,sha256 FROM documents "
                "WHERE deleted_at IS NULL ORDER BY storage_key"
            ):
                key = document["storage_key"]
                if not STORAGE_KEY_PATTERN.fullmatch(key):
                    raise RuntimeError("A document has an invalid server storage key.")
                file_path = upload_path / key
                if file_path.is_symlink() or file_path.resolve(strict=True).parent != upload_path:
                    raise RuntimeError("A document upload path is unsafe.")
                content = file_path.read_bytes()
                if (
                    len(content) > MAX_DOCUMENT_SIZE
                    or len(content) != document["size_bytes"]
                    or hashlib.sha256(content).hexdigest() != document["sha256"]
                ):
                    raise RuntimeError("A document failed its stored size or digest check.")
                status, existing = _storage_request("GET", key)
                if status == 404:
                    _storage_request("POST", key, content)
                elif hashlib.sha256(existing).hexdigest() != document["sha256"]:
                    raise RuntimeError("Supabase already has a different object with this key.")
                files_copied += 1

            for table in TABLES:
                columns = [
                    row[0]
                    for row in destination.execute(
                        """
                        SELECT column_name
                        FROM information_schema.columns
                        WHERE table_schema = current_schema()
                          AND table_name = ?
                          AND is_generated = 'NEVER'
                        ORDER BY ordinal_position
                        """,
                        (table,),
                    ).fetchall()
                ]
                names = ", ".join(f'"{column}"' for column in columns)
                placeholders = ", ".join("?" for _ in columns)
                order = " ORDER BY sequence" if table == "audit_logs" else ""
                insert = f"INSERT INTO {table} ({names}) VALUES ({placeholders})"
                for row in source.execute(f"SELECT {names} FROM {table}{order}"):
                    destination.execute(insert, tuple(row))

            migrated_audit = verify_audit_integrity(destination)
            if not migrated_audit["valid"]:
                raise RuntimeError("Supabase audit chain failed post-migration verification.")
    finally:
        source.close()
        destination.close()

    return files_copied, source_audit["events_checked"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sqlite-path", required=True, help="Existing SQLite database path")
    parser.add_argument("--upload-path", default=str(Config.UPLOAD_FOLDER))
    args = parser.parse_args()
    file_count, audit_count = migrate(args.sqlite_path, args.upload_path)
    print(f"Migrated {file_count} private documents and {audit_count} audit events.")
