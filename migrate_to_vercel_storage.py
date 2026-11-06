"""Copy a local SQLite TrustVault instance to PostgreSQL and private S3 storage."""

import argparse
import hashlib
import re
import sqlite3
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

from audit import verify_audit_integrity
from config import Config
from database import connect, initialize_database, transaction


TABLES = (
    "users",
    "registration_invites",
    "login_attempts",
    "server_sessions",
    "documents",
    "document_permissions",
    "audit_logs",
)
STORAGE_KEY_PATTERN = re.compile(r"[0-9a-f]{32}\.(?:pdf|png|jpg|jpeg|txt)\Z")
MAX_DOCUMENT_SIZE = 5 * 1024 * 1024


def migrate(sqlite_path, upload_path, *, execute=False):
    database_url = Config.DATABASE_URL
    bucket = Config.OBJECT_STORAGE_BUCKET
    if not database_url.startswith(("postgres://", "postgresql://")) or not all(
        (
            bucket,
            Config.OBJECT_STORAGE_ENDPOINT,
            Config.OBJECT_STORAGE_ACCESS_KEY_ID,
            Config.OBJECT_STORAGE_SECRET_ACCESS_KEY,
        )
    ):
        raise RuntimeError(
            "Set DATABASE_URL and all required private object-storage environment variables first."
        )
    if not execute:
        raise RuntimeError("Migration is a write operation; rerun with --execute to proceed.")

    sqlite_path = Path(sqlite_path).resolve(strict=True)
    upload_path = Path(upload_path).resolve(strict=True)
    initialize_database(database_url)
    source = sqlite3.connect(f"file:{sqlite_path.as_posix()}?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    destination = connect(database_url)
    object_store = boto3.client(
        "s3",
        endpoint_url=Config.OBJECT_STORAGE_ENDPOINT,
        aws_access_key_id=Config.OBJECT_STORAGE_ACCESS_KEY_ID,
        aws_secret_access_key=Config.OBJECT_STORAGE_SECRET_ACCESS_KEY,
        region_name=Config.OBJECT_STORAGE_REGION,
    )
    uploaded_keys = []
    try:
        source.execute("BEGIN")
        integrity = source.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError("SQLite integrity check failed; migration stopped.")
        audit_report = verify_audit_integrity(source)
        if not audit_report["valid"]:
            raise RuntimeError("Audit chain verification failed; migration stopped.")

        with transaction(destination):
            destination.execute("SELECT pg_advisory_xact_lock(73510423)")
            for table in TABLES:
                if destination.execute(f"SELECT count(*) FROM {table}").fetchone()[0]:
                    raise RuntimeError(
                        f"PostgreSQL table {table} is not empty; migration will not overwrite data."
                    )

            for document in source.execute(
                "SELECT storage_key, size_bytes, sha256 FROM documents "
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
                try:
                    existing = object_store.get_object(Bucket=bucket, Key=key)
                except ClientError as error:
                    if error.response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 404:
                        raise
                    object_store.put_object(
                        Bucket=bucket,
                        Key=key,
                        Body=content,
                        ContentType="application/octet-stream",
                    )
                else:
                    try:
                        existing_content = existing["Body"].read(MAX_DOCUMENT_SIZE + 1)
                    finally:
                        existing["Body"].close()
                    if hashlib.sha256(existing_content).hexdigest() != document["sha256"]:
                        raise RuntimeError(
                            "A matching object key already exists with different content."
                        )
                uploaded_keys.append(key)

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
                column_sql = ", ".join(f'"{column}"' for column in columns)
                placeholders = ", ".join("?" for _ in columns)
                insert = f"INSERT INTO {table} ({column_sql}) VALUES ({placeholders})"
                for row in source.execute(f"SELECT {column_sql} FROM {table}"):
                    destination.execute(insert, tuple(row))

            migrated_audit = verify_audit_integrity(destination)
            if not migrated_audit["valid"]:
                raise RuntimeError("Migrated PostgreSQL audit chain failed verification.")
    finally:
        source.close()
        destination.close()

    return len(uploaded_keys), audit_report["events_checked"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sqlite-path", required=True, help="Path to the existing SQLite database")
    parser.add_argument("--upload-path", default=str(Config.UPLOAD_FOLDER))
    parser.add_argument("--execute", action="store_true", help="Perform the migration")
    arguments = parser.parse_args()
    files, events = migrate(
        arguments.sqlite_path,
        arguments.upload_path,
        execute=arguments.execute,
    )
    print(f"Migrated {files} private documents and {events} audit events.")
