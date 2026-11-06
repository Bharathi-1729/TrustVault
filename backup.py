"""Create a private SQLite snapshot and a matching live-upload archive."""

import argparse
import hashlib
import io
import os
import re
import sqlite3
import stat
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from config import Config
from database import connect


STORAGE_KEY_PATTERN = re.compile(r"[0-9a-f]{32}\.(?:pdf|png|jpg|jpeg|txt)\Z")


def create_backup(config=Config):
    if str(config.DATABASE_PATH).startswith(("postgres://", "postgresql://")):
        raise RuntimeError(
            "This backup command supports local SQLite only; use PostgreSQL provider backups and object-storage versioning."
        )
    if Path(config.DATABASE_PATH).is_symlink() or Path(config.UPLOAD_FOLDER).is_symlink():
        raise RuntimeError("Database and upload paths must not be symbolic links.")
    database_path = Path(config.DATABASE_PATH).resolve(strict=True)
    upload_path = Path(config.UPLOAD_FOLDER).resolve(strict=True)
    backup_path = Path(config.BACKUP_DIR)
    if backup_path.is_symlink():
        raise RuntimeError("Backup directory must not be a symbolic link.")
    backup_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup_path = backup_path.resolve(strict=True)
    public_root = (Path(__file__).parent / "static").resolve(strict=True)
    if backup_path == public_root or public_root in backup_path.parents:
        raise RuntimeError("Backups must be outside the public web root.")
    if backup_path == upload_path or backup_path.is_relative_to(upload_path):
        raise RuntimeError("Backups must not be stored inside private upload storage.")
    if os.name == "posix":
        os.chmod(backup_path, 0o700)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    suffix = uuid4().hex[:8]
    database_file = backup_path / f"trustvault-{timestamp}-{suffix}.sqlite3"
    archive_file = backup_path / f"trustvault-uploads-{timestamp}-{suffix}.tar.gz"
    temporary_database = database_file.with_suffix(".sqlite3.tmp")
    temporary_archive = archive_file.with_suffix(".tar.gz.tmp")

    try:
        source = connect(database_path, config.SQLITE_BUSY_TIMEOUT_MS)
        try:
            destination = sqlite3.connect(temporary_database)
            try:
                destination.row_factory = sqlite3.Row
                destination.execute("PRAGMA foreign_keys = ON")
                destination.execute("PRAGMA synchronous = FULL")
                source.backup(destination)
                destination.commit()
                live_files = [
                    (row["storage_key"], row["size_bytes"], row["sha256"])
                    for row in destination.execute(
                        "SELECT storage_key, size_bytes, sha256 FROM documents "
                        "WHERE deleted_at IS NULL ORDER BY storage_key"
                    ).fetchall()
                ]
            finally:
                destination.close()
        finally:
            source.close()

        if os.name == "posix":
            os.chmod(temporary_database, 0o600)
        os.replace(temporary_database, database_file)

        with tarfile.open(temporary_archive, mode="w:gz") as archive:
            for storage_key, expected_size, expected_digest in live_files:
                if not STORAGE_KEY_PATTERN.fullmatch(storage_key):
                    raise RuntimeError("Database contains an invalid private storage key.")
                file_path = upload_path / storage_key
                if file_path.is_symlink():
                    raise RuntimeError("Private upload archive contains a symbolic link.")
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
                descriptor = os.open(file_path, flags)
                try:
                    metadata = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_size > 5 * 1024 * 1024
                        or metadata.st_size != expected_size
                    ):
                        raise RuntimeError("Private upload file is not a regular supported-size file.")
                    with os.fdopen(descriptor, "rb", closefd=False) as source_file:
                        content = source_file.read(5 * 1024 * 1024 + 1)
                    if hashlib.sha256(content).hexdigest() != expected_digest:
                        raise RuntimeError("Private upload content does not match its stored digest.")
                    info = tarfile.TarInfo(storage_key)
                    info.size = len(content)
                    info.mode = 0o600
                    info.mtime = 0
                    archive.addfile(info, io.BytesIO(content))
                finally:
                    os.close(descriptor)

        if os.name == "posix":
            os.chmod(temporary_archive, 0o600)
        os.replace(temporary_archive, archive_file)
    except Exception:
        for temporary_file in (temporary_database, temporary_archive, database_file):
            try:
                temporary_file.unlink()
            except FileNotFoundError:
                pass
        raise
    return database_file, archive_file


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a private TrustVault backup pair.")
    parser.parse_args()
    database_backup, upload_backup = create_backup()
    print(f"Database snapshot: {database_backup.name}")
    print(f"Private upload archive: {upload_backup.name}")
