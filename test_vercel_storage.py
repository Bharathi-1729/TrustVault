from io import BytesIO

import pytest
from flask import Flask

import documents
from config import validate_production_config
from database import POSTGRES_SCHEMA_PATH, _split_postgres_script


class MemoryObjectStore:
    def __init__(self):
        self.objects = {}

    def put_object(self, *, Bucket, Key, Body, ContentType):
        self.objects[(Bucket, Key)] = Body

    def get_object(self, *, Bucket, Key):
        return {"Body": BytesIO(self.objects[(Bucket, Key)])}

    def delete_object(self, *, Bucket, Key):
        del self.objects[(Bucket, Key)]


def _vercel_config():
    return {
        "APP_ENV": "production",
        "DEBUG": False,
        "SESSION_COOKIE_SECURE": True,
        "SESSION_HASH_KEY_CONFIGURED": True,
        "SESSION_HASH_KEY": "s" * 48,
        "VERCEL": True,
        "DATABASE_URL": "postgresql://user:password@example.invalid/database",
        "OBJECT_STORAGE_BUCKET": "trustvault-private",
        "OBJECT_STORAGE_ENDPOINT": "https://example.r2.cloudflarestorage.com",
        "OBJECT_STORAGE_ACCESS_KEY_ID": "access-key",
        "OBJECT_STORAGE_SECRET_ACCESS_KEY": "secret-key",
    }


def test_postgres_schema_parser_preserves_function_body_semicolons():
    statements = _split_postgres_script(
        "CREATE FUNCTION f() RETURNS TEXT AS $$ BEGIN RETURN 'a;b'; END; $$ "
        "LANGUAGE plpgsql; SELECT 'c;d';"
    )
    assert len(statements) == 2
    assert "RETURN 'a;b';" in statements[0]
    assert statements[1] == "SELECT 'c;d'"


def test_postgres_schema_contains_append_only_audit_triggers():
    statements = _split_postgres_script(POSTGRES_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert any("trustvault_validate_audit_insert" in statement for statement in statements)
    assert any("audit_logs_prevent_update" in statement for statement in statements)
    assert any("audit_logs_prevent_delete" in statement for statement in statements)


def test_vercel_production_requires_postgres_and_private_storage():
    config = _vercel_config()
    validate_production_config(config)

    config["DATABASE_URL"] = "sqlite:///tmp/trustvault.sqlite3"
    with pytest.raises(RuntimeError, match="PostgreSQL"):
        validate_production_config(config)


def test_document_storage_uses_private_object_store(monkeypatch):
    app = Flask(__name__)
    app.config.update(
        OBJECT_STORAGE_BUCKET="private-bucket",
        OBJECT_STORAGE_ENDPOINT="https://example.r2.cloudflarestorage.com",
        OBJECT_STORAGE_ACCESS_KEY_ID="access-key",
        OBJECT_STORAGE_SECRET_ACCESS_KEY="secret-key",
        OBJECT_STORAGE_REGION="auto",
    )
    store = MemoryObjectStore()
    monkeypatch.setattr(documents, "_object_storage_client", lambda: store)
    key = "0123456789abcdef0123456789abcdef.pdf"

    with app.app_context():
        documents._write_private_file(key, b"private document")
        assert documents._read_private_file(key) == b"private document"
        documents._unlink_private_file(key)

    assert not store.objects
