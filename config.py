import os
from datetime import timedelta
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent


class Config:
    """Non-secret application settings sourced from the environment."""

    APP_ENV = os.environ.get("TRUSTVAULT_ENV", "development").strip().lower()
    DATA_DIR = Path(os.environ.get("TRUSTVAULT_DATA_DIR", PROJECT_ROOT / "instance"))
    DATABASE_PATH = Path(
        os.environ.get("TRUSTVAULT_DATABASE_PATH", DATA_DIR / "trustvault.sqlite3")
    )
    UPLOAD_FOLDER = Path(
        os.environ.get("TRUSTVAULT_UPLOAD_DIR", DATA_DIR / "uploads")
    )
    BACKUP_DIR = Path(os.environ.get("TRUSTVAULT_BACKUP_DIR", DATA_DIR / "backups"))
    MAX_DOCUMENT_SIZE_BYTES = 5 * 1024 * 1024
    MAX_CONTENT_LENGTH = MAX_DOCUMENT_SIZE_BYTES + 64 * 1024
    SQLITE_BUSY_TIMEOUT_MS = int(os.environ.get("TRUSTVAULT_SQLITE_BUSY_TIMEOUT_MS", 5000))
    SQLITE_JOURNAL_MODE = "WAL"
    SQLITE_SYNCHRONOUS = "FULL"
    SESSION_HASH_KEY_CONFIGURED = bool(os.environ.get("TRUSTVAULT_SESSION_HASH_KEY"))
    SESSION_HASH_KEY = os.environ.get(
        "TRUSTVAULT_SESSION_HASH_KEY", "local-development-key-not-for-production"
    )
    SESSION_COOKIE_NAME = "trustvault_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = os.environ.get("TRUSTVAULT_COOKIE_SECURE", "true").lower() == "true"
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_PATH = "/"
    SESSION_COOKIE_DOMAIN = None
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    SESSION_REFRESH_EACH_REQUEST = True
    AUTH_MAX_FAILED_ATTEMPTS = 5
    AUTH_RATE_WINDOW_SECONDS = int(os.environ.get("TRUSTVAULT_LOGIN_WINDOW_SECONDS", 15 * 60))
    ROLES = ("administrator", "document_owner", "viewer")
    DOCUMENT_PERMISSIONS = ("read", "edit")
    DEBUG = False
    PREFERRED_URL_SCHEME = "https"
    TRUST_PROXY_HEADERS = APP_ENV == "production"
    TRUSTED_HOSTS = [
        host.strip()
        for host in os.environ.get(
            "TRUSTVAULT_ALLOWED_HOSTS", os.environ.get("RENDER_EXTERNAL_HOSTNAME", "")
        ).split(",")
        if host.strip()
    ] or None


def validate_production_config(config):
    """Fail closed when required deployment boundaries are not configured."""
    if config["APP_ENV"] != "production":
        return
    if config["DEBUG"]:
        raise RuntimeError("Debug mode must be disabled in production.")
    if not config["SESSION_COOKIE_SECURE"]:
        raise RuntimeError("Secure session cookies are mandatory in production.")
    session_key = config["SESSION_HASH_KEY"]
    if (
        not config.get("SESSION_HASH_KEY_CONFIGURED")
        or not isinstance(session_key, str)
        or len(session_key.encode("utf-8")) < 32
    ):
        raise RuntimeError(
            "TRUSTVAULT_SESSION_HASH_KEY must contain at least 32 bytes in production."
        )

    data_dir = Path(config["DATA_DIR"]).resolve()
    database_path = Path(config["DATABASE_PATH"]).resolve()
    upload_path = Path(config["UPLOAD_FOLDER"]).resolve()
    backup_path = Path(config["BACKUP_DIR"]).resolve()
    if (
        not database_path.is_relative_to(data_dir)
        or not upload_path.is_relative_to(data_dir)
        or not backup_path.is_relative_to(data_dir)
    ):
        raise RuntimeError(
            "Production database, uploads, and backups must be under TRUSTVAULT_DATA_DIR."
        )
    if (
        database_path == upload_path
        or database_path.is_relative_to(upload_path)
        or backup_path == upload_path
        or backup_path.is_relative_to(upload_path)
    ):
        raise RuntimeError("Database, backups, and upload storage must use separate paths.")


def ensure_private_directories(config):
    """Create the database and upload directories with restrictive defaults."""
    database_path = Path(config["DATABASE_PATH"])
    upload_path = Path(config["UPLOAD_FOLDER"])
    database_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    upload_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if database_path.exists() and database_path.is_symlink():
        raise RuntimeError("Database file must not be a symbolic link.")
    if upload_path.is_symlink() or not upload_path.is_dir():
        raise RuntimeError("Private upload directory must be a real directory, not a symlink.")
    resolved_upload_path = upload_path.resolve(strict=True)
    public_root = (PROJECT_ROOT / "static").resolve(strict=True)
    if resolved_upload_path == public_root or public_root in resolved_upload_path.parents:
        raise RuntimeError("Private uploads must be stored outside the public web root.")
    if os.name == "posix":
        os.chmod(database_path.parent.resolve(strict=True), 0o700)
        os.chmod(resolved_upload_path, 0o700)
