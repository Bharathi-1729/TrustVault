import hashlib
import hmac
import re
import secrets
from uuid import uuid4


ROLES = frozenset({"administrator", "document_owner", "viewer"})
DOCUMENT_PERMISSIONS = frozenset({"read", "edit"})
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s.]+(?:\.[^@\s.]+)+$")


def normalize_email(email):
    if not isinstance(email, str):
        raise ValueError("Email must be a string.")
    normalized = email.strip().lower()
    if len(normalized) > 254 or not EMAIL_PATTERN.fullmatch(normalized):
        raise ValueError("A valid email address is required.")
    return normalized


def is_valid_role(role):
    return isinstance(role, str) and role in ROLES


def is_valid_permission(permission):
    return isinstance(permission, str) and permission in DOCUMENT_PERMISSIONS


def new_id():
    """Generate an opaque identifier for internal database records."""
    return uuid4().hex


def new_session_token():
    """Generate a high-entropy token; callers must store only its digest."""
    return secrets.token_urlsafe(32)


def hash_session_token(token, secret=None):
    if not isinstance(token, str) or not token:
        raise ValueError("A non-empty session token is required.")
    message = token.encode("utf-8")
    if secret is None:
        return hashlib.sha256(message).hexdigest()
    if not isinstance(secret, str) or len(secret.encode("utf-8")) < 32:
        raise ValueError("A session hash key of at least 32 bytes is required.")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def hash_registration_invite(token):
    if not isinstance(token, str) or not token:
        raise ValueError("A non-empty registration invite is required.")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_login_identifier(normalized_username):
    if not isinstance(normalized_username, str):
        raise ValueError("A normalized username string is required.")
    return hashlib.sha256(normalized_username.encode("utf-8")).hexdigest()


def secure_compare(left, right):
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
