"""Time-based one-time password support for administrator authentication."""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

from cryptography.fernet import Fernet


def generate_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _fernet(session_hash_key):
    if not isinstance(session_hash_key, str) or not session_hash_key:
        raise ValueError("A stable session hash key is required to protect MFA secrets.")
    derived_key = hmac.new(
        session_hash_key.encode("utf-8"),
        b"TrustVault TOTP secret encryption v1",
        hashlib.sha256,
    ).digest()
    return Fernet(base64.urlsafe_b64encode(derived_key))


def encrypt_totp_secret(secret, session_hash_key):
    return _fernet(session_hash_key).encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_totp_secret(encrypted_secret, session_hash_key):
    return _fernet(session_hash_key).decrypt(encrypted_secret.encode("ascii")).decode("ascii")


def totp_setup_uri(secret, email, issuer="TrustVault"):
    label = quote(f"{issuer}:{email}", safe="")
    query = urlencode({
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
    })
    return f"otpauth://totp/{label}?{query}"


def _totp_code(secret, counter):
    padded_secret = secret + "=" * (-len(secret) % 8)
    key = base64.b32decode(padded_secret, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def matching_totp_counter(secret, supplied_code, at_time=None):
    if not isinstance(supplied_code, str) or len(supplied_code) != 6:
        return None
    if not supplied_code.isascii() or not supplied_code.isdigit():
        return None
    current_counter = int((time.time() if at_time is None else at_time) // 30)
    for drift in (-1, 0, 1):
        counter = current_counter + drift
        if hmac.compare_digest(_totp_code(secret, counter), supplied_code):
            return counter
    return None


def verify_totp(secret, supplied_code, at_time=None):
    return matching_totp_counter(secret, supplied_code, at_time) is not None
