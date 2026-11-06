import json
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Blueprint,
    current_app,
    g,
    jsonify,
    request,
    session,
)
from flask.sessions import SessionInterface, SessionMixin
from werkzeug.security import check_password_hash, generate_password_hash

from audit import append_event
from database import connect, get_db, transaction, utc_now
from security import (
    hash_login_identifier,
    hash_registration_invite,
    hash_session_token,
    new_id,
    new_session_token,
    normalize_email,
    secure_compare,
)

auth = Blueprint("auth", __name__, url_prefix="/api/auth")
GENERIC_LOGIN_ERROR = "Invalid email or password."
_DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32))


class ServerSideSession(dict, SessionMixin):
    def __init__(self, initial=None, sid=None, new=False):
        super().__init__(initial or {})
        self.sid = sid
        self.new = new
        self.modified = False
        self.accessed = False

    def __getitem__(self, key):
        self.accessed = True
        return super().__getitem__(key)

    def get(self, key, default=None):
        self.accessed = True
        return super().get(key, default)

    def __setitem__(self, key, value):
        self.modified = True
        super().__setitem__(key, value)

    def __delitem__(self, key):
        self.modified = True
        super().__delitem__(key)

    def clear(self):
        self.modified = True
        super().clear()

    def pop(self, key, *args):
        self.modified = True
        return super().pop(key, *args)

    def update(self, *args, **kwargs):
        self.modified = True
        super().update(*args, **kwargs)


class SQLiteSessionInterface(SessionInterface):
    def open_session(self, app, request):
        sid = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
        if not sid or len(sid) > 128:
            return ServerSideSession(sid=new_session_token(), new=True)

        sid_hash = hash_session_token(sid, app.config["SESSION_HASH_KEY"])
        connection = connect(
            app.config["DATABASE_PATH"], app.config["SQLITE_BUSY_TIMEOUT_MS"]
        )
        try:
            row = connection.execute(
                """
                SELECT user_id, auth_version, data_json, expires_at
                FROM server_sessions WHERE sid_hash = ?
                """,
                (sid_hash,),
            ).fetchone()
            if row is None:
                return ServerSideSession(sid=new_session_token(), new=True)
            if row["expires_at"] <= utc_now():
                connection.execute(
                    "DELETE FROM server_sessions WHERE sid_hash = ?", (sid_hash,)
                )
                return ServerSideSession(sid=new_session_token(), new=True)
            data = json.loads(row["data_json"])
            if not isinstance(data, dict):
                raise ValueError("Invalid session payload.")
            if (
                data.get("user_id") != row["user_id"]
                or data.get("auth_version") != row["auth_version"]
            ):
                raise ValueError("Session identity data is inconsistent.")
            return ServerSideSession(data, sid=sid)
        except (json.JSONDecodeError, TypeError, ValueError):
            connection.execute(
                "DELETE FROM server_sessions WHERE sid_hash = ?", (sid_hash,)
            )
            return ServerSideSession(sid=new_session_token(), new=True)
        finally:
            connection.close()

    def save_session(self, app, session_obj, response):
        if session_obj.accessed:
            response.vary.add("Cookie")
        name = app.config["SESSION_COOKIE_NAME"]
        if not session_obj:
            if session_obj.sid:
                connection = connect(
                    app.config["DATABASE_PATH"], app.config["SQLITE_BUSY_TIMEOUT_MS"]
                )
                try:
                    connection.execute(
                        "DELETE FROM server_sessions WHERE sid_hash = ?",
                        (hash_session_token(session_obj.sid, app.config["SESSION_HASH_KEY"]),),
                    )
                finally:
                    connection.close()
            response.delete_cookie(
                name,
                path=app.config["SESSION_COOKIE_PATH"],
                domain=app.config["SESSION_COOKIE_DOMAIN"],
                secure=app.config["SESSION_COOKIE_SECURE"],
                httponly=app.config["SESSION_COOKIE_HTTPONLY"],
                samesite=app.config["SESSION_COOKIE_SAMESITE"],
            )
            return

        now = utc_now()
        expires = datetime.now(timezone.utc) + app.config["PERMANENT_SESSION_LIFETIME"]
        expires_at = expires.isoformat(timespec="microseconds").replace("+00:00", "Z")
        user_id = session_obj.get("user_id")
        auth_version = session_obj.get("auth_version")
        payload = json.dumps(dict(session_obj), separators=(",", ":"), sort_keys=True)
        connection = connect(
            app.config["DATABASE_PATH"], app.config["SQLITE_BUSY_TIMEOUT_MS"]
        )
        try:
            connection.execute(
                "DELETE FROM server_sessions WHERE expires_at <= ?", (now,)
            )
            connection.execute(
                """
                INSERT INTO server_sessions
                    (sid_hash, user_id, auth_version, data_json, expires_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sid_hash) DO UPDATE SET
                    user_id = excluded.user_id,
                    auth_version = excluded.auth_version,
                    data_json = excluded.data_json,
                    expires_at = excluded.expires_at,
                    updated_at = excluded.updated_at
                """,
                (
                    hash_session_token(session_obj.sid, app.config["SESSION_HASH_KEY"]),
                    user_id,
                    auth_version,
                    payload,
                    expires_at,
                    now,
                    now,
                ),
            )
        finally:
            connection.close()

        response.set_cookie(
            name,
            session_obj.sid,
            max_age=int(app.config["PERMANENT_SESSION_LIFETIME"].total_seconds()),
            expires=expires,
            httponly=app.config["SESSION_COOKIE_HTTPONLY"],
            secure=app.config["SESSION_COOKIE_SECURE"],
            samesite=app.config["SESSION_COOKIE_SAMESITE"],
            path=app.config["SESSION_COOKIE_PATH"],
            domain=app.config["SESSION_COOKIE_DOMAIN"],
        )

    def regenerate(self, session_obj):
        old_sid = session_obj.sid
        if old_sid:
            connection = connect(
                current_app.config["DATABASE_PATH"],
                current_app.config["SQLITE_BUSY_TIMEOUT_MS"],
            )
            try:
                connection.execute(
                    "DELETE FROM server_sessions WHERE sid_hash = ?",
                    (
                        hash_session_token(
                            old_sid, current_app.config["SESSION_HASH_KEY"]
                        ),
                    ),
                )
            finally:
                connection.close()
        session_obj.clear()
        session_obj.sid = new_session_token()
        session_obj.new = True


def _session_interface():
    return current_app.session_interface


def _json_error(message, status):
    return jsonify({"error": message}), status


def _csrf_valid():
    supplied = request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf_token", "")
    return bool(supplied and expected and secure_compare(supplied, expected))


def _new_csrf_token():
    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    session.permanent = True
    return token


def _request_data():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _request_username(value):
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if len(value) > 320:
        return value[:320].casefold()
    try:
        return normalize_email(value)
    except ValueError:
        return value.casefold()


def _remote_address():
    return (request.remote_addr or "unknown")[:64]


def _cutoff_timestamp():
    window_seconds = max(1, int(current_app.config["AUTH_RATE_WINDOW_SECONDS"]))
    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=window_seconds
    )
    return cutoff.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _failed_attempt_count(connection, username_key, source_ip):
    cutoff = _cutoff_timestamp()
    row = connection.execute(
        """
        SELECT COUNT(*) AS failures
        FROM login_attempts
        WHERE outcome = 'failed' AND attempted_at >= ?
          AND (username_key = ? OR source_ip = ?)
        """,
        (cutoff, username_key, source_ip),
    ).fetchone()
    connection.execute(
        "DELETE FROM login_attempts WHERE attempted_at < ?", (cutoff,)
    )
    return row["failures"]


def _record_login_attempt(connection, username_key, source_ip, outcome):
    connection.execute(
        """
        INSERT INTO login_attempts (id, username_key, source_ip, attempted_at, outcome)
        VALUES (?, ?, ?, ?, ?)
        """,
        (new_id(), username_key, source_ip, utc_now(), outcome),
    )


def _validate_password(password):
    if not isinstance(password, str) or len(password) < 12 or len(password) > 1024:
        return False
    return True


def _user_response(user):
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
    }


def _audit_request_context():
    return {
        "ip_address": _remote_address(),
        "user_agent": request.user_agent.string[:512],
    }


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = getattr(g, "current_user", None)
        if user is None:
            return _json_error("Authentication required.", 401)
        return view(*args, **kwargs)

    return wrapped


def init_auth(app):
    app.session_interface = SQLiteSessionInterface()

    @app.before_request
    def enforce_csrf_and_load_user():
        g.current_user = None
        user_id = session.get("user_id")
        if user_id:
            row = get_db().execute(
                """
                SELECT id, name, email, role, status,
                       CASE WHEN status = 'active' THEN 1 ELSE 0 END AS is_active,
                       auth_version
                FROM users WHERE id = ?
                """,
                (user_id,),
            ).fetchone()
            if (
                row is None
                or not row["is_active"]
                or row["auth_version"] != session.get("auth_version")
            ):
                session.clear()
            else:
                g.current_user = dict(row)

        if request.method not in {"GET", "HEAD", "OPTIONS"} and request.endpoint != "auth.csrf_token":
            if not _csrf_valid():
                return _json_error("CSRF token is missing or invalid.", 400)
        return None

    @app.after_request
    def prevent_auth_response_caching(response):
        if request.endpoint and request.endpoint.startswith("auth."):
            response.headers["Cache-Control"] = "no-store"
        return response

    app.register_blueprint(auth)


@auth.get("/csrf")
def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = _new_csrf_token()
    return jsonify({"csrf_token": token})


@auth.post("/register")
def register():
    data = _request_data()
    email_input = data.get("email")
    name = data.get("name")
    password = data.get("password")
    invite_token = data.get("invite_token")

    try:
        email = normalize_email(email_input)
    except (TypeError, ValueError):
        return _json_error("A valid email, name, password, and registration invite are required.", 400)
    if (
        not isinstance(name, str)
        or not name.strip()
        or len(name.strip()) > 120
        or not _validate_password(password)
        or not isinstance(invite_token, str)
        or not invite_token
        or len(invite_token) > 128
    ):
        return _json_error("A valid email, name, password, and registration invite are required.", 400)

    db = get_db()
    now = utc_now()
    invite_hash = hash_registration_invite(invite_token)
    try:
        with transaction(db):
            invite = db.execute(
                """
                SELECT id FROM registration_invites
                WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?
                """,
                (invite_hash, now),
            ).fetchone()
            if invite is None:
                append_event(
                    db,
                    action="registration_denied",
                    result="denied",
                    metadata={"reason": "invalid_invite"},
                    **_audit_request_context(),
                )
                return _json_error(
                    "Registration invitation is invalid, expired, or already used. "
                    "Generate a new one-time token with `python seed.py --create-invite`.",
                    400,
                )
            password_hash = generate_password_hash(password)
            user_id = new_id()
            db.execute(
                """
                INSERT INTO users (id, name, email, password_hash, role, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'viewer', 'active', ?, ?)
                """,
                (
                    user_id,
                    name.strip(),
                    email,
                    password_hash,
                    now,
                    now,
                ),
            )
            db.execute(
                "UPDATE registration_invites SET consumed_at = ? WHERE id = ?",
                (now, invite["id"]),
            )
            append_event(
                db,
                action="user_registered",
                actor_id=user_id,
                metadata={"email": email, "role": "viewer"},
                **_audit_request_context(),
            )
    except sqlite3.IntegrityError as exc:
        if "users.email" in str(exc):
            return _json_error("An account with that email already exists.", 409)
        raise

    return jsonify({"user": {"id": user_id, "name": name.strip(), "email": email, "role": "viewer"}}), 201


@auth.post("/login")
def login():
    data = _request_data()
    username = _request_username(data.get("email"))
    audit_username = (username or (
        data.get("email", "").strip()[:254]
        if isinstance(data.get("email"), str)
        else None
    ))
    if audit_username is not None:
        audit_username = audit_username[:254]
    password = data.get("password")
    username_key = hash_login_identifier(username)
    source_ip = _remote_address()
    db = get_db()

    attempt_limit = max(1, min(5, int(current_app.config["AUTH_MAX_FAILED_ATTEMPTS"])))
    blocked = False
    authenticated_user = None
    with transaction(db):
        if _failed_attempt_count(db, username_key, source_ip) >= attempt_limit:
            _record_login_attempt(db, username_key, source_ip, "blocked")
            append_event(
                db,
                action="login_rate_limited",
                result="denied",
                metadata={"username_key": username_key},
                username=audit_username,
                **_audit_request_context(),
            )
            blocked = True
        else:
            user = None
            if username:
                user = db.execute(
                    """
                    SELECT id, name, email, password_hash, role, status,
                           CASE WHEN status = 'active' THEN 1 ELSE 0 END AS is_active,
                           auth_version
                    FROM users WHERE email = ?
                    """,
                    (username,),
                ).fetchone()

            password_matches = False
            if isinstance(password, str):
                try:
                    password_matches = check_password_hash(
                        user["password_hash"] if user is not None else _DUMMY_PASSWORD_HASH,
                        password if len(password) <= 1024 else "",
                    )
                except (ValueError, TypeError):
                    password_matches = False

            if not password_matches or user is None or not user["is_active"]:
                _record_login_attempt(db, username_key, source_ip, "failed")
                append_event(
                    db,
                    action="login_failed",
                    result="failure",
                    actor_id=user["id"] if user is not None else None,
                    metadata={"username_key": username_key},
                    username=audit_username,
                    **_audit_request_context(),
                )
            else:
                _record_login_attempt(db, username_key, source_ip, "success")
                append_event(
                    db,
                    action="login_succeeded",
                    actor_id=user["id"],
                    username=user["email"],
                    metadata={},
                    **_audit_request_context(),
                )
                authenticated_user = user

    if blocked:
        return _json_error(GENERIC_LOGIN_ERROR, 429)
    if authenticated_user is None:
        return _json_error(GENERIC_LOGIN_ERROR, 401)

    user = authenticated_user

    _session_interface().regenerate(session)
    session["user_id"] = user["id"]
    session["auth_version"] = user["auth_version"]
    csrf = _new_csrf_token()
    session.permanent = True
    return jsonify({"user": _user_response(user), "csrf_token": csrf})


@auth.post("/logout")
@login_required
def logout():
    user_id = g.current_user["id"]
    db = get_db()
    with transaction(db):
        append_event(
            db,
            action="logout_succeeded",
            actor_id=user_id,
            metadata={},
            **_audit_request_context(),
        )
    session.clear()
    return jsonify({"message": "Logged out."})


@auth.get("/me")
@login_required
def current_session():
    return jsonify({"user": _user_response(g.current_user)})


def create_registration_invite(connection, lifetime=timedelta(hours=24), created_by=None):
    if lifetime <= timedelta(0):
        raise ValueError("Invite lifetime must be positive.")
    token = new_session_token()
    created = datetime.now(timezone.utc)
    created_at = created.isoformat(timespec="microseconds").replace("+00:00", "Z")
    expires_at = (created + lifetime).isoformat(timespec="microseconds").replace("+00:00", "Z")
    connection.execute(
        """
        INSERT INTO registration_invites (id, token_hash, created_at, expires_at, created_by)
        VALUES (?, ?, ?, ?, ?)
        """,
        (new_id(), hash_registration_invite(token), created_at, expires_at, created_by),
    )
    return token
