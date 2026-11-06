"""Database-backed, deny-by-default document authorization."""

from functools import wraps
from flask import g, has_request_context, jsonify, request

from audit import append_event
from database import get_db, utc_now
from security import DOCUMENT_PERMISSIONS


class PermissionDenied(Exception):
    """Raised when an account cannot access a document."""

    def __init__(self):
        super().__init__("The requested resource is not available.")
        self.status_code = 404


def _identity_id(user):
    if user is None:
        return None
    try:
        user_id = user["id"]
    except (KeyError, IndexError, TypeError):
        return None
    return user_id if isinstance(user_id, str) and user_id else None


def _audit_denial(connection, actor_id, document_id, permission, reason):
    details = {}
    if permission in DOCUMENT_PERMISSIONS:
        details["required_permission"] = permission
    if reason:
        details["reason"] = reason

    context = {}
    if has_request_context():
        context = {
            "ip_address": (request.remote_addr or "unknown")[:64],
            "user_agent": request.user_agent.string[:512],
        }

    append_event(
        connection,
        action="authorization_denied",
        result="denied",
        actor_id=actor_id,
        document_id=document_id,
        metadata=details,
        **context,
    )


def _deny(connection, actor_id, permission, reason, document_id=None):
    _audit_denial(connection, actor_id, document_id, permission, reason)
    raise PermissionDenied()


def authorize(user, document_id, required_permission, *, connection=None):
    """Return authorized document metadata or deny access.

    ``user`` supplies only a candidate server-side identity. Its role and status
    are deliberately ignored: the account and current ACL are read from SQLite
    for every call. Administrators receive no implicit access to private
    document contents; ownership or an active explicit grant is still required.
    """
    if required_permission not in DOCUMENT_PERMISSIONS:
        raise ValueError("Unsupported document permission.")

    db = connection if connection is not None else get_db()
    candidate_id = _identity_id(user)
    actor = None
    if candidate_id:
        actor = db.execute(
            "SELECT id, role, status FROM users WHERE id = ?",
            (candidate_id,),
        ).fetchone()

    if actor is None or actor["status"] != "active":
        _deny(
            db,
            actor["id"] if actor is not None else None,
            required_permission,
            "inactive_or_unknown_user",
        )

    if not isinstance(document_id, str) or not document_id or len(document_id) > 128:
        _deny(db, actor["id"], required_permission, "invalid_document_reference")

    document = db.execute(
        """
        SELECT id, owner_id, storage_key, name, description, category, mime_type, size_bytes,
               sha256, scan_status, created_at, updated_at
        FROM documents
        WHERE id = ? AND deleted_at IS NULL
        """,
        (document_id,),
    ).fetchone()
    if document is None:
        _deny(db, actor["id"], required_permission, "resource_unavailable")

    is_owner = document["owner_id"] == actor["id"]
    if is_owner:
        if required_permission == "edit" and actor["role"] == "viewer":
            _deny(
                db,
                actor["id"],
                required_permission,
                "viewer_is_read_only",
                document["id"],
            )
        return document

    grant = db.execute(
        """
        SELECT permission
        FROM document_permissions
        WHERE document_id = ?
          AND user_id = ?
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > ?)
        ORDER BY granted_at DESC
        LIMIT 1
        """,
        (document["id"], actor["id"], utc_now()),
    ).fetchone()

    if grant is None:
        _deny(db, actor["id"], required_permission, "resource_unavailable", document["id"])

    if required_permission == "edit":
        if actor["role"] == "viewer":
            _deny(
                db,
                actor["id"],
                required_permission,
                "viewer_is_read_only",
                document["id"],
            )
        if grant["permission"] != "edit":
            _deny(
                db,
                actor["id"],
                required_permission,
                "insufficient_grant",
                document["id"],
            )

    return document


def authorize_owner(user, document_id, *, connection=None):
    """Require the active document owner, not merely an editor, to manage ACLs."""
    document = authorize(user, document_id, "edit", connection=connection)
    db = connection if connection is not None else get_db()
    actor_id = _identity_id(user)
    actor = db.execute(
        "SELECT id, role, status FROM users WHERE id = ?",
        (actor_id,),
    ).fetchone()
    if (
        actor is None
        or actor["status"] != "active"
        or actor["role"] != "document_owner"
        or document["owner_id"] != actor["id"]
    ):
        _deny(
            db,
            actor_id,
            "edit",
            "document_owner_required",
            document["id"],
        )
    return document


def check_permission(user, document_id, required_permission, *, connection=None):
    """Return whether an authorization check succeeds; denials are audited."""
    try:
        authorize(
            user,
            document_id,
            required_permission,
            connection=connection,
        )
    except PermissionDenied:
        return False
    return True


def _current_active_user():
    candidate_id = _identity_id(getattr(g, "current_user", None))
    if not candidate_id:
        return None
    return get_db().execute(
        """
        SELECT id, name, email, role, status, auth_version
        FROM users
        WHERE id = ? AND status = 'active'
        """,
        (candidate_id,),
    ).fetchone()


def _unauthenticated_denial():
    _audit_denial(
        get_db(),
        None,
        None,
        None,
        "authentication_required",
    )
    return jsonify({"error": "Authentication required."}), 401


def require_authentication():
    """Require a currently active server-authenticated account."""
    def decorate(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = _current_active_user()
            if user is None:
                return _unauthenticated_denial()
            g.current_user = dict(user)
            return view(*args, **kwargs)

        return wrapped

    return decorate


def require_permission(required_permission, *, document_id_arg="document_id"):
    """Authorize a route using a fixed policy and its path document ID.

    The permission is fixed when the route is declared, and the principal is
    taken only from the authenticated server-side session. Request payload
    fields named user_id, role, or permission_level are not consulted.
    """
    if required_permission not in DOCUMENT_PERMISSIONS:
        raise ValueError("Unsupported document permission.")

    def decorate(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = _current_active_user()
            if user is None:
                return _unauthenticated_denial()

            g.current_user = dict(user)
            document_id = kwargs.get(document_id_arg)
            try:
                g.authorized_document = authorize(
                    user,
                    document_id,
                    required_permission,
                )
            except PermissionDenied:
                return jsonify({"error": "The requested resource is not available."}), 404
            return view(*args, **kwargs)

        return wrapped

    return decorate
