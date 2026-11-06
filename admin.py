"""Administrator-only metadata, account, permission, and reporting APIs."""

import math
from functools import wraps

from flask import Blueprint, g, jsonify, request

from audit import append_event
from database import get_db, transaction, utc_now
from security import is_valid_role


admin_api = Blueprint("admin_api", __name__, url_prefix="/api/admin")
_MAX_PAGE_SIZE = 100
_MAX_PAGE = 10000
_PERMISSION_STATUS = """
CASE
    WHEN p.revoked_at IS NOT NULL THEN 'revoked'
    WHEN p.expires_at IS NOT NULL AND p.expires_at <= ? THEN 'expired'
    ELSE 'active'
END
"""


def _admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = getattr(g, "current_user", None)
        if user is None:
            return jsonify({"error": "Authentication required."}), 401
        active = get_db().execute(
            "SELECT role, status FROM users WHERE id = ?", (user["id"],)
        ).fetchone()
        if active is None or active["status"] != "active":
            return jsonify({"error": "Authentication required."}), 401
        if active["role"] != "administrator":
            return jsonify({"error": "Administrator access required."}), 403
        return view(*args, **kwargs)

    return wrapped


def _page_args():
    try:
        page = int(request.args.get("page", "1"))
        page_size = int(request.args.get("page_size", "20"))
    except (TypeError, ValueError):
        return None, None, (jsonify({"error": "Invalid pagination values."}), 400)
    if page < 1 or page > _MAX_PAGE or page_size < 1 or page_size > _MAX_PAGE_SIZE:
        return None, None, (
            jsonify({"error": f"Page must be 1-{_MAX_PAGE}; page_size must be 1-{_MAX_PAGE_SIZE}."}),
            400,
        )
    return page, page_size, None


def _pagination(items, total, page, page_size):
    return jsonify({
        "items": [dict(row) for row in items],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": math.ceil(total / page_size) if total else 0,
    })


def _search_clause(value, columns):
    if not value:
        return "", []
    needle = str(value).strip().lower()[:254]
    needle = needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return "(" + " OR ".join(
        f"lower({column}) LIKE ? ESCAPE '\\'" for column in columns
    ) + ")", [f"%{needle}%"] * len(columns)


def _audit(action, actor_id, metadata):
    append_event(
        get_db(),
        action=action,
        actor_id=actor_id,
        metadata=metadata,
        ip_address=(request.remote_addr or "unknown")[:64],
        user_agent=request.user_agent.string[:512],
    )


def _permission_query():
    return f"""
        SELECT p.id, p.document_id, d.name AS document_name,
               d.owner_id, owner.name AS owner_name, owner.email AS owner_email,
               p.user_id AS recipient_id, recipient.name AS recipient_name,
               recipient.email AS recipient_email, recipient.role AS recipient_role,
               p.permission, p.granted_by, grantor.name AS grantor_name,
               grantor.email AS grantor_email, p.granted_at, p.expires_at,
               p.revoked_at, {_PERMISSION_STATUS} AS status
        FROM document_permissions AS p
        JOIN documents AS d ON d.id = p.document_id
        JOIN users AS owner ON owner.id = d.owner_id
        JOIN users AS recipient ON recipient.id = p.user_id
        JOIN users AS grantor ON grantor.id = p.granted_by
    """


def _permission_filters(current_only=False):
    clauses = []
    params = []
    permission = request.args.get("permission")
    status = request.args.get("status")
    search, search_params = _search_clause(
        request.args.get("q"),
        ["d.name", "owner.name", "owner.email", "recipient.name", "recipient.email"],
    )
    if permission:
        if not isinstance(permission, str) or permission not in {"read", "edit"}:
            return None, None, (jsonify({"error": "Permission must be read or edit."}), 400)
        clauses.append("p.permission = ?")
        params.append(permission)
    if status:
        if not isinstance(status, str) or status not in {"active", "revoked", "expired"}:
            return None, None, (jsonify({"error": "Status must be active, revoked, or expired."}), 400)
        clauses.append(f"({_PERMISSION_STATUS}) = ?")
        params.extend([utc_now(), status])
    elif current_only:
        clauses.append(f"({_PERMISSION_STATUS}) = 'active'")
        params.append(utc_now())
    if search:
        clauses.append(search)
        params.extend(search_params)
    sql = " WHERE " + " AND ".join(clauses) if clauses else ""
    return sql, params, None


def _filtered_permissions(current_only=False):
    where, params, error = _permission_filters(current_only=current_only)
    if error:
        return None, None, None, error
    page, page_size, error = _page_args()
    if error:
        return None, None, None, error
    db = get_db()
    total = db.execute(
        "SELECT COUNT(*) FROM document_permissions AS p "
        "JOIN documents AS d ON d.id = p.document_id "
        "JOIN users AS owner ON owner.id = d.owner_id "
        "JOIN users AS recipient ON recipient.id = p.user_id "
        "JOIN users AS grantor ON grantor.id = p.granted_by" + where,
        params,
    ).fetchone()[0]
    rows = db.execute(
        _permission_query() + where
        + " ORDER BY p.granted_at DESC, p.id LIMIT ? OFFSET ?",
        [utc_now(), *params, page_size, (page - 1) * page_size],
    ).fetchall()
    return rows, total, (page, page_size), None


@admin_api.get("/dashboard")
@_admin_required
def dashboard_data():
    db = get_db()
    now = utc_now()
    counts = {
        row["key"]: row["value"]
        for row in db.execute(
            """
            SELECT 'total_users' AS key, COUNT(*) AS value FROM users
            UNION ALL SELECT 'administrators', COUNT(*) FROM users WHERE role = 'administrator'
            UNION ALL SELECT 'document_owners', COUNT(*) FROM users WHERE role = 'document_owner'
            UNION ALL SELECT 'viewers', COUNT(*) FROM users WHERE role = 'viewer'
            UNION ALL SELECT 'active_users', COUNT(*) FROM users WHERE status = 'active'
            UNION ALL SELECT 'disabled_users', COUNT(*) FROM users WHERE status = 'disabled'
            UNION ALL SELECT 'total_documents', COUNT(*) FROM documents
            UNION ALL SELECT 'shared_documents', COUNT(DISTINCT document_id)
                FROM document_permissions
                WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
            UNION ALL SELECT 'read_permissions', COUNT(*) FROM document_permissions
                WHERE permission = 'read' AND revoked_at IS NULL
                  AND (expires_at IS NULL OR expires_at > ?)
            UNION ALL SELECT 'edit_permissions', COUNT(*) FROM document_permissions
                WHERE permission = 'edit' AND revoked_at IS NULL
                  AND (expires_at IS NULL OR expires_at > ?)
            """,
            (now, now, now),
        )
    }

    def recent(sql, params=()):
        return [dict(row) for row in db.execute(sql, params).fetchall()]

    return jsonify({
        "counts": counts,
        "recent_users": recent(
            "SELECT id, name, email, role, status, created_at FROM users "
            "ORDER BY created_at DESC LIMIT 8"
        ),
        "recent_documents": recent(
            """
            SELECT d.id, d.name, d.mime_type, d.created_at, u.name AS owner_name,
                   u.email AS owner_email
            FROM documents AS d JOIN users AS u ON u.id = d.owner_id
            ORDER BY d.created_at DESC LIMIT 8
            """
        ),
        "recent_permissions": recent(
            """
            SELECT p.id, p.document_id, d.name AS document_name,
                   p.permission, p.granted_at, p.revoked_at,
                   recipient.email AS recipient_email,
                   grantor.email AS grantor_email,
                   CASE WHEN p.revoked_at IS NOT NULL THEN 'revoked'
                        WHEN p.expires_at IS NOT NULL AND p.expires_at <= ? THEN 'expired'
                        ELSE 'active' END AS status
            FROM document_permissions AS p
            JOIN documents AS d ON d.id = p.document_id
            JOIN users AS recipient ON recipient.id = p.user_id
            JOIN users AS grantor ON grantor.id = p.granted_by
            ORDER BY COALESCE(p.revoked_at, p.granted_at) DESC LIMIT 10
            """,
            (now,),
        ),
        "recent_security_events": recent(
            """
            SELECT a.id, a.timestamp, a.username, a.action, a.status, a.ip_address,
                   a.document_id, actor.role AS actor_role
            FROM audit_logs AS a LEFT JOIN users AS actor ON actor.id = a.user_id
            WHERE a.status IN ('denied', 'failure')
            ORDER BY a.sequence DESC LIMIT 10
            """
        ),
    })


@admin_api.get("/users")
@_admin_required
def users():
    page, page_size, error = _page_args()
    if error:
        return error
    clauses = []
    params = []
    role = request.args.get("role")
    status = request.args.get("status")
    if role:
        if not is_valid_role(role):
            return jsonify({"error": "Invalid role."}), 400
        clauses.append("u.role = ?")
        params.append(role)
    if status:
        if status not in {"active", "disabled"}:
            return jsonify({"error": "Status must be active or disabled."}), 400
        clauses.append("u.status = ?")
        params.append(status)
    search, search_params = _search_clause(request.args.get("q"), ["u.name", "u.email"])
    if search:
        clauses.append(search)
        params.extend(search_params)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM users AS u" + where, params).fetchone()[0]
    rows = db.execute(
        """
        SELECT u.id, u.name, u.email, u.role, u.status, u.created_at,
               (SELECT COUNT(*) FROM documents d WHERE d.owner_id = u.id) AS uploaded_documents,
               (SELECT COUNT(DISTINCT p.document_id) FROM document_permissions p
                WHERE p.granted_by = u.id) AS shared_documents
        FROM users AS u
        """
        + where + " ORDER BY u.created_at DESC, u.id LIMIT ? OFFSET ?",
        [*params, page_size, (page - 1) * page_size],
    ).fetchall()
    return _pagination(rows, total, page, page_size)


@admin_api.get("/users/<user_id>")
@_admin_required
def user_details(user_id):
    db = get_db()
    user = db.execute(
        """
        SELECT id, name, email, role, status, created_at, updated_at,
               (SELECT COUNT(*) FROM documents d WHERE d.owner_id = users.id) AS uploaded_documents,
               (SELECT COUNT(DISTINCT p.document_id) FROM document_permissions p
                WHERE p.granted_by = users.id) AS shared_documents
        FROM users WHERE id = ?
        """,
        (user_id,),
    ).fetchone()
    if user is None:
        return jsonify({"error": "User not found."}), 404
    return jsonify({"user": dict(user)})


@admin_api.get("/users/<user_id>/documents")
@_admin_required
def user_documents(user_id):
    page, page_size, error = _page_args()
    if error:
        return error
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone() is None:
        return jsonify({"error": "User not found."}), 404
    total = db.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT d.id FROM documents d WHERE d.owner_id = ?
            UNION
            SELECT d.id FROM documents d
            JOIN document_permissions p ON p.document_id = d.id
            WHERE p.user_id = ? AND p.revoked_at IS NULL
              AND (p.expires_at IS NULL OR p.expires_at > ?)
        )
        """,
        (user_id, user_id, utc_now()),
    ).fetchone()[0]
    rows = db.execute(
        """
        SELECT d.id, d.name, d.category, d.mime_type, d.size_bytes,
               d.scan_status, d.created_at, d.updated_at, d.deleted_at,
               CASE WHEN d.owner_id = ? THEN 'owned' ELSE 'shared' END AS access_type,
               (SELECT p.permission FROM document_permissions p
                WHERE p.document_id = d.id AND p.user_id = ?
                  AND p.revoked_at IS NULL AND (p.expires_at IS NULL OR p.expires_at > ?)
                ORDER BY p.granted_at DESC LIMIT 1) AS permission,
               (SELECT COUNT(*) FROM document_permissions p
                WHERE p.document_id = d.id AND p.revoked_at IS NULL
                  AND (p.expires_at IS NULL OR p.expires_at > ?)) AS active_recipients
        FROM documents d
        WHERE d.owner_id = ? OR d.id IN (
            SELECT p.document_id FROM document_permissions p
            WHERE p.user_id = ? AND p.revoked_at IS NULL
              AND (p.expires_at IS NULL OR p.expires_at > ?)
        )
        ORDER BY d.created_at DESC LIMIT ? OFFSET ?
        """,
        (
            user_id,
            user_id,
            utc_now(),
            utc_now(),
            user_id,
            user_id,
            utc_now(),
            page_size,
            (page - 1) * page_size,
        ),
    ).fetchall()
    return _pagination(rows, total, page, page_size)


@admin_api.get("/users/<user_id>/activity")
@_admin_required
def user_activity(user_id):
    page, page_size, error = _page_args()
    if error:
        return error
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone() is None:
        return jsonify({"error": "User not found."}), 404
    total = db.execute(
        "SELECT COUNT(*) FROM audit_logs WHERE user_id = ?", (user_id,)
    ).fetchone()[0]
    rows = db.execute(
        """
        SELECT id, timestamp, username, action, document_id, status,
               details, ip_address
        FROM audit_logs WHERE user_id = ?
        ORDER BY sequence DESC LIMIT ? OFFSET ?
        """,
        (user_id, page_size, (page - 1) * page_size),
    ).fetchall()
    return _pagination(rows, total, page, page_size)


@admin_api.patch("/users/<user_id>/role")
@_admin_required
def update_user_role(user_id):
    data = request.get_json(silent=True)
    if (
        not isinstance(data, dict)
        or set(data) != {"role"}
        or not is_valid_role(data["role"])
    ):
        return jsonify({"error": "Provide a valid role."}), 400
    db = get_db()
    if user_id == g.current_user["id"]:
        return jsonify({"error": "You cannot change your own role."}), 400
    with transaction(db):
        target = db.execute(
            "SELECT id, role, status FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if target is None:
            return jsonify({"error": "User not found."}), 404
        if target["role"] == "administrator" and target["status"] == "active":
            active_admins = db.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'administrator' AND status = 'active'"
            ).fetchone()[0]
            if active_admins <= 1 and data["role"] != "administrator":
                return jsonify({"error": "The last active administrator cannot be demoted."}), 409
        if target["role"] != data["role"]:
            db.execute(
                "UPDATE users SET role = ?, auth_version = auth_version + 1, updated_at = ? WHERE id = ?",
                (data["role"], utc_now(), user_id),
            )
            _audit(
                "admin_user_role_changed",
                g.current_user["id"],
                {"target_user_id": user_id, "previous_role": target["role"], "new_role": data["role"]},
            )
    return jsonify({"message": "Role updated.", "user_id": user_id, "role": data["role"]})


@admin_api.patch("/users/<user_id>/status")
@_admin_required
def update_user_status(user_id):
    data = request.get_json(silent=True)
    if (
        not isinstance(data, dict)
        or set(data) != {"status"}
        or not isinstance(data["status"], str)
        or data["status"] not in {"active", "disabled"}
    ):
        return jsonify({"error": "Status must be active or disabled."}), 400
    db = get_db()
    if user_id == g.current_user["id"] and data["status"] != "active":
        return jsonify({"error": "You cannot disable your own account."}), 400
    with transaction(db):
        target = db.execute(
            "SELECT id, role, status FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if target is None:
            return jsonify({"error": "User not found."}), 404
        if (
            target["role"] == "administrator"
            and target["status"] == "active"
            and data["status"] == "disabled"
        ):
            active_admins = db.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'administrator' AND status = 'active'"
            ).fetchone()[0]
            if active_admins <= 1:
                return jsonify({"error": "The last active administrator cannot be disabled."}), 409
        if target["status"] != data["status"]:
            db.execute(
                "UPDATE users SET status = ?, auth_version = auth_version + 1, updated_at = ? WHERE id = ?",
                (data["status"], utc_now(), user_id),
            )
            _audit(
                "admin_user_status_changed",
                g.current_user["id"],
                {"target_user_id": user_id, "previous_status": target["status"], "new_status": data["status"]},
            )
    return jsonify({"message": "Account status updated.", "user_id": user_id, "status": data["status"]})


@admin_api.get("/documents")
@_admin_required
def documents():
    page, page_size, error = _page_args()
    if error:
        return error
    clauses = []
    params = []
    search, search_params = _search_clause(
        request.args.get("q"), ["d.name", "owner.name", "owner.email", "d.category", "d.mime_type"]
    )
    if search:
        clauses.append(search)
        params.extend(search_params)
    owner_id = request.args.get("owner_id")
    if owner_id:
        clauses.append("d.owner_id = ?")
        params.append(owner_id)
    mime_type = request.args.get("mime_type")
    if mime_type:
        if len(mime_type) > 127:
            return jsonify({"error": "Invalid document type."}), 400
        clauses.append("d.mime_type = ?")
        params.append(mime_type)
    sharing = request.args.get("sharing")
    if sharing:
        if sharing not in {"shared", "private"}:
            return jsonify({"error": "Sharing must be shared or private."}), 400
        clauses.append(
            ("EXISTS" if sharing == "shared" else "NOT EXISTS")
            + """ (SELECT 1 FROM document_permissions p
                 WHERE p.document_id = d.id AND p.revoked_at IS NULL
                   AND (p.expires_at IS NULL OR p.expires_at > ?))"""
        )
        params.append(utc_now())
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    db = get_db()
    from_sql = " FROM documents d JOIN users owner ON owner.id = d.owner_id"
    total = db.execute("SELECT COUNT(*)" + from_sql + where, params).fetchone()[0]
    rows = db.execute(
        """
        SELECT d.id, d.name, d.category, d.mime_type, d.size_bytes, d.scan_status,
               d.created_at, d.updated_at, d.deleted_at, d.owner_id,
               owner.name AS owner_name, owner.email AS owner_email,
               (SELECT COUNT(*) FROM document_permissions p
                WHERE p.document_id = d.id AND p.revoked_at IS NULL
                  AND (p.expires_at IS NULL OR p.expires_at > ?)) AS active_recipients,
               CASE WHEN EXISTS (
                   SELECT 1 FROM document_permissions p
                   WHERE p.document_id = d.id AND p.revoked_at IS NULL
                     AND (p.expires_at IS NULL OR p.expires_at > ?)
               ) THEN 'shared' ELSE 'private' END AS sharing_status
        """
        + from_sql + where + " ORDER BY d.created_at DESC LIMIT ? OFFSET ?",
        [utc_now(), utc_now(), *params, page_size, (page - 1) * page_size],
    ).fetchall()
    return _pagination(rows, total, page, page_size)


@admin_api.get("/documents/<document_id>/access")
@admin_api.get("/documents/<document_id>/permissions")
@_admin_required
def document_access(document_id):
    db = get_db()
    document = db.execute(
        """
        SELECT d.id, d.name, d.category, d.mime_type, d.size_bytes, d.scan_status,
               d.created_at, d.updated_at, d.deleted_at, d.owner_id,
               owner.name AS owner_name, owner.email AS owner_email
        FROM documents d JOIN users owner ON owner.id = d.owner_id WHERE d.id = ?
        """,
        (document_id,),
    ).fetchone()
    if document is None:
        return jsonify({"error": "Document not found."}), 404
    permissions = db.execute(
        _permission_query() + " WHERE p.document_id = ? ORDER BY p.granted_at DESC",
        [utc_now(), document_id],
    ).fetchall()
    history = db.execute(
        """
        SELECT a.id, a.timestamp, a.user_id, a.username, actor.role AS actor_role,
               a.action, a.status, a.details, a.ip_address
        FROM audit_logs a LEFT JOIN users actor ON actor.id = a.user_id
        WHERE a.document_id = ? AND a.action LIKE 'document_permission_%'
        ORDER BY a.sequence DESC
        """,
        (document_id,),
    ).fetchall()
    return jsonify({
        "document": dict(document),
        "permissions": [dict(row) for row in permissions],
        "history": [dict(row) for row in history],
    })


@admin_api.get("/documents/<document_id>/permission-history")
@_admin_required
def document_permission_history(document_id):
    db = get_db()
    if db.execute("SELECT 1 FROM documents WHERE id = ?", (document_id,)).fetchone() is None:
        return jsonify({"error": "Document not found."}), 404
    history = db.execute(
        """
        SELECT a.id, a.timestamp, a.user_id, a.username, actor.role AS actor_role,
               a.action, a.status, a.details, a.ip_address
        FROM audit_logs a LEFT JOIN users actor ON actor.id = a.user_id
        WHERE a.document_id = ? AND a.action LIKE 'document_permission_%'
        ORDER BY a.sequence DESC
        """,
        (document_id,),
    ).fetchall()
    return jsonify({"document_id": document_id, "history": [dict(row) for row in history]})


@admin_api.get("/permissions")
@_admin_required
def permissions():
    rows, total, page_data, error = _filtered_permissions()
    if error:
        return error
    return _pagination(rows, total, *page_data)


@admin_api.get("/shares")
@_admin_required
def shares():
    rows, total, page_data, error = _filtered_permissions(
        current_only=request.args.get("current_only") == "true"
    )
    if error:
        return error
    return _pagination(rows, total, *page_data)


@admin_api.get("/activity")
@admin_api.get("/audit-logs")
@_admin_required
def activity():
    page, page_size, error = _page_args()
    if error:
        return error
    clauses = []
    params = []
    action = request.args.get("action")
    status = request.args.get("status")
    if action:
        if len(action) > 100:
            return jsonify({"error": "Invalid action filter."}), 400
        clauses.append("a.action = ?")
        params.append(action)
    if status:
        if status not in {"success", "failure", "denied"}:
            return jsonify({"error": "Invalid audit status."}), 400
        clauses.append("a.status = ?")
        params.append(status)
    search, search_params = _search_clause(
        request.args.get("q"), ["a.username", "a.action", "a.document_id", "a.details"]
    )
    if search:
        clauses.append(search)
        params.extend(search_params)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    db = get_db()
    from_sql = " FROM audit_logs a LEFT JOIN users actor ON actor.id = a.user_id"
    total = db.execute("SELECT COUNT(*)" + from_sql + where, params).fetchone()[0]
    rows = db.execute(
        """
        SELECT a.id, a.sequence, a.timestamp, a.user_id AS actor_id, a.username,
               actor.name AS actor_name, actor.role AS actor_role,
               a.action, a.document_id, d.name AS document_name,
               a.ip_address, a.status, a.details
        """
        + from_sql + " LEFT JOIN documents d ON d.id = a.document_id"
        + where + " ORDER BY a.sequence DESC LIMIT ? OFFSET ?",
        [*params, page_size, (page - 1) * page_size],
    ).fetchall()
    return _pagination(rows, total, page, page_size)


@admin_api.get("/reports")
@_admin_required
def reports():
    db = get_db()
    return jsonify({
        "users_by_role": [dict(row) for row in db.execute(
            "SELECT role, COUNT(*) AS count FROM users GROUP BY role ORDER BY role"
        )],
        "users_by_status": [dict(row) for row in db.execute(
            "SELECT status, COUNT(*) AS count FROM users GROUP BY status ORDER BY status"
        )],
        "documents_by_type": [dict(row) for row in db.execute(
            "SELECT mime_type, COUNT(*) AS count FROM documents GROUP BY mime_type ORDER BY count DESC, mime_type"
        )],
        "permissions_by_type": [dict(row) for row in db.execute(
            "SELECT permission, COUNT(*) AS count FROM document_permissions GROUP BY permission ORDER BY permission"
        )],
        "permissions_by_status": [dict(row) for row in db.execute(
            f"SELECT {_PERMISSION_STATUS} AS status, COUNT(*) AS count "
            "FROM document_permissions p GROUP BY status ORDER BY status",
            (utc_now(),),
        )],
        "uploads_by_month": [dict(row) for row in db.execute(
            """
            SELECT substr(created_at, 1, 7) AS month, COUNT(*) AS count
            FROM documents GROUP BY month ORDER BY month DESC LIMIT 12
            """
        )],
    })


def init_admin_api(app):
    app.register_blueprint(admin_api)
