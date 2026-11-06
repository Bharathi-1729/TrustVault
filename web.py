"""Server-rendered TrustVault pages and the administrator audit dashboard."""

import secrets

from flask import (
    Blueprint,
    current_app,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from audit import append_event, verify_audit_integrity
from database import get_db, transaction, utc_now
from documents import parse_search_parameters, search_documents
from permissions import PermissionDenied, authorize_owner


web = Blueprint("web", __name__)


def _csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
        session.permanent = True
    return token


def _audit(action, status, user_id=None, details=None, document_id=None):
    append_event(
        get_db(),
        action=action,
        result=status,
        actor_id=user_id,
        document_id=document_id,
        metadata=details or {},
        ip_address=(request.remote_addr or "unknown")[:64],
        user_agent=request.user_agent.string[:512],
    )


def _login_required():
    if getattr(g, "current_user", None) is None:
        return redirect(url_for("web.login_page"))
    return None


@web.app_context_processor
def inject_navigation_csrf_token():
    if getattr(g, "current_user", None) is None:
        return {"navigation_csrf_token": None}
    return {"navigation_csrf_token": _csrf_token()}


@web.after_request
def set_page_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; object-src 'none'"
    )
    if request.endpoint and request.endpoint.startswith("web."):
        response.headers["Cache-Control"] = "private, no-store"
    return response


@web.get("/")
def home():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for("web.document_list_page"))
    return redirect(url_for("web.login_page"))


@web.get("/login")
def login_page():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for("web.document_list_page"))
    return render_template("login.html", csrf_token=_csrf_token())


@web.get("/register")
def register_page():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for("web.document_list_page"))
    return render_template("register.html", csrf_token=_csrf_token())


@web.get("/profile")
def profile_page():
    denied = _login_required()
    if denied is not None:
        return denied
    user = get_db().execute(
        """
        SELECT name, email, role, status, created_at
        FROM users WHERE id = ?
        """,
        (g.current_user["id"],),
    ).fetchone()
    if user is None:
        session.clear()
        return redirect(url_for("web.login_page"))
    return render_template("profile.html", profile=user)


@web.get("/documents")
def document_list_page():
    denied = _login_required()
    if denied is not None:
        return denied
    try:
        query, page, page_size = parse_search_parameters(request.args)
    except ValueError as error:
        _audit(
            "document_search_failed",
            "failure",
            g.current_user["id"],
            {"reason": "invalid_parameters"},
        )
        return render_template(
            "document_list.html",
            documents=[],
            query="",
            page=1,
            page_size=20,
            total=0,
            error=str(error),
            csrf_token=_csrf_token(),
        ), 400
    result = search_documents(g.current_user, query, page, page_size)
    return render_template(
        "document_list.html",
        **result,
        query=query,
        error=None,
        csrf_token=_csrf_token(),
    )


@web.get("/search")
def search_page():
    denied = _login_required()
    if denied is not None:
        return denied
    try:
        query, page, page_size = parse_search_parameters(request.args)
    except ValueError as error:
        _audit(
            "document_search_failed",
            "failure",
            g.current_user["id"],
            {"reason": "invalid_parameters"},
        )
        return render_template(
            "search.html",
            documents=[],
            query="",
            page=1,
            page_size=20,
            total=0,
            error=str(error),
            csrf_token=_csrf_token(),
        ), 400
    result = search_documents(g.current_user, query, page, page_size)
    return render_template(
        "search.html",
        **result,
        query=query,
        error=None,
        csrf_token=_csrf_token(),
    )


@web.get("/upload")
def upload_page():
    denied = _login_required()
    if denied is not None:
        return denied
    if g.current_user["role"] != "document_owner":
        _audit(
            "document_upload_page_denied",
            "denied",
            g.current_user["id"],
            {"reason": "owner_role_required"},
        )
        if g.current_user["role"] == "viewer":
            return render_template("upload_unavailable.html"), 403
        return "The requested operation is not available.", 403
    return render_template("upload.html", csrf_token=_csrf_token())


@web.get("/documents/<document_id>/sharing")
def sharing_page(document_id):
    denied = _login_required()
    if denied is not None:
        return denied
    user = g.current_user
    db = get_db()
    try:
        with transaction(db):
            document = authorize_owner(user, document_id, connection=db)
            grants = db.execute(
                """
                SELECT p.id, u.email AS recipient_email, u.name AS recipient_name,
                       p.permission, p.granted_at, p.expires_at, p.revoked_at,
                       CASE
                           WHEN p.revoked_at IS NOT NULL THEN 'revoked'
                           WHEN p.expires_at IS NOT NULL AND p.expires_at <= ? THEN 'expired'
                           ELSE 'active'
                       END AS grant_status
                FROM document_permissions AS p
                JOIN users AS u ON u.id = p.user_id
                WHERE p.document_id = ?
                ORDER BY p.granted_at DESC
                """,
                (utc_now(), document_id),
            ).fetchall()
            _audit(
                "document_sharing_page_viewed",
                "success",
                user["id"],
                {"grant_count": len(grants)},
                document_id,
            )
    except PermissionDenied:
        _audit(
            "document_sharing_page_denied",
            "denied",
            user["id"],
            {"reason": "document_owner_required"},
            document_id,
        )
        return "The requested resource is not available.", 404
    return render_template(
        "sharing.html",
        document=document,
        grants=grants,
        csrf_token=_csrf_token(),
    )


@web.get("/admin")
def admin_dashboard():
    user = getattr(g, "current_user", None)
    if user is None:
        _audit("admin_dashboard_denied", "denied", details={"reason": "authentication_required"})
        return redirect(url_for("web.login_page"))

    db = get_db()
    active_user = db.execute(
        "SELECT id, role, status FROM users WHERE id = ?",
        (user["id"],),
    ).fetchone()
    if active_user is None or active_user["status"] != "active":
        _audit(
            "admin_dashboard_denied",
            "denied",
            user["id"],
            {"reason": "inactive_or_unknown_user"},
        )
        return redirect(url_for("web.login_page"))
    if active_user["role"] != "administrator":
        _audit(
            "admin_dashboard_denied",
            "denied",
            user["id"],
            {"reason": "administrator_required"},
        )
        return "Administrator access required.", 403

    with transaction(db):
        _audit("admin_dashboard_viewed", "success", user["id"], {"view": "audit_dashboard"})
        users = db.execute(
            """
            SELECT id, name, email, role, status, created_at
            FROM users
            ORDER BY status ASC, lower(email) ASC
            """
        ).fetchall()
        documents = db.execute(
            """
            SELECT d.id, d.name, d.owner_id, owner.name AS owner_name,
                   owner.email AS owner_email, d.created_at, d.scan_status
            FROM documents AS d
            JOIN users AS owner ON owner.id = d.owner_id
            WHERE d.deleted_at IS NULL
            ORDER BY d.created_at DESC
            LIMIT 200
            """
        ).fetchall()
        grants = db.execute(
            """
            SELECT p.id, p.document_id, d.name AS document_name,
                   recipient.name AS recipient_name, recipient.email AS recipient_email,
                   p.permission, p.granted_at, p.expires_at, p.revoked_at,
                   CASE
                       WHEN p.revoked_at IS NOT NULL THEN 'revoked'
                       WHEN p.expires_at IS NOT NULL AND p.expires_at <= ? THEN 'expired'
                       ELSE 'active'
                   END AS grant_status
            FROM document_permissions AS p
            JOIN documents AS d ON d.id = p.document_id
            JOIN users AS recipient ON recipient.id = p.user_id
            ORDER BY p.granted_at DESC
            LIMIT 500
            """,
            (utc_now(),),
        ).fetchall()
        audit_events = db.execute(
            """
            SELECT sequence, timestamp, username, action, document_id,
                   status, details, ip_address
            FROM audit_logs
            WHERE status IN ('success', 'denied')
            ORDER BY sequence DESC
            LIMIT 200
            """
        ).fetchall()
        integrity = verify_audit_integrity(db)

    return render_template(
        "admin_audit.html",
        users=users,
        documents=documents,
        grants=grants,
        audit_events=audit_events,
        integrity=integrity,
        csrf_token=_csrf_token(),
    )


def init_web(app):
    app.register_blueprint(web)
