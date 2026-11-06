import json

from audit import record_audit
from database import utc_now


def _login_as(client, user_id, csrf="web-test-csrf"):
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["auth_version"] = 1
        session["csrf_token"] = csrf
        session.permanent = True
    return {"X-CSRF-Token": csrf}


def _insert_user(db, user_id, role, status="active", name=None):
    now = utc_now()
    db.execute(
        """
        INSERT INTO users (
            id, email, name, password_hash, role, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            f"{user_id}@example.test",
            name or user_id,
            "test-only-hash",
            role,
            status,
            now,
            now,
        ),
    )


def _insert_document(db, document_id, owner_id, name, created_at=None):
    timestamp = created_at or utc_now()
    db.execute(
        """
        INSERT INTO documents (
            id, owner_id, storage_key, name, category, mime_type,
            size_bytes, sha256, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            document_id,
            owner_id,
            f"{document_id}.pdf",
            name,
            "general",
            "application/pdf",
            1,
            "a" * 64,
            timestamp,
            timestamp,
        ),
    )


def _grant(db, grant_id, document_id, recipient_id, owner_id):
    db.execute(
        """
        INSERT INTO document_permissions (
            id, document_id, user_id, granted_by, permission, granted_at
        ) VALUES (?, ?, ?, ?, 'read', ?)
        """,
        (grant_id, document_id, recipient_id, owner_id, utc_now()),
    )


def test_registration_page_hides_terminal_invitation_instructions(client):
    response = client.get("/register")

    assert response.status_code == 200
    assert b'name="invite_token"' in response.data
    assert b"python seed.py --create-invite" not in response.data
    assert b"Do not enter a role name" not in response.data


def test_profile_page_is_authenticated_and_shows_current_account(client, sample_user):
    anonymous = client.get("/profile")
    assert anonymous.status_code == 302
    assert anonymous.headers["Location"].endswith("/login")

    _login_as(client, sample_user["id"])
    response = client.get("/profile")

    assert response.status_code == 200
    assert b"Your profile" in response.data
    assert b"Test User" in response.data
    assert b"user@example.test" in response.data
    assert b"Document Owner" in response.data
    assert b"Active" in response.data
    assert b'href="/profile"' in response.data
    assert b'data-logout-form' in response.data
    assert b'data-csrf=' in response.data


def test_logout_navigation_posts_csrf_and_invalidates_profile_session(client, db, sample_user):
    _login_as(client, sample_user["id"], csrf="profile-logout-csrf")
    profile = client.get("/profile")
    assert profile.status_code == 200

    response = client.post(
        "/api/auth/logout",
        headers={"X-CSRF-Token": "profile-logout-csrf"},
    )
    assert response.status_code == 200
    assert client.get("/profile").headers["Location"].endswith("/login")
    event = db.execute(
        "SELECT action FROM audit_logs WHERE action = 'logout_succeeded'"
    ).fetchone()
    assert event["action"] == "logout_succeeded"


def test_search_only_returns_owned_or_live_granted_documents(client, db, sample_user, sample_document):
    _insert_user(db, "other-owner", "document_owner")
    _insert_user(db, "recipient", "viewer")
    _insert_document(db, "private-doc", "other-owner", "secret-title-private.pdf")
    _insert_document(db, "granted-doc", "other-owner", "shared-notes.pdf")
    _grant(db, "grant-live", "granted-doc", "recipient", "other-owner")

    _login_as(client, "recipient")
    result = client.get("/api/documents?q=secret").json
    assert result["total"] == 0
    assert result["documents"] == []
    assert "secret-title-private.pdf" not in json.dumps(result)

    shared = client.get("/api/documents?q=shared")
    assert shared.status_code == 200
    assert [doc["name"] for doc in shared.json["documents"]] == ["shared-notes.pdf"]


def test_search_uses_literal_parameterized_terms_and_limits_pagination(client, db, sample_user):
    for index in range(3):
        _insert_document(
            db,
            f"page-doc-{index}",
            sample_user["id"],
            f"note {index} %_ OR 1=1.pdf",
            f"2026-01-0{index + 1}T00:00:00.000000Z",
        )
    _login_as(client, sample_user["id"])

    injection = client.get("/api/documents?q=%27%20OR%201%3D1%20--")
    assert injection.status_code == 200
    assert injection.json["total"] == 0

    first_page = client.get("/api/documents?q=note&page=1&page_size=2")
    second_page = client.get("/api/documents?q=note&page=2&page_size=2")
    assert first_page.status_code == second_page.status_code == 200
    assert first_page.json["total"] == 3
    assert len(first_page.json["documents"]) == 2
    assert len(second_page.json["documents"]) == 1
    assert first_page.json["documents"][0]["id"] != second_page.json["documents"][0]["id"]

    for query in (
        "/api/documents?page=0",
        "/api/documents?page=1&page_size=51",
        "/api/documents?page=10001",
        "/api/documents?page=1&page=2",
        "/api/documents?q=one&search=two",
        "/api/documents?q=%00",
    ):
        assert client.get(query).status_code == 400


def test_search_honors_permission_revocation_on_the_next_request(
    client, db, sample_user, sample_document
):
    _insert_user(db, "search-viewer", "viewer")
    _grant(db, "search-grant", sample_document["id"], "search-viewer", sample_user["id"])
    _login_as(client, "search-viewer")

    before = client.get("/api/documents?q=test")
    assert before.status_code == 200
    assert before.json["total"] == 1

    db.execute(
        "UPDATE document_permissions SET revoked_at = ? WHERE id = ?",
        (utc_now(), "search-grant"),
    )
    after = client.get("/api/documents?q=test")
    assert after.status_code == 200
    assert after.json["total"] == 0
    assert after.json["documents"] == []


def test_admin_dashboard_is_admin_only_and_audits_dashboard_access(
    client, db, sample_user, sample_document
):
    _insert_user(db, "site-admin", "administrator", name="Site Admin")
    _insert_user(db, "disabled-user", "viewer", status="disabled")
    _insert_user(db, "shared-user", "viewer")
    _insert_user(db, "expired-user", "viewer")
    _grant(db, "admin-view-grant", sample_document["id"], "shared-user", sample_user["id"])
    _grant(db, "admin-expired-grant", sample_document["id"], "expired-user", sample_user["id"])
    db.execute(
        "UPDATE document_permissions SET granted_at = ?, expires_at = ? WHERE id = ?",
        (
            "2020-01-01T00:00:00.000000Z",
            "2020-02-01T00:00:00.000000Z",
            "admin-expired-grant",
        ),
    )
    record_audit(db, action="example_denied_event", status="denied", details={"reason": "test"})

    _login_as(client, sample_user["id"])
    forbidden = client.get("/admin")
    assert forbidden.status_code == 403
    assert db.execute(
        """
        SELECT COUNT(*) FROM audit_logs
        WHERE action = 'admin_dashboard_denied' AND status = 'denied'
        """
    ).fetchone()[0] == 1

    _login_as(client, "site-admin")
    dashboard = client.get("/admin")
    assert dashboard.status_code == 200
    assert "default-src 'self'" in dashboard.headers["Content-Security-Policy"]
    assert dashboard.headers["X-Content-Type-Options"] == "nosniff"
    body = dashboard.get_data(as_text=True)
    assert "Audit-chain integrity" in body
    assert "VERIFIED" in body
    assert "SUCCESS" in body
    assert "DENIED" in body
    assert "disabled-user@example.test" in body
    assert "Inactive (disabled)" in body
    assert "sample.pdf" not in body
    assert "test.pdf" in body
    assert "shared-user@example.test" in body
    assert "expired-user@example.test" in body
    assert ">expired<" in body
    assert db.execute(
        """
        SELECT COUNT(*) FROM audit_logs
        WHERE action = 'admin_dashboard_viewed' AND status = 'success'
        """
    ).fetchone()[0] == 1


def test_jinja_templates_escape_document_and_audit_controlled_values(
    client, db, sample_user, sample_document
):
    _insert_user(db, "site-admin", "administrator")
    db.execute(
        "UPDATE documents SET name = ? WHERE id = ?",
        ("<img src=x onerror=alert(1)>.pdf", sample_document["id"]),
    )
    record_audit(
        db,
        action="<script>alert(1)</script>",
        status="success",
        username="<svg onload=alert(1)>",
        details={"label": "<script>alert(2)</script>"},
    )

    _login_as(client, sample_user["id"])
    search_html = client.get("/search").get_data(as_text=True)
    assert "&lt;img src=x onerror=alert(1)&gt;.pdf" in search_html
    assert "<img src=x onerror=alert(1)>" not in search_html

    _login_as(client, "site-admin")
    admin_html = client.get("/admin").get_data(as_text=True)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in admin_html
    assert "&lt;svg onload=alert(1)&gt;" in admin_html
    assert "<script>alert(1)</script>" not in admin_html
    assert "<svg onload=alert(1)>" not in admin_html
    assert "default-src &#39;self&#39;" not in admin_html


def test_state_changing_document_operations_require_csrf(client, db, sample_user, sample_document):
    _login_as(client, sample_user["id"])
    response = client.post(
        f"/api/documents/{sample_document['id']}/permissions",
        json={"recipient_email": "recipient@example.test", "permission": "read"},
    )
    assert response.status_code == 400
    assert db.execute("SELECT COUNT(*) FROM document_permissions").fetchone()[0] == 0


def test_document_pages_render_and_sharing_page_remains_owner_only(
    client, db, sample_user, sample_document
):
    _login_as(client, sample_user["id"])
    for path in ("/documents", "/search", "/upload"):
        response = client.get(path)
        assert response.status_code == 200
        assert "Content-Security-Policy" in response.headers
        assert response.headers["Cache-Control"] == "private, no-store"
    sharing = client.get(f"/documents/{sample_document['id']}/sharing")
    assert sharing.status_code == 200
    assert "Grant access" in sharing.get_data(as_text=True)

    _insert_user(db, "web-viewer", "viewer")
    _login_as(client, "web-viewer")
    upload_denied = client.get("/upload")
    assert upload_denied.status_code == 403
    assert b"Your Viewer role does not have permission to upload documents." in upload_denied.data
    assert b'href="/documents"' in upload_denied.data
    denied = client.get(f"/documents/{sample_document['id']}/sharing")
    assert denied.status_code == 404
    assert db.execute(
        """
        SELECT COUNT(*) FROM audit_logs
        WHERE action IN ('document_sharing_page_denied', 'document_upload_page_denied')
          AND status = 'denied'
        """
    ).fetchone()[0] == 2
