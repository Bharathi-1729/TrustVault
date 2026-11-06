"""Flask application factory for the TrustVault foundation."""

import sqlite3

from flask import Flask, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config, ensure_private_directories, validate_production_config
from database import init_app, initialize_database
from auth import init_auth
from documents import init_documents
from observability import configure_logging
from web import init_web


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    validate_production_config(app.config)
    ensure_private_directories(app.config)
    if app.config["APP_ENV"] == "production":
        app.config["DEBUG"] = False
        app.config["PROPAGATE_EXCEPTIONS"] = False
        if app.config["TRUST_PROXY_HEADERS"]:
            app.wsgi_app = ProxyFix(
                app.wsgi_app,
                x_for=1,
                x_proto=1,
                x_host=1,
                x_port=0,
                x_prefix=0,
            )

    configure_logging(app)
    initialize_database(
        app.config["DATABASE_PATH"],
        app.config["SQLITE_BUSY_TIMEOUT_MS"],
    )
    init_app(app)
    init_auth(app)
    init_documents(app)
    init_web(app)

    @app.get("/healthz")
    def health_check():
        try:
            from database import get_db

            get_db().execute("SELECT 1").fetchone()
            return jsonify({"status": "ok"}), 200
        except sqlite3.Error:
            app.logger.exception("health_check_database_unavailable")
            return jsonify({"status": "unavailable"}), 503

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'",
        )
        if request.path.startswith("/api/") or request.path == "/healthz":
            response.headers.setdefault("Cache-Control", "no-store")
        if request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        if isinstance(error, HTTPException):
            return error
        app.logger.exception("unhandled_application_error")
        payload = {
            "error": "Internal server error.",
            "request_id": getattr(g, "request_id", None),
        }
        if request.path.startswith("/api/") or request.path == "/healthz":
            return jsonify(payload), 500
        return render_template(
            "error.html",
            status_code=500,
            message="An unexpected error occurred. Please try again later.",
        ), 500

    return app
