"""Structured, secret-conscious request and application logging."""

import json
import logging
import time
import uuid

from flask import g, has_request_context, request


class JsonLogFormatter(logging.Formatter):
    converter = time.gmtime

    def format(self, record):
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S") + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if has_request_context():
            payload["request_id"] = getattr(g, "request_id", None)
        for field in ("http_method", "http_status", "duration_ms"):
            if hasattr(record, field):
                payload[field] = getattr(record, field)
        if record.exc_info and record.exc_info[0] is not None:
            payload["exception_type"] = record.exc_info[0].__name__
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def configure_logging(app):
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())
    app.logger.handlers.clear()
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    app.logger.propagate = False

    @app.before_request
    def begin_request_logging():
        g.request_id = uuid.uuid4().hex
        g.request_started_at = time.monotonic()

    @app.after_request
    def finish_request_logging(response):
        elapsed_ms = round(
            (time.monotonic() - getattr(g, "request_started_at", time.monotonic()))
            * 1000,
            2,
        )
        response.headers["X-Request-ID"] = getattr(g, "request_id", "unavailable")
        app.logger.info(
            "http_request",
            extra={
                "http_method": request.method,
                "http_status": response.status_code,
                "duration_ms": elapsed_ms,
            },
        )
        return response
