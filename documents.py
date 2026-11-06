"""Private, validated document storage and authorization-protected routes."""

import hashlib
import os
import re
import sqlite3
import stat
import struct
import uuid
import zlib
import warnings
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path

from flask import Blueprint, current_app, g, jsonify, request, send_file
from PIL import Image, UnidentifiedImageError
from pypdf import PdfReader
from pypdf.errors import PdfReadError
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge
from werkzeug.utils import secure_filename

from audit import append_event
from database import get_db, transaction, utc_now
from permissions import (
    PermissionDenied,
    authorize,
    authorize_owner,
    require_authentication,
    require_permission,
)


documents = Blueprint("documents", __name__, url_prefix="/api/documents")
MAX_FILE_SIZE = 5 * 1024 * 1024
MAX_SEARCH_PAGE_SIZE = 50
MAX_SEARCH_PAGE = 10000
ALLOWED_FORMATS = {
    ".pdf": ("application/pdf", "pdf"),
    ".png": ("image/png", "png"),
    ".jpg": ("image/jpeg", "jpeg"),
    ".jpeg": ("image/jpeg", "jpeg"),
    ".txt": ("text/plain", "text"),
}
_EXECUTABLE_PREFIXES = (
    b"MZ",
    b"\x7fELF",
    b"#!",
    b"PK\x03\x04",
    b"\xca\xfe\xba\xbe",
    b"\xfe\xed\xfa",
    b"\xcf\xfa\xed\xfe",
)
_ACTIVE_MARKUP = re.compile(
    rb"<!doctype\s+html|<!--|</?[a-z][a-z0-9:-]*(?:\s+[^>]*)?>",
    re.IGNORECASE,
)
_PDF_ACTIVE_MARKERS = re.compile(
    rb"/(?:JavaScript|JS|Launch|EmbeddedFile|OpenAction|AA|Filespec|EF|"
    rb"RichMedia|AcroForm|XFA|SubmitForm|ImportData|GoToR|URI|Rendition|Sound|Movie)\b",
    re.IGNORECASE,
)
_PDF_START_XREF = re.compile(rb"startxref\s+(\d+)\s+%%EOF\s*$")
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_ALLOWED_CRITICAL_CHUNKS = {b"IHDR", b"PLTE", b"IDAT", b"IEND"}
_JPEG_SOF_MARKERS = {
    0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
    0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF,
}


class UploadRejected(ValueError):
    """Raised when an uploaded file does not match the supported safe formats."""

    def __init__(self, message, reason):
        super().__init__(message)
        self.reason = reason


def _event(action, result, actor_id=None, document_id=None, metadata=None):
    append_event(
        get_db(),
        action=action,
        result=result,
        actor_id=actor_id,
        document_id=document_id,
        ip_address=(request.remote_addr or "unknown")[:64],
        user_agent=request.user_agent.string[:512],
        metadata=metadata or {},
    )


def _private_storage_dir():
    configured = Path(current_app.config["UPLOAD_FOLDER"])
    if configured.is_symlink():
        raise RuntimeError("Private storage directory must not be a symbolic link.")
    resolved = configured.resolve(strict=True)
    public_root = Path(current_app.static_folder).resolve(strict=True)
    if resolved == public_root or public_root in resolved.parents:
        raise RuntimeError("Private storage must be outside the public web root.")
    if not resolved.is_dir():
        raise RuntimeError("Private storage path is not a directory.")
    if os.name == "posix":
        os.chmod(resolved, 0o700)
    return resolved


def _storage_name(storage_key):
    if (
        not isinstance(storage_key, str)
        or not re.fullmatch(r"[0-9a-f]{32}\.(?:pdf|png|jpg|jpeg|txt)", storage_key)
    ):
        raise RuntimeError("Invalid server-generated storage key.")
    return storage_key


@contextmanager
def _storage_directory_fd():
    directory = _private_storage_dir()
    if os.name == "posix" and hasattr(os, "O_NOFOLLOW"):
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
        fd = os.open(directory, flags)
        try:
            if not stat.S_ISDIR(os.fstat(fd).st_mode):
                raise RuntimeError("Private storage path is not a directory.")
            yield fd, directory
        finally:
            os.close(fd)
    else:
        yield None, directory


def _write_private_file(storage_key, content):
    name = _storage_name(storage_key)
    with _storage_directory_fd() as (directory_fd, directory):
        if directory_fd is not None:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
            path = None
        else:
            path = directory / name
            if path.exists() or path.is_symlink():
                raise FileExistsError("Generated storage name already exists.")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            fd = os.open(path, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("Private storage target is not a regular file.")
            with os.fdopen(fd, "wb", closefd=False) as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            if os.name == "posix":
                os.fchmod(fd, 0o600)
        except OSError:
            try:
                os.close(fd)
            except OSError:
                pass
            if directory_fd is not None:
                try:
                    os.unlink(name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
            elif path is not None:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            raise
        try:
            os.close(fd)
        except OSError:
            if directory_fd is not None:
                try:
                    os.unlink(name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
            elif path is not None:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            raise


def _read_private_file(storage_key):
    name = _storage_name(storage_key)
    with _storage_directory_fd() as (directory_fd, directory):
        if directory_fd is not None:
            flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
            fd = os.open(name, flags, dir_fd=directory_fd)
        else:
            path = directory / name
            if path.is_symlink() or path.resolve(strict=True).parent != directory:
                raise FileNotFoundError("Private file is unavailable.")
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
            fd = os.open(path, flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise FileNotFoundError("Private file is unavailable.")
            with os.fdopen(fd, "rb", closefd=False) as source:
                content = source.read(MAX_FILE_SIZE + 1)
            if len(content) > MAX_FILE_SIZE:
                raise OSError("Stored document exceeds the configured size limit.")
            return content
        finally:
            os.close(fd)


def _unlink_private_file(storage_key):
    name = _storage_name(storage_key)
    with _storage_directory_fd() as (directory_fd, directory):
        if directory_fd is not None:
            os.unlink(name, dir_fd=directory_fd)
        else:
            path = directory / name
            if path.is_symlink() or path.resolve(strict=True).parent != directory:
                raise OSError("Private file path is unsafe.")
            path.unlink()


def _validate_png(content):
    if not content.startswith(_PNG_SIGNATURE):
        raise UploadRejected("The file is not a valid PNG image.", "invalid_png_signature")
    offset = len(_PNG_SIGNATURE)
    saw_ihdr = saw_idat = saw_iend = False
    width = height = 0
    while offset + 12 <= len(content):
        length = struct.unpack(">I", content[offset : offset + 4])[0]
        chunk_type = content[offset + 4 : offset + 8]
        end = offset + 12 + length
        if end > len(content) or length > MAX_FILE_SIZE:
            raise UploadRejected("The PNG image is malformed.", "malformed_png")
        chunk_data = content[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", content[offset + 8 + length : end])[0]
        actual_crc = zlib.crc32(chunk_type)
        actual_crc = zlib.crc32(chunk_data, actual_crc) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            raise UploadRejected("The PNG image is malformed.", "invalid_png_crc")
        if not saw_ihdr:
            if chunk_type != b"IHDR" or length != 13:
                raise UploadRejected("The PNG image is malformed.", "invalid_png_header")
            width, height, depth, color_type, compression, filtering, interlace = struct.unpack(
                ">IIBBBBB", chunk_data
            )
            if (
                width == 0
                or height == 0
                or width * height > 100_000_000
                or depth not in {1, 2, 4, 8, 16}
                or color_type not in {0, 2, 3, 4, 6}
                or compression != 0
                or filtering != 0
                or interlace not in {0, 1}
            ):
                raise UploadRejected("The PNG image is malformed.", "invalid_png_dimensions")
            saw_ihdr = True
        elif chunk_type == b"IHDR":
            raise UploadRejected("The PNG image is malformed.", "duplicate_png_header")
        if chunk_type and 65 <= chunk_type[0] <= 90 and chunk_type not in _PNG_ALLOWED_CRITICAL_CHUNKS:
            raise UploadRejected("The PNG image uses an unsupported critical chunk.", "unknown_png_chunk")
        if chunk_type == b"IDAT":
            if saw_iend:
                raise UploadRejected("The PNG image is malformed.", "png_data_after_end")
            saw_idat = True
        if chunk_type == b"IEND":
            if length != 0 or not saw_idat:
                raise UploadRejected("The PNG image is malformed.", "invalid_png_end")
            saw_iend = True
            offset = end
            break
        offset = end
    if not saw_ihdr or not saw_iend or offset != len(content):
        raise UploadRejected("The PNG image is malformed.", "incomplete_png")


def _validate_jpeg(content):
    if len(content) < 4 or content[:2] != b"\xff\xd8" or content[-2:] != b"\xff\xd9":
        raise UploadRejected("The file is not a complete JPEG image.", "invalid_jpeg_signature")

    offset = 2
    saw_frame = False
    saw_scan = False
    while offset < len(content) - 2:
        if content[offset] != 0xFF:
            raise UploadRejected("The JPEG image is malformed.", "invalid_jpeg_marker")
        while offset < len(content) and content[offset] == 0xFF:
            offset += 1
        if offset >= len(content):
            break
        marker = content[offset]
        offset += 1
        if marker == 0xD9:
            if offset != len(content):
                raise UploadRejected("The JPEG image contains trailing data.", "jpeg_trailing_data")
            break
        if marker in {0xD8, 0x00} or marker in range(0xD0, 0xD8):
            continue
        if offset + 2 > len(content):
            raise UploadRejected("The JPEG image is malformed.", "truncated_jpeg_segment")
        segment_length = struct.unpack(">H", content[offset : offset + 2])[0]
        if segment_length < 2 or offset + segment_length > len(content):
            raise UploadRejected("The JPEG image is malformed.", "truncated_jpeg_segment")
        segment = content[offset + 2 : offset + segment_length]
        if marker in _JPEG_SOF_MARKERS:
            if len(segment) < 6:
                raise UploadRejected("The JPEG image is malformed.", "invalid_jpeg_frame")
            height, width = struct.unpack(">HH", segment[1:5])
            if width == 0 or height == 0 or width * height > 100_000_000:
                raise UploadRejected("The JPEG image dimensions are invalid.", "invalid_jpeg_dimensions")
            saw_frame = True
        if marker == 0xDA:
            saw_scan = True
            offset += segment_length
            while offset < len(content) - 2:
                if content[offset] != 0xFF:
                    offset += 1
                    continue
                next_byte = content[offset + 1]
                if next_byte == 0x00 or next_byte in range(0xD0, 0xD8):
                    offset += 2
                    continue
                break
            continue
        offset += segment_length
    if not saw_frame or not saw_scan:
        raise UploadRejected("The JPEG image is malformed.", "incomplete_jpeg")


def _validate_image_with_decoder(content, expected_format):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            image = Image.open(BytesIO(content))
            if image.format != expected_format or image.width * image.height > 40_000_000:
                raise UploadRejected("The image format or dimensions are not supported.", "invalid_image")
            image.verify()
            image = Image.open(BytesIO(content))
            image.load()
    except UploadRejected:
        raise
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        OSError,
        SyntaxError,
        UnidentifiedImageError,
    ) as error:
        raise UploadRejected("The image is malformed or unsafe.", "invalid_image") from error


def _validate_pdf(content):
    if not content.startswith(b"%PDF-") or b"%%EOF" not in content[-2048:]:
        raise UploadRejected("The file is not a complete PDF document.", "invalid_pdf")
    if _PDF_ACTIVE_MARKERS.search(content):
        raise UploadRejected("Active PDF content is not supported.", "active_pdf")
    startxref = _PDF_START_XREF.search(content)
    if startxref is None:
        raise UploadRejected("The PDF structure is invalid.", "invalid_pdf_structure")
    offset = int(startxref.group(1))
    if offset >= len(content):
        raise UploadRejected("The PDF cross-reference is invalid.", "invalid_pdf_xref")
    xref_target = content[offset : offset + 4]
    if xref_target != b"xref" and not re.match(rb"\d+\s+\d+\s+obj\b", content[offset : offset + 32]):
        raise UploadRejected("The PDF cross-reference is invalid.", "invalid_pdf_xref")
    try:
        reader = PdfReader(BytesIO(content), strict=True)
        if reader.is_encrypted or not reader.pages or len(reader.pages) > 10_000:
            raise UploadRejected("The PDF document is not supported.", "invalid_pdf_document")
        if reader.trailer["/Root"].get("/Type") != "/Catalog":
            raise UploadRejected("The PDF catalog is invalid.", "invalid_pdf_catalog")
    except UploadRejected:
        raise
    except (
        PdfReadError,
        ValueError,
        KeyError,
        IndexError,
        AttributeError,
        TypeError,
        OSError,
        RecursionError,
    ) as error:
        raise UploadRejected("The PDF structure is invalid.", "invalid_pdf_structure") from error


def _validate_content(content, format_name):
    if not content:
        raise UploadRejected("Empty files are not allowed.", "empty_file")
    if content.startswith(_EXECUTABLE_PREFIXES):
        raise UploadRejected("Executable and archive files are not supported.", "executable_content")
    if _ACTIVE_MARKUP.search(content):
        raise UploadRejected("HTML, SVG, and active markup are not supported.", "active_markup")
    recognized_signatures = (
        (b"%PDF-", "pdf"),
        (_PNG_SIGNATURE, "png"),
        (b"\xff\xd8", "jpeg"),
    )
    for signature, detected_format in recognized_signatures:
        if content.startswith(signature) and detected_format != format_name:
            raise UploadRejected(
                "The file extension does not match the detected file content.",
                "content_extension_mismatch",
            )

    if format_name == "pdf":
        _validate_pdf(content)
        return
    if format_name == "png":
        _validate_png(content)
        _validate_image_with_decoder(content, "PNG")
        return
    if format_name == "jpeg":
        _validate_jpeg(content)
        _validate_image_with_decoder(content, "JPEG")
        return
    if format_name == "text":
        try:
            decoded = content.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError as error:
            raise UploadRejected("Text documents must be valid UTF-8.", "invalid_text_encoding") from error
        if "\x00" in decoded or any(
            ord(character) < 32 and character not in "\t\n\r\f"
            for character in decoded
        ):
            raise UploadRejected("Text contains unsupported control characters.", "binary_text")
        return
    raise UploadRejected("This file format is not supported.", "unsupported_format")


def _validated_upload(upload):
    original_name = upload.filename
    if not isinstance(original_name, str) or not original_name.strip():
        raise UploadRejected("A filename is required.", "missing_filename")
    extension = Path(original_name.replace("\\", "/").rsplit("/", 1)[-1]).suffix.lower()
    expected = ALLOWED_FORMATS.get(extension)
    if expected is None:
        raise UploadRejected("This file extension is not supported.", "unsupported_extension")
    expected_mime, format_name = expected
    if upload.mimetype.lower() != expected_mime:
        raise UploadRejected("The file extension and MIME type do not match.", "mime_mismatch")
    content = upload.stream.read(MAX_FILE_SIZE + 1)
    if len(content) > MAX_FILE_SIZE:
        raise UploadRejected("Files must be 5 MB or smaller.", "file_too_large")
    _validate_content(content, format_name)
    if "/" in original_name or "\\" in original_name or Path(original_name).name != original_name:
        raise UploadRejected("Filenames must not contain path components.", "path_traversal_filename")
    display_name = secure_filename(original_name)
    if not display_name or len(display_name) > 255:
        raise UploadRejected("A safe filename is required.", "invalid_filename")
    return display_name, expected_mime, content


def _document_metadata(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "category": row["category"],
        "mime_type": row["mime_type"],
        "size_bytes": row["size_bytes"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def parse_search_parameters(args):
    """Validate bounded search inputs before they reach a SQL statement."""
    for key in ("q", "search", "page", "page_size"):
        if len(args.getlist(key)) > 1:
            raise ValueError(f"Search parameter '{key}' must appear once.")
    if "q" in args and "search" in args:
        raise ValueError("Use either 'q' or 'search', not both.")

    query = args.get("q", args.get("search", ""))
    if len(query) > 200 or any(ord(char) < 32 for char in query):
        raise ValueError("Search text must be at most 200 printable characters.")

    raw_page = args.get("page", "1")
    raw_page_size = args.get("page_size", "20")
    if not raw_page.isdecimal() or not raw_page_size.isdecimal():
        raise ValueError("Page and page size must be positive integers.")
    page = int(raw_page)
    page_size = int(raw_page_size)
    if not 1 <= page <= MAX_SEARCH_PAGE:
        raise ValueError("Page is outside the supported range.")
    if not 1 <= page_size <= MAX_SEARCH_PAGE_SIZE:
        raise ValueError(f"Page size must be between 1 and {MAX_SEARCH_PAGE_SIZE}.")
    return query, page, page_size


def search_documents(user, query, page, page_size, *, connection=None):
    """Return only live-authorized document metadata using bounded SQL paging."""
    db = connection if connection is not None else get_db()
    escaped = query.casefold().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = f"%{escaped}%"
    now = utc_now()
    access_filter = """
        d.deleted_at IS NULL
        AND EXISTS (
            SELECT 1
            FROM users AS active_user
            WHERE active_user.id = ?
              AND active_user.status = 'active'
        )
        AND (
            d.owner_id = ?
            OR EXISTS (
                SELECT 1
                FROM document_permissions AS p
                WHERE p.document_id = d.id
                  AND p.user_id = ?
                  AND p.revoked_at IS NULL
                  AND (p.expires_at IS NULL OR p.expires_at > ?)
            )
        )
        AND (
            ? = ''
            OR lower(d.name) LIKE ? ESCAPE '\\'
            OR lower(d.description) LIKE ? ESCAPE '\\'
            OR lower(d.category) LIKE ? ESCAPE '\\'
        )
    """
    filter_values = (
        user["id"],
        user["id"],
        user["id"],
        now,
        escaped,
        pattern,
        pattern,
        pattern,
    )
    with transaction(db):
        total = db.execute(
            f"SELECT COUNT(*) AS count FROM documents AS d WHERE {access_filter}",
            filter_values,
        ).fetchone()["count"]
        rows = db.execute(
            f"""
            SELECT d.id
            FROM documents AS d
            WHERE {access_filter}
            ORDER BY d.created_at DESC, d.id ASC
            LIMIT ? OFFSET ?
            """,
            (*filter_values, page_size, (page - 1) * page_size),
        ).fetchall()
        results = []
        for row in rows:
            try:
                document = authorize(user, row["id"], "read", connection=db)
            except PermissionDenied:
                continue
            results.append(_document_metadata(document))
        _event(
            "document_searched" if query else "document_listed",
            "success",
            user["id"],
            metadata={
                "count": len(results),
                "query_length": len(query),
                "page": page,
                "page_size": page_size,
                "total": total,
            },
        )
    return {"documents": results, "total": total, "page": page, "page_size": page_size}


def _authorize_transaction(user, document_id, permission, owner_only=False):
    @contextmanager
    def manager():
        db = get_db()
        try:
            with transaction(db):
                if owner_only:
                    authorized = authorize_owner(user, document_id, connection=db)
                else:
                    authorized = authorize(user, document_id, permission, connection=db)
                yield db, authorized
        except PermissionDenied:
            # Authorization denial events made inside the rolled-back operation
            # transaction need a separate durable append.
            append_event(
                db,
                action="authorization_denied",
                result="denied",
                actor_id=user["id"],
                metadata={"required_permission": permission, "reason": "authorization_changed"},
                ip_address=(request.remote_addr or "unknown")[:64],
                user_agent=request.user_agent.string[:512],
            )
            raise

    return manager()


def _response_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "sandbox; default-src 'none'"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "private, no-store"
    return response


@documents.errorhandler(RequestEntityTooLarge)
def request_too_large(_error):
    user = getattr(g, "current_user", None)
    actor_id = user.get("id") if isinstance(user, dict) else None
    _event("document_upload_failed", "failure", actor_id, metadata={"reason": "request_too_large"})
    return jsonify({"error": "Files must be 5 MB or smaller."}), 413


@documents.errorhandler(BadRequest)
def invalid_document_request(_error):
    user = getattr(g, "current_user", None)
    actor_id = user.get("id") if isinstance(user, dict) else None
    _event("document_request_failed", "failure", actor_id, metadata={"reason": "malformed_request"})
    return jsonify({"error": "The document request is malformed."}), 400


@documents.get("")
@require_authentication()
def list_documents():
    user = g.current_user
    try:
        query, page, page_size = parse_search_parameters(request.args)
    except ValueError as error:
        _event(
            "document_search_failed",
            "failure",
            user["id"],
            metadata={"reason": "invalid_parameters"},
        )
        return jsonify({"error": str(error)}), 400
    result = search_documents(user, query, page, page_size)
    return _response_headers(jsonify(result))


@documents.post("")
@require_authentication()
def upload_document():
    user = g.current_user
    if user["role"] != "document_owner":
        _event("document_upload_denied", "denied", user["id"], metadata={"reason": "owner_role_required"})
        return jsonify({"error": "The requested operation is not available."}), 403

    upload = request.files.get("file")
    if upload is None:
        _event("document_upload_failed", "failure", user["id"], metadata={"reason": "missing_file"})
        return jsonify({"error": "A file is required."}), 400
    try:
        display_name, mime_type, content = _validated_upload(upload)
    except UploadRejected as error:
        _event("document_upload_failed", "failure", user["id"], metadata={"reason": error.reason})
        return jsonify({"error": str(error)}), 400
    except OSError:
        _event("document_upload_failed", "failure", user["id"], metadata={"reason": "upload_read_error"})
        current_app.logger.exception("Failed to read uploaded document.")
        return jsonify({"error": "The uploaded file could not be read."}), 500

    description = request.form.get("description", "").strip()
    category = request.form.get("category", "general").strip()
    if len(description) > 2000 or not category or len(category) > 64:
        _event("document_upload_failed", "failure", user["id"], metadata={"reason": "invalid_metadata"})
        return jsonify({"error": "Document metadata is invalid."}), 400

    extension = Path(display_name).suffix.lower()
    document_id = uuid.uuid4().hex
    storage_key = f"{uuid.uuid4().hex}{extension}"
    digest = hashlib.sha256(content).hexdigest()
    now = utc_now()
    file_written = False
    db = get_db()
    try:
        _write_private_file(storage_key, content)
        file_written = True
        with transaction(db):
            db.execute(
                """
                INSERT INTO documents (
                    id, owner_id, storage_key, name, description, category,
                    mime_type, size_bytes, sha256, scan_status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved', ?, ?)
                """,
                (
                    document_id,
                    user["id"],
                    storage_key,
                    display_name,
                    description,
                    category,
                    mime_type,
                    len(content),
                    digest,
                    now,
                    now,
                ),
            )
            authorize(user, document_id, "edit", connection=db)
            append_event(
                db,
                action="document_uploaded",
                actor_id=user["id"],
                document_id=document_id,
                metadata={"name": display_name, "size_bytes": len(content), "sha256": digest},
                ip_address=(request.remote_addr or "unknown")[:64],
                user_agent=request.user_agent.string[:512],
            )
    except (OSError, sqlite3.Error, PermissionDenied) as error:
        if file_written:
            try:
                _unlink_private_file(storage_key)
            except FileNotFoundError:
                pass
            except (OSError, RuntimeError):
                current_app.logger.exception("Failed to remove an uncommitted uploaded file.")
        if isinstance(error, PermissionDenied):
            _event("document_upload_failed", "denied", user["id"], metadata={"reason": "authorization_denied"})
            return jsonify({"error": "The requested operation is not available."}), 403
        _event("document_upload_failed", "failure", user["id"], metadata={"reason": "storage_or_database_error"})
        current_app.logger.exception("Document upload failed.")
        return jsonify({"error": "The document could not be stored."}), 500
    except RuntimeError:
        if file_written:
            try:
                _unlink_private_file(storage_key)
            except FileNotFoundError:
                pass
            except (OSError, RuntimeError):
                current_app.logger.exception("Failed to remove an uncommitted uploaded file.")
        _event("document_upload_failed", "failure", user["id"], metadata={"reason": "unsafe_storage"})
        current_app.logger.exception("Document upload storage validation failed.")
        return jsonify({"error": "The document could not be stored."}), 500

    row = db.execute(
        """
        SELECT id, name, description, category, mime_type,
               size_bytes, created_at, updated_at
        FROM documents WHERE id = ?
        """,
        (document_id,),
    ).fetchone()
    return _response_headers(jsonify({"document": _document_metadata(row)})), 201


@documents.get("/<document_id>")
@require_permission("read")
def view_document(document_id):
    user = g.current_user
    try:
        with _authorize_transaction(user, document_id, "read") as (db, document):
            content = _read_private_file(document["storage_key"])
            append_event(
                db,
                action="document_viewed",
                actor_id=user["id"],
                document_id=document_id,
                metadata={"size_bytes": len(content)},
                ip_address=(request.remote_addr or "unknown")[:64],
                user_agent=request.user_agent.string[:512],
            )
            mime_type = document["mime_type"]
            filename = document["name"]
    except PermissionDenied:
        return jsonify({"error": "The requested resource is not available."}), 404
    except (FileNotFoundError, OSError, RuntimeError):
        _event("document_view_failed", "failure", user["id"], document_id, {"reason": "storage_unavailable"})
        return jsonify({"error": "The requested resource is not available."}), 404

    response = send_file(
        BytesIO(content),
        mimetype=mime_type,
        as_attachment=False,
        download_name=filename,
        conditional=False,
        max_age=0,
    )
    response.headers["Content-Disposition"] = f'inline; filename="{secure_filename(filename)}"'
    return _response_headers(response)


@documents.get("/<document_id>/download")
@require_permission("read")
def download_document(document_id):
    user = g.current_user
    try:
        with _authorize_transaction(user, document_id, "read") as (db, document):
            content = _read_private_file(document["storage_key"])
            append_event(
                db,
                action="document_downloaded",
                actor_id=user["id"],
                document_id=document_id,
                metadata={"size_bytes": len(content)},
                ip_address=(request.remote_addr or "unknown")[:64],
                user_agent=request.user_agent.string[:512],
            )
            mime_type = document["mime_type"]
            filename = document["name"]
    except PermissionDenied:
        return jsonify({"error": "The requested resource is not available."}), 404
    except (FileNotFoundError, OSError, RuntimeError):
        _event("document_download_failed", "failure", user["id"], document_id, {"reason": "storage_unavailable"})
        return jsonify({"error": "The requested resource is not available."}), 404

    response = send_file(
        BytesIO(content),
        mimetype=mime_type,
        as_attachment=True,
        download_name=filename,
        conditional=False,
        max_age=0,
    )
    return _response_headers(response)


@documents.patch("/<document_id>")
@require_permission("edit")
def edit_document_metadata(document_id):
    user = g.current_user
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data or set(data) - {"name", "description", "category"}:
        _event("document_metadata_edit_failed", "failure", user["id"], document_id, {"reason": "invalid_metadata"})
        return jsonify({"error": "Only name, description, and category may be updated."}), 400

    changes = {}
    if "name" in data:
        if not isinstance(data["name"], str):
            changes["name"] = None
        else:
            sanitized = secure_filename(data["name"])
            changes["name"] = sanitized[:255] if sanitized else None
    if "description" in data:
        changes["description"] = data["description"] if isinstance(data["description"], str) else None
    if "category" in data:
        changes["category"] = data["category"].strip() if isinstance(data["category"], str) else None
    if (
        ("name" in changes and not changes["name"])
        or ("description" in changes and (changes["description"] is None or len(changes["description"]) > 2000))
        or ("category" in changes and (not changes["category"] or len(changes["category"]) > 64))
    ):
        _event("document_metadata_edit_failed", "failure", user["id"], document_id, {"reason": "invalid_metadata"})
        return jsonify({"error": "Document metadata is invalid."}), 400

    now = utc_now()
    assignments = ", ".join(f"{key} = ?" for key in changes)
    params = [*changes.values(), now, document_id]
    try:
        with _authorize_transaction(user, document_id, "edit") as (db, _document):
            db.execute(
                f"UPDATE documents SET {assignments}, updated_at = ? WHERE id = ?",
                params,
            )
            append_event(
                db,
                action="document_metadata_edited",
                actor_id=user["id"],
                document_id=document_id,
                metadata={"fields": sorted(changes)},
                ip_address=(request.remote_addr or "unknown")[:64],
                user_agent=request.user_agent.string[:512],
            )
            row = db.execute(
                """
                SELECT id, name, description, category, mime_type,
                       size_bytes, created_at, updated_at
                FROM documents WHERE id = ?
                """,
                (document_id,),
            ).fetchone()
            result = _document_metadata(row)
    except PermissionDenied:
        return jsonify({"error": "The requested resource is not available."}), 404
    except sqlite3.Error:
        _event("document_metadata_edit_failed", "failure", user["id"], document_id, {"reason": "database_error"})
        current_app.logger.exception("Document metadata update failed.")
        return jsonify({"error": "The document metadata could not be updated."}), 500
    return _response_headers(jsonify({"document": result}))


@documents.delete("/<document_id>")
@require_permission("edit")
def delete_document(document_id):
    user = g.current_user
    db = get_db()
    try:
        with _authorize_transaction(user, document_id, "edit") as (connection, document):
            now = utc_now()
            connection.execute(
                "UPDATE documents SET deleted_at = ?, updated_at = ? WHERE id = ?",
                (now, now, document_id),
            )
            append_event(
                connection,
                action="document_deleted",
                actor_id=user["id"],
                document_id=document_id,
                metadata={},
                ip_address=(request.remote_addr or "unknown")[:64],
                user_agent=request.user_agent.string[:512],
            )
            storage_key = document["storage_key"]
    except PermissionDenied:
        return jsonify({"error": "The requested resource is not available."}), 404
    except sqlite3.Error:
        _event("document_delete_failed", "failure", user["id"], document_id, {"reason": "database_error"})
        current_app.logger.exception("Document deletion failed.")
        return jsonify({"error": "The document could not be deleted."}), 500

    try:
        _unlink_private_file(storage_key)
    except FileNotFoundError:
        _event("document_delete_storage_failed", "failure", user["id"], document_id, {"reason": "storage_missing"})
        return jsonify({"error": "Document access was revoked, but private storage cleanup failed."}), 500
    except (OSError, RuntimeError):
        _event("document_delete_storage_failed", "failure", user["id"], document_id, {"reason": "storage_cleanup_error"})
        current_app.logger.exception("Deleted document storage cleanup failed.")
        return jsonify({"error": "Document access was revoked, but private storage cleanup failed."}), 500
    return _response_headers(jsonify({"message": "Document deleted."}))


@documents.get("/<document_id>/permissions")
@require_authentication()
def list_document_permissions(document_id):
    user = g.current_user
    try:
        with _authorize_transaction(user, document_id, "edit", owner_only=True) as (db, _document):
            rows = db.execute(
                """
                SELECT p.id, u.email AS recipient_email, u.name AS recipient_name,
                       p.permission, p.granted_at, p.expires_at, p.revoked_at
                FROM document_permissions AS p
                JOIN users AS u ON u.id = p.user_id
                WHERE p.document_id = ?
                ORDER BY p.granted_at DESC
                """,
                (document_id,),
            ).fetchall()
            grants = [dict(row) for row in rows]
            _event(
                "document_permissions_listed",
                "success",
                user["id"],
                document_id,
                {"grant_count": len(grants)},
            )
    except PermissionDenied:
        return jsonify({"error": "The requested resource is not available."}), 404
    return _response_headers(jsonify({"permissions": grants}))


@documents.post("/<document_id>/permissions")
@require_authentication()
def grant_document_permission(document_id):
    user = g.current_user
    try:
        with _authorize_transaction(user, document_id, "edit", owner_only=True):
            pass
    except PermissionDenied:
        return jsonify({"error": "The requested resource is not available."}), 404

    data = request.get_json(silent=True)
    if (
        not isinstance(data, dict)
        or set(data) != {"recipient_email", "permission"}
        or not isinstance(data["recipient_email"], str)
        or not isinstance(data["permission"], str)
        or data["permission"] not in {"read", "edit"}
    ):
        _event(
            "document_permission_grant_failed",
            "failure",
            user["id"],
            document_id,
            {"reason": "invalid_grant_request"},
        )
        return jsonify({"error": "Provide a recipient email and a read or edit permission."}), 400

    recipient_email = data["recipient_email"].strip().lower()
    if len(recipient_email) > 254 or not re.fullmatch(
        r"[^@\s]{1,64}@[^@\s.]+(?:\.[^@\s.]+)+",
        recipient_email,
    ):
        _event(
            "document_permission_grant_failed",
            "failure",
            user["id"],
            document_id,
            {"reason": "invalid_recipient"},
        )
        return jsonify({"error": "The recipient is not eligible for sharing."}), 404

    now = utc_now()
    try:
        with _authorize_transaction(user, document_id, "edit", owner_only=True) as (db, document):
            recipient = db.execute(
                """
                SELECT id, email, role, status
                FROM users
                WHERE email = ? COLLATE NOCASE
                """,
                (recipient_email,),
            ).fetchone()
            if (
                recipient is None
                or recipient["status"] != "active"
                or recipient["id"] == user["id"]
                or (recipient["role"] == "viewer" and data["permission"] == "edit")
            ):
                append_event(
                    db,
                    action="document_permission_grant_failed",
                    result="denied",
                    actor_id=user["id"],
                    document_id=document["id"],
                    metadata={"reason": "recipient_not_eligible"},
                    ip_address=(request.remote_addr or "unknown")[:64],
                    user_agent=request.user_agent.string[:512],
                )
                return jsonify({"error": "The recipient is not eligible for sharing."}), 404

            active_grant = db.execute(
                """
                SELECT id FROM document_permissions
                WHERE document_id = ?
                  AND user_id = ?
                  AND revoked_at IS NULL
                  AND (expires_at IS NULL OR expires_at > ?)
                """,
                (document["id"], recipient["id"], now),
            ).fetchone()
            if active_grant is not None:
                append_event(
                    db,
                    action="document_permission_grant_failed",
                    result="failure",
                    actor_id=user["id"],
                    document_id=document["id"],
                    metadata={"reason": "duplicate_grant", "recipient_id": recipient["id"]},
                    ip_address=(request.remote_addr or "unknown")[:64],
                    user_agent=request.user_agent.string[:512],
                )
                return jsonify({"error": "A permission grant already exists; revoke it before granting again."}), 409

            expired_grants = db.execute(
                """
                SELECT id, permission FROM document_permissions
                WHERE document_id = ?
                  AND user_id = ?
                  AND revoked_at IS NULL
                  AND expires_at IS NOT NULL
                  AND expires_at <= ?
                """,
                (document["id"], recipient["id"], now),
            ).fetchall()
            for expired in expired_grants:
                db.execute(
                    "UPDATE document_permissions SET revoked_at = ? WHERE id = ?",
                    (now, expired["id"]),
                )
                append_event(
                    db,
                    action="document_permission_expired",
                    actor_id=user["id"],
                    document_id=document["id"],
                    metadata={"recipient_id": recipient["id"], "permission": expired["permission"]},
                    ip_address=(request.remote_addr or "unknown")[:64],
                    user_agent=request.user_agent.string[:512],
                )

            grant_id = uuid.uuid4().hex
            db.execute(
                """
                INSERT INTO document_permissions (
                    id, document_id, user_id, granted_by, permission, granted_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    grant_id,
                    document["id"],
                    recipient["id"],
                    user["id"],
                    data["permission"],
                    now,
                ),
            )
            append_event(
                db,
                action="document_permission_granted",
                actor_id=user["id"],
                document_id=document["id"],
                metadata={
                    "grant_id": grant_id,
                    "recipient_id": recipient["id"],
                    "permission": data["permission"],
                },
                ip_address=(request.remote_addr or "unknown")[:64],
                user_agent=request.user_agent.string[:512],
            )
    except PermissionDenied:
        return jsonify({"error": "The requested resource is not available."}), 404
    except sqlite3.IntegrityError:
        _event(
            "document_permission_grant_failed",
            "failure",
            user["id"],
            document_id,
            {"reason": "grant_conflict"},
        )
        return jsonify({"error": "A permission grant could not be created."}), 409
    except sqlite3.Error:
        _event(
            "document_permission_grant_failed",
            "failure",
            user["id"],
            document_id,
            {"reason": "database_error"},
        )
        current_app.logger.exception("Document permission grant failed.")
        return jsonify({"error": "The permission could not be granted."}), 500

    return _response_headers(
        jsonify(
            {
                "permission": {
                    "id": grant_id,
                    "document_id": document_id,
                    "recipient_email": recipient["email"],
                    "permission": data["permission"],
                    "granted_at": now,
                }
            }
        )
    ), 201


@documents.delete("/<document_id>/permissions/<grant_id>")
@require_authentication()
def revoke_document_permission(document_id, grant_id):
    user = g.current_user
    db = get_db()
    now = utc_now()
    try:
        with _authorize_transaction(user, document_id, "edit", owner_only=True) as (db, document):
            grant = db.execute(
                """
                SELECT id, user_id, permission, revoked_at
                FROM document_permissions
                WHERE id = ? AND document_id = ?
                """,
                (grant_id, document["id"]),
            ).fetchone()
            if grant is None or grant["revoked_at"] is not None:
                append_event(
                    db,
                    action="document_permission_revoke_failed",
                    result="denied",
                    actor_id=user["id"],
                    document_id=document["id"],
                    metadata={"reason": "grant_unavailable"},
                    ip_address=(request.remote_addr or "unknown")[:64],
                    user_agent=request.user_agent.string[:512],
                )
                return jsonify({"error": "The requested permission is not available."}), 404
            db.execute(
                "UPDATE document_permissions SET revoked_at = ? WHERE id = ?",
                (now, grant["id"]),
            )
            append_event(
                db,
                action="document_permission_revoked",
                actor_id=user["id"],
                document_id=document["id"],
                metadata={
                    "grant_id": grant["id"],
                    "recipient_id": grant["user_id"],
                    "permission": grant["permission"],
                },
                ip_address=(request.remote_addr or "unknown")[:64],
                user_agent=request.user_agent.string[:512],
            )
    except PermissionDenied:
        return jsonify({"error": "The requested resource is not available."}), 404
    except sqlite3.Error:
        _event(
            "document_permission_revoke_failed",
            "failure",
            user["id"],
            document_id,
            {"reason": "database_error"},
        )
        current_app.logger.exception("Document permission revocation failed.")
        return jsonify({"error": "The permission could not be revoked."}), 500

    return _response_headers(jsonify({"message": "Permission revoked."}))


def init_documents(app):
    app.register_blueprint(documents)

    @app.after_request
    def secure_document_response(response):
        if request.path.startswith("/api/documents"):
            _response_headers(response)
        return response
