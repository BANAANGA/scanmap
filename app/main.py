"""scanmap - a small web interface for nmap and zmap.

The whole server is Python's standard library: no pip dependencies, nothing to
compile, small image. Run it with ``python3 -m app.main``.
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import signal
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .jobs import JobManager
from .scanners import ValidationError, build_argv, tool_info

VERSION = "0.1.0"
APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".json": "application/json",
}

MAX_BODY_BYTES = 64 * 1024


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


class Config:
    def __init__(self) -> None:
        self.host = os.environ.get("SCANMAP_HOST", "0.0.0.0")
        self.port = env_int("SCANMAP_PORT", 8080)
        self.data_dir = os.environ.get("SCANMAP_DATA_DIR", "/data")
        self.max_parallel = env_int("SCANMAP_MAX_PARALLEL", 2)
        self.max_jobs = env_int("SCANMAP_MAX_JOBS", 100)
        self.user = os.environ.get("SCANMAP_USER", "")
        self.password = os.environ.get("SCANMAP_PASSWORD", "")

    @property
    def auth_enabled(self) -> bool:
        return bool(self.user and self.password)


CONFIG = Config()
JOBS = JobManager(
    max_parallel=CONFIG.max_parallel, max_jobs=CONFIG.max_jobs, data_dir=CONFIG.data_dir
)

_tools_lock = threading.Lock()
_tools_cache: list[dict[str, Any]] | None = None


def get_tools(refresh: bool = False) -> list[dict[str, Any]]:
    global _tools_cache
    with _tools_lock:
        if _tools_cache is None or refresh:
            _tools_cache = tool_info()
        return _tools_cache


class ScanMapHandler(BaseHTTPRequestHandler):
    server_version = f"scanmap/{VERSION}"
    sys_version = ""  # do not advertise the Python patch level
    protocol_version = "HTTP/1.1"

    # -- plumbing ---------------------------------------------------------- #

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(f"[scanmap] {self.address_string()} {fmt % args}\n")

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; form-action 'none'; frame-ancestors 'none'",
        )

    def _send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _error(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message})

    def _read_json(self) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._error(HTTPStatus.BAD_REQUEST, "invalid Content-Length")
            return None
        if length <= 0:
            self._error(HTTPStatus.BAD_REQUEST, "request body is required")
            return None
        if length > MAX_BODY_BYTES:
            self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request body is too large")
            return None
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._error(HTTPStatus.BAD_REQUEST, "request body must be valid JSON")
            return None
        if not isinstance(payload, dict):
            self._error(HTTPStatus.BAD_REQUEST, "request body must be a JSON object")
            return None
        return payload

    def _authorized(self) -> bool:
        if not CONFIG.auth_enabled:
            return True
        header = self.headers.get("Authorization", "")
        if header.startswith("Basic "):
            try:
                decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                decoded = ""
            user, _, password = decoded.partition(":")
            if hmac.compare_digest(user, CONFIG.user) and hmac.compare_digest(
                password, CONFIG.password
            ):
                return True
        body = b"authentication required\n"
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="scanmap", charset="UTF-8"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        return False

    # -- routing ----------------------------------------------------------- #

    def do_GET(self) -> None:  # noqa: N802
        if not self._authorized():
            return
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)

        if path == "/api/health":
            self._send_json(HTTPStatus.OK, {"status": "ok", "version": VERSION})
        elif path == "/api/tools":
            refresh = query.get("refresh", ["0"])[0] in {"1", "true", "yes"}
            self._send_json(HTTPStatus.OK, {"tools": get_tools(refresh)})
        elif path == "/api/jobs":
            self._send_json(HTTPStatus.OK, {"jobs": JOBS.list()})
        elif path.startswith("/api/jobs/"):
            job_id = unquote(path[len("/api/jobs/") :])
            job = JOBS.get(job_id)
            if job is None:
                self._error(HTTPStatus.NOT_FOUND, "job not found")
                return
            try:
                since = max(0, int(query.get("since", ["0"])[0]))
            except ValueError:
                since = 0
            self._send_json(HTTPStatus.OK, job.detail(since))
        elif path == "/" or path == "/index.html":
            self._serve_static("index.html")
        elif path.startswith("/static/"):
            self._serve_static(unquote(path[len("/static/") :]))
        elif path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Content-Length", "0")
            self._security_headers()
            self.end_headers()
        else:
            self._error(HTTPStatus.NOT_FOUND, "not found")

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorized():
            return
        path = urlparse(self.path).path.rstrip("/") or "/"

        if path == "/api/jobs":
            self._create_job()
        elif path == "/api/preview":
            self._preview_job()
        elif path.startswith("/api/jobs/") and path.endswith("/cancel"):
            job_id = unquote(path[len("/api/jobs/") : -len("/cancel")]).rstrip("/")
            if JOBS.cancel(job_id):
                self._send_json(HTTPStatus.OK, {"cancelled": job_id})
            else:
                self._error(HTTPStatus.CONFLICT, "job is not running")
        else:
            self._error(HTTPStatus.NOT_FOUND, "not found")

    def do_DELETE(self) -> None:  # noqa: N802
        if not self._authorized():
            return
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path.startswith("/api/jobs/"):
            job_id = unquote(path[len("/api/jobs/") :])
            if JOBS.delete(job_id):
                self.send_response(HTTPStatus.NO_CONTENT)
                self.send_header("Content-Length", "0")
                self._security_headers()
                self.end_headers()
            else:
                self._error(HTTPStatus.CONFLICT, "job is unknown or still running")
        else:
            self._error(HTTPStatus.NOT_FOUND, "not found")

    # -- handlers ---------------------------------------------------------- #

    def _create_job(self) -> None:
        payload = self._read_json()
        if payload is None:
            return
        scanner = str(payload.get("scanner", "")).strip().lower()
        params = payload.get("params") or {}
        try:
            argv = build_argv(scanner, params, CONFIG.data_dir)
        except ValidationError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
            return

        available = {tool["name"]: tool["available"] for tool in get_tools()}
        if not available.get(scanner, False):
            self._error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                f"{scanner} is not installed in this container",
            )
            return

        job = JOBS.submit(scanner, argv)
        self._send_json(HTTPStatus.ACCEPTED, job.summary())

    def _preview_job(self) -> None:
        """Return the exact argv a request would run, without running it."""
        payload = self._read_json()
        if payload is None:
            return
        scanner = str(payload.get("scanner", "")).strip().lower()
        params = payload.get("params") or {}
        try:
            argv = build_argv(scanner, params, CONFIG.data_dir)
        except ValidationError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        self._send_json(HTTPStatus.OK, {"argv": argv})

    def _serve_static(self, relative: str) -> None:
        relative = relative.lstrip("/") or "index.html"
        candidate = (STATIC_DIR / relative).resolve()
        try:
            candidate.relative_to(STATIC_DIR)
        except ValueError:
            self._error(HTTPStatus.FORBIDDEN, "forbidden")
            return
        if not candidate.is_file():
            self._error(HTTPStatus.NOT_FOUND, "not found")
            return

        body = candidate.read_bytes()
        content_type = CONTENT_TYPES.get(candidate.suffix.lower(), "application/octet-stream")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self._security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()


class ScanMapServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> int:
    os.makedirs(CONFIG.data_dir, exist_ok=True)
    tools = get_tools()
    for tool in tools:
        state = tool["version"] if tool["available"] else "NOT INSTALLED"
        print(f"[scanmap] {tool['name']}: {state}", flush=True)

    try:
        server = ScanMapServer((CONFIG.host, CONFIG.port), ScanMapHandler)
    except OSError as exc:
        print(
            f"[scanmap] could not bind {CONFIG.host}:{CONFIG.port}: {exc}\n"
            f"[scanmap] is another process already using the port? "
            f"Set SCANMAP_PORT to pick a different one.",
            file=sys.stderr,
            flush=True,
        )
        return 1

    def shutdown(signum: int, _frame: Any) -> None:
        print(f"[scanmap] received signal {signum}, shutting down", flush=True)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    print(
        f"[scanmap] listening on http://{CONFIG.host}:{CONFIG.port} "
        f"(data dir: {CONFIG.data_dir}, auth: {'on' if CONFIG.auth_enabled else 'off'})",
        flush=True,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
