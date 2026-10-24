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
from .auth import AuthManager

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
        self.port = env_int("SCANMAP_PORT", 8420)
        self.data_dir = os.environ.get("SCANMAP_DATA_DIR", "/data")
        self.max_parallel = env_int("SCANMAP_MAX_PARALLEL", 2)
        self.max_jobs = env_int("SCANMAP_MAX_JOBS", 100)
        self.user = os.environ.get("SCANMAP_USER", "")
        self.password = os.environ.get("SCANMAP_PASSWORD", "")
        self.auth_required = os.environ.get("SCANMAP_AUTH_REQUIRED", "auto").lower()

    @property
    def basic_auth_enabled(self) -> bool:
        return bool(self.user and self.password)


CONFIG = Config()
JOBS = JobManager(
    max_parallel=CONFIG.max_parallel, max_jobs=CONFIG.max_jobs, data_dir=CONFIG.data_dir
)
AUTH = AuthManager(CONFIG.data_dir)

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
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self' data:; form-action 'self'; frame-ancestors 'none'",
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

    def _get_cookie(self, name: str) -> str:
        header = self.headers.get("Cookie", "")
        for part in header.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                if k.strip() == name:
                    return unquote(v.strip())
        return ""

    def _set_cookie(self, name: str, value: str, max_age: int = 7 * 24 * 3600) -> None:
        self.send_header("Set-Cookie", f"{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}")

    def _clear_cookie(self, name: str) -> None:
        self.send_header("Set-Cookie", f"{name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")

    def _needs_auth(self) -> bool:
        if CONFIG.basic_auth_enabled:
            return True
        if CONFIG.auth_required == "false":
            return False
        if CONFIG.auth_required == "true":
            return True
        return AUTH.has_users()

    def _get_user(self):
        if CONFIG.basic_auth_enabled:
            return None
        token = self._get_cookie("scanmap_session")
        return AUTH.get_user_by_session(token)

    def _authorized(self) -> bool:
        if CONFIG.basic_auth_enabled:
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
        if not self._needs_auth():
            return True
        if self._get_user():
            return True
        return False

    # -- routing ----------------------------------------------------------- #

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)

        # Allow auth endpoints without session auth
        if path in ("/api/health", "/api/auth/me", "/login", "/setup"):
            pass
        elif not self._authorized():
            # For browser requests to root, redirect to login
            if path == "/" and not CONFIG.basic_auth_enabled:
                self.send_response(HTTPStatus.FOUND)
                if not AUTH.has_users():
                    self.send_header("Location", "/setup")
                else:
                    self.send_header("Location", "/login")
                self._security_headers()
                self.end_headers()
                return
            return
        else:
            pass

        if path == "/login":
            self._serve_login()
            return
        elif path == "/setup":
            self._serve_setup()
            return
        elif path == "/api/health":
            self._send_json(HTTPStatus.OK, {"status": "ok", "version": VERSION, "auth_required": self._needs_auth(), "has_users": AUTH.has_users()})
        elif path == "/api/auth/me":
            if CONFIG.basic_auth_enabled:
                self._send_json(HTTPStatus.OK, {"user": None, "auth": "basic"})
                return
            user = self._get_user()
            if user:
                self._send_json(HTTPStatus.OK, {"user": {"username": user.username, "is_admin": user.is_admin}, "auth": "session"})
            else:
                if not AUTH.has_users():
                    self._send_json(HTTPStatus.OK, {"user": None, "setup": True, "auth": "session"})
                elif self._needs_auth():
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"user": None, "auth": "session"})
                else:
                    self._send_json(HTTPStatus.OK, {"user": None, "auth": "session"})
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
        path = urlparse(self.path).path.rstrip("/") or "/"
        # Auth endpoints
        if path == "/api/auth/setup":
            self._do_setup()
            return
        if path == "/api/auth/login":
            self._do_login()
            return
        if path == "/api/auth/logout":
            self._do_logout()
            return
        if not self._authorized():
            return

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


    # -- auth pages/methods ------------------------------------------------ #

    def _serve_login(self) -> None:
        if CONFIG.basic_auth_enabled:
            self._error(HTTPStatus.BAD_REQUEST, "basic auth is enabled via environment")
            return
        if not AUTH.has_users():
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/setup")
            self._security_headers()
            self.end_headers()
            return
        if self._get_user():
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/")
            self._security_headers()
            self.end_headers()
            return
        body = self._login_html().encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _serve_setup(self) -> None:
        if CONFIG.basic_auth_enabled:
            self._error(HTTPStatus.BAD_REQUEST, "basic auth is enabled via environment")
            return
        if AUTH.has_users():
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/login")
            self._security_headers()
            self.end_headers()
            return
        body = self._setup_html().encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _do_setup(self) -> None:
        if CONFIG.basic_auth_enabled:
            self._error(HTTPStatus.BAD_REQUEST, "basic auth is enabled via environment")
            return
        if AUTH.has_users():
            self._error(HTTPStatus.FORBIDDEN, "admin already exists")
            return
        payload = self._read_json()
        if payload is None:
            return
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        try:
            user = AUTH.create_user(username, password, is_admin=True)
        except ValueError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        if not user:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "failed to create user")
            return
        token = AUTH.create_session(user.id)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        body = json.dumps({"ok": True, "username": user.username}).encode("utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._set_cookie("scanmap_session", token)
        self._security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _do_login(self) -> None:
        if CONFIG.basic_auth_enabled:
            self._error(HTTPStatus.BAD_REQUEST, "basic auth is enabled via environment")
            return
        payload = self._read_json()
        if payload is None:
            return
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        user = AUTH.verify_user(username, password)
        if not user:
            self._error(HTTPStatus.UNAUTHORIZED, "invalid username or password")
            return
        token = AUTH.create_session(user.id)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        body = json.dumps({"ok": True, "username": user.username}).encode("utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._set_cookie("scanmap_session", token)
        self._security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _do_logout(self) -> None:
        token = self._get_cookie("scanmap_session")
        if token:
            AUTH.delete_session(token)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        body = b'{"ok":true}'
        self.send_header("Content-Length", "11")
        self._clear_cookie("scanmap_session")
        self._security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _login_html(self) -> str:
        return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Login - scanmap</title>
<link rel="stylesheet" href="/static/style.css">
<style>
.auth-wrap{max-width:420px;margin:80px auto;padding:24px}
.auth-card{background:linear-gradient(180deg,var(--panel),#0c1420);border:1px solid var(--line);border-radius:var(--radius);padding:28px;box-shadow:0 12px 40px rgba(0,0,0,.28)}
.auth-card h1{margin:0 0 6px;font-size:22px}
.auth-card p{margin:0 0 18px;color:var(--muted)}
.auth-card label{display:flex;flex-direction:column;gap:6px;margin-bottom:14px}
.auth-card input{padding:10px 12px;border-radius:9px;border:1px solid var(--line);background:#0a121d;color:var(--text);font:inherit}
.auth-card button{width:100%;padding:11px;border-radius:9px;border:0;background:linear-gradient(135deg,var(--accent),#1fb98d);color:#04120d;font-weight:700;cursor:pointer}
.auth-card .err{color:var(--danger);font-size:13px;margin-top:10px;min-height:18px}
</style></head>
<body>
<div class="auth-wrap">
<div class="auth-card">
<div class="brand" style="margin-bottom:18px"><svg class="logo" viewBox="0 0 64 64"><circle cx="32" cy="32" r="18" fill="none" stroke="currentColor" stroke-width="4"/><circle cx="32" cy="32" r="7" fill="currentColor"/><circle cx="32" cy="32" r="27" fill="none" stroke="currentColor" stroke-width="2" stroke-dasharray="4 8"/></svg><div><h1>scanmap</h1><p>sign in to continue</p></div></div>
<form id="login-form">
<label><span>Username</span><input name="username" autocomplete="username" required></label>
<label><span>Password</span><input type="password" name="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button>
<div class="err" id="err"></div>
</form>
</div></div>
<script>
document.getElementById('login-form').addEventListener('submit',async e=>{
e.preventDefault();
const form=new FormData(e.target);
const body={username:form.get('username'),password:form.get('password')};
const res=await fetch('/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
if(res.ok){location.href='/'}else{document.getElementById('err').textContent=(await res.json()).error||'login failed'}
});
</script>
</body></html>"""

    def _setup_html(self) -> str:
        return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Setup - scanmap</title>
<link rel="stylesheet" href="/static/style.css">
<style>
.auth-wrap{max-width:420px;margin:80px auto;padding:24px}
.auth-card{background:linear-gradient(180deg,var(--panel),#0c1420);border:1px solid var(--line);border-radius:var(--radius);padding:28px;box-shadow:0 12px 40px rgba(0,0,0,.28)}
.auth-card h1{margin:0 0 6px;font-size:22px}
.auth-card p{margin:0 0 18px;color:var(--muted)}
.auth-card label{display:flex;flex-direction:column;gap:6px;margin-bottom:14px}
.auth-card input{padding:10px 12px;border-radius:9px;border:1px solid var(--line);background:#0a121d;color:var(--text);font:inherit}
.auth-card button{width:100%;padding:11px;border-radius:9px;border:0;background:linear-gradient(135deg,var(--accent),#1fb98d);color:#04120d;font-weight:700;cursor:pointer}
.auth-card .err{color:var(--danger);font-size:13px;margin-top:10px;min-height:18px}
.auth-card .ok{color:var(--accent);font-size:13px;margin-top:10px;min-height:18px}
</style></head>
<body>
<div class="auth-wrap">
<div class="auth-card">
<div class="brand" style="margin-bottom:18px"><svg class="logo" viewBox="0 0 64 64"><circle cx="32" cy="32" r="18" fill="none" stroke="currentColor" stroke-width="4"/><circle cx="32" cy="32" r="7" fill="currentColor"/><circle cx="32" cy="32" r="27" fill="none" stroke="currentColor" stroke-width="2" stroke-dasharray="4 8"/></svg><div><h1>Welcome to scanmap</h1><p>Create your admin account</p></div></div>
<form id="setup-form">
<label><span>Username</span><input name="username" autocomplete="username" minlength="3" required></label>
<label><span>Password</span><input type="password" name="password" autocomplete="new-password" minlength="8" required></label>
<label><span>Confirm password</span><input type="password" name="confirm" autocomplete="new-password" minlength="8" required></label>
<button type="submit">Create admin account</button>
<div class="err" id="err"></div>
<div class="ok" id="ok"></div>
</form>
</div></div>
<script>
document.getElementById('setup-form').addEventListener('submit',async e=>{
e.preventDefault();
const form=new FormData(e.target);
if(form.get('password')!==form.get('confirm')){document.getElementById('err').textContent='passwords do not match';return}
const body={username:form.get('username'),password:form.get('password')};
const res=await fetch('/api/auth/setup',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
const data=await res.json();
if(res.ok){document.getElementById('err').textContent='';document.getElementById('ok').textContent='Admin created, signing in...';const r2=await fetch('/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});if(r2.ok)location.href='/'}else{document.getElementById('err').textContent=data.error||'setup failed'}
});
</script>
</body></html>"""


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
        f"(data dir: {CONFIG.data_dir}, auth: {'on' if CONFIG.basic_auth_enabled else 'off'})",
        flush=True,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
