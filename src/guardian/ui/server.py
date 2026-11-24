"""Stdlib HTTP server for the review console, bound to 127.0.0.1 only.

Everything shown is attacker-controlled text (package names, advisories, commit messages,
Jira comments), so the defences assume the page is a target:

* Host header must be ``127.0.0.1:<port>`` or ``localhost:<port>`` (DNS rebinding).
* Every ``/api`` request needs the per-launch token in ``X-Guardian-Token`` (compared in
  constant time); when ``Origin`` is sent it must be this server (CSRF).
* JSON bodies only, at most 16 KB.
* Static files come from a fixed allowlist inside the package, never from a path.
* Strict CSP, ``nosniff``, ``no-referrer``, no caching of API responses; the access log is
  silent so the token never reaches a terminal or log file.
"""

import hmac
import json
import logging
import re
import secrets
import sqlite3
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from typing import Any
from urllib.parse import urlsplit

from guardian.core.config import GuardianSettings
from guardian.core.exceptions import GuardianError
from guardian.storage.database import Database
from guardian.storage.remediation import RemediationCaseNotFoundError
from guardian.ui import payloads
from guardian.ui.decisions import DecisionError, DecisionHandler, DecisionService
from guardian.ui.investigation import (
    InvestigationConflictError,
    InvestigationJobs,
    architecture,
    codebase,
)

logger = logging.getLogger(__name__)

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_BODY_BYTES = 16 * 1024
DEFAULT_INVESTIGATE_TOP = 5
MAX_TOP = 25
TOKEN_HEADER = "X-Guardian-Token"  # noqa: S105 - a header name, not a secret

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)
SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

STATIC_FILES: dict[str, tuple[str, str]] = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
_CASE_PATH = re.compile(r"/api/cases/(rc_[0-9a-f]{12})")
_DECISION_PATH = re.compile(r"/api/cases/(rc_[0-9a-f]{12})/decision")


@dataclass(slots=True)
class Response:
    status: int
    body: bytes = b""
    content_type: str = "application/json; charset=utf-8"
    headers: dict[str, str] = field(default_factory=dict)


def _json(status: int, payload: object) -> Response:
    return Response(status, json.dumps(payload, separators=(",", ":")).encode("utf-8"))


def _error(status: int, message: str) -> Response:
    return _json(status, {"error": message})


def finalize(response: Response) -> Response:
    """Add the security headers every response carries."""
    response.headers = SECURITY_HEADERS | response.headers
    if response.content_type.startswith("application/json"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


def static_asset(name: str) -> bytes:
    return files("guardian.ui").joinpath("static", name).read_bytes()


class ConsoleApp:
    """Request routing and checks, independent of the socket layer (so tests call it directly)."""

    def __init__(  # noqa: PLR0913 - keyword-only injection points for tests and the integrator
        self,
        settings: GuardianSettings,
        *,
        token: str | None = None,
        port: int = DEFAULT_PORT,
        handler: DecisionHandler | None = None,
        decisions: DecisionService | None = None,
        risk: payloads.RiskCache | None = None,
        jobs: InvestigationJobs | None = None,
    ) -> None:
        self.settings = settings
        self.token = token or secrets.token_urlsafe(32)
        self.port = port
        self.decisions = decisions or DecisionService(settings, handler)
        self.risk = risk or payloads.RiskCache()
        self.jobs = jobs or InvestigationJobs(settings)

    @property
    def launch_url(self) -> str:
        return f"http://{HOST}:{self.port}/?token={self.token}"

    def _allowed_hosts(self) -> frozenset[str]:
        return frozenset({f"127.0.0.1:{self.port}", f"localhost:{self.port}"})

    def _allowed_origins(self) -> frozenset[str]:
        return frozenset(f"http://{host}" for host in self._allowed_hosts())

    # --- entry point -------------------------------------------------------------------

    def handle(self, method: str, target: str, headers: dict[str, str], body: bytes) -> Response:
        """``headers`` keys are lower-case. ``body`` is already capped by the caller."""
        return finalize(self._route(method, target, headers, body))

    def _route(  # noqa: PLR0911 - one early return per refused check
        self, method: str, target: str, headers: dict[str, str], body: bytes
    ) -> Response:
        if headers.get("host", "").lower() not in self._allowed_hosts():
            return _error(421, "Unexpected Host header; open the URL printed by `guardian ui`.")
        path = urlsplit(target).path
        if not path.startswith("/api/"):
            return self._static(method, path)
        origin = headers.get("origin")
        if origin is not None and origin not in self._allowed_origins():
            return _error(403, "Cross-origin request refused.")
        supplied = headers.get(TOKEN_HEADER.lower(), "")
        if not hmac.compare_digest(supplied.encode("utf-8"), self.token.encode("utf-8")):
            return _error(
                401, "Missing or wrong session token; open the URL printed by `guardian ui`."
            )
        if match := _DECISION_PATH.fullmatch(path):
            if method != "POST":
                return _error(405, "Method not allowed.")
            return self._post_decision(match.group(1), headers, body)
        if path == "/api/investigate":
            if method == "POST":
                return self._post_investigate(headers, body)
            if method == "GET":
                return _json(200, self.jobs.status())
            return _error(405, "Method not allowed.")
        if method == "GET":
            return self._get(path)
        return _error(405, "Method not allowed.")

    def _static(self, method: str, path: str) -> Response:
        entry = STATIC_FILES.get(path)
        if entry is None:
            return _error(404, "Not found.")
        if method not in {"GET", "HEAD"}:
            return _error(405, "Method not allowed.")
        name, content_type = entry
        return Response(200, static_asset(name), content_type, {"Cache-Control": "no-cache"})

    # --- API ---------------------------------------------------------------------------

    def _open(self) -> Database:
        return Database(self.settings.database_path)

    def _get(self, path: str) -> Response:  # noqa: PLR0911 - one return per route
        if path == "/api/health":
            return self._health()
        with self._open() as db:
            if path == "/api/cases":
                pending = self.decisions.pending()
                return _json(200, {"cases": payloads.case_list(db, self.settings, pending)})
            if path == "/api/audit/verify":
                return _json(200, payloads.audit_status(db))
            if path == "/api/architecture":
                return _json(
                    200,
                    architecture(
                        db, self.risk, self.jobs.status(), pr_enabled=self.settings.pr_enabled
                    ),
                )
            if path == "/api/codebase":
                return _json(200, codebase(db, self.risk))
            if match := _CASE_PATH.fullmatch(path):
                try:
                    case = db.remediation.get(match.group(1))
                except RemediationCaseNotFoundError as exc:
                    return _error(404, str(exc))
                pending = case.id in self.decisions.pending()
                detail = payloads.case_detail(db, case, self.settings, self.risk, pending=pending)
                return _json(200, detail)
        return _error(404, "Not found.")

    def _health(self) -> Response:
        try:
            with self._open() as db:
                db.conn.execute("SELECT 1").fetchone()
                return _json(200, payloads.health(db, self.settings, None))
        except (GuardianError, sqlite3.Error, OSError) as exc:
            return _json(200, payloads.health(None, self.settings, type(exc).__name__))

    def _post_investigate(  # noqa: PLR0911 - one early return per refused check
        self, headers: dict[str, str], body: bytes
    ) -> Response:
        """Start an AI investigation of the latest scan on a worker thread (409 if one runs)."""
        top = DEFAULT_INVESTIGATE_TOP
        if body.strip():
            content_type = headers.get("content-type", "").split(";")[0].strip().lower()
            if content_type != "application/json":
                return _error(415, "Send options as application/json.")
            if len(body) > MAX_BODY_BYTES:
                return _error(413, f"Request body is larger than {MAX_BODY_BYTES} bytes.")
            try:
                parsed: Any = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return _error(400, "Request body is not valid JSON.")
            if not isinstance(parsed, dict) or set(parsed) - {"top"}:
                return _error(400, 'Options must be a JSON object with at most "top".')
            top = parsed.get("top", top)
            if not isinstance(top, int) or isinstance(top, bool) or not 1 <= top <= MAX_TOP:
                return _error(400, f"top must be an integer from 1 to {MAX_TOP}.")
        with self._open() as db:
            try:
                db.scans.resolve("latest")
            except GuardianError:
                return _error(404, "No scan recorded yet; run `guardian scan <path>` first.")
        try:
            self.jobs.start(top)
        except InvestigationConflictError as exc:
            return _json(409, {"error": str(exc), "job": self.jobs.status()})
        return _json(202, {"message": "AI investigation started.", "job": self.jobs.status()})

    def _post_decision(self, case_id: str, headers: dict[str, str], body: bytes) -> Response:
        content_type = headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type != "application/json":
            return _error(415, "Send the decision as application/json.")
        if len(body) > MAX_BODY_BYTES:
            return _error(413, f"Request body is larger than {MAX_BODY_BYTES} bytes.")
        try:
            parsed: Any = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _error(400, "Request body is not valid JSON.")
        if not isinstance(parsed, dict):
            return _error(400, "Request body must be a JSON object.")
        with self._open() as db:
            try:
                recorded = self.decisions.submit(db, case_id, parsed)
            except DecisionError as exc:
                return _json(exc.status, exc.to_json())
        return _json(
            202,
            {
                "recorded": recorded.summary,
                "decision": recorded.decision.model_dump(mode="json"),
                "status": recorded.status,
                "message": (
                    f"Decision recorded: {recorded.summary}. Guardian is moving the case on."
                ),
            },
        )


class _RequestHandler(BaseHTTPRequestHandler):
    server_version = "GuardianConsole"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        """Silent: request lines carry the session token."""

    def _app(self) -> "ConsoleApp":
        server = self.server
        if not isinstance(server, ConsoleServer):  # pragma: no cover - only ConsoleServer uses us
            msg = "request handler is bound to an unexpected server"
            raise TypeError(msg)
        return server.app

    def _headers(self) -> dict[str, str]:
        return {k.lower(): v for k, v in self.headers.items()}

    def _send(self, response: Response, *, head: bool = False) -> None:
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        for name, value in response.headers.items():
            self.send_header(name, value)
        self.end_headers()
        if not head:
            self.wfile.write(response.body)

    def _dispatch(self, method: str) -> None:
        body = b""
        if method == "POST":
            raw_length = self.headers.get("Content-Length")
            try:
                length = int(raw_length) if raw_length is not None else -1
            except ValueError:
                length = -1
            if length < 0:
                self.close_connection = True
                self._send(finalize(_error(411, "Content-Length is required.")))
                return
            if length > MAX_BODY_BYTES:
                self.close_connection = True  # the unread body must not be parsed as a request
                message = f"Request body is larger than {MAX_BODY_BYTES} bytes."
                self._send(finalize(_error(413, message)))
                return
            body = self.rfile.read(length)
        response = self._app().handle(
            "GET" if method == "HEAD" else method, self.path, self._headers(), body
        )
        self._send(response, head=method == "HEAD")

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_HEAD(self) -> None:
        self._dispatch("HEAD")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._send(finalize(_error(405, "Method not allowed.")))

    def do_DELETE(self) -> None:
        self._send(finalize(_error(405, "Method not allowed.")))


class ConsoleServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, app: ConsoleApp, port: int) -> None:
        super().__init__((HOST, port), _RequestHandler)
        self.app = app
        app.port = self.server_address[1]


def make_server(app: ConsoleApp, port: int = DEFAULT_PORT) -> ConsoleServer:
    """Bind 127.0.0.1:<port> (0 picks a free port; ``app.port`` is updated to match)."""
    return ConsoleServer(app, port)
