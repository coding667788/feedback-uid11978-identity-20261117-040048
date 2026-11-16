"""HTTP layer for the relying party (RP).

All interaction is over real HTTP on 127.0.0.1.  No TLS, no reverse proxy, no
framework: ``http.server`` with a threaded server is enough for the local test
protocol.

Endpoints
---------
POST /v1/login              {"ticket": "<compact HS256>"}
GET  /v1/authcheck          Authorization: Bearer <session_id>
POST /v1/logout/events      {"logout": "<compact HS256>"}     (the IdP->RP push)
GET  /v1/status             this process's cache/epoch view
GET  /admin/state           shared-state snapshot
POST /admin/hooks           arm a controllable stop point
GET  /admin/health          liveness + pid
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import db
from .claims import validate_login, validate_logout
from .config import Config
from .store import (
    EventConflict,
    SessionRejected,
    SidReuseConflict,
    Store,
    StoreError,
    add_hook,
)
from .strictjson import StrictJSONError, loads_strict
from .tokens import TokenError, check_not_expired, parse_structure, verify_signature

MAX_BODY = 64 * 1024
AUTH_HEADER = "Authorization"


class BadRequest(Exception):
    def __init__(self, detail: str) -> None:
        super().__init__(detail)


def _json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, default=str).encode("utf-8")


class RPHandler(BaseHTTPRequestHandler):
    server: "RPServer"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:  # quieter tests
        if self.server.verbose:
            sys.stderr.write(f"[rp:{self.server.server_port}] {fmt % args}\n")

    # -- request plumbing -------------------------------------------------

    def _read_body(self) -> bytes:
        length_header = self.headers.get("Content-Length")
        if length_header is None:
            raise BadRequest("Content-Length required")
        try:
            length = int(length_header)
        except ValueError as exc:
            raise BadRequest("invalid Content-Length") from exc
        if length < 0 or length > MAX_BODY:
            raise BadRequest("body too large")
        body = self.rfile.read(length)
        if len(body) != length:
            raise BadRequest("truncated body")
        return body

    def _json_body(self) -> dict[str, Any]:
        raw = self._read_body()
        if not raw:
            raise BadRequest("empty body")
        try:
            doc = loads_strict(raw)
        except StrictJSONError as exc:
            # Duplicate JSON members in a request are rejected here too.
            raise BadRequest(f"invalid JSON: {exc}") from exc
        if not isinstance(doc, dict):
            raise BadRequest("body must be a JSON object")
        return doc

    def _respond(self, status: int, payload: Any) -> None:
        body = _json_bytes(payload)
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _error(self, status: int, code: str, detail: str = "") -> None:
        self._respond(status, {"error": code, "detail": detail})

    def _dispatch(self, method: str) -> None:
        path = self.path.split("?", 1)[0]
        store = self.server.store
        try:
            if method == "POST" and path == "/v1/login":
                return self._handle_login()
            if method == "GET" and path == "/v1/authcheck":
                return self._handle_authcheck()
            if method == "POST" and path == "/v1/logout/events":
                return self._handle_logout()
            if method == "GET" and path == "/v1/status":
                payload = store.process_stats()
                payload["pid"] = os.getpid()
                payload["port"] = self.server.server_port
                return self._respond(200, payload)
            if method == "GET" and path == "/admin/state":
                return self._respond(200, store.dump())
            if method == "POST" and path == "/admin/hooks":
                return self._handle_hook()
            if method == "GET" and path == "/admin/health":
                return self._respond(
                    200,
                    {
                        "ok": True,
                        "pid": os.getpid(),
                        "port": self.server.server_port,
                        "uptime": time.time() - self.server.started_at,
                    },
                )
            if path in {
                "/v1/login",
                "/v1/logout/events",
                "/admin/hooks",
            } and method != "POST":
                return self._error(405, "method_not_allowed", "use POST")
            if path in {"/v1/authcheck", "/v1/status", "/admin/state", "/admin/health"} and method != "GET":
                return self._error(405, "method_not_allowed", "use GET")
            return self._error(404, "not_found", path)
        except BadRequest as exc:
            return self._error(400, "bad_request", str(exc))
        except EventConflict as exc:
            return self._error(exc.status, exc.code, exc.detail)
        except SessionRejected as exc:
            return self._error(exc.status, exc.code, exc.detail)
        except SidReuseConflict as exc:
            return self._error(exc.status, exc.code, exc.detail)
        except StoreError as exc:
            return self._error(exc.status, exc.code, exc.detail)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:  # pragma: no cover - defensive
            return self._error(500, "internal", f"{type(exc).__name__}: {exc}")

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    # -- handlers ---------------------------------------------------------

    def _handle_login(self) -> None:
        doc = self._json_body()
        ticket = doc.get("ticket")
        if not isinstance(ticket, str):
            raise BadRequest("ticket must be a string")
        config: Config = self.server.config
        now = int(time.time())
        try:
            parsed = parse_structure(ticket)
            login = validate_login(parsed, config, now=now)
        except TokenError as exc:
            return self._error(401, exc.reason, exc.detail)
        status, payload = self.server.store.login(login)
        self._respond(status, payload)

    def _handle_authcheck(self) -> None:
        header = self.headers.get(AUTH_HEADER, "")
        if not header.startswith("Bearer "):
            return self._error(401, "missing_bearer", "Authorization: Bearer required")
        session_id = header[len("Bearer ") :].strip()
        decision = self.server.store.authenticate(session_id)
        if decision.allowed:
            return self._respond(200, decision.as_payload())
        return self._respond(401, decision.as_payload())

    def _handle_logout(self) -> None:
        doc = self._json_body()
        token = doc.get("logout")
        if not isinstance(token, str):
            raise BadRequest("logout must be a string")
        config: Config = self.server.config
        now = int(time.time())
        try:
            parsed = parse_structure(token)
            event = validate_logout(parsed, config, now=now)
        except TokenError as exc:
            return self._error(401, exc.reason, exc.detail)
        payload = self.server.store.receive_logout(event)
        # A 2xx here is produced only after the revocation transaction
        # committed.  Anything else is 4xx/5xx and carries no acknowledgment.
        self._respond(200, payload)

    def _handle_hook(self) -> None:
        doc = self._json_body()
        phase = doc.get("phase")
        mode = doc.get("mode", "sleep")
        millis = doc.get("millis", 0)
        port = doc.get("port", 0)
        if not isinstance(phase, str) or not isinstance(mode, str):
            raise BadRequest("phase and mode must be strings")
        if type(millis) is not int or type(port) is not int:
            raise BadRequest("millis and port must be integers")
        try:
            hook_id = add_hook(
                self.server.store.db_path,
                phase,
                port=port,
                mode=mode,
                millis=millis,
            )
        except ValueError as exc:
            raise BadRequest(str(exc)) from exc
        return self._respond(201, {"hook_id": hook_id, "phase": phase, "mode": mode})


class RPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        *,
        config: Config,
        db_path: str,
        verbose: bool = False,
        cache_ttl: float = 30.0,
    ) -> None:
        super().__init__(address, RPHandler)
        self.config = config
        self.verbose = verbose
        self.started_at = time.time()
        self.store = Store(
            db_path=db_path, config=config, port=self.server_port, cache_ttl=cache_ttl
        )


def serve(
    db_path: str,
    config: Config,
    host: str,
    port: int,
    *,
    verbose: bool = False,
    ready_file: str | None = None,
) -> None:
    server = RPServer(
        (host, port), config=config, db_path=db_path, verbose=verbose
    )
    actual_port = server.server_port
    if ready_file:
        tmp = f"{ready_file}.tmp{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"port": actual_port, "pid": os.getpid()}))
        os.replace(tmp, ready_file)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
