"""Local identity-provider simulator (fixed HS256 tickets, no OAuth dance).

Two jobs:

1. **Issue login tickets.**  ``generation`` is a per-(iss, sub) counter that
   starts at 1 and increments on every new login.  ``sid`` is never reused
   within an issuer, tracked in ``used_sids`` and enforced in one immediate
   transaction.

2. **Mint and deliver logout events.**  Events carry their own ``event_id`` and
   are signed by a separate logout key, so the RP proves it is receiving a
   *notification*, not a replayed login ticket.

There is no discovery endpoint, no key URL, and no token introspection: the RP
is configured with keys out of band, exactly as the protocol states.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .config import Config
from .strictjson import loads_strict
from .tokens import encode_token

LOGIN_TTL_SECONDS = 3600
LOGOUT_TTL_SECONDS = 24 * 3600


class IdPState:
    """Generation/sid bookkeeping persisted next to the ticket keys.

    Kept in JSON with an exclusive-create lock file rather than SQLite: the IdP
    deliberately has *no* shared database with the RP, so the RP cannot read
    generation state out of band.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.lock = threading.Lock()
        self.data: dict[str, Any] = {"generations": {}, "used_sids": {}}
        if self.path.exists():
            self.data = loads_strict(self.path.read_text(encoding="utf-8"))
            self.data.setdefault("generations", {})
            self.data.setdefault("used_sids", {})

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(f".tmp{os.getpid()}")
        tmp.write_text(json.dumps(self.data, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)

    def observe_login(self, iss: str, sub: str, sid: str, generation: int) -> None:
        """Record an externally specified login (used by tests/imports)."""

        with self.lock:
            key = f"{iss}\x00{sub}"
            current = int(self.data["generations"].get(key, 0))
            if generation <= current:
                raise ValueError(
                    f"generation {generation} for {iss}/{sub} is not above {current}"
                )
            sids = self.data["used_sids"].setdefault(iss, [])
            if sid in sids:
                raise ValueError(f"sid {sid!r} was already used by issuer {iss}")
            self.data["generations"][key] = generation
            sids.append(sid)
            self._save()

    def next_login(self, iss: str, sub: str, *, sid: str | None = None) -> tuple[str, int]:
        with self.lock:
            key = f"{iss}\x00{sub}"
            generation = int(self.data["generations"].get(key, 0)) + 1
            sids = self.data["used_sids"].setdefault(iss, [])
            sid = sid or f"s-{secrets.token_hex(8)}"
            if sid in sids:
                raise ValueError(f"sid {sid!r} was already used by issuer {iss}")
            # Persist before returning: a restarted simulator must never issue
            # a duplicate generation or sid.
            self.data["generations"][key] = generation
            sids.append(sid)
            self._save()
            return sid, generation


def mint_login_ticket(
    config: Config,
    state: IdPState,
    *,
    iss: str,
    sub: str,
    sid: str | None = None,
    generation: int | None = None,
    ttl: int = LOGIN_TTL_SECONDS,
    now: int | None = None,
) -> dict[str, Any]:
    issuer = config.login_issuer(iss)
    if issuer is None:
        raise ValueError(f"issuer {iss!r} is not configured")
    if sub not in issuer.subjects:
        raise ValueError(f"subject {sub!r} is not provisioned for {iss!r}")
    if generation is None:
        chosen_sid, chosen_generation = state.next_login(iss, sub, sid=sid)
    else:
        if not sid:
            raise ValueError("an explicit generation requires an explicit sid")
        state.observe_login(iss, sub, sid, generation)
        chosen_sid, chosen_generation = sid, generation
    issued_at = int(now if now is not None else time.time())
    claims = {
        "iss": iss,
        "sub": sub,
        "sid": chosen_sid,
        "generation": chosen_generation,
        "aud": config.audience,
        "exp": issued_at + ttl,
        "iat": issued_at,
    }
    return {
        "ticket": encode_token(claims, issuer.key),
        "claims": claims,
    }


def record_existing_login(
    state: IdPState, *, iss: str, sub: str, sid: str, generation: int
) -> None:
    """Adopt a (sid, generation) pair the IdP already handed out.

    Tests pre-provision a fixed matrix of tickets; the simulator has to know
    those generations so later logins continue the sequence and sids stay
    unique.
    """

    state.observe_login(iss, sub, sid, generation)


def mint_logout_event(
    config: Config,
    *,
    event_id: str,
    kind: str,
    target_iss: str,
    sub: str | None = None,
    sid: str | None = None,
    cutoff_generation: int | None = None,
    event_iss: str,
    ttl: int = LOGOUT_TTL_SECONDS,
    now: int | None = None,
) -> dict[str, Any]:
    issuer = config.logout_issuer(event_iss)
    if issuer is None:
        raise ValueError(f"logout issuer {event_iss!r} is not configured")
    issued_at = int(now if now is not None else time.time())
    claims: dict[str, Any] = {
        "v": 1,
        "event_id": event_id,
        "iss": event_iss,
        "type": kind,
        "target_iss": target_iss,
        "iat": issued_at,
        "exp": issued_at + ttl,
    }
    if kind == "sid":
        if not sid or sub is None:
            raise ValueError("sid logout needs sid and sub")
        claims["sid"] = sid
        claims["sub"] = sub
    elif kind == "range":
        if cutoff_generation is None or sub is None:
            raise ValueError("range logout needs cutoff_generation and sub")
        if cutoff_generation < 0:
            raise ValueError("cutoff_generation must be >= 0")
        claims["cutoff_generation"] = cutoff_generation
        claims["sub"] = sub
    else:
        raise ValueError(f"unknown logout kind {kind!r}")
    return {"logout": encode_token(claims, issuer.key), "claims": claims}


def post_json(url: str, payload: Any, *, timeout: float = 15.0) -> tuple[int, Any]:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            parsed = {"raw": raw.decode("utf-8", "replace")}
        return exc.code, parsed


def get_json(url: str, *, timeout: float = 15.0) -> tuple[int, Any]:
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            parsed = {"raw": raw.decode("utf-8", "replace")}
        return exc.code, parsed


class IdPHandler(BaseHTTPRequestHandler):
    server: "IdPServer"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        if self.server.verbose:
            sys.stderr.write(f"[idp] {fmt % args}\n")

    def _respond(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 64 * 1024:
            raise ValueError("invalid body length")
        doc = loads_strict(self.rfile.read(length))
        if not isinstance(doc, dict):
            raise ValueError("body must be an object")
        return doc

    def do_GET(self) -> None:
        if self.path == "/idp/health":
            self._respond(200, {"ok": True, "pid": os.getpid()})
            return
        if self.path == "/idp/config":
            self._respond(200, self.server.config.describe())
            return
        self._respond(404, {"error": "not_found"})

    def do_POST(self) -> None:
        try:
            doc = self._body()
        except ValueError as exc:
            self._respond(400, {"error": "bad_request", "detail": str(exc)})
            return
        try:
            if self.path == "/idp/login":
                result = mint_login_ticket(
                    self.server.config,
                    self.server.state,
                    iss=doc["iss"],
                    sub=doc["sub"],
                    sid=doc.get("sid"),
                    generation=doc.get("generation"),
                    ttl=int(doc.get("ttl", LOGIN_TTL_SECONDS)),
                )
                self._respond(200, result)
                return
            if self.path == "/idp/logout":
                result = mint_logout_event(
                    self.server.config,
                    event_id=doc["event_id"],
                    kind=doc["type"],
                    target_iss=doc["target_iss"],
                    sub=doc.get("sub"),
                    sid=doc.get("sid"),
                    cutoff_generation=doc.get("cutoff_generation"),
                    event_iss=doc.get("iss", "idp-logout"),
                )
                self._respond(200, result)
                return
            if self.path == "/idp/adopt":
                record_existing_login(
                    self.server.state,
                    iss=doc["iss"],
                    sub=doc["sub"],
                    sid=doc["sid"],
                    generation=int(doc["generation"]),
                )
                self._respond(200, {"ok": True})
                return
        except (KeyError, ValueError, TypeError) as exc:
            self._respond(400, {"error": "bad_request", "detail": str(exc)})
            return
        self._respond(404, {"error": "not_found"})


class IdPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], *, config: Config, state: IdPState, verbose: bool) -> None:
        super().__init__(address, IdPHandler)
        self.config = config
        self.state = state
        self.verbose = verbose


def serve_idp(
    config: Config, state_path: str, host: str, port: int, *, verbose: bool = False, ready_file: str | None = None
) -> None:
    server = IdPServer(
        (host, port), config=config, state=IdPState(state_path), verbose=verbose
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
