"""In-process test harness: real child processes + real HTTP only.

The harness never imports the RP's HTTP handlers.  It starts servers with
``subprocess.Popen`` and talks to them with ``urllib``.  Process deaths use a
hook consumed *inside* the server, so the death is the server process really
calling ``os._exit``.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
PYTHON = sys.executable


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def http_json(
    method: str,
    url: str,
    payload: Any | None = None,
    *,
    timeout: float = 20.0,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any]:
    body = None
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return exc.code, {"raw": raw.decode("utf-8", "replace")}


def http_raw(
    url: str,
    body: bytes,
    *,
    timeout: float = 20.0,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any]:
    """POST an exact byte body (used to smuggle duplicate JSON members)."""

    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    request = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return exc.code, {"raw": raw.decode("utf-8", "replace")}


def wait_ready(path: Path, timeout: float = 20.0, proc: subprocess.Popen | None = None) -> dict[str, Any]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None and not path.exists():
            raise RuntimeError(f"process exited early with {proc.returncode}")
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        time.sleep(0.02)
    raise TimeoutError(f"server did not become ready: {path}")


@dataclass
class Service:
    name: str
    url: str
    port: int
    proc: subprocess.Popen
    ready_file: Path
    log_path: Path

    def stop(self) -> int | None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
        return self.proc.returncode

    def alive(self) -> bool:
        return self.proc.poll() is None


class Cluster:
    """One temp dir, N RP child processes, one IdP child process."""

    def __init__(self, *, rp_count: int = 4, base_dir: Path | None = None) -> None:
        self.dir = Path(
            tempfile.mkdtemp(prefix="ssotest-", dir=str(base_dir))
            if base_dir
            else tempfile.mkdtemp(prefix="ssotest-")
        ).resolve()
        self.db_path = self.dir / "rp.db"
        self.config_path = self.dir / "config.json"
        self.config = self._make_config()
        self.config_path.write_text(json.dumps(self.config, indent=2), encoding="utf-8")
        self.rps: list[Service] = []
        self.idp: Service | None = None
        self.idp_state = self.dir / "idp-state.json"
        self.rp_count = rp_count
        self.events: list[dict[str, Any]] = []

    # -- provisioning ----------------------------------------------------

    KEY_ALPHA = base64.urlsafe_b64encode(b"alpha-test-signing-key-0001").decode()
    KEY_BETA = base64.urlsafe_b64encode(b"beta-test-signing-key-0002").decode()
    KEY_OTHER = base64.urlsafe_b64encode(b"other-test-signing-key-03").decode()
    KEY_LOGOUT_A = base64.urlsafe_b64encode(b"alpha-test-logout-key-001").decode()
    KEY_LOGOUT_B = base64.urlsafe_b64encode(b"beta-test-logout-key-002").decode()

    ISS_A = "https://idp-alpha.test"
    ISS_B = "https://idp-beta.test"
    ISS_OTHER = "https://idp-other.test"
    LOGOUT_A = "alpha-logout"
    LOGOUT_B = "beta-logout"
    AUDIENCE = "rp-test"

    def _make_config(self) -> dict[str, Any]:
        return {
            "audience": self.AUDIENCE,
            "clock_skew_seconds": 0,
            "issuers": {
                self.ISS_A: {
                    "key": f"b64:{self.KEY_ALPHA}",
                    "subjects": ["alice", "bob"],
                },
                self.ISS_B: {
                    "key": f"b64:{self.KEY_BETA}",
                    "subjects": ["alice", "bob"],
                },
            },
            "logout_issuers": {
                self.LOGOUT_A: f"b64:{self.KEY_LOGOUT_A}",
                self.LOGOUT_B: f"b64:{self.KEY_LOGOUT_B}",
            },
        }

    # -- process control -------------------------------------------------

    def _run(self, args: list[str], name: str) -> tuple[subprocess.Popen, Path, Path]:
        ready = self.dir / f"{name}.ready.json"
        if ready.exists():
            ready.unlink()
        log = self.dir / f"{name}.log"
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO)
        env["PYTHONUNBUFFERED"] = "1"
        handle = open(log, "ab")
        proc = subprocess.Popen(
            [a.replace("{ready}", str(ready)) for a in args],
            cwd=str(REPO),
            env=env,
            stdout=handle,
            stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        return proc, ready, log

    def init_db(self) -> None:
        result = subprocess.run(
            [PYTHON, "-m", "sso_local", "init", "--db", str(self.db_path)],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(REPO)},
        )
        if result.returncode != 0:
            raise RuntimeError(f"init failed: {result.stderr}")

    def start_idp(self) -> Service:
        port = free_port()
        proc, ready, log = self._run(
            [
                PYTHON,
                "-m",
                "sso_local",
                "idp",
                "--config",
                str(self.config_path),
                "--state",
                str(self.idp_state),
                "--port",
                str(port),
                "--ready-file",
                "{ready}",
            ],
            "idp",
        )
        info = wait_ready(ready, proc=proc)
        self.idp = Service("idp", f"http://127.0.0.1:{info['port']}", info["port"], proc, ready, log)
        return self.idp

    def start_rp(self, index: int | None = None) -> Service:
        index = index if index is not None else len(self.rps) + len(
            [r for r in self.rps if not r.alive()]
        )
        name = f"rp{index}"
        port = free_port()
        proc, ready, log = self._run(
            [
                PYTHON,
                "-m",
                "sso_local",
                "rp",
                "--db",
                str(self.db_path),
                "--config",
                str(self.config_path),
                "--port",
                str(port),
                "--ready-file",
                "{ready}",
            ],
            name,
        )
        info = wait_ready(ready, proc=proc)
        service = Service(name, f"http://127.0.0.1:{info['port']}", info["port"], proc, ready, log)
        self.rps.append(service)
        return service

    def start(self) -> "Cluster":
        self.init_db()
        self.start_idp()
        for i in range(self.rp_count):
            self.start_rp(i)
        return self

    def restart_rp(self, service: Service) -> Service:
        """Restart a dead RP on a fresh free port under the same name."""

        service.stop()
        self.rps = [r for r in self.rps if r is not service]
        return self.start_rp(int(service.name.removeprefix("rp")))

    def stop_all(self) -> None:
        for service in list(self.rps):
            service.stop()
        if self.idp is not None:
            self.idp.stop()

    def cleanup(self) -> None:
        self.stop_all()
        shutil.rmtree(self.dir, ignore_errors=True)

    # -- IdP helpers -----------------------------------------------------

    def _idp_post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        assert self.idp is not None
        status, body = http_json("POST", f"{self.idp.url}{path}", payload)
        if status != 200:
            raise RuntimeError(f"idp {path} failed: {status} {body}")
        return body

    def ticket(self, *, iss: str, sub: str, sid: str | None = None, generation: int | None = None, ttl: int = 3600) -> dict[str, Any]:
        payload: dict[str, Any] = {"iss": iss, "sub": sub, "ttl": ttl}
        if sid is not None:
            payload["sid"] = sid
        if generation is not None:
            payload["generation"] = generation
        return self._idp_post("/idp/login", payload)

    def adopt(self, *, iss: str, sub: str, sid: str, generation: int) -> None:
        self._idp_post("/idp/adopt", {"iss": iss, "sub": sub, "sid": sid, "generation": generation})

    def logout_event(
        self,
        *,
        event_id: str,
        kind: str,
        target_iss: str,
        sub: str | None = None,
        sid: str | None = None,
        cutoff: int | None = None,
        event_iss: str = LOGOUT_A,
        ttl: int = 24 * 3600,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "event_id": event_id,
            "type": kind,
            "target_iss": target_iss,
            "iss": event_iss,
            "ttl": ttl,
        }
        if sub is not None:
            payload["sub"] = sub
        if sid is not None:
            payload["sid"] = sid
        if cutoff is not None:
            payload["cutoff_generation"] = cutoff
        body = self._idp_post("/idp/logout", payload)
        self.events.append(body["claims"])
        return body

    # -- RP helpers ------------------------------------------------------

    def rp(self, index: int = 0) -> Service:
        return self.rps[index]

    def login(self, ticket: str, rp: Service | None = None) -> tuple[int, Any]:
        service = rp or self.rps[0]
        return http_json("POST", f"{service.url}/v1/login", {"ticket": ticket})

    def send_logout(self, token: str, rp: Service | None = None) -> tuple[int, Any]:
        service = rp or self.rps[0]
        return http_json("POST", f"{service.url}/v1/logout/events", {"logout": token})

    def check(self, session_id: str, rp: Service | None = None) -> tuple[int, Any]:
        service = rp or self.rps[0]
        return http_json(
            "GET",
            f"{service.url}/v1/authcheck",
            headers={"Authorization": f"Bearer {session_id}"},
        )

    def admin_state(self, rp: Service | None = None) -> dict[str, Any]:
        service = rp or self.rps[0]
        status, body = http_json("GET", f"{service.url}/admin/state")
        if status != 200:
            raise RuntimeError(f"admin state failed: {status} {body}")
        return body

    def hook(self, phase: str, *, port: int = 0, mode: str = "sleep", millis: int = 0) -> int:
        service = self.rps[0]
        status, body = http_json(
            "POST",
            f"{service.url}/admin/hooks",
            {"phase": phase, "port": port, "mode": mode, "millis": millis},
        )
        if status != 201:
            raise RuntimeError(f"hook failed: {status} {body}")
        return int(body["hook_id"])

    def usable(self, rp: Service | None = None) -> set[str]:
        from sso_local.state import rp_usable_set

        state = self.admin_state(rp)
        return rp_usable_set(state, now=time.time())

    def wait_until(self, predicate, timeout: float = 15.0, interval: float = 0.02) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return True
            time.sleep(interval)
        return False
