"""Transactional core: the only place that mutates or judges session state.

Consistency model
-----------------
Every state-changing operation (session creation, logout application) runs in
``BEGIN IMMEDIATE``.  SQLite grants at most one write transaction at a time, so
all RP processes observe one total order over:

    login-establish  <->  logout-apply

A read (protected-endpoint authentication) takes its snapshot with
``BEGIN`` (deferred) and therefore sees a prefix of that total order.

The two critical invariants this buys:

1. A login cannot insert a session that the revocation watermark already
   covers.  Its checks and its INSERT are in the same write transaction, so
   either the login commits first (and the later logout's UPDATE revokes the
   row) or the logout commits first (and the login's in-transaction check sees
   the watermark and refuses).
2. An acknowledgment for a logout event is only produced after the revocation
   transaction has committed.  The dedup record is committed *before* the
   revocation work, in a separate transaction, and carries ``applied=0``.  A
   crash in between leaves ``applied=0``; no 2xx was sent; redelivery resumes.

Revocation scope is decided purely from ticket generations, never from local
arrival time.
"""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from . import db
from .claims import LoginClaims, LogoutClaims
from .config import Config

# Hook phases (controllable synchronization points).
PHASE_LOGIN_BEFORE_BEGIN = "login.before_begin"
PHASE_LOGIN_BEFORE_INSERT = "login.before_insert"
PHASE_LOGIN_AFTER_COMMIT = "login.after_commit"
PHASE_LOGOUT_AFTER_DEDUP = "logout.after_dedup"
PHASE_LOGOUT_HOLD = "logout.hold"
PHASE_LOGOUT_AFTER_COMMIT = "logout.after_commit"
PHASE_AUTH_BEFORE_CHECK = "auth.before_check"
PHASE_AUTH_AFTER_READ = "auth.after_read"

HOOK_PHASES = frozenset(
    {
        PHASE_LOGIN_BEFORE_BEGIN,
        PHASE_LOGIN_BEFORE_INSERT,
        PHASE_LOGIN_AFTER_COMMIT,
        PHASE_LOGOUT_AFTER_DEDUP,
        PHASE_LOGOUT_HOLD,
        PHASE_LOGOUT_AFTER_COMMIT,
        PHASE_AUTH_BEFORE_CHECK,
        PHASE_AUTH_AFTER_READ,
    }
)
HOOK_MODES = frozenset({"die", "sleep"})
SELF_TERMINATE_CODE = 97

EPOCH_KEY = "revocation_epoch"
STATE_ACTIVE = "active"
STATE_REVOKED = "revoked"
STATE_EXPIRED = "expired"


class StoreError(Exception):
    status = 500
    code = "internal"

    def __init__(self, detail: str = "") -> None:
        super().__init__(detail or self.code)
        self.detail = detail

    def as_payload(self) -> dict[str, Any]:
        return {"error": self.code, "detail": self.detail}


class EventConflict(StoreError):
    status = 409
    code = "event_conflict"


class SessionRejected(StoreError):
    status = 409
    code = "session_revoked"


class SidReuseConflict(StoreError):
    """The issuer promised never to reuse a sid within one issuer."""

    status = 409
    code = "sid_reuse_conflict"


def _now() -> float:
    return time.time()


@dataclass
class AuthDecision:
    allowed: bool
    reason: str
    session: dict[str, Any] | None = None
    cache: str = "miss"

    def as_payload(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ok": self.allowed,
            "reason": self.reason,
            "cache": self.cache,
        }
        if self.session is not None:
            out.update(self.session)
        return out


@dataclass
class _CacheEntry:
    epoch: int
    allowed: bool
    reason: str
    session: dict[str, Any] | None
    stored_at: float


@dataclass
class Store:
    db_path: str
    config: Config
    port: int = 0
    cache_ttl: float = 30.0
    log_requests: bool = True
    _cache: dict[str, _CacheEntry] = field(default_factory=dict)
    stats: dict[str, int] = field(
        default_factory=lambda: {"cache_hits": 0, "cache_misses": 0, "grows": 0}
    )

    # -- plumbing ---------------------------------------------------------

    def _connect(self):
        return db.connect(self.db_path)

    def _epoch(self, conn) -> int:
        row = conn.execute(
            "SELECT value FROM meta WHERE key = ?", (EPOCH_KEY,)
        ).fetchone()
        return int(row["value"]) if row else 0

    def _bump_epoch(self, conn) -> None:
        conn.execute(
            "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) "
            "WHERE key = ?",
            (EPOCH_KEY,),
        )

    def epoch(self) -> int:
        conn = self._connect()
        try:
            return self._epoch(conn)
        finally:
            conn.close()

    def _take_hook(self, conn, phase: str) -> None:
        """Consume at most one hook for this phase, atomically, then act.

        ``DELETE ... RETURNING`` is a single statement, so two processes can
        never consume the same hook.  ``die`` is an abrupt ``os._exit``: no
        finally blocks, no flush, no interpreter shutdown.  SQLite recovers
        the WAL on the next open, which is the point of the exercise.
        """

        row = conn.execute(
            "DELETE FROM hooks WHERE id = ("
            "  SELECT id FROM hooks WHERE phase = ?"
            "    AND (port = 0 OR port = ?)"
            "  ORDER BY id LIMIT 1"
            ") RETURNING id, mode, millis",
            (phase, self.port),
        ).fetchone()
        if row is None:
            return
        self._act_hook(row["mode"], row["millis"])

    @staticmethod
    def _act_hook(mode: str, millis: int) -> None:
        if mode == "die":
            os._exit(SELF_TERMINATE_CODE)
        if mode == "sleep":
            time.sleep(max(0, int(millis)) / 1000.0)

    def _take_hook_side_connection(self, phase: str) -> None:
        """Consume a hook on its own connection.

        Used for stop points that must fire *while the caller holds a read
        transaction*.  In WAL mode a writer on another connection does not
        block our reader, so the snapshot stays pinned for the duration.
        """

        conn = self._connect()
        try:
            row = conn.execute(
                "DELETE FROM hooks WHERE id = ("
                "  SELECT id FROM hooks WHERE phase = ?"
                "    AND (port = 0 OR port = ?)"
                "  ORDER BY id LIMIT 1"
                ") RETURNING id, mode, millis",
                (phase, self.port),
            ).fetchone()
        finally:
            conn.close()
        if row is not None:
            self._act_hook(row["mode"], row["millis"])

    def _log(self, conn, kind: str, detail: str, decision: str) -> None:
        if not self.log_requests:
            return
        conn.execute(
            "INSERT INTO request_log(at, kind, detail, decision) VALUES(?,?,?,?)",
            (_now(), kind, detail[:500], decision[:200]),
        )

    # -- logout reception -------------------------------------------------

    def receive_logout(self, event: LogoutClaims) -> dict[str, Any]:
        """Apply a logout event.  Returns a payload only after it is applied."""

        conn = self._connect()
        try:
            outcome = self._dedup_phase(conn, event)
            if outcome == "duplicate":
                return self._logout_payload(conn, event, status="duplicate")

            self._take_hook(conn, PHASE_LOGOUT_AFTER_DEDUP)

            applied = self._apply_phase(conn, event)
            self._take_hook(conn, PHASE_LOGOUT_AFTER_COMMIT)
            # If a concurrent delivery applied it first, this one is a
            # duplicate even though it took the "resume" path.
            return self._logout_payload(
                conn, event, status="applied" if applied else "duplicate"
            )
        finally:
            conn.close()

    def _dedup_phase(self, conn, event: LogoutClaims) -> str:
        """Durably record the event id, or detect a replay/conflict.

        This transaction commits *before* anything is revoked, which is exactly
        what makes the crash point ``logout.after_dedup`` recoverable: the
        record is on disk with applied=0, no success was reported, and the
        next delivery re-enters ``_apply_phase``.
        """

        with db.immediate(conn):
            row = conn.execute(
                "SELECT body_sha256, event_iss, applied FROM seen_events WHERE event_id = ?",
                (event.event_id,),
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO seen_events(event_id, event_iss, body_sha256, "
                    "body_json, first_seen, applied) VALUES(?,?,?,?,?,0)",
                    (
                        event.event_id,
                        event.event_iss,
                        event.digest,
                        "",
                        _now(),
                    ),
                )
                return "new"
            if row["body_sha256"] != event.digest or row["event_iss"] != event.event_iss:
                # Same event id, different content.  Never apply either body;
                # the operator has to resolve the identifier collision.
                raise EventConflict(
                    f"event_id {event.event_id} was already seen with different content"
                )
            return "resume" if not row["applied"] else "duplicate"

    def _apply_phase(self, conn, event: LogoutClaims) -> bool:
        """Apply the revocation.  Returns False if a peer already applied it."""

        with db.immediate(conn):
            self._take_hook(conn, PHASE_LOGOUT_HOLD)
            row = conn.execute(
                "SELECT applied FROM seen_events WHERE event_id = ?", (event.event_id,)
            ).fetchone()
            if row is None:
                raise StoreError("event row vanished")
            if row["applied"]:
                # Another process applied it between the two transactions.
                return False
            if event.kind == "sid":
                self._revoke_sid(conn, event)
            else:
                self._revoke_range(conn, event)
            conn.execute(
                "UPDATE seen_events SET applied = 1 WHERE event_id = ?",
                (event.event_id,),
            )
            self._bump_epoch(conn)
            self._log(
                conn,
                "logout",
                f"{event.event_id} kind={event.kind} target={event.iss}/{event.sub}",
                "applied",
            )
            return True

    def _revoke_sid(self, conn, event: LogoutClaims) -> None:
        conn.execute(
            "INSERT INTO sid_revocations(iss, sid, generation, reason_event, revoked_at) "
            "VALUES(?,?,NULL,?,?) ON CONFLICT(iss, sid) DO NOTHING",
            (event.iss, event.sid, event.event_id, _now()),
        )
        conn.execute(
            "UPDATE sessions SET revoked = 1, revoked_at = ?, revoked_by = ?, "
            "revoke_kind = 'sid' WHERE iss = ? AND sid = ? AND revoked = 0",
            (_now(), event.event_id, event.iss, event.sid),
        )

    def _revoke_range(self, conn, event: LogoutClaims) -> None:
        cutoff = event.cutoff_generation or 0
        row = conn.execute(
            "SELECT cutoff_generation FROM subjects WHERE iss = ? AND sub = ?",
            (event.iss, event.sub),
        ).fetchone()
        current = int(row["cutoff_generation"]) if row else 0
        # Watermarks only ever move forward.
        effective = max(current, cutoff)
        if row is None:
            conn.execute(
                "INSERT INTO subjects(iss, sub, cutoff_generation, updated_at) "
                "VALUES(?,?,?,?)",
                (event.iss, event.sub, effective, _now()),
            )
        elif effective != current:
            conn.execute(
                "UPDATE subjects SET cutoff_generation = ?, updated_at = ? "
                "WHERE iss = ? AND sub = ?",
                (effective, _now(), event.iss, event.sub),
            )
        # Revoke against the effective watermark, not this event's cutoff, so a
        # late, lower-cutoff notification can never leave a gap.
        conn.execute(
            "UPDATE sessions SET revoked = 1, revoked_at = ?, revoked_by = ?, "
            "revoke_kind = 'range' WHERE iss = ? AND sub = ? "
            "AND generation <= ? AND revoked = 0",
            (_now(), event.event_id, event.iss, event.sub, effective),
        )

    def _logout_payload(self, conn, event: LogoutClaims, *, status: str) -> dict[str, Any]:
        watermark = None
        if event.kind == "range":
            row = conn.execute(
                "SELECT cutoff_generation FROM subjects WHERE iss = ? AND sub = ?",
                (event.iss, event.sub),
            ).fetchone()
            watermark = int(row["cutoff_generation"]) if row else 0
        sid_row = None
        if event.kind == "sid":
            sid_row = conn.execute(
                "SELECT 1 FROM sid_revocations WHERE iss = ? AND sid = ?",
                (event.iss, event.sid),
            ).fetchone()
        return {
            "event_id": event.event_id,
            "status": status,
            "kind": event.kind,
            "target": {"iss": event.iss, "sub": event.sub},
            "sid": event.sid,
            "cutoff_generation": event.cutoff_generation,
            "watermark": watermark,
            "sid_recorded": sid_row is not None,
            "epoch": self._epoch(conn),
        }

    # -- login / session creation ----------------------------------------

    def login(self, ticket: LoginClaims) -> tuple[int, dict[str, Any]]:
        conn = self._connect()
        try:
            self._take_hook(conn, PHASE_LOGIN_BEFORE_BEGIN)
            with db.immediate(conn):
                self._take_hook(conn, PHASE_LOGIN_BEFORE_INSERT)
                status, payload = self._login_locked(conn, ticket)
                self._log(
                    conn,
                    "login",
                    f"{ticket.iss}/{ticket.sub} sid={ticket.sid} gen={ticket.generation}",
                    payload.get("state", "?"),
                )
                # The auth-cache epoch bump is the *only* shared-state signal a
                # read-only authentication can observe.  New sessions do not
                # need it (a cache miss re-reads the DB), but a re-login that
                # un-revokes nothing still never resurrects anything.
            self._take_hook(conn, PHASE_LOGIN_AFTER_COMMIT)
            return status, payload
        finally:
            conn.close()

    def _login_locked(self, conn, ticket: LoginClaims) -> tuple[int, dict[str, Any]]:
        existing = conn.execute(
            "SELECT * FROM sessions WHERE iss = ? AND sid = ?",
            (ticket.iss, ticket.sid),
        ).fetchone()
        if existing is not None:
            if (
                existing["sub"] != ticket.sub
                or existing["generation"] != ticket.generation
            ):
                # The issuer promised never to reuse a sid.  Two different
                # tickets under one sid is an issuer bug or a forgery attempt;
                # never mutate the stored session.
                raise SidReuseConflict(
                    "sid already bound to a different sub/generation"
                )
            state = self._session_state(conn, existing, now=_now())
            payload = self._session_payload(existing, state)
            payload["idempotent"] = True
            return (200 if state == STATE_ACTIVE else 409), payload

        state, reason, by = True, "", ""
        sid_row = conn.execute(
            "SELECT reason_event FROM sid_revocations WHERE iss = ? AND sid = ?",
            (ticket.iss, ticket.sid),
        ).fetchone()
        if sid_row is not None:
            state, reason, by = False, "sid_revoked", sid_row["reason_event"]

        wm_row = conn.execute(
            "SELECT cutoff_generation FROM subjects WHERE iss = ? AND sub = ?",
            (ticket.iss, ticket.sub),
        ).fetchone()
        watermark = int(wm_row["cutoff_generation"]) if wm_row else 0
        if ticket.generation <= watermark:
            state, reason, by = False, "watermark_covered", f"watermark={watermark}"

        session_id = secrets.token_hex(16)
        expires_at = min(float(ticket.exp), _now() + 7 * 24 * 3600)
        conn.execute(
            "INSERT INTO sessions(session_id, iss, sub, sid, generation, aud, "
            "created_at, expires_at, revoked, revoked_at, revoked_by, revoke_kind) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                session_id,
                ticket.iss,
                ticket.sub,
                ticket.sid,
                ticket.generation,
                ticket.aud,
                _now(),
                expires_at,
                0 if state else 1,
                None if state else _now(),
                None if state else by,
                None if state else ("sid" if reason == "sid_revoked" else "watermark"),
            ),
        )
        row = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        payload = self._session_payload(row, STATE_ACTIVE if state else STATE_REVOKED)
        payload["idempotent"] = False
        if not state:
            payload["reason"] = reason
            payload["watermark"] = watermark
            return 409, payload
        return 200, payload

    def _session_state(self, conn, row, *, now: float) -> str:
        if row["revoked"]:
            return STATE_REVOKED
        if now >= row["expires_at"]:
            return STATE_EXPIRED
        return STATE_ACTIVE

    @staticmethod
    def _session_payload(row, state: str) -> dict[str, Any]:
        return {
            "session_id": row["session_id"],
            "iss": row["iss"],
            "sub": row["sub"],
            "sid": row["sid"],
            "generation": row["generation"],
            "state": state,
            "usable": state == STATE_ACTIVE,
            "expires_at": row["expires_at"],
            "revoked_at": row["revoked_at"],
            "revoked_by": row["revoked_by"],
            "revoke_kind": row["revoke_kind"],
        }

    # -- protected-endpoint authentication --------------------------------

    def authenticate(self, session_id: str) -> AuthDecision:
        if not isinstance(session_id, str) or not session_id:
            return AuthDecision(False, "missing_session_id")
        if len(session_id) > 128:
            return AuthDecision(False, "malformed_session_id")

        conn = self._connect()
        try:
            self._take_hook(conn, PHASE_AUTH_BEFORE_CHECK)

            # Linearization point for the cache.  A logout's acknowledgment is
            # sent only after its epoch bump committed, so any authentication
            # that *starts* after the logout response reads the bumped epoch
            # and cannot be served from a pre-logout cache entry.
            epoch = self._epoch(conn)
            cached = self._cache.get(session_id)
            if cached is not None:
                fresh = time.monotonic() - cached.stored_at <= self.cache_ttl
                if cached.epoch == epoch and fresh and self._cache_still_valid(cached):
                    self.stats["cache_hits"] += 1
                    return AuthDecision(
                        cached.allowed, cached.reason, cached.session, cache="hit"
                    )
            self.stats["cache_misses"] += 1
            self._cache.pop(session_id, None)

            with db.deferred(conn):
                epoch = self._epoch(conn)
                row = conn.execute(
                    "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
                ).fetchone()
                decision = self._decide(conn, row, now=_now())
                if decision.allowed:
                    self._cache[session_id] = _CacheEntry(
                        epoch=epoch,
                        allowed=True,
                        reason=decision.reason,
                        session=decision.session,
                        stored_at=time.monotonic(),
                    )
                decision.cache = "miss"
                # Must run on a side connection: this reader holds a snapshot
                # and the hook write needs the write lock.
                self._take_hook_side_connection(PHASE_AUTH_AFTER_READ)
                return decision
        finally:
            conn.close()

    @staticmethod
    def _cache_still_valid(entry: "_CacheEntry") -> bool:
        """Wall-clock expiry is not covered by the epoch; check it separately."""

        session = entry.session
        return bool(session) and float(session["expires_at"]) > _now()

    def _decide(self, conn, row, *, now: float) -> AuthDecision:
        if row is None:
            return AuthDecision(False, "unknown_session")
        if row["revoked"]:
            return AuthDecision(
                False,
                f"revoked:{row['revoke_kind'] or 'unknown'}",
                self._session_payload(row, STATE_REVOKED),
            )
        if now >= row["expires_at"]:
            return AuthDecision(
                False, "expired", self._session_payload(row, STATE_EXPIRED)
            )
        # Defense in depth: even if a revocation somehow missed the row, the
        # durable watermark and the per-sid record are authoritative.
        sid_row = conn.execute(
            "SELECT 1 FROM sid_revocations WHERE iss = ? AND sid = ?",
            (row["iss"], row["sid"]),
        ).fetchone()
        if sid_row is not None:
            return AuthDecision(
                False,
                "revoked:sid",
                self._session_payload(row, STATE_REVOKED),
            )
        wm_row = conn.execute(
            "SELECT cutoff_generation FROM subjects WHERE iss = ? AND sub = ?",
            (row["iss"], row["sub"]),
        ).fetchone()
        watermark = int(wm_row["cutoff_generation"]) if wm_row else 0
        if row["generation"] <= watermark:
            return AuthDecision(
                False,
                "revoked:watermark",
                self._session_payload(row, STATE_REVOKED),
            )
        return AuthDecision(True, "ok", self._session_payload(row, STATE_ACTIVE))

    # -- admin / status ---------------------------------------------------

    def dump(self) -> dict[str, Any]:
        conn = self._connect()
        try:
            with db.deferred(conn):
                sessions = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT session_id, iss, sub, sid, generation, aud, "
                        "created_at, expires_at, revoked, revoked_by, revoke_kind "
                        "FROM sessions ORDER BY iss, sub, generation, sid"
                    )
                ]
                subjects = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT iss, sub, cutoff_generation, updated_at FROM subjects "
                        "ORDER BY iss, sub"
                    )
                ]
                sids = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT iss, sid, reason_event, revoked_at FROM sid_revocations "
                        "ORDER BY iss, sid"
                    )
                ]
                events = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT event_id, event_iss, body_sha256, first_seen, applied "
                        "FROM seen_events ORDER BY first_seen, event_id"
                    )
                ]
                hooks = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT id, phase, port, mode, millis FROM hooks ORDER BY id"
                    )
                ]
                epoch = self._epoch(conn)
            active = sum(1 for s in sessions if not s["revoked"])
            return {
                "epoch": epoch,
                "sessions": sessions,
                "subjects": subjects,
                "sid_revocations": sids,
                "events": events,
                "hooks": hooks,
                "counts": {
                    "sessions": len(sessions),
                    "active": active,
                    "revoked": len(sessions) - active,
                    "events": len(events),
                    "events_pending": sum(1 for e in events if not e["applied"]),
                },
            }
        finally:
            conn.close()

    def process_stats(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "cache": dict(self.stats),
            "cached_entries": len(self._cache),
            "epoch_seen": self.epoch(),
        }


# -- CLI-side helpers (no Server involved) --------------------------------


def add_hook(
    db_path: str, phase: str, *, port: int = 0, mode: str = "sleep", millis: int = 0
) -> int:
    if phase not in HOOK_PHASES:
        raise ValueError(f"unknown phase {phase!r}; known: {sorted(HOOK_PHASES)}")
    if mode not in HOOK_MODES:
        raise ValueError(f"unknown mode {mode!r}; known: {sorted(HOOK_MODES)}")
    conn = db.connect(db_path)
    try:
        with db.immediate(conn):
            cur = conn.execute(
                "INSERT INTO hooks(phase, port, mode, millis, created_at) "
                "VALUES(?,?,?,?,?)",
                (phase, port, mode, max(0, int(millis)), _now()),
            )
            return int(cur.lastrowid)
    finally:
        conn.close()


def clear_hooks(db_path: str) -> int:
    conn = db.connect(db_path)
    try:
        with db.immediate(conn):
            cur = conn.execute("DELETE FROM hooks")
            return int(cur.rowcount or 0)
    finally:
        conn.close()
