"""State snapshot, provisioning and reference-state comparison helpers.

The *reference state machine* is independent of the RP's SQL text: it replays
the same events from scratch in pure Python and answers "which (iss, sid) are
currently usable?"  Tests compare RP output against it, and operators can run
``compare`` against a live database.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from . import db


@dataclass
class ReferenceState:
    """Pure-Python model of the agreed protocol (no arrival-time inputs)."""

    started_at: float = 0.0
    watermark: dict[tuple[str, str], int] = field(default_factory=dict)
    killed_sids: list[dict[str, Any]] = field(default_factory=list)
    logins: list[dict[str, Any]] = field(default_factory=list)

    def apply_logout(
        self,
        *,
        kind: str,
        iss: str,
        sub: str,
        sid: str | None = None,
        cutoff: int | None = None,
    ) -> None:
        if kind == "sid":
            assert sid
            self.killed_sids.append({"iss": iss, "sub": sub, "sid": sid})
            return
        assert kind == "range" and cutoff is not None
        self.watermark[(iss, sub)] = max(self.watermark.get((iss, sub), 0), cutoff)

    def add_login(
        self, *, iss: str, sub: str, sid: str, generation: int, expires_at: float
    ) -> None:
        self.logins.append(
            {
                "iss": iss,
                "sub": sub,
                "sid": sid,
                "generation": generation,
                "expires_at": expires_at,
            }
        )

    def usable(self) -> dict[str, dict[str, Any]]:
        """Map ``iss|sid`` -> login record for currently-usable sessions."""

        out: dict[str, dict[str, Any]] = {}
        killed = {(k["iss"], k["sid"]) for k in self.killed_sids}
        for login in self.logins:
            if (login["iss"], login["sid"]) in killed:
                continue
            if login["generation"] <= self.watermark.get(
                (login["iss"], login["sub"]), 0
            ):
                continue
            if login["expires_at"] <= self.started_at:
                continue
            out[f"{login['iss']}|{login['sid']}"] = login
        return out


def reference_usable(events: Iterable[dict[str, Any]], logins: Iterable[dict[str, Any]]) -> set[str]:
    """Convenience: build a reference model and return its usable sid set.

    Event dicts use the wire claim shape.  Ordering of the input does not
    matter: the watermark is a max and sid kills are a set.
    """

    state = ReferenceState()
    for login in logins:
        state.add_login(
            iss=login["iss"],
            sub=login["sub"],
            sid=login["sid"],
            generation=login["generation"],
            expires_at=float(login["expires_at"]),
        )
    for ev in events:
        if ev["type"] == "sid":
            state.apply_logout(
                kind="sid", iss=ev["target_iss"], sub=ev["sub"], sid=ev["sid"]
            )
        else:
            state.apply_logout(
                kind="range",
                iss=ev["target_iss"],
                sub=ev["sub"],
                cutoff=ev["cutoff_generation"],
            )
    return set(state.usable())


def rp_usable_set(dump: dict[str, Any], *, now: float) -> set[str]:
    """Usable set from an RP ``/admin/state`` dump, honoring expiry.

    "Usable" is derived from the durable facts only (session row + watermark +
    sid kill + expiry), so an RP bug that mislabels a session as usable cannot
    make this comparison pass by accident.
    """

    usable: set[str] = set()
    watermark = {(s["iss"], s["sub"]): s["cutoff_generation"] for s in dump["subjects"]}
    killed = {(k["iss"], k["sid"]) for k in dump["sid_revocations"]}
    for s in dump["sessions"]:
        if s.get("revoked"):
            continue
        if (s["iss"], s["sid"]) in killed:
            continue
        if s["generation"] <= watermark.get((s["iss"], s["sub"]), 0):
            continue
        if s["expires_at"] <= now:
            continue
        usable.add(f"{s['iss']}|{s['sid']}")
    return usable


def provision_issuer_key(db_path: str, iss: str, key_id: str) -> None:
    conn = db.connect(db_path)
    try:
        with db.immediate(conn):
            conn.execute(
                "INSERT INTO issuer_keys(iss, key_id) VALUES(?,?) "
                "ON CONFLICT(iss) DO UPDATE SET key_id = excluded.key_id",
                (iss, key_id),
            )
    finally:
        conn.close()


def export_state(db_path: str) -> dict[str, Any]:
    """Plain-SQL export, independent of :class:`sso_local.store.Store`."""

    conn = db.connect(db_path)
    try:
        with db.deferred(conn):
            sessions = [
                dict(r)
                for r in conn.execute(
                    "SELECT session_id, iss, sub, sid, generation, aud, created_at, "
                    "expires_at, revoked, revoked_at, revoked_by, revoke_kind "
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
                    "SELECT event_id, event_iss, body_sha256, applied, first_seen "
                    "FROM seen_events ORDER BY event_id"
                )
            ]
            epoch_row = conn.execute(
                "SELECT value FROM meta WHERE key = 'revocation_epoch'"
            ).fetchone()
        return {
            "epoch": int(epoch_row["value"]) if epoch_row else 0,
            "sessions": sessions,
            "subjects": subjects,
            "sid_revocations": sids,
            "events": events,
        }
    finally:
        conn.close()


def summarize_state(state: dict[str, Any], *, now: float) -> dict[str, Any]:
    watermark = {(s["iss"], s["sub"]): s["cutoff_generation"] for s in state["subjects"]}
    killed = {(k["iss"], k["sid"]) for k in state["sid_revocations"]}
    usable = rp_usable_set(state, now=now)
    return {
        "epoch": state["epoch"],
        "usable": sorted(usable),
        "watermarks": {
            f"{iss}|{sub}": cutoff for (iss, sub), cutoff in sorted(watermark.items())
        },
        "killed_sids": sorted(f"{iss}|{sid}" for iss, sid in killed),
        "pending_events": sorted(
            e["event_id"] for e in state["events"] if not e["applied"]
        ),
        "counts": {
            "sessions": len(state["sessions"]),
            "events": len(state["events"]),
        },
    }


def dump_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, default=str)
