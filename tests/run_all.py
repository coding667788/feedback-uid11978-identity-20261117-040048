"""End-to-end protocol tests.  Real child processes, real HTTP, no shortcuts.

Run with::

    python -m tests.run_all            # everything
    python -m tests.run_all token      # only cases whose name contains "token"

Each test builds a fresh temp cluster (SQLite + IdP + 4 RP processes), so no
test can be rescued by another test's state.
"""

from __future__ import annotations

import base64
import copy
import json
import os
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Callable

from .harness import Cluster, http_json, http_raw

# -- helpers --------------------------------------------------------------


def make_ticket(
    cluster: Cluster,
    *,
    iss: str,
    sub: str,
    sid: str,
    generation: int,
    claims_patch: dict[str, Any] | None = None,
    drop: tuple[str, ...] = (),
    header_patch: dict[str, Any] | None = None,
    key: bytes | None = None,
    ttl: int = 3600,
    **extra: Any,
) -> str:
    """Mint a ticket with full control over the claim set / header.

    Bypasses the IdP HTTP endpoint on purpose: these are *attack* tickets and
    must not require the simulator's cooperation.  The signing key still comes
    from the same provisioned configuration.
    """

    from sso_local.tokens import encode_token, sign_hs256, b64url_encode

    claims: dict[str, Any] = {
        "iss": iss,
        "sub": sub,
        "sid": sid,
        "generation": generation,
        "aud": cluster.AUDIENCE,
        "exp": int(time.time()) + ttl,
    }
    claims.update(extra)
    if claims_patch:
        claims.update(claims_patch)
    for name in drop:
        claims.pop(name, None)
    signing_key = key if key is not None else default_login_key(cluster, iss)
    if header_patch is not None:
        header = {"alg": "HS256", "typ": "JWT", **header_patch}
        h = b64url_encode(json.dumps(header, sort_keys=True).encode())
        p = b64url_encode(json.dumps(claims, sort_keys=True).encode())
        sig = b64url_encode(sign_hs256(f"{h}.{p}".encode(), signing_key))
        return f"{h}.{p}.{sig}"
    return encode_token(claims, signing_key)


def default_login_key(cluster: Cluster, iss: str) -> bytes:
    mapping = {
        cluster.ISS_A: base64.urlsafe_b64decode(cluster.KEY_ALPHA + "=="),
        cluster.ISS_B: base64.urlsafe_b64decode(cluster.KEY_BETA + "=="),
    }
    return mapping[iss]


def session_of(body: dict[str, Any]) -> str:
    assert body and "session_id" in body, body
    return body["session_id"]


def login_ok(cluster: Cluster, ticket: str, rp=None) -> str:
    status, body = cluster.login(ticket, rp)
    assert status == 200, (status, body)
    return session_of(body)


def rejected(status: int, body: Any) -> bool:
    return status in (401, 409) and isinstance(body, dict) and "error" in body


# -- tests ----------------------------------------------------------------


def test_token_validation_matrix(cluster: Cluster) -> None:
    """Rejections the task names explicitly, plus adjacent type confusion."""

    iss = cluster.ISS_A
    good = make_ticket(cluster, iss=iss, sub="alice", sid="sess-1", generation=1)
    assert cluster.login(good)[0] == 200

    cases: list[tuple[str, str, dict[str, Any]]] = [
        (
            "unknown_issuer",
            make_ticket(
                cluster,
                iss="https://evil.test",
                sub="alice",
                sid="sess-evil",
                generation=1,
                key=b"not-configured-key",
            ),
            {"error": "unknown_issuer"},
        ),
        (
            "bad_signature",
            make_ticket(
                cluster,
                iss=iss,
                sub="alice",
                sid="sess-2",
                generation=1,
                key=b"wrong-key-entirely",
            ),
            {"error": "bad_signature"},
        ),
        (
            "bad_audience",
            make_ticket(
                cluster, iss=iss, sub="alice", sid="sess-3", generation=1, aud="other"
            ),
            {"error": "bad_audience"},
        ),
        (
            "unknown_subject",
            make_ticket(
                cluster, iss=iss, sub="mallory", sid="sess-4", generation=1
            ),
            {"error": "unknown_subject"},
        ),
        (
            "expired",
            make_ticket(
                cluster, iss=iss, sub="alice", sid="sess-5", generation=1, exp=int(time.time()) - 5
            ),
            {"error": "expired"},
        ),
        (
            "missing_generation",
            make_ticket(
                cluster,
                iss=iss,
                sub="alice",
                sid="sess-6",
                generation=1,
                drop=("generation",),
            ),
            {"error": "invalid_type"},
        ),
        (
            "string_generation",
            make_ticket(
                cluster,
                iss=iss,
                sub="alice",
                sid="sess-7",
                generation=1,
                claims_patch={"generation": "1"},
            ),
            {"error": "invalid_type"},
        ),
        (
            "bool_generation",
            make_ticket(
                cluster,
                iss=iss,
                sub="alice",
                sid="sess-8",
                generation=1,
                claims_patch={"generation": True},
            ),
            {"error": "invalid_type"},
        ),
        (
            "alg_none",
            make_ticket(
                cluster,
                iss=iss,
                sub="alice",
                sid="sess-9",
                generation=1,
                header_patch={"alg": "none"},
            ),
            {"error": "invalid_header"},
        ),
        (
            "alg_hs512",
            make_ticket(
                cluster,
                iss=iss,
                sub="alice",
                sid="sess-10",
                generation=1,
                header_patch={"alg": "HS512"},
            ),
            {"error": "invalid_header"},
        ),
        (
            "header_key_url",
            make_ticket(
                cluster,
                iss=iss,
                sub="alice",
                sid="sess-11",
                generation=1,
                header_patch={"jku": "https://evil.test/keys.json"},
            ),
            {"error": "invalid_header"},
        ),
        (
            "header_jwk",
            make_ticket(
                cluster,
                iss=iss,
                sub="alice",
                sid="sess-12",
                generation=1,
                header_patch={"jwk": {"kty": "oct", "k": "AAAA"}},
            ),
            {"error": "invalid_header"},
        ),
        (
            "header_kid",
            make_ticket(
                cluster,
                iss=iss,
                sub="alice",
                sid="sess-13",
                generation=1,
                header_patch={"kid": "attacker"},
            ),
            {"error": "invalid_header"},
        ),
        ("garbage", "not-a-token", {"error": "malformed_token"}),
        ("empty", "", {"error": "malformed_token"}),
    ]
    for name, ticket, expect in cases:
        status, body = cluster.login(ticket)
        assert rejected(status, body), f"{name}: expected rejection, got {status} {body}"
        assert body["error"] == expect["error"], f"{name}: {body} != {expect}"
        print(f"    {name}: {status} {body['error']}")

    # Valid ticket still works after all the noise.
    ok = make_ticket(cluster, iss=iss, sub="bob", sid="sess-ok", generation=1)
    assert cluster.login(ok)[0] == 200

    # Non-string / oversized inputs at the JSON layer.
    status, body = http_json("POST", f"{cluster.rp().url}/v1/login", {"ticket": 123})
    assert status == 400 and body["error"] == "bad_request", (status, body)
    status, body = http_json(
        "POST", f"{cluster.rp().url}/v1/login", {"ticket": "a." + "B" * 20000 + ".c"}
    )
    assert status == 401 and body["error"] == "token_too_large", (status, body)


def test_duplicate_json_members_rejected(cluster: Cluster) -> None:
    """Duplicate members must be rejected in tokens *and* in request bodies."""

    from sso_local.tokens import b64url_encode, sign_hs256

    iss = cluster.ISS_A
    key = default_login_key(cluster, iss)
    header = b64url_encode(b'{"alg":"HS256","typ":"JWT"}')
    now = int(time.time())

    # Build a payload with a duplicate "iss" member by hand.
    dup_payload = (
        '{"iss":"' + iss + '","sub":"alice","sid":"sess-dup","generation":1,'
        '"aud":"' + cluster.AUDIENCE + '","exp":' + str(now + 600) + ',"iss":"https://evil.test"}'
    ).encode()
    payload = b64url_encode(dup_payload)
    sig = b64url_encode(sign_hs256(f"{header}.{payload}".encode(), key))
    token = f"{header}.{payload}.{sig}"
    status, body = cluster.login(token)
    assert status == 401 and body["error"] == "invalid_json", (status, body)
    assert "duplicate" in body["detail"], body
    print(f"    duplicate iss member: {status} {body['error']}")

    # Duplicate member in the protected header.
    dup_header = b64url_encode(b'{"alg":"HS256","typ":"JWT","alg":"none"}')
    ok_payload = b64url_encode(
        json.dumps(
            {
                "iss": iss,
                "sub": "alice",
                "sid": "sess-hdr",
                "generation": 9,
                "aud": cluster.AUDIENCE,
                "exp": now + 600,
            }
        ).encode()
    )
    sig2 = b64url_encode(sign_hs256(f"{dup_header}.{ok_payload}".encode(), key))
    status, body = cluster.login(f"{dup_header}.{ok_payload}.{sig2}")
    assert status == 401 and body["error"] == "invalid_json", (status, body)
    print(f"    duplicate header member: {status} {body['error']}")

    # Duplicate member in a logout request body is the RP's own JSON boundary.
    # Sent as exact bytes: a Python dict cannot carry two identical keys.
    raw = ('{"logout":"%s","logout":"%s"}' % (token, token)).encode()
    status, body = http_raw(f"{cluster.rp().url}/v1/logout/events", raw)
    assert status == 400 and body["error"] == "bad_request", (status, body)
    assert "duplicate" in body["detail"], body
    print(f"    duplicate request member: {status} {body['error']}")


def test_logout_event_validation(cluster: Cluster) -> None:
    """Notification-side rejections: shape, signature, key source, expiry."""

    from sso_local.tokens import b64url_encode, encode_token

    logout_a = base64.urlsafe_b64decode(cluster.KEY_LOGOUT_A + "==")
    logout_b = base64.urlsafe_b64decode(cluster.KEY_LOGOUT_B + "==")
    now = int(time.time())

    def mint(claims: dict[str, Any], key: bytes, *, drop: tuple[str, ...] = ()) -> str:
        base = {
            "v": 1,
            "event_id": "shape-evt",
            "iss": cluster.LOGOUT_A,
            "type": "sid",
            "target_iss": cluster.ISS_A,
            "sub": "alice",
            "sid": "shape-sid",
            "exp": now + 600,
        }
        base.update(claims)
        for name in drop:
            base.pop(name, None)
        return encode_token(base, key)

    cases = [
        ("unknown_logout_issuer", mint({"iss": "rogue-logout"}, logout_a), "unknown_issuer"),
        ("wrong_logout_key", mint({}, logout_b), "bad_signature"),
        ("expired_event", mint({"exp": now - 10}, logout_a), "expired"),
        ("sid_with_cutoff", mint({"cutoff_generation": 3}, logout_a), "invalid_shape"),
        (
            "range_with_sid",
            mint({"type": "range", "cutoff_generation": 3}, logout_a),
            "invalid_shape",
        ),
        (
            "range_cutoff_string",
            mint(
                {"type": "range", "cutoff_generation": "3"}, logout_a, drop=("sid",)
            ),
            "invalid_type",
        ),
        (
            "range_cutoff_negative",
            mint(
                {"type": "range", "cutoff_generation": -1}, logout_a, drop=("sid",)
            ),
            "invalid_value",
        ),
        ("bad_version", mint({"v": 2}, logout_a), "invalid_version"),
        ("bad_type", mint({"type": "everything"}, logout_a), "invalid_value"),
        ("missing_event_id", mint({"event_id": ""}, logout_a), "invalid_value"),
    ]
    for name, token, expected in cases:
        status, body = cluster.send_logout(token)
        assert rejected(status, body), f"{name}: expected rejection, {status} {body}"
        assert body["error"] == expected, f"{name}: {body['error']} != {expected}"
        print(f"    {name}: {status} {body['error']}")

    # "alg=none" with an empty signature must not be accepted.
    header = b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64url_encode(
        json.dumps(
            {
                "v": 1,
                "event_id": "none-evt",
                "iss": cluster.LOGOUT_A,
                "type": "sid",
                "target_iss": cluster.ISS_A,
                "sub": "alice",
                "sid": "none-sid",
                "exp": now + 600,
            }
        ).encode()
    )
    status, body = cluster.send_logout(f"{header}.{payload}.")
    assert status == 401 and body["error"] == "invalid_header", (status, body)
    print(f"    alg_none_empty_sig: {status} {body['error']}")

    # A logout event must not be accepted where a login ticket belongs, and
    # vice versa (different keys).
    good_event = cluster.logout_event(
        event_id="cross-type", kind="sid", target_iss=cluster.ISS_A,
        sub="alice", sid="cross-sid",
    )
    status, body = cluster.login(good_event["logout"])
    assert status == 401, (status, body)
    print(f"    event-as-ticket: {status} {body['error']}")

    login_ticket = make_ticket(
        cluster, iss=cluster.ISS_A, sub="alice", sid="cross-sid2", generation=1
    )
    status, body = cluster.send_logout(login_ticket)
    assert status == 401 and body["error"] == "invalid_version", (status, body)
    print(f"    ticket-as-event: {status} {body['error']}")

    # Valid notification still applies afterwards.
    ok = cluster.logout_event(
        event_id="shape-ok", kind="sid", target_iss=cluster.ISS_A, sub="alice",
        sid="shape-sid",
    )
    assert cluster.send_logout(ok["logout"])[0] == 200


def test_event_resign_same_semantics_is_duplicate(cluster: Cluster) -> None:
    """Re-signing the same event with a new exp is a retry, not a conflict."""

    iss, sub, sid = cluster.ISS_A, "alice", "resign-sid"
    ticket = make_ticket(cluster, iss=iss, sub=sub, sid=sid, generation=1)
    login_ok(cluster, ticket)

    first = cluster.logout_event(
        event_id="resign", kind="sid", target_iss=iss, sub=sub, sid=sid
    )
    status, body = cluster.send_logout(first["logout"])
    assert status == 200 and body["status"] == "applied", (status, body)

    # Same claims except a longer validity window -> same semantic digest.
    from sso_local.config import load_config
    from sso_local.tokens import encode_token

    config = load_config(cluster.config_path)
    claims = dict(first["claims"])
    claims["exp"] = int(claims["exp"]) + 3600
    claims["iat"] = int(claims["iat"]) + 5
    resigned = encode_token(claims, config.logout_issuers[cluster.LOGOUT_A].key)

    status, body = cluster.send_logout(resigned)
    assert status == 200 and body["status"] == "duplicate", (status, body)
    print("    re-signed retry accepted as duplicate")


def test_login_idempotency_and_sid_reuse(cluster: Cluster) -> None:
    iss = cluster.ISS_A
    ticket = make_ticket(cluster, iss=iss, sub="alice", sid="sid-fixed", generation=3)
    sid1 = login_ok(cluster, ticket)
    sid2 = login_ok(cluster, ticket)
    assert sid1 == sid2, (sid1, sid2)
    state = cluster.admin_state()
    assert sum(1 for s in state["sessions"] if s["sid"] == "sid-fixed") == 1
    print(f"    retry same ticket -> same session {sid1[:8]}")

    # Same sid, different generation: sid reuse.  Must be refused, and must not
    # disturb the stored session.
    conflicting = make_ticket(cluster, iss=iss, sub="alice", sid="sid-fixed", generation=4)
    status, body = cluster.login(conflicting)
    assert status == 409 and body["error"] == "sid_reuse_conflict", (status, body)
    assert cluster.check(sid1)[0] == 200

    # Revoke, then retry the *original* ticket: must stay revoked (no revival).
    event = cluster.logout_event(
        event_id="ev-retry", kind="sid", target_iss=iss, sub="alice", sid="sid-fixed"
    )
    assert cluster.send_logout(event["logout"])[0] == 200
    assert cluster.check(sid1)[0] == 401
    status, body = cluster.login(ticket)
    assert status == 409, (status, body)
    assert body["state"] == "revoked", body
    assert cluster.check(sid1)[0] == 401, "retried ticket resurrected a revoked session"
    print("    retry after revoke stays revoked")


def test_sid_logout_before_login(cluster: Cluster) -> None:
    """A sid revocation that arrives before its ticket must still bite."""

    iss, sub, sid = cluster.ISS_A, "alice", "sid-early"
    ticket = make_ticket(cluster, iss=iss, sub=sub, sid=sid, generation=2)
    event = cluster.logout_event(
        event_id="ev-early", kind="sid", target_iss=iss, sub=sub, sid=sid
    )
    status, body = cluster.send_logout(event["logout"])
    assert status == 200 and body["status"] == "applied", (status, body)
    assert body["sid_recorded"] is True

    status, body = cluster.login(ticket)
    assert status == 409, (status, body)
    assert body["reason"] == "sid_revoked", body
    assert cluster.admin_state()["counts"]["active"] == 0
    print("    logout-before-login: login refused")


def test_range_watermark_monotonic(cluster: Cluster) -> None:
    """cutoff is a max; a lower late notification cannot lower it."""

    iss, sub = cluster.ISS_A, "alice"
    tickets = {}
    for gen in (1, 2, 3, 4):
        sid = f"rng-{gen}"
        tickets[gen] = make_ticket(cluster, iss=iss, sub=sub, sid=sid, generation=gen)
        login_ok(cluster, tickets[gen])

    high = cluster.logout_event(
        event_id="ev-high", kind="range", target_iss=iss, sub=sub, cutoff=3
    )
    status, body = cluster.send_logout(high["logout"])
    assert status == 200 and body["watermark"] == 3, (status, body)
    usable = cluster.usable()
    assert usable == {f"{iss}|rng-4"}, usable
    print(f"    after cutoff=3 usable={sorted(usable)}")

    low = cluster.logout_event(
        event_id="ev-low", kind="range", target_iss=iss, sub=sub, cutoff=1
    )
    status, body = cluster.send_logout(low["logout"])
    assert status == 200 and body["watermark"] == 3, (status, body)
    assert cluster.usable() == {f"{iss}|rng-4"}, "lower cutoff moved the watermark back"
    print(f"    after late cutoff=1 watermark still {body['watermark']}")

    # Generation 4 was *not* covered by cutoff=3, so a fresh gen-4 login is
    # admissible (same generation, different sid is legitimate here because
    # generation numbering is per (iss, sub), not per sid).
    gen4b = make_ticket(cluster, iss=iss, sub=sub, sid="rng-4b", generation=4)
    status, body = cluster.login(gen4b)
    assert status == 200, (status, body)

    # Now raise the watermark to 4; the just-created gen-4 session dies and a
    # gen-4 login can no longer be established.
    ev4 = cluster.logout_event(
        event_id="ev-four", kind="range", target_iss=iss, sub=sub, cutoff=4
    )
    assert cluster.send_logout(ev4["logout"])[0] == 200
    covered = make_ticket(cluster, iss=iss, sub=sub, sid="rng-4c", generation=4)
    status, body = cluster.login(covered)
    assert status == 409 and body["reason"] == "watermark_covered", (status, body)
    # Generation 5 is above it and fine.
    newer = make_ticket(cluster, iss=iss, sub=sub, sid="rng-5", generation=5)
    assert cluster.login(newer)[0] == 200
    print("    watermark blocks gen<=cutoff and admits gen>cutoff")


def test_old_logout_after_new_login(cluster: Cluster) -> None:
    """The headline case: delayed logout must not kill the newer session."""

    iss, sub = cluster.ISS_A, "alice"
    old = make_ticket(cluster, iss=iss, sub=sub, sid="old", generation=1)
    new = make_ticket(cluster, iss=iss, sub=sub, sid="new", generation=2)
    old_sid = login_ok(cluster, old)
    new_sid = login_ok(cluster, new)

    # Logged out at generation 1, but the notification is delivered only now,
    # after generation 2 has already logged in.
    event = cluster.logout_event(
        event_id="ev-old", kind="range", target_iss=iss, sub=sub, cutoff=1
    )
    assert cluster.send_logout(event["logout"])[0] == 200

    assert cluster.check(old_sid)[0] == 401, "old session survived its own logout"
    assert cluster.check(new_sid)[0] == 200, "delayed logout killed the newer session"
    assert cluster.usable() == {f"{iss}|new"}
    print("    old session dead, new session alive")


def test_logout_before_login_range(cluster: Cluster) -> None:
    """Range logout for a subject that has never logged in, then the login."""

    iss, sub = cluster.ISS_A, "bob"
    event = cluster.logout_event(
        event_id="ev-pre", kind="range", target_iss=iss, sub=sub, cutoff=2
    )
    assert cluster.send_logout(event["logout"])[0] == 200

    for gen, should_pass in ((1, False), (2, False), (3, True)):
        ticket = make_ticket(cluster, iss=iss, sub=sub, sid=f"pre-{gen}", generation=gen)
        status, body = cluster.login(ticket)
        if should_pass:
            assert status == 200, (gen, status, body)
        else:
            assert status == 409, (gen, status, body)
            assert body["reason"] == "watermark_covered", body
    print("    pre-arrived range logout blocks gen<=2, admits gen 3")


def test_cross_issuer_isolation(cluster: Cluster) -> None:
    """Same sub and same sid text under two issuers must be independent."""

    sub, sid = "alice", "shared-text"
    a = make_ticket(cluster, iss=cluster.ISS_A, sub=sub, sid=sid, generation=1)
    b = make_ticket(cluster, iss=cluster.ISS_B, sub=sub, sid=sid, generation=1)
    sa = login_ok(cluster, a)
    sb = login_ok(cluster, b)
    assert sa != sb

    ev = cluster.logout_event(
        event_id="ev-a-sid", kind="sid", target_iss=cluster.ISS_A, sub=sub, sid=sid
    )
    assert cluster.send_logout(ev["logout"])[0] == 200

    assert cluster.check(sa)[0] == 401, "alpha session survived"
    assert cluster.check(sb)[0] == 200, "beta session was killed by alpha's logout"

    # Range revocation under beta must not touch alpha.
    a2 = make_ticket(cluster, iss=cluster.ISS_A, sub=sub, sid="alpha-2", generation=2)
    b2 = make_ticket(cluster, iss=cluster.ISS_B, sub=sub, sid="beta-2", generation=2)
    sa2 = login_ok(cluster, a2)
    sb2 = login_ok(cluster, b2)
    ev2 = cluster.logout_event(
        event_id="ev-b-range",
        kind="range",
        target_iss=cluster.ISS_B,
        sub=sub,
        cutoff=2,
        event_iss=cluster.LOGOUT_B,
    )
    assert cluster.send_logout(ev2["logout"])[0] == 200
    assert cluster.check(sb2)[0] == 401
    assert cluster.check(sa2)[0] == 200

    # beta's range logout also killed beta's generation-1 "shared-text".
    assert cluster.usable() == {f"{cluster.ISS_A}|alpha-2"}, cluster.usable()
    print("    issuers fully isolated")


def test_event_dedup_and_conflict(cluster: Cluster) -> None:
    iss, sub, sid = cluster.ISS_A, "alice", "dedup-sid"
    ticket = make_ticket(cluster, iss=iss, sub=sub, sid=sid, generation=1)
    login_ok(cluster, ticket)
    event = cluster.logout_event(
        event_id="ev-dup", kind="sid", target_iss=iss, sub=sub, sid=sid
    )
    first = cluster.send_logout(event["logout"])
    assert first[0] == 200 and first[1]["status"] == "applied", first
    epoch_after = first[1]["epoch"]

    again = cluster.send_logout(event["logout"])
    assert again[0] == 200 and again[1]["status"] == "duplicate", again
    assert again[1]["epoch"] == epoch_after, "duplicate re-bumped the epoch"
    print(f"    duplicate -> status=duplicate, epoch stable at {epoch_after}")

    # Same event id, different target: must be a conflict and must not apply.
    other = cluster.logout_event(
        event_id="ev-dup", kind="sid", target_iss=iss, sub="bob", sid="bob-sid"
    )
    bob = make_ticket(cluster, iss=iss, sub="bob", sid="bob-sid", generation=1)
    bob_sid = login_ok(cluster, bob)
    status, body = cluster.send_logout(other["logout"])
    assert status == 409 and body["error"] == "event_conflict", (status, body)
    assert cluster.check(bob_sid)[0] == 200, "conflicting body was applied anyway"
    print("    conflicting body -> 409 and not applied")

    # Duplicate delivery across a *different* RP and with a new connection.
    status, body = cluster.send_logout(event["logout"], rp=cluster.rp(2))
    assert status == 200 and body["status"] == "duplicate", (status, body)


def test_login_logout_race(cluster: Cluster) -> None:
    """Interleaved login/logout cannot leave a watermark-covered session live."""

    iss, sub = cluster.ISS_A, "alice"
    # Prepare a login that blocks *inside* its write transaction, just before
    # insert.  The logout must then wait for that transaction, or win first.
    ticket = make_ticket(cluster, iss=iss, sub=sub, sid="race-7", generation=7)
    event = cluster.logout_event(
        event_id="ev-race", kind="range", target_iss=iss, sub=sub, cutoff=7
    )

    errors: list[BaseException] = []
    result: dict[str, Any] = {}

    def do_login() -> None:
        try:
            result["login"] = cluster.login(ticket, cluster.rp(0))
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    def do_logout() -> None:
        try:
            time.sleep(0.05)  # give the login time to take the write lock
            result["logout"] = cluster.send_logout(event["logout"], cluster.rp(1))
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    cluster.hook("login.before_insert", port=cluster.rp(0).port, millis=400)
    t1 = threading.Thread(target=do_login)
    t2 = threading.Thread(target=do_logout)
    t1.start()
    t2.start()
    t1.join(timeout=20)
    t2.join(timeout=20)
    assert not errors, errors
    assert not t1.is_alive() and not t2.is_alive()

    status, body = result["login"]
    out_status, out_body = result["logout"]
    assert out_status == 200 and out_body["status"] == "applied", result["logout"]
    print(f"    login={status} logout={out_status} watermark={out_body['watermark']}")

    # Whatever order won, the final verdict must be: not usable.
    assert cluster.usable() == set(), "race produced a live, watermark-covered session"
    state = cluster.admin_state()
    inserted = [s for s in state["sessions"] if s["sid"] == "race-7"]
    assert len(inserted) <= 1
    if inserted:
        assert inserted[0]["revoked"] == 1, inserted


def test_authcheck_after_logout_response(cluster: Cluster) -> None:
    """No stale cache hit for an auth that starts after the logout returned."""

    iss, sub = cluster.ISS_A, "alice"
    ticket = make_ticket(cluster, iss=iss, sub=sub, sid="cache-sid", generation=1)
    session = login_ok(cluster, ticket, rp=cluster.rp(0))

    # Warm the cache on *every* process.
    for rp in cluster.rps:
        status, body = cluster.check(session, rp)
        assert status == 200, (status, body)
        status, body = cluster.check(session, rp)
        assert status == 200 and body["cache"] == "hit", body
    print("    caches warmed on all processes")

    event = cluster.logout_event(
        event_id="ev-cache", kind="sid", target_iss=iss, sub=sub, sid="cache-sid"
    )
    status, body = cluster.send_logout(event["logout"], rp=cluster.rp(1))
    assert status == 200

    for index, rp in enumerate(cluster.rps):
        status, body = cluster.check(session, rp)
        assert status == 401, f"rp{index} served a stale cache entry: {body}"
        assert body["reason"] == "revoked:sid", body
    print("    all processes reject immediately after logout response")


def test_cached_positive_then_range_logout(cluster: Cluster) -> None:
    iss, sub = cluster.ISS_A, "bob"
    t1 = make_ticket(cluster, iss=iss, sub=sub, sid="c1", generation=1)
    t2 = make_ticket(cluster, iss=iss, sub=sub, sid="c2", generation=2)
    s1 = login_ok(cluster, t1)
    s2 = login_ok(cluster, t2)
    for rp in cluster.rps:
        assert cluster.check(s1, rp)[0] == 200
        assert cluster.check(s2, rp)[0] == 200
    ev = cluster.logout_event(
        event_id="ev-c-range", kind="range", target_iss=iss, sub=sub, cutoff=1
    )
    assert cluster.send_logout(ev["logout"], rp=cluster.rp(3))[0] == 200
    for index, rp in enumerate(cluster.rps):
        assert cluster.check(s1, rp)[0] == 401, f"rp{index} stale for revoked s1"
        assert cluster.check(s2, rp)[0] == 200, f"rp{index} wrongly killed s2"


def test_cache_gate_across_logout_response(cluster: Cluster) -> None:
    """An auth accepted before the logout but resolving after it must not pass.

    This is stronger than the stated requirement: the request was already in
    the handler when the logout committed, yet the epoch read happens after,
    so the warm cache entry is invalidated mid-request.
    """

    iss, sub = cluster.ISS_A, "alice"
    ticket = make_ticket(cluster, iss=iss, sub=sub, sid="gate-sid", generation=1)
    session = login_ok(cluster, ticket, cluster.rp(0))

    slow = cluster.rp(1)
    # Warm the cache, so a stale hit is actually available.
    assert cluster.check(session, slow)[0] == 200
    status, body = cluster.check(session, slow)
    assert body["cache"] == "hit", body

    cluster.hook("auth.before_check", port=slow.port, millis=700)
    result: dict[str, Any] = {}

    def auth_later() -> None:
        result["auth"] = cluster.check(session, slow)

    thread = threading.Thread(target=auth_later)
    thread.start()
    time.sleep(0.25)  # hook consumed; the handler is parked before the epoch read

    event = cluster.logout_event(
        event_id="gate-evt", kind="sid", target_iss=iss, sub=sub, sid="gate-sid"
    )
    status, body = cluster.send_logout(event["logout"], cluster.rp(2))
    assert status == 200 and body["status"] == "applied", (status, body)
    ack = time.time()

    thread.join(timeout=20)
    assert not thread.is_alive()
    status, body = result["auth"]
    assert status == 401, f"parked auth returned {status} {body} after the logout ack"
    assert body["reason"] == "revoked:sid", body
    print(f"    parked auth resolved after ack -> {status} {body['reason']}")

    # An auth started fresh after the ack is also rejected.
    assert cluster.check(session, slow)[0] == 401
    print("    fresh auth after ack rejected")


def test_crash_after_dedup_before_revocation(cluster: Cluster) -> None:
    """Crash point 1: event id durably recorded, revocation not done."""

    iss, sub, sid = cluster.ISS_A, "alice", "crash1"
    ticket = make_ticket(cluster, iss=iss, sub=sub, sid=sid, generation=1)
    session = login_ok(cluster, ticket)
    assert cluster.check(session)[0] == 200

    victim = cluster.rp(0)
    event = cluster.logout_event(
        event_id="ev-crash1", kind="sid", target_iss=iss, sub=sub, sid=sid
    )
    cluster.hook("logout.after_dedup", port=victim.port, mode="die")

    try:
        cluster.send_logout(event["logout"], victim)
        raise AssertionError("expected the connection to die")
    except Exception:
        pass
    assert cluster.wait_until(lambda: not victim.alive(), timeout=20), "victim did not die"
    print(f"    {victim.name} self-terminated at after_dedup (rc={victim.proc.returncode})")

    state = cluster.admin_state(rp=cluster.rp(1))
    pending = [e for e in state["events"] if e["event_id"] == "ev-crash1"]
    assert len(pending) == 1 and pending[0]["applied"] == 0, pending
    # Not acknowledged => the session is allowed to still be alive here.
    print("    dedup row present with applied=0")

    # Redelivery (to a healthy process) must complete the revocation.
    restarted = cluster.restart_rp(victim)
    status, body = cluster.send_logout(event["logout"], restarted)
    assert status == 200 and body["status"] == "applied", (status, body)
    assert cluster.check(session, restarted)[0] == 401
    assert cluster.usable() == set()
    state = cluster.admin_state(rp=restarted)
    assert all(e["applied"] == 1 for e in state["events"] if e["event_id"] == "ev-crash1")
    print("    redelivery completed revocation; no acknowledged-but-unrevoked state")


def test_crash_after_commit_before_response(cluster: Cluster) -> None:
    """Crash point 2: revocation committed, HTTP response never sent."""

    iss, sub, sid = cluster.ISS_A, "alice", "crash2"
    ticket = make_ticket(cluster, iss=iss, sub=sub, sid=sid, generation=1)
    session = login_ok(cluster, ticket)

    victim = cluster.rp(2)
    event = cluster.logout_event(
        event_id="ev-crash2", kind="sid", target_iss=iss, sub=sub, sid=sid
    )
    cluster.hook("logout.after_commit", port=victim.port, mode="die")
    try:
        cluster.send_logout(event["logout"], victim)
        raise AssertionError("expected the connection to die")
    except Exception:
        pass
    assert cluster.wait_until(lambda: not victim.alive(), timeout=20)
    print(f"    {victim.name} self-terminated at after_commit (rc={victim.proc.returncode})")

    # Committed: revocation is visible from every surviving process even
    # though no acknowledgment was ever produced.
    for rp in cluster.rps:
        if rp.alive():
            assert cluster.check(session, rp)[0] == 401
    state = cluster.admin_state(rp=cluster.rp(1))
    assert any(
        e["event_id"] == "ev-crash2" and e["applied"] == 1 for e in state["events"]
    )

    # Redelivery is a plain duplicate, and still does nothing bad.
    restarted = cluster.restart_rp(victim)
    status, body = cluster.send_logout(event["logout"], restarted)
    assert status == 200 and body["status"] == "duplicate", (status, body)
    assert cluster.check(session, restarted)[0] == 401
    print("    redelivery reported duplicate; state unchanged")


def test_crash_during_login_transaction(cluster: Cluster) -> None:
    """A login that dies inside its write transaction must not half-insert."""

    iss, sub = cluster.ISS_A, "alice"
    ticket = make_ticket(cluster, iss=iss, sub=sub, sid="crash-login", generation=1)
    victim = cluster.rp(1)
    cluster.hook("login.before_insert", port=victim.port, mode="die")
    try:
        cluster.login(ticket, victim)
        raise AssertionError("expected the connection to die")
    except Exception:
        pass
    assert cluster.wait_until(lambda: not victim.alive(), timeout=20)

    restarted = cluster.restart_rp(victim)
    state = cluster.admin_state(rp=restarted)
    assert not [s for s in state["sessions"] if s["sid"] == "crash-login"]
    assert state["counts"]["active"] == 0
    # The same ticket can still be used afterwards: nothing was half-written.
    session = login_ok(cluster, ticket, restarted)
    assert cluster.check(session, restarted)[0] == 200
    print("    aborted transaction left no partial session; retry works")


def test_multi_process_concurrent_delivery(cluster: Cluster) -> None:
    """Deliver a mixed event batch concurrently to all 4 processes."""

    iss_a, iss_b = cluster.ISS_A, cluster.ISS_B
    logins: list[dict[str, Any]] = []
    sessions: dict[str, str] = {}

    # alice@A generations 1..4, alice@B generation 1..2, bob@A 1..2
    spec = [
        (iss_a, "alice", [(1, "a1"), (2, "a2"), (3, "a3"), (4, "a4")]),
        (iss_b, "alice", [(1, "b1"), (2, "b2")]),
        (iss_a, "bob", [(1, "c1"), (2, "c2")]),
    ]
    for iss, sub, entries in spec:
        for gen, sid in entries:
            ticket = make_ticket(cluster, iss=iss, sub=sub, sid=sid, generation=gen)
            sessions[f"{iss}|{sid}"] = login_ok(cluster, ticket, cluster.rp(gen % 4))
            logins.append(
                {
                    "iss": iss,
                    "sub": sub,
                    "sid": sid,
                    "generation": gen,
                    "expires_at": time.time() + 3000,
                }
            )

    # Every process must have seen at least one session (cache spread).
    for rp in cluster.rps:
        dummy = next(iter(sessions.values()))
        cluster.check(dummy, rp)

    events: list[tuple[str, str]] = []
    def ev(event_id: str, kind: str, target: str, **kw: Any) -> None:
        body = cluster.logout_event(
            event_id=event_id, kind=kind, target_iss=target, **kw
        )
        events.append((event_id, body["logout"]))
        # Also record for the reference run.

    ev("m1", "range", iss_a, sub="alice", cutoff=2)
    ev("m2", "sid", iss_a, sub="alice", sid="a3")
    ev("m3", "range", iss_b, sub="alice", cutoff=2)
    ev("m4", "sid", iss_a, sub="bob", sid="c1")
    ev("m5", "range", iss_a, sub="alice", cutoff=1)  # late, lower
    ev("m6", "sid", iss_b, sub="alice", sid="never-existed")
    ev("m7", "range", iss_a, sub="bob", cutoff=2)

    reference_events = [
        {
            "type": "range" if e["type"] == "range" else "sid",
            "target_iss": e["target_iss"],
            "sub": e["sub"],
            "sid": e.get("sid"),
            "cutoff_generation": e.get("cutoff_generation"),
        }
        for e in cluster.events
    ]
    from sso_local.state import reference_usable

    expected = reference_usable(reference_events, logins)

    # Interleave: shuffled-ish order plus duplicates, spread over 8 threads.
    order = [0, 3, 1, 4, 6, 2, 0, 5, 3, 1, 6, 2, 4, 5, 0, 6]
    failures: list[str] = []

    def deliver(index: int, token: str) -> None:
        rp = cluster.rp(index % len(cluster.rps))
        status, body = cluster.send_logout(token, rp)
        if status != 200:
            failures.append(f"{index}: {status} {body}")

    threads = [
        threading.Thread(target=deliver, args=(i % 4, events[i][1]))
        for i in order
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not failures, failures

    actual = cluster.usable()
    assert actual == expected, f"\n  actual  : {sorted(actual)}\n  expected: {sorted(expected)}"
    print(f"    concurrent delivery converged: {sorted(actual)}")

    # All event ids recorded exactly once, all applied.
    state = cluster.admin_state()
    ids = [e["event_id"] for e in state["events"]]
    assert sorted(ids) == sorted({e[0] for e in events}), ids
    assert all(e["applied"] == 1 for e in state["events"])

    # And every stored session's HTTP verdict agrees with the DB.
    for key, session_id in sessions.items():
        status, body = cluster.check(session_id)
        should_be_usable = key in expected
        assert (status == 200) == should_be_usable, (key, status, body)


def test_permutation_matrix(cluster: Cluster) -> None:
    """Same login/logout set, many orders + duplicates + concurrency.

    Every run must reproduce the reference state machine's usable sid set.
    The reference is order-independent (max watermark + sid kill set), which is
    exactly the property under test.
    """

    from sso_local.state import reference_usable

    iss_a, iss_b = cluster.ISS_A, cluster.ISS_B

    login_spec = [
        (iss_a, "alice", 1, "A-a1"),
        (iss_a, "alice", 2, "A-a2"),
        (iss_a, "alice", 3, "A-a3"),
        (iss_a, "alice", 4, "A-a4"),
        (iss_b, "alice", 1, "B-a1"),
        (iss_b, "alice", 2, "B-a2"),
        (iss_a, "bob", 1, "A-b1"),
        (iss_b, "bob", 1, "B-b1"),
    ]
    event_spec = [
        # event_id, kind, target_iss, event_iss, sub, sid, cutoff
        ("p-range-a2", "range", iss_a, cluster.LOGOUT_A, "alice", None, 2),
        ("p-sid-a3", "sid", iss_a, cluster.LOGOUT_A, "alice", "A-a3", None),
        ("p-range-b1", "range", iss_b, cluster.LOGOUT_B, "alice", None, 1),
        ("p-sid-bob", "sid", iss_a, cluster.LOGOUT_A, "bob", "A-b1", None),
        # Late lower range event: must not undo p-range-a2.
        ("p-range-a1", "range", iss_a, cluster.LOGOUT_A, "alice", None, 1),
        # Range for a subject/sid pair that has no session at all.
        ("p-sid-ghost", "sid", iss_b, cluster.LOGOUT_B, "alice", "B-ghost", None),
        # Range covering beta alice's generation 2 as well.
        ("p-range-b2", "range", iss_b, cluster.LOGOUT_B, "alice", None, 2),
    ]

    logins_for_ref = [
        {"iss": iss, "sub": sub, "sid": sid, "generation": gen, "expires_at": time.time() + 3000}
        for iss, sub, gen, sid in login_spec
    ]
    events_for_ref = [
        {
            "type": kind,
            "target_iss": target,
            "sub": sub,
            "sid": sid,
            "cutoff_generation": cutoff,
        }
        for (_, kind, target, _, sub, sid, cutoff) in event_spec
    ]
    expected = reference_usable(events_for_ref, logins_for_ref)

    # A duplicate event id with a *different* body must never be applied; it is
    # checked separately, so it is not part of this matrix.

    permutations: list[list[tuple[str, int]]] = []

    def build(order: list[int], dup_at: list[int] | None = None) -> list[tuple[str, int]]:
        """order indexes into the merged [logins..., events...] sequence."""

        dup_at = dup_at or []
        merged: list[tuple[str, int]] = [("L", i) for i in range(len(login_spec))] + [
            ("E", i) for i in range(len(event_spec))
        ]
        seq = [merged[i] for i in order]
        for pos in dup_at:
            if pos < len(seq):
                seq.append(seq[pos])  # retransmission of the same event/login
        return seq

    n = len(login_spec) + len(event_spec)
    login_first = list(range(len(login_spec))) + list(
        range(len(login_spec), n)
    )
    events_first = list(range(len(login_spec), n)) + list(range(len(login_spec)))
    interleaved = [0, 8, 1, 11, 2, 9, 3, 13, 4, 10, 5, 12, 6, 14, 7]
    reverse = list(reversed(interleaved))
    permutations = [
        ("login-first", build(login_first, dup_at=[2, 10])),
        ("events-first", build(events_first, dup_at=[0, 4])),
        ("interleaved", build(interleaved)),
        ("reverse", build(reverse, dup_at=[1, 7, 9])),
        (
            "dupes-everywhere",
            build(interleaved, dup_at=list(range(0, len(interleaved)))),
        ),
    ]

    for label, seq in permutations:
        cluster.events = []
        # Fresh state for each permutation: wipe mutable tables, keep config.
        _reset_cluster_state(cluster)
        statuses: dict[int, str] = {}
        for kind, index in seq:
            if kind == "L":
                iss, sub, gen, sid = login_spec[index]
                ticket = make_ticket(cluster, iss=iss, sub=sub, sid=sid, generation=gen)
                status, body = cluster.login(ticket, cluster.rp(index % 4))
                assert status in (200, 409), (label, index, status, body)
                if status == 200:
                    statuses[index] = session_of(body)
            else:
                event_id, kind_name, target, ev_iss, sub, sid, cutoff = event_spec[index]
                body = cluster.logout_event(
                    event_id=event_id,
                    kind=kind_name,
                    target_iss=target,
                    sub=sub,
                    sid=sid,
                    cutoff=cutoff,
                    event_iss=ev_iss,
                )
                status, payload = cluster.send_logout(body["logout"], cluster.rp(index % 4))
                assert status == 200, (label, event_id, status, payload)
                assert payload["status"] in ("applied", "duplicate"), payload

        actual = cluster.usable()
        assert actual == expected, (
            f"{label}: usable mismatch\n  actual  : {sorted(actual)}\n"
            f"  expected: {sorted(expected)}"
        )

        # Every HTTP verdict must agree with the durable state.
        for index, session_id in statuses.items():
            iss, sub, gen, sid = login_spec[index]
            status, payload = cluster.check(session_id, cluster.rp(index % 4))
            should = f"{iss}|{sid}" in expected
            assert (status == 200) == should, (label, sid, status, payload)

        # No event left half-applied.
        state = cluster.admin_state()
        assert all(e["applied"] == 1 for e in state["events"]), label
        print(f"    {label:<18} usable={sorted(actual)}")

    # Same set, delivered concurrently from 8 threads in shuffled order.
    _reset_cluster_state(cluster)
    plan: list[tuple[str, int]] = []
    for index in range(len(login_spec)):
        plan.append(("L", index))
    for index in range(len(event_spec)):
        plan.append(("E", index))
    plan = [plan[i] for i in (3, 9, 0, 12, 5, 14, 1, 8, 4, 11, 6, 13, 2, 10, 7)]
    plan = plan + plan[2:6]  # a few retransmissions
    sessions: dict[int, str] = {}
    errors: list[str] = []

    def work(kind: str, index: int, slot: int) -> None:
        try:
            rp = cluster.rp(slot % 4)
            if kind == "L":
                iss, sub, gen, sid = login_spec[index]
                ticket = make_ticket(cluster, iss=iss, sub=sub, sid=sid, generation=gen)
                status, body = cluster.login(ticket, rp)
                if status not in (200, 409):
                    errors.append(f"login {sid}: {status} {body}")
                elif status == 200:
                    sessions[index] = session_of(body)
            else:
                event_id, kind_name, target, ev_iss, sub, sid, cutoff = event_spec[index]
                body = cluster.logout_event(
                    event_id=event_id,
                    kind=kind_name,
                    target_iss=target,
                    sub=sub,
                    sid=sid,
                    cutoff=cutoff,
                    event_iss=ev_iss,
                )
                status, payload = cluster.send_logout(body["logout"], rp)
                if status != 200:
                    errors.append(f"logout {event_id}: {status} {payload}")
        except Exception as exc:  # pragma: no cover
            errors.append(f"{kind}{index}: {exc}")

    threads = [
        threading.Thread(target=work, args=(kind, index, slot))
        for slot, (kind, index) in enumerate(plan)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not errors, errors
    assert cluster.usable() == expected, (
        f"concurrent: {sorted(cluster.usable())} != {sorted(expected)}"
    )
    state = cluster.admin_state()
    ids = [e["event_id"] for e in state["events"]]
    assert sorted(ids) == sorted(e[0] for e in event_spec), ids
    print(f"    {'concurrent':<18} usable={sorted(expected)}")


def _reset_cluster_state(cluster: Cluster) -> None:
    """Clear mutable RP state so each permutation starts from zero.

    Only ever used between permutations of one test; it touches the database,
    never a live handler's memory.  RPs are restarted so their in-process auth
    caches are empty too.
    """

    from sso_local import db as sdb

    conn = sdb.connect(cluster.db_path)
    try:
        with sdb.immediate(conn):
            for table in (
                "sessions",
                "subjects",
                "sid_revocations",
                "seen_events",
                "request_log",
                "hooks",
            ):
                conn.execute(f"DELETE FROM {table}")
            conn.execute("UPDATE meta SET value = '0' WHERE key = 'revocation_epoch'")
    finally:
        conn.close()
    for rp in cluster.rps:
        rp.stop()
    cluster.rps = []
    for i in range(4):
        cluster.start_rp(i)


def test_auth_ordering_under_concurrency(cluster: Cluster) -> None:
    """Hammer auth while a logout lands; every verdict is consistent."""

    iss, sub = cluster.ISS_A, "alice"
    ticket = make_ticket(cluster, iss=iss, sub=sub, sid="hot", generation=1)
    session = login_ok(cluster, ticket)
    for rp in cluster.rps:
        cluster.check(session, rp)
        cluster.check(session, rp)

    stop = threading.Event()
    observations: list[tuple[float, int]] = []
    lock = threading.Lock()

    def hammer() -> None:
        while not stop.is_set():
            rp = cluster.rp(int(time.time() * 1000) % len(cluster.rps))
            start = time.time()
            try:
                status, _ = cluster.check(session, rp)
            except Exception:
                continue
            with lock:
                observations.append((start, status))

    threads = [threading.Thread(target=hammer) for _ in range(6)]
    for t in threads:
        t.start()
    time.sleep(0.3)
    event = cluster.logout_event(
        event_id="ev-hot", kind="sid", target_iss=iss, sub=sub, sid="hot"
    )
    status, body = cluster.send_logout(event["logout"], cluster.rp(1))
    assert status == 200, (status, body)
    ack_time = time.time()
    time.sleep(0.3)
    stop.set()
    for t in threads:
        t.join(timeout=10)

    after = [s for (t, s) in observations if t > ack_time + 0.02]
    allowed_after = [s for s in after if s == 200]
    assert not allowed_after, f"{len(allowed_after)} auth checks allowed after logout ack"
    print(f"    {len(observations)} auth checks, 0 allowed after ack ({len(after)} sampled)")


def test_restart_persistence(cluster: Cluster) -> None:
    """Kill every RP; watermarks and sid kills must survive the restart."""

    iss = cluster.ISS_A
    t1 = make_ticket(cluster, iss=iss, sub="alice", sid="p1", generation=1)
    t2 = make_ticket(cluster, iss=iss, sub="alice", sid="p2", generation=2)
    s1 = login_ok(cluster, t1)
    s2 = login_ok(cluster, t2)
    ev1 = cluster.logout_event(event_id="p-range", kind="range", target_iss=iss, sub="alice", cutoff=1)
    ev2 = cluster.logout_event(event_id="p-sid", kind="sid", target_iss=iss, sub="alice", sid="p2")
    assert cluster.send_logout(ev1["logout"])[0] == 200
    assert cluster.send_logout(ev2["logout"])[0] == 200
    wm_before = {f"{s['iss']}|{s['sub']}": s["cutoff_generation"] for s in cluster.admin_state()["subjects"]}

    old = list(cluster.rps)
    for rp in old:
        rp.stop()
    assert all(not rp.alive() for rp in old)
    cluster.rps = []
    for i in range(4):
        cluster.start_rp(i)
    print("    all 4 RP processes restarted against the same DB")

    # Both dead sessions stay dead.
    for index, rp in enumerate(cluster.rps):
        assert cluster.check(s1, rp)[0] == 401, f"rp{index}: p1 revived"
        assert cluster.check(s2, rp)[0] == 401, f"rp{index}: p2 revived"

    # Redelivering the same events is a duplicate, not a re-application.
    status, body = cluster.send_logout(ev1["logout"], cluster.rp(2))
    assert status == 200 and body["status"] == "duplicate", (status, body)
    status, body = cluster.send_logout(ev2["logout"], cluster.rp(3))
    assert status == 200 and body["status"] == "duplicate", (status, body)

    # Replaying the *tickets* after restart must not resurrect anything.
    assert cluster.login(t1)[0] == 409
    assert cluster.login(t2)[0] == 409

    wm_after = {f"{s['iss']}|{s['sub']}": s["cutoff_generation"] for s in cluster.admin_state()["subjects"]}
    assert wm_after == wm_before, (wm_after, wm_before)
    assert cluster.usable() == set()
    print("    watermarks, sid kills and dedup all persisted")


def test_notification_cannot_lower_after_restart(cluster: Cluster) -> None:
    iss, sub = cluster.ISS_B, "alice"
    hi = cluster.logout_event(event_id="hi", kind="range", target_iss=iss, sub=sub, cutoff=4, event_iss=cluster.LOGOUT_B)
    assert cluster.send_logout(hi["logout"])[0] == 200
    lo = cluster.logout_event(event_id="lo", kind="range", target_iss=iss, sub=sub, cutoff=1, event_iss=cluster.LOGOUT_B)
    # Restart one process between the two deliveries.
    cluster.restart_rp(cluster.rp(0))
    status, body = cluster.send_logout(lo["logout"], cluster.rp(1))
    assert status == 200 and body["watermark"] == 4, (status, body)
    state = cluster.admin_state()
    wm = {(s["iss"], s["sub"]): s["cutoff_generation"] for s in state["subjects"]}
    assert wm[(iss, sub)] == 4
    print("    late lower notification after restart kept watermark at 4")


def test_arrival_time_is_not_authority(cluster: Cluster) -> None:
    """Generation decides scope, never local receipt time."""

    iss, sub = cluster.ISS_A, "bob"
    # New session first, then a *numerically older* range event.
    new = make_ticket(cluster, iss=iss, sub=sub, sid="time-new", generation=9)
    s_new = login_ok(cluster, new)
    old = make_ticket(cluster, iss=iss, sub=sub, sid="time-old", generation=2)
    s_old = login_ok(cluster, old)

    ev = cluster.logout_event(
        event_id="t-old", kind="range", target_iss=iss, sub=sub, cutoff=2
    )
    assert cluster.send_logout(ev["logout"])[0] == 200
    assert cluster.check(s_old)[0] == 401
    assert cluster.check(s_new)[0] == 200

    # Reverse: cutoff that would cover both, delivered late.
    ev2 = cluster.logout_event(
        event_id="t-all", kind="range", target_iss=iss, sub=sub, cutoff=9
    )
    assert cluster.send_logout(ev2["logout"])[0] == 200
    assert cluster.check(s_new)[0] == 401
    print("    scope follows generation, not arrival order")


def test_session_not_usable_before_logout_but_watermark_blocks(cluster: Cluster) -> None:
    """Sessions inserted below a pre-existing watermark must be born revoked."""

    iss, sub = cluster.ISS_A, "alice"
    ev = cluster.logout_event(event_id="pre-wm", kind="range", target_iss=iss, sub=sub, cutoff=5)
    assert cluster.send_logout(ev["logout"])[0] == 200

    covered = make_ticket(cluster, iss=iss, sub=sub, sid="covered", generation=5)
    status, body = cluster.login(covered)
    assert status == 409 and body["state"] == "revoked", (status, body)
    # Still recorded (for audit) but dead.
    state = cluster.admin_state()
    rows = [s for s in state["sessions"] if s["sid"] == "covered"]
    assert len(rows) == 1 and rows[0]["revoked"] == 1, rows
    assert cluster.usable() == set()
    print("    covered login recorded as born-revoked, never usable")


# -- registry -------------------------------------------------------------

TESTS: list[tuple[str, Callable[[Cluster], None], int]] = [
    ("token-validation", test_token_validation_matrix, 4),
    ("logout-validation", test_logout_event_validation, 3),
    ("event-resign", test_event_resign_same_semantics_is_duplicate, 2),
    ("duplicate-json", test_duplicate_json_members_rejected, 2),
    ("login-idempotency", test_login_idempotency_and_sid_reuse, 3),
    ("sid-logout-early", test_sid_logout_before_login, 2),
    ("range-watermark", test_range_watermark_monotonic, 3),
    ("old-logout-new-login", test_old_logout_after_new_login, 3),
    ("range-before-login", test_logout_before_login_range, 2),
    ("cross-issuer", test_cross_issuer_isolation, 3),
    ("event-dedup", test_event_dedup_and_conflict, 4),
    ("login-logout-race", test_login_logout_race, 4),
    ("auth-after-logout", test_authcheck_after_logout_response, 4),
    ("cache-gate", test_cache_gate_across_logout_response, 4),
    ("cached-range-logout", test_cached_positive_then_range_logout, 4),
    ("crash-after-dedup", test_crash_after_dedup_before_revocation, 4),
    ("crash-after-commit", test_crash_after_commit_before_response, 4),
    ("crash-mid-login", test_crash_during_login_transaction, 3),
    ("concurrent-mixed", test_multi_process_concurrent_delivery, 4),
    ("permutation-matrix", test_permutation_matrix, 4),
    ("auth-concurrency", test_auth_ordering_under_concurrency, 4),
    ("restart-persistence", test_restart_persistence, 4),
    ("watermark-after-restart", test_notification_cannot_lower_after_restart, 3),
    ("arrival-time", test_arrival_time_is_not_authority, 3),
    ("born-revoked", test_session_not_usable_before_logout_but_watermark_blocks, 2),
]


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="tests.run_all")
    parser.add_argument("filters", nargs="*", help="substring filters on test names")
    parser.add_argument("--keep", action="store_true", help="keep temp dirs")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(argv)

    if args.list:
        for name, _, _ in TESTS:
            print(name)
        return 0

    selected = [
        (n, f, c)
        for (n, f, c) in TESTS
        if not args.filters or any(flt in n for flt in args.filters)
    ]
    if not selected:
        print("no tests matched", file=os.sys.stderr)
        return 2

    results: list[tuple[str, bool, str]] = []
    started = time.time()
    for name, func, rp_count in selected:
        print(f"\n[{name}] ", flush=True)
        cluster = Cluster(rp_count=rp_count)
        t0 = time.time()
        try:
            cluster.start()
            func(cluster)
            elapsed = time.time() - t0
            results.append((name, True, f"{elapsed:.1f}s"))
            print(f"  PASS ({elapsed:.1f}s)", flush=True)
        except Exception as exc:  # noqa: BLE001 - report everything
            elapsed = time.time() - t0
            detail = f"{type(exc).__name__}: {exc}"
            results.append((name, False, detail))
            print(f"  FAIL ({elapsed:.1f}s): {detail}", flush=True)
            traceback.print_exc()
            log_dir = cluster.dir
            print(f"  artifacts: {log_dir}", flush=True)
            for log in sorted(Path(log_dir).glob("*.log")):
                text = log.read_text(errors="replace").strip()
                if text:
                    print(f"  --- {log.name} ---\n{text[-2500:]}", flush=True)
            if args.keep:
                cluster.stop_all()
                continue
        finally:
            if not args.keep:
                cluster.cleanup()

    total_time = time.time() - started
    passed = sum(1 for _, ok, _ in results if ok)
    print("\n" + "=" * 70)
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<32} {detail}")
    print(f"\n{passed}/{len(results)} passed in {total_time:.1f}s")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
