"""Command-line surface: RP, IdP, ticket minting, admin and probes.

Everything that talks to a running service uses real HTTP via urllib.  The
in-process commands (``state``, ``compare``, ``hook``) operate on the SQLite
file, which is how an operator inspects durable state.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from . import db
from .config import ConfigError, load_config
from .idp import (
    IdPState,
    LOGIN_TTL_SECONDS,
    LOGOUT_TTL_SECONDS,
    get_json,
    mint_login_ticket,
    mint_logout_event,
    post_json,
    serve_idp,
)
from .rp_server import serve as serve_rp
from .state import (
    dump_json,
    export_state,
    reference_usable,
    rp_usable_set,
    summarize_state,
)
from .store import add_hook, clear_hooks


def _config(args: argparse.Namespace):
    return load_config(args.config)


def _print(obj: Any) -> None:
    print(dump_json(obj))


# -- service commands -----------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    db.initialize_database(args.db)
    print(json.dumps({"ok": True, "db": str(Path(args.db).resolve())}))
    return 0


def cmd_rp(args: argparse.Namespace) -> int:
    config = _config(args)
    db.initialize_database(args.db)
    serve_rp(
        args.db,
        config,
        args.host,
        args.port,
        verbose=args.verbose,
        ready_file=args.ready_file,
    )
    return 0


def cmd_idp(args: argparse.Namespace) -> int:
    config = _config(args)
    serve_idp(
        config,
        args.state,
        args.host,
        args.port,
        verbose=args.verbose,
        ready_file=args.ready_file,
    )
    return 0


# -- ticket / event minting ----------------------------------------------


def cmd_ticket(args: argparse.Namespace) -> int:
    config = _config(args)
    state = IdPState(args.state)
    try:
        result = mint_login_ticket(
            config,
            state,
            iss=args.iss,
            sub=args.sub,
            sid=args.sid,
            generation=args.generation,
            ttl=args.ttl,
        )
    except ValueError as exc:
        print(json.dumps({"error": "bad_request", "detail": str(exc)}))
        return 2
    _print(result)
    return 0


def cmd_logout_event(args: argparse.Namespace) -> int:
    config = _config(args)
    try:
        result = mint_logout_event(
            config,
            event_id=args.event_id,
            kind=args.type,
            target_iss=args.target_iss,
            sub=args.sub,
            sid=args.sid,
            cutoff_generation=args.cutoff,
            event_iss=args.event_iss,
            ttl=args.ttl,
        )
    except ValueError as exc:
        print(json.dumps({"error": "bad_request", "detail": str(exc)}))
        return 2
    _print(result)
    return 0


# -- HTTP clients ---------------------------------------------------------


def cmd_login(args: argparse.Namespace) -> int:
    status, payload = post_json(f"{args.rp}/v1/login", {"ticket": args.ticket})
    _print({"status": status, "body": payload})
    return 0 if status < 500 else 1


def cmd_logout_send(args: argparse.Namespace) -> int:
    status, payload = post_json(
        f"{args.rp}/v1/logout/events", {"logout": args.logout}
    )
    _print({"status": status, "body": payload})
    return 0 if status < 500 else 1


def cmd_check(args: argparse.Namespace) -> int:
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        f"{args.rp}/v1/authcheck",
        headers={"Authorization": f"Bearer {args.session_id}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status, body = resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        status, body = exc.code, json.loads(exc.read() or b"null")
    _print({"status": status, "body": body})
    return 0 if status == 200 else 1


def cmd_status(args: argparse.Namespace) -> int:
    status, body = get_json(f"{args.rp}/admin/state")
    _print({"status": status, "body": body})
    return 0 if status == 200 else 1


def cmd_summary(args: argparse.Namespace) -> int:
    state = export_state(args.db)
    _print(summarize_state(state, now=time.time()))
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    """Compare live RP usable set against the independent reference machine.

    Input is a JSON file: {"events": [...], "logins": [...]} in wire-claim
    shape.  Only the RP's *stored* sessions are considered, so a reference
    login that the RP correctly refused is expected to be absent from
    ``restricted``.
    """

    doc = json.loads(Path(args.expected).read_text(encoding="utf-8"))
    state = export_state(args.db)
    now = time.time()
    actual = rp_usable_set(state, now=now)
    reference = reference_usable(doc["events"], doc["logins"])
    # Reference may contain logins the RP refused at insert time; only compare
    # the intersection of *attempted* sessions the RP actually stored.
    stored = {f"{s['iss']}|{s['sid']}" for s in state["sessions"]}
    expected = reference if args.all_logins else reference & stored
    report = {
        "actual": sorted(actual),
        "expected": sorted(expected),
        "missing": sorted(expected - actual),
        "unexpected": sorted(actual - expected),
        "equal": actual == expected,
    }
    _print(report)
    return 0 if report["equal"] else 1


# -- admin hooks ----------------------------------------------------------


def cmd_hook(args: argparse.Namespace) -> int:
    if args.action == "add":
        try:
            hook_id = add_hook(
                args.db, args.phase, port=args.port, mode=args.mode, millis=args.millis
            )
        except ValueError as exc:
            print(json.dumps({"error": "bad_request", "detail": str(exc)}))
            return 2
        print(json.dumps({"ok": True, "hook_id": hook_id}))
        return 0
    if args.action == "clear":
        print(json.dumps({"ok": True, "cleared": clear_hooks(args.db)}))
        return 0
    if args.action == "list":
        state = export_state(args.db)
        conn = db.connect(args.db)
        try:
            rows = [dict(r) for r in conn.execute("SELECT * FROM hooks ORDER BY id")]
        finally:
            conn.close()
        _print({"hooks": rows, "epoch": state["epoch"]})
        return 0
    raise SystemExit(f"unknown hook action {args.action}")


# -- parser ---------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sso_local",
        description="local SSO session + out-of-order logout notification service",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create/migrate the shared SQLite database")
    p.add_argument("--db", required=True)
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("rp", help="run one RP process")
    p.add_argument("--db", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--ready-file", default=None)
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_rp)

    p = sub.add_parser("idp", help="run the identity-provider simulator")
    p.add_argument("--config", required=True)
    p.add_argument("--state", required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--ready-file", default=None)
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_idp)

    p = sub.add_parser("ticket", help="mint a login ticket")
    p.add_argument("--config", required=True)
    p.add_argument("--state", required=True)
    p.add_argument("--iss", required=True)
    p.add_argument("--sub", required=True)
    p.add_argument("--sid", default=None)
    p.add_argument("--generation", type=int, default=None)
    p.add_argument("--ttl", type=int, default=LOGIN_TTL_SECONDS)
    p.set_defaults(func=cmd_ticket)

    p = sub.add_parser("logout-event", help="mint a signed logout event")
    p.add_argument("--config", required=True)
    p.add_argument("--event-id", required=True)
    p.add_argument("--type", choices=["sid", "range"], required=True)
    p.add_argument("--target-iss", required=True)
    p.add_argument("--event-iss", default="idp-logout")
    p.add_argument("--sub", default=None)
    p.add_argument("--sid", default=None)
    p.add_argument("--cutoff", type=int, default=None)
    p.add_argument("--ttl", type=int, default=LOGOUT_TTL_SECONDS)
    p.set_defaults(func=cmd_logout_event)

    p = sub.add_parser("login", help="POST a ticket to an RP")
    p.add_argument("--rp", required=True)
    p.add_argument("--ticket", required=True)
    p.set_defaults(func=cmd_login)

    p = sub.add_parser("logout-send", help="POST a logout event to an RP")
    p.add_argument("--rp", required=True)
    p.add_argument("--logout", required=True)
    p.set_defaults(func=cmd_logout_send)

    p = sub.add_parser("check", help="call the protected endpoint")
    p.add_argument("--rp", required=True)
    p.add_argument("--session-id", required=True)
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("status", help="GET /admin/state from a live RP")
    p.add_argument("--rp", required=True)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("summary", help="summarize durable state from the DB")
    p.add_argument("--db", required=True)
    p.set_defaults(func=cmd_summary)

    p = sub.add_parser("compare", help="compare RP state with the reference machine")
    p.add_argument("--db", required=True)
    p.add_argument("--expected", required=True, help="JSON with events and logins")
    p.add_argument(
        "--all-logins",
        action="store_true",
        help="compare all reference logins, not just those the RP stored",
    )
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("hook", help="manage controllable synchronization points")
    p.add_argument("--db", required=True)
    p.add_argument("action", choices=["add", "clear", "list"])
    p.add_argument("--phase", default=None)
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--mode", choices=["sleep", "die"], default="sleep")
    p.add_argument("--millis", type=int, default=0)
    p.set_defaults(func=cmd_hook)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except ConfigError as exc:
        print(json.dumps({"error": "config", "detail": str(exc)}), file=sys.stderr)
        return 2
