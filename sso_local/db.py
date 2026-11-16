"""SQLite schema and connection management.

One database, many processes.  Every state change runs in ``BEGIN IMMEDIATE``
so that all RP processes are serialized on SQLite's write lock.  That gives a
single total order over (login, logout, protected-auth-check), which is the
consistency backbone of the whole exercise.

Tables
------
seen_events      durable event-id dedup with the canonical signed body digest;
                 ``applied`` flips only in the same transaction as the
                 revocation, so a crash between them leaves the event
                 re-deliverable and never acknowledged.
subjects         one row per (iss, sub): monotonic revocation watermark.
sid_revocations  permanent per-issuer sid kills, including sids never seen.
sessions         locally established sessions, with the generation they were
                 minted from and the revocation provenance.
hooks            controllable synchronization points.
"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path

SCHEMA_VERSION = "1"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS issuer_keys (
    iss       TEXT PRIMARY KEY,
    key_id    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS seen_events (
    event_id     TEXT PRIMARY KEY,
    event_iss    TEXT NOT NULL,
    body_sha256  TEXT NOT NULL,
    body_json    TEXT NOT NULL,
    first_seen   REAL NOT NULL,
    applied      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS subjects (
    iss               TEXT NOT NULL,
    sub               TEXT NOT NULL,
    cutoff_generation INTEGER NOT NULL DEFAULT 0,
    updated_at        REAL NOT NULL,
    PRIMARY KEY (iss, sub)
);

CREATE TABLE IF NOT EXISTS sid_revocations (
    iss            TEXT NOT NULL,
    sid            TEXT NOT NULL,
    generation     INTEGER,
    reason_event   TEXT NOT NULL,
    revoked_at     REAL NOT NULL,
    PRIMARY KEY (iss, sid)
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    iss          TEXT NOT NULL,
    sub          TEXT NOT NULL,
    sid          TEXT NOT NULL,
    generation   INTEGER NOT NULL,
    aud          TEXT NOT NULL,
    created_at   REAL NOT NULL,
    expires_at   REAL NOT NULL,
    revoked      INTEGER NOT NULL DEFAULT 0,
    revoked_at   REAL,
    revoked_by   TEXT,
    revoke_kind  TEXT,
    UNIQUE (iss, sid)
);

CREATE INDEX IF NOT EXISTS ix_sessions_subject
    ON sessions(iss, sub, generation);

CREATE TABLE IF NOT EXISTS request_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         REAL NOT NULL,
    kind       TEXT NOT NULL,
    detail     TEXT NOT NULL,
    decision   TEXT NOT NULL
);

-- Controllable synchronization points.  Consumed one at a time by the handler
-- named in ``phase``.  ``mode`` is 'die' (os._exit, a real abrupt death) or
-- 'sleep' (hold whatever lock the phase holds for ``millis``).
CREATE TABLE IF NOT EXISTS hooks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    phase      TEXT NOT NULL,
    port       INTEGER NOT NULL DEFAULT 0,
    mode       TEXT NOT NULL,
    millis     INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_hooks_phase ON hooks(phase, port);
"""


def connect(path: str | Path, *, timeout: float = 30.0) -> sqlite3.Connection:
    uri = f"file:{Path(path).as_posix()}?mode=rwc"
    conn = sqlite3.connect(
        uri,
        uri=True,
        timeout=timeout,
        isolation_level=None,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize_database(path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        # WAL lets readers proceed while a writer holds the write lock; the
        # writers are still fully serialized by BEGIN IMMEDIATE.
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = FULL")
        conn.executescript(SCHEMA_SQL)
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)",
            (SCHEMA_VERSION,),
        )
        # Seed the revocation epoch explicitly.  It is bumped in the same
        # transaction as every applied logout, and it is the only value a
        # read-only auth check consults before trusting its cache.
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES('revocation_epoch', '0')"
        )
    finally:
        conn.close()


@contextlib.contextmanager
def immediate(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """BEGIN IMMEDIATE ... COMMIT, rolling back on any exception."""

    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        with contextlib.suppress(sqlite3.Error):
            conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


@contextlib.contextmanager
def deferred(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    conn.execute("BEGIN")
    try:
        yield conn
    except BaseException:
        with contextlib.suppress(sqlite3.Error):
            conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")
