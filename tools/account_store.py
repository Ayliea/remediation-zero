# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Local sign-in accounts, in their own SQLite file.

`accounts.sqlite3` is in neither `AGENT_FILES` nor `SHARED` of
`tools.local_layout`, so no agent stage's docstore can open it. This is a thin
storage layer over plain `sqlite3`: the rules (password policy, lockout, roles)
live in `tools/accounts.py` and call these methods. No clock is read here;
every timestamp is supplied by the caller.

Every write runs inside `transaction()` (`BEGIN IMMEDIATE`). The two `spend_*`
methods are a single conditional UPDATE judged by `rowcount`, so a token or
code can be spent once even when two requests race. Standard library only.
"""

import json
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL COLLATE NOCASE,
        role TEXT CHECK(role IN ('owner','tech')),
        status TEXT CHECK(status IN ('invited','active','removed')),
        password_hash TEXT,
        totp_secret TEXT,
        last_totp_step INTEGER,
        failed_count INTEGER DEFAULT 0,
        first_failed_at REAL,
        locked_until REAL,
        real_ts REAL,
        sim_ts REAL,
        updated_real_ts REAL,
        updated_sim_ts REAL)""",
    """CREATE TABLE IF NOT EXISTS recovery_codes (
        account_id TEXT,
        code_hash TEXT,
        spent INTEGER DEFAULT 0,
        PRIMARY KEY (account_id, code_hash))""",
    """CREATE TABLE IF NOT EXISTS invites (
        token_hash TEXT PRIMARY KEY,
        kind TEXT CHECK(kind IN ('join','reset_password','reset_mfa','recover')),
        email TEXT,
        role TEXT,
        account_id TEXT,
        created_by TEXT,
        totp_secret TEXT,
        expires_at REAL,
        used INTEGER DEFAULT 0,
        revoked INTEGER DEFAULT 0,
        real_ts REAL,
        sim_ts REAL)""",
    """CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        account_id TEXT,
        csrf TEXT,
        created_at REAL,
        last_seen REAL,
        confirmed_until REAL)""",
    """CREATE TABLE IF NOT EXISTS account_events (
        id INTEGER PRIMARY KEY,
        event TEXT,
        actor_id TEXT,
        subject_id TEXT,
        via TEXT,
        source TEXT,
        detail TEXT,
        real_ts REAL,
        sim_ts REAL)""",
    # Values private to this file: the per-workspace HMAC key for unknown
    # sign-in emails (`email_hmac_key`, 32 random bytes as hex) and the
    # timing pad's filler row (`write_pad`, see `pad_write`).
    """CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT)""",
)

_EMAIL_KEY = "email_hmac_key"
_PAD_KEY = "write_pad"

# Keys an event's `detail` may carry. Anything else is refused, and a key that
# contains one of the words in _SECRET_WORDS is refused even if added here,
# unless it is also named in _REVIEWED_KEYS.
ALLOWED_DETAIL_KEYS = frozenset({
    "from", "to", "role", "kind", "reason", "email", "count", "outcome",
    "locked_until", "invite_kind", "mfa", "method", "email_hmac", "connection", "jobs",
})
_SECRET_WORDS = ("password", "code", "token", "secret", "totp", "session", "csrf", "hash",
                 "sha", "hmac")
# Allowlisted keys that contain a secret word, each reviewed by name; the
# denylist still refuses every other such key. `email_hmac` is HMAC-SHA256 of
# a typed, well-formed email under the workspace key in `meta`: owners can see
# repeated guesses at one address without the address, and without the
# offline dictionary attack an unsalted hash allows. Adding a name here is a
# deliberate security decision.
_REVIEWED_KEYS = frozenset({"email_hmac"})


class AccountStore:
    def __init__(self, path: Path) -> None:
        from tools.local_layout import _private_file  # file is 0600 before SQLite opens it
        self.path = Path(path)
        _private_file(self.path)
        conn = self._connect()
        try:
            for ddl in _SCHEMA:
                conn.execute(ddl)
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        # isolation_level=None: transactions are explicit (BEGIN IMMEDIATE).
        conn = sqlite3.connect(self.path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Cursor]:
        """A cursor inside BEGIN IMMEDIATE: COMMIT on exit, ROLLBACK on error."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn.cursor()
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")
        finally:
            conn.close()

    def _one(self, sql: str, args: tuple = ()) -> Optional[sqlite3.Row]:
        conn = self._connect()
        try:
            return conn.execute(sql, args).fetchone()
        finally:
            conn.close()

    def account_by_email(self, email: str) -> Optional[sqlite3.Row]:
        return self._one("SELECT * FROM accounts WHERE email = ?", (email.strip().lower(),))

    def account_by_id(self, account_id: str) -> Optional[sqlite3.Row]:
        return self._one("SELECT * FROM accounts WHERE id = ?", (account_id,))

    def active_owner_count(self) -> int:
        return self._one("SELECT COUNT(*) FROM accounts WHERE role = 'owner' "
                         "AND status = 'active'")[0]

    def count_accounts(self) -> int:
        return self._one("SELECT COUNT(*) FROM accounts")[0]

    def insert_event(self, event: str, actor_id: Optional[str], subject_id: Optional[str],
                     via: Optional[str], source: Optional[str],
                     detail: Optional[dict[str, Any]], *, real_ts: float, sim_ts: float,
                     cur: Optional[sqlite3.Cursor] = None) -> None:
        """Append an audit row. `detail` keys are checked before anything is written.

        With `cur` (a cursor from `transaction()`), the row is written in that
        transaction, so it commits or rolls back with the change it records.
        """
        for key in (detail or {}):
            low = str(key).lower()
            if key not in ALLOWED_DETAIL_KEYS or (
                    key not in _REVIEWED_KEYS and any(w in low for w in _SECRET_WORDS)):
                raise ValueError(f"event detail key not allowed: {key!r}")
        text = json.dumps(detail, sort_keys=True) if detail else None
        args = (event, actor_id, subject_id, via, source, text, real_ts, sim_ts)
        sql = ("INSERT INTO account_events (event, actor_id, subject_id, via, source, "
               "detail, real_ts, sim_ts) VALUES (?,?,?,?,?,?,?,?)")
        if cur is not None:
            cur.execute(sql, args)
            return
        with self.transaction() as own:
            own.execute(sql, args)

    def events(self, limit: int = 200) -> list[sqlite3.Row]:
        conn = self._connect()
        try:
            return conn.execute("SELECT * FROM account_events ORDER BY id DESC LIMIT ?",
                                (int(limit),)).fetchall()
        finally:
            conn.close()

    # Read-only views for the owners' Accounts page. They carry no credential column:
    # no password hash, TOTP secret, token hash or lockout counter leaves this module.

    def account_list(self) -> list[sqlite3.Row]:
        """Every account, removed ones included (so old events still name them)."""
        conn = self._connect()
        try:
            return conn.execute("SELECT id, email, role, status FROM accounts "
                                "ORDER BY status = 'removed', email").fetchall()
        finally:
            conn.close()

    def live_invites(self, now: float) -> list[sqlite3.Row]:
        """Unused, unrevoked, unexpired links, soonest to expire first. `id` is the row's
        SQLite rowid: the page names a link by it, never by its token hash."""
        conn = self._connect()
        try:
            return conn.execute("SELECT rowid AS id, kind, email, role, expires_at FROM invites "
                                "WHERE used = 0 AND revoked = 0 AND expires_at > ? "
                                "ORDER BY expires_at, rowid", (now,)).fetchall()
        finally:
            conn.close()

    def invite_hash(self, invite_id: int) -> Optional[str]:
        """The token hash of the link with this rowid, for `Accounts.revoke_invite`; None if none."""
        row = self._one("SELECT token_hash FROM invites WHERE rowid = ?", (int(invite_id),))
        return row[0] if row is not None else None

    def spend_invite(self, token_hash: str, now: float,
                     cur: Optional[sqlite3.Cursor] = None) -> Optional[sqlite3.Row]:
        """Mark an unused, unrevoked, unexpired invite used and return it; else None.

        With `cur`, the spend happens inside the caller's transaction, so a
        later failure in that transaction rolls it back and the link survives.
        """
        if cur is not None:
            return self._spend_invite(cur, token_hash, now)
        with self.transaction() as own:
            return self._spend_invite(own, token_hash, now)

    @staticmethod
    def _spend_invite(cur: sqlite3.Cursor, token_hash: str, now: float) -> Optional[sqlite3.Row]:
        cur.execute("UPDATE invites SET used = 1 WHERE token_hash = ? AND used = 0 "
                    "AND revoked = 0 AND expires_at > ?", (token_hash, now))
        if cur.rowcount != 1:
            return None
        return cur.execute("SELECT * FROM invites WHERE token_hash = ?",
                           (token_hash,)).fetchone()

    @staticmethod
    def email_key(cur: sqlite3.Cursor) -> bytes:
        """The workspace's 32-byte email HMAC key, created on first need inside
        the caller's transaction. Never logged, never put in an event or error."""
        cur.execute("INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)",
                    (_EMAIL_KEY, secrets.token_bytes(32).hex()))
        return bytes.fromhex(cur.execute("SELECT value FROM meta WHERE key = ?",
                                         (_EMAIL_KEY,)).fetchone()[0])

    @staticmethod
    def pad_write(cur: sqlite3.Cursor) -> None:
        """Change one row so the transaction commits a real write (journal and
        fsync), as a lockout reservation does: sign-in failure paths stay alike
        in cost. The value must differ each time; SQLite skips the disk write
        for an update that leaves the page unchanged. It is random filler,
        meaningful to nothing."""
        cur.execute("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) "
                    "DO UPDATE SET value = excluded.value",
                    (_PAD_KEY, secrets.token_hex(8)))

    def spend_recovery_code(self, account_id: str, code_hash: str,
                            cur: Optional[sqlite3.Cursor] = None) -> bool:
        """Spend an unspent recovery code; True exactly once.

        With `cur`, the spend happens inside the caller's transaction (as for
        `spend_invite`), so a later failure there leaves the code unspent.
        """
        if cur is not None:
            return self._spend_code(cur, account_id, code_hash)
        with self.transaction() as own:
            return self._spend_code(own, account_id, code_hash)

    @staticmethod
    def _spend_code(cur: sqlite3.Cursor, account_id: str, code_hash: str) -> bool:
        cur.execute("UPDATE recovery_codes SET spent = 1 WHERE account_id = ? "
                    "AND code_hash = ? AND spent = 0", (account_id, code_hash))
        return cur.rowcount == 1
