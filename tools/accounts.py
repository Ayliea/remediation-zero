# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Local accounts: the first account, invites, resets, roles and removal.

The rules live here; `tools.account_store` only stores rows and
`tools.access` holds the permission table. Every mutation reads what it checks
and writes what it changes inside one `store.transaction()` (BEGIN IMMEDIATE),
on the transaction's own cursor, so two requests cannot both pass a check that
only one of them should: the last active owner cannot be removed or demoted
even by two owners acting at once, and a link is spent exactly once.

Every mutation writes one `account_events` row in that same transaction and
one structured log line after it commits. Neither ever carries a password,
code, token, token hash, TOTP secret, session id or email address; accounts
are named by their opaque id. Persisted records are stamped by `SimClock`
(`real_ts`, `sim_ts`). Link expiry and the TOTP window are runtime security
timers and use the injected wall clock `now`, by default `clock.now().real_ts`
(wall time in every clock mode; never shifted by simulated time).

A pending invite is not a joined owner: only `active` accounts count. Removed
accounts keep their row, marked `removed`, so records that name them still
resolve; their email is not invited again (`email_taken`). An `invited`
account whose links have all expired or been revoked may be invited again,
reusing its row.

Standard library only.
"""

import hashlib
import json
import logging
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Any, Callable, Optional

from tools import access, passwords, totp
from tools.account_store import AccountStore
from tools.clock import SimClock, Stamp

logger = logging.getLogger("remediation_zero.accounts")

INVITE_TTL_SECONDS = 7 * 24 * 3600
ROLES = ("owner", "tech")
RESET_KINDS = ("reset_password", "reset_mfa")
# Invite kinds whose acceptance enrols a new TOTP secret and recovery codes.
_ENROLS = ("join", "reset_mfa", "recover")
_MAX_EMAIL = 254


class AccountRefused(Exception):
    """A rule refused the request. `code` is one of: accounts_exist,
    not_allowed, last_owner, no_such_account, invalid_link, bad_code,
    password, email_taken. For `password`, `reason` is PasswordRefused's
    reason ('too_short', 'too_long', 'breached'), 'missing', or 'incorrect'
    when a current password did not match."""

    def __init__(self, code: str, reason: Optional[str] = None) -> None:
        super().__init__(code)
        self.code = code
        self.reason = reason


@dataclass(frozen=True)
class InviteView:
    kind: str
    email: str
    role: str
    totp_secret: Optional[str]


def normalise_email(email: str) -> str:
    """Strip and lowercase; raise ValueError on anything that is not one plausible address."""
    if not isinstance(email, str):
        raise ValueError("email must be text")
    value = email.strip().lower()
    local, _, domain = value.partition("@")
    if (len(value) > _MAX_EMAIL or value.count("@") != 1 or not local or not domain
            or any(ch.isspace() for ch in value) or not value.isprintable()):
        raise ValueError("not an email address")
    return value


def _check_role(role: str) -> None:
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _log(event: str, actor_id: Optional[str], subject_id: Optional[str],
         via: Optional[str], detail: Optional[dict[str, Any]]) -> None:
    logger.info(json.dumps(
        {"event": event, "actor_id": actor_id, "subject_id": subject_id, "via": via,
         **(detail or {})},
        sort_keys=True, default=str,
    ))


class Accounts:
    def __init__(self, store: AccountStore, clock: SimClock,
                 now: Optional[Callable[[], float]] = None) -> None:
        """`now` is the wall clock for link expiry and the TOTP window. By
        default it is the clock's `real_ts`, which is always wall time: a tool
        module never reads the system clock itself (tests/test_clock.py)."""
        self.store = store
        self.clock = clock
        self._now = now if now is not None else (lambda: clock.now().real_ts)

    # --- reads ----------------------------------------------------------

    def owner_exists(self) -> bool:
        """True when at least one *active* owner exists; an invite does not count."""
        return self.store.active_owner_count() > 0

    def invite_view(self, token: str) -> Optional[InviteView]:
        """What a live link is for, without spending it. An enrolling link
        (join, reset_mfa, recover) gets its TOTP secret on first view, kept so
        the secret the person scans is the one accepted."""
        if not isinstance(token, str) or not token:
            return None
        th = _token_hash(token)
        with self.store.transaction() as cur:
            found = self._live(cur, th, self._now())
            if found is None:
                return None
            inv, acct = found
            secret = inv["totp_secret"]
            if inv["kind"] in _ENROLS and secret is None:
                secret = totp.new_secret()
                cur.execute("UPDATE invites SET totp_secret = ? WHERE token_hash = ?",
                            (secret, th))
        return InviteView(inv["kind"], acct["email"], acct["role"],
                          secret if inv["kind"] in _ENROLS else None)

    # --- mutations --------------------------------------------------------

    def setup_first(self, email: str, role: str, password: str, secret: str, code: str,
                    *, via: Optional[str] = None, source: Optional[str] = None) -> list[str]:
        """Create the first, active account; return its 10 recovery codes.

        `secret` is the TOTP secret the caller showed the person and `code`
        must match it. Refused once any account exists, invited or removed
        ones included."""
        email = normalise_email(email)
        _check_role(role)
        if self.store.count_accounts() > 0:
            raise AccountRefused("accounts_exist")
        clean = self._new_password(password)
        step = totp.match(secret, code, self._now(), None)
        if step is None:
            raise AccountRefused("bad_code")
        pw_hash = passwords.hash_password(clean)
        codes = passwords.new_recovery_codes()
        stamp = self.clock.now()
        account_id = secrets.token_hex(16)
        detail = {"role": role}
        with self.store.transaction() as cur:
            if cur.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] > 0:
                raise AccountRefused("accounts_exist")
            cur.execute("INSERT INTO accounts (id, email, role, status, password_hash, "
                        "totp_secret, last_totp_step, real_ts, sim_ts, updated_real_ts, "
                        "updated_sim_ts) VALUES (?,?,?,'active',?,?,?,?,?,?,?)",
                        (account_id, email, role, pw_hash, secret, step, stamp.real_ts,
                         stamp.sim_ts, stamp.real_ts, stamp.sim_ts))
            self._replace_codes(cur, account_id, codes)
            self._event(cur, "setup", account_id, account_id, via, source, detail, stamp)
        _log("setup", account_id, account_id, via, detail)
        return codes

    def invite(self, by_id: str, email: str, role: str, *,
               via: Optional[str] = None, source: Optional[str] = None) -> str:
        """Create a join link for `email` as `role`; return the raw token, once."""
        email = normalise_email(email)
        _check_role(role)
        now = self._now()
        stamp = self.clock.now()
        detail = {"invite_kind": "join", "role": role}
        with self.store.transaction() as cur:
            actor = self._actor(cur, by_id)
            if not access.may_invite(actor["role"], role, self._owners(cur) > 0):
                raise AccountRefused("not_allowed")
            existing = cur.execute("SELECT * FROM accounts WHERE email = ?",
                                   (email,)).fetchone()
            if existing is not None:
                if existing["status"] != "invited" or self._has_live_invite(
                        cur, existing["id"], now):
                    raise AccountRefused("email_taken")
                account_id = existing["id"]
                cur.execute("UPDATE accounts SET role = ?, updated_real_ts = ?, "
                            "updated_sim_ts = ? WHERE id = ?",
                            (role, stamp.real_ts, stamp.sim_ts, account_id))
            else:
                account_id = secrets.token_hex(16)
                cur.execute("INSERT INTO accounts (id, email, role, status, real_ts, sim_ts, "
                            "updated_real_ts, updated_sim_ts) VALUES (?,?,?,'invited',?,?,?,?)",
                            (account_id, email, role, stamp.real_ts, stamp.sim_ts,
                             stamp.real_ts, stamp.sim_ts))
            token = self._insert_invite(cur, "join", email, role, account_id, actor["id"],
                                        now, stamp)
            self._event(cur, "invite_created", actor["id"], account_id, via, source, detail,
                        stamp)
        _log("invite_created", actor["id"], account_id, via, detail)
        return token

    def reset_link(self, by_id: str, account_id: str, kind: str, *,
                   via: Optional[str] = None, source: Optional[str] = None) -> str:
        """An owner makes a one-time link for someone else to set a new password
        (`reset_password`) or MFA (`reset_mfa`). Nothing changes until it is used."""
        if kind not in RESET_KINDS:
            raise ValueError(f"kind must be one of {RESET_KINDS}")
        now = self._now()
        stamp = self.clock.now()
        detail = {"invite_kind": kind}
        with self.store.transaction() as cur:
            actor = self._actor(cur, by_id)
            if not access.allowed(actor["role"], "manage_accounts") or account_id == actor["id"]:
                raise AccountRefused("not_allowed")
            target = self._account(cur, account_id)
            if target is None or target["status"] != "active":
                raise AccountRefused("no_such_account")
            token = self._insert_invite(cur, kind, target["email"], target["role"],
                                        target["id"], actor["id"], now, stamp)
            self._event(cur, "reset_link_created", actor["id"], target["id"], via, source,
                        detail, stamp)
        _log("reset_link_created", actor["id"], target["id"], via, detail)
        return token

    def recover_owner(self, email: str, promote: bool = False, *,
                      source: Optional[str] = None) -> str:
        """The server command's last resort when no owner can sign in.

        For an active owner (or an active tech with `promote`, who becomes
        owner): clear password and MFA, end every session, revoke their other
        links and return a one-time `recover` link to set new ones. Refuses an
        email with no active account; never creates one."""
        email = normalise_email(email)
        now = self._now()
        stamp = self.clock.now()
        via = "command_line"
        with self.store.transaction() as cur:
            row = cur.execute("SELECT * FROM accounts WHERE email = ?", (email,)).fetchone()
            if row is None or row["status"] != "active":
                raise AccountRefused("no_such_account")
            if row["role"] != "owner" and not promote:
                raise AccountRefused("not_allowed")
            detail = ({"role": "owner"} if row["role"] == "owner"
                      else {"from": row["role"], "to": "owner"})
            cur.execute("UPDATE accounts SET role = 'owner', password_hash = NULL, "
                        "totp_secret = NULL, last_totp_step = NULL, failed_count = 0, "
                        "first_failed_at = NULL, locked_until = NULL, updated_real_ts = ?, "
                        "updated_sim_ts = ? WHERE id = ?",
                        (stamp.real_ts, stamp.sim_ts, row["id"]))
            cur.execute("DELETE FROM recovery_codes WHERE account_id = ?", (row["id"],))
            self._revoke_links(cur, row["id"])
            self._end_sessions(cur, row["id"])
            token = self._insert_invite(cur, "recover", email, "owner", row["id"], None,
                                        now, stamp)
            self._event(cur, "recover_owner", None, row["id"], via, source, detail, stamp)
        _log("recover_owner", None, row["id"], via, detail)
        return token

    def accept_invite(self, token: str, password: Optional[str], code: Optional[str], *,
                      current_password: Optional[str] = None,
                      current_code: Optional[str] = None,
                      via: Optional[str] = None,
                      source: Optional[str] = None) -> tuple[str, Optional[list[str]]]:
        """Use a link. Returns (account id, recovery codes or None).

        - join, recover: `password` is the new password, `code` is from the
          link's new TOTP secret.
        - reset_password: `password` is the new password, `current_code` is
          from the account's existing TOTP secret.
        - reset_mfa: `current_password` is the account's password, `code` is
          from the link's new TOTP secret.

        Everything is checked before the link is spent, and the spend commits
        with the account change, so a refused attempt leaves the link usable.
        """
        if not isinstance(token, str) or not token:
            raise AccountRefused("invalid_link")
        th = _token_hash(token)
        now = self._now()
        with self.store.transaction() as cur:     # a read; BEGIN IMMEDIATE keeps it simple
            found = self._live(cur, th, now)
        if found is None:
            raise AccountRefused("invalid_link")
        inv, acct = found
        kind = inv["kind"]

        pw_hash = None
        if kind in ("join", "recover", "reset_password"):
            pw_hash = passwords.hash_password(self._new_password(password))
        if kind == "reset_mfa":
            if not isinstance(current_password, str) or not passwords.verify(
                    current_password, acct["password_hash"]):
                raise AccountRefused("password", "incorrect")
        if kind == "reset_password":
            secret = acct["totp_secret"]
            step = (totp.match(secret, current_code, now, acct["last_totp_step"])
                    if secret else None)
        else:
            secret = inv["totp_secret"]          # set on first view
            step = totp.match(secret, code, now, None) if secret else None
        if step is None:
            raise AccountRefused("bad_code")
        codes = passwords.new_recovery_codes() if kind in _ENROLS else None

        stamp = self.clock.now()
        account_id = acct["id"]
        with self.store.transaction() as cur:
            spent = self.store.spend_invite(th, now, cur=cur)
            if spent is None:
                raise AccountRefused("invalid_link")
            fresh = self._account(cur, account_id)
            if not self._fits(spent, fresh):
                raise AccountRefused("invalid_link")
            if kind == "reset_password" and (
                    fresh["totp_secret"] != secret or (fresh["last_totp_step"] is not None
                                                       and step <= fresh["last_totp_step"])):
                raise AccountRefused("bad_code")    # the code was used meanwhile
            if kind == "reset_mfa" and fresh["password_hash"] != acct["password_hash"]:
                raise AccountRefused("password", "incorrect")
            touch = (stamp.real_ts, stamp.sim_ts, account_id)
            if kind in ("join", "recover"):
                cur.execute("UPDATE accounts SET status = 'active', password_hash = ?, "
                            "totp_secret = ?, last_totp_step = ?, failed_count = 0, "
                            "first_failed_at = NULL, locked_until = NULL, updated_real_ts = ?, "
                            "updated_sim_ts = ? WHERE id = ?", (pw_hash, secret, step, *touch))
            elif kind == "reset_password":
                cur.execute("UPDATE accounts SET password_hash = ?, last_totp_step = ?, "
                            "failed_count = 0, first_failed_at = NULL, locked_until = NULL, "
                            "updated_real_ts = ?, updated_sim_ts = ? WHERE id = ?",
                            (pw_hash, step, *touch))
            else:
                cur.execute("UPDATE accounts SET totp_secret = ?, last_totp_step = ?, "
                            "updated_real_ts = ?, updated_sim_ts = ? WHERE id = ?",
                            (secret, step, *touch))
            if codes is not None:
                self._replace_codes(cur, account_id, codes)
            self._end_sessions(cur, account_id)
            event, detail = {
                "join": ("invite_accepted", {"invite_kind": "join", "role": fresh["role"]}),
                "recover": ("invite_accepted", {"invite_kind": "recover",
                                                "role": fresh["role"]}),
                "reset_password": ("password_reset", None),
                "reset_mfa": ("mfa_reset", None),
            }[kind]
            self._event(cur, event, account_id, account_id, via, source, detail, stamp)
        _log(event, account_id, account_id, via, detail)
        return account_id, codes

    def revoke_invite(self, by_id: str, token_hash: str, *,
                      via: Optional[str] = None, source: Optional[str] = None) -> None:
        """Revoke an unused link. An owner may revoke any; anyone may revoke one they made."""
        stamp = self.clock.now()
        with self.store.transaction() as cur:
            actor = self._actor(cur, by_id)
            inv = cur.execute("SELECT * FROM invites WHERE token_hash = ?",
                              (token_hash,)).fetchone()
            if inv is None or inv["used"] or inv["revoked"]:
                raise AccountRefused("invalid_link")
            if not (access.allowed(actor["role"], "manage_accounts")
                    or inv["created_by"] == actor["id"]):
                raise AccountRefused("not_allowed")
            cur.execute("UPDATE invites SET revoked = 1 WHERE token_hash = ?", (token_hash,))
            detail = {"invite_kind": inv["kind"]}
            self._event(cur, "invite_revoked", actor["id"], inv["account_id"], via, source,
                        detail, stamp)
        _log("invite_revoked", actor["id"], inv["account_id"], via, detail)

    def set_role(self, by_id: str, account_id: str, role: str, *,
                 via: Optional[str] = None, source: Optional[str] = None) -> None:
        """An owner changes an active account's role. The last active owner
        cannot be demoted, by anyone including themself. Ends the subject's sessions."""
        _check_role(role)
        stamp = self.clock.now()
        with self.store.transaction() as cur:
            actor = self._actor(cur, by_id)
            if not access.allowed(actor["role"], "manage_accounts"):
                raise AccountRefused("not_allowed")
            target = self._account(cur, account_id)
            if target is None or target["status"] != "active":
                raise AccountRefused("no_such_account")
            if target["role"] == role:
                return                                   # nothing changes, nothing recorded
            if target["role"] == "owner" and self._owners(cur) <= 1:
                raise AccountRefused("last_owner")
            cur.execute("UPDATE accounts SET role = ?, updated_real_ts = ?, updated_sim_ts = ? "
                        "WHERE id = ?", (role, stamp.real_ts, stamp.sim_ts, account_id))
            self._end_sessions(cur, account_id)
            detail = {"from": target["role"], "to": role}
            self._event(cur, "role_changed", actor["id"], account_id, via, source, detail, stamp)
        _log("role_changed", actor["id"], account_id, via, detail)

    def remove(self, by_id: str, account_id: str, *,
               via: Optional[str] = None, source: Optional[str] = None) -> None:
        """An owner removes an account (active or invited). The row stays,
        marked removed, with its credentials, recovery codes, links and
        sessions gone. The last active owner cannot be removed."""
        stamp = self.clock.now()
        with self.store.transaction() as cur:
            actor = self._actor(cur, by_id)
            if not access.allowed(actor["role"], "manage_accounts"):
                raise AccountRefused("not_allowed")
            target = self._account(cur, account_id)
            if target is None or target["status"] == "removed":
                raise AccountRefused("no_such_account")
            if (target["status"] == "active" and target["role"] == "owner"
                    and self._owners(cur) <= 1):
                raise AccountRefused("last_owner")
            cur.execute("UPDATE accounts SET status = 'removed', password_hash = NULL, "
                        "totp_secret = NULL, last_totp_step = NULL, updated_real_ts = ?, "
                        "updated_sim_ts = ? WHERE id = ?",
                        (stamp.real_ts, stamp.sim_ts, account_id))
            cur.execute("DELETE FROM recovery_codes WHERE account_id = ?", (account_id,))
            self._revoke_links(cur, account_id)
            self._end_sessions(cur, account_id)
            detail = {"role": target["role"]}
            self._event(cur, "removed", actor["id"], account_id, via, source, detail, stamp)
        _log("removed", actor["id"], account_id, via, detail)

    # --- helpers (all take the transaction's cursor) ---------------------

    @staticmethod
    def _new_password(password: Optional[str]) -> str:
        if not isinstance(password, str):
            raise AccountRefused("password", "missing")
        try:
            return passwords.check_new(password)
        except passwords.PasswordRefused as exc:
            raise AccountRefused("password", exc.reason) from None

    @staticmethod
    def _account(cur: sqlite3.Cursor, account_id: Optional[str]) -> Optional[sqlite3.Row]:
        if account_id is None:
            return None
        return cur.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()

    def _actor(self, cur: sqlite3.Cursor, by_id: Optional[str]) -> sqlite3.Row:
        row = self._account(cur, by_id)
        if row is None or row["status"] != "active":
            raise AccountRefused("not_allowed")
        return row

    @staticmethod
    def _owners(cur: sqlite3.Cursor) -> int:
        return cur.execute("SELECT COUNT(*) FROM accounts WHERE role = 'owner' "
                           "AND status = 'active'").fetchone()[0]

    @staticmethod
    def _fits(inv: sqlite3.Row, acct: Optional[sqlite3.Row]) -> bool:
        """A join link is for an invited account; every other link for an active one."""
        if acct is None:
            return False
        return acct["status"] == ("invited" if inv["kind"] == "join" else "active")

    def _live(self, cur: sqlite3.Cursor, th: str,
              now: float) -> Optional[tuple[sqlite3.Row, sqlite3.Row]]:
        inv = cur.execute("SELECT * FROM invites WHERE token_hash = ? AND used = 0 "
                          "AND revoked = 0 AND expires_at > ?", (th, now)).fetchone()
        if inv is None:
            return None
        acct = self._account(cur, inv["account_id"])
        return (inv, acct) if self._fits(inv, acct) else None

    @staticmethod
    def _has_live_invite(cur: sqlite3.Cursor, account_id: str, now: float) -> bool:
        return cur.execute("SELECT 1 FROM invites WHERE account_id = ? AND used = 0 "
                           "AND revoked = 0 AND expires_at > ?",
                           (account_id, now)).fetchone() is not None

    @staticmethod
    def _insert_invite(cur: sqlite3.Cursor, kind: str, email: str, role: str,
                       account_id: str, created_by: Optional[str], now: float,
                       stamp: Stamp) -> str:
        token = secrets.token_urlsafe(32)                 # 256 bits
        cur.execute("INSERT INTO invites (token_hash, kind, email, role, account_id, "
                    "created_by, expires_at, real_ts, sim_ts) VALUES (?,?,?,?,?,?,?,?,?)",
                    (_token_hash(token), kind, email, role, account_id, created_by,
                     now + INVITE_TTL_SECONDS, stamp.real_ts, stamp.sim_ts))
        return token

    @staticmethod
    def _revoke_links(cur: sqlite3.Cursor, account_id: str) -> None:
        cur.execute("UPDATE invites SET revoked = 1 WHERE account_id = ? AND used = 0",
                    (account_id,))

    @staticmethod
    def _end_sessions(cur: sqlite3.Cursor, account_id: str) -> None:
        cur.execute("DELETE FROM sessions WHERE account_id = ?", (account_id,))

    @staticmethod
    def _replace_codes(cur: sqlite3.Cursor, account_id: str, codes: list[str]) -> None:
        cur.execute("DELETE FROM recovery_codes WHERE account_id = ?", (account_id,))
        cur.executemany("INSERT INTO recovery_codes (account_id, code_hash) VALUES (?, ?)",
                        [(account_id, passwords.recovery_hash(c)) for c in codes])

    def _event(self, cur: sqlite3.Cursor, event: str, actor_id: Optional[str],
               subject_id: Optional[str], via: Optional[str], source: Optional[str],
               detail: Optional[dict[str, Any]], stamp: Stamp) -> None:
        self.store.insert_event(event, actor_id, subject_id, via, source, detail,
                                real_ts=stamp.real_ts, sim_ts=stamp.sim_ts, cur=cur)
