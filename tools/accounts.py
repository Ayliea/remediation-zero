# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Local accounts: the first account, invites, resets, roles, removal,
sign-in, sessions, lockout and re-confirmation.

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
resolve. A removed account, or an `invited` one whose links have all expired
or been revoked, may be invited again: the same row and id come back as
`invited` with the new role (the event says `reason: reinvited` for a removed
one), so old records still name the same person. An active account's email,
or one with a live link, is `email_taken`.

No TOTP secret is stored for a link: every view of an enrolling link shows a
new one, and acceptance enrols the one the submitted page carried.

Sign-in has one failure path. An unknown email, an invited or removed
account, a locked account, a wrong password and a wrong code all return None,
write one `sign_in_failed` event of the same shape, and run exactly one scrypt
(`passwords.verify(pw, None)` when there is no hash to check against), and
each commits the same number of write transactions: a path that reserves no
attempt (unknown, invited, removed, malformed, locked) commits a pad write
first (`AccountStore.pad_write`), so the lockout reservation's fsync is not a
timing tell. For a well-formed email with no account the event names nobody
and carries only `email_hmac`, HMAC-SHA256 of the normalised email under the
workspace's random key (`AccountStore.email_key`); malformed input records
`{"reason": "malformed"}`. The structured log line for a failure carries no
email-derived value at all. Every guess at a known, active account is reserved against the lockout before
it is verified (`_reserve_attempt`, shared with reset links and re-confirm),
so parallel guesses cannot exceed LOCK_AFTER and all three share one counter.

Sessions: a 256-bit token, stored only as its SHA-256; a per-session CSRF
token; idle IDLE_SECONDS and absolute ABSOLUTE_SECONDS. `session()` reads the
account row on every call, so a removed account's sessions end and a changed
role applies on the next request even if it was written by another path.

Standard library only.
"""

import hashlib
import hmac
import json
import logging
import math
import secrets
import sqlite3
import threading
import time
from collections import OrderedDict, deque
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
# Lockout, shared with sign-in: LOCK_AFTER failures within LOCK_WINDOW seconds
# lock the account for LOCK_SECONDS. Runtime security timers on wall time.
LOCK_AFTER = 5
LOCK_WINDOW = 15 * 60
LOCK_SECONDS = 15 * 60
# Sessions and re-confirmation, runtime security timers on the same wall clock.
IDLE_SECONDS = 30 * 60
ABSOLUTE_SECONDS = 12 * 3600
CONFIRM_SECONDS = 5 * 60
_VIA = "dashboard"


def _is_locked(row: sqlite3.Row, now: float) -> bool:
    return row["locked_until"] is not None and row["locked_until"] > now


class AccountRefused(Exception):
    """A rule refused the request. `code` is one of: accounts_exist,
    not_allowed, last_owner, no_such_account, invalid_link, bad_code,
    password, email_taken, locked (a reset link used while the account is
    locked out). For `password`, `reason` is PasswordRefused's
    reason ('too_short', 'too_long', 'breached'), 'missing', or 'incorrect'
    when a current password did not match."""

    def __init__(self, code: str, reason: Optional[str] = None) -> None:
        super().__init__(code)
        self.code = code
        self.reason = reason


@dataclass(frozen=True)
class Session:
    """A live session. `role` is the account's role as of this request and
    `confirmed` is True while a re-confirmation (CONFIRM_SECONDS) lasts."""
    account_id: str
    email: str
    role: str
    csrf: str
    confirmed: bool


class _Failed(Exception):
    """Internal: roll back a sign-in or confirm transaction."""


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


_SECRET_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def _is_secret(value: Any) -> bool:
    """A TOTP secret as totp.new_secret makes them: 32 base32 characters."""
    return isinstance(value, str) and len(value) == 32 and set(value) <= _SECRET_CHARS


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

    def overview(self, limit: int = 200) -> dict[str, list[sqlite3.Row]]:
        """What the owners' Accounts page lists: every account (id, email, role,
        status), the live links (rowid id, kind, email, role, expires_at) and the
        newest `limit` events. Read only; no credential column is included. The
        caller checks `manage_accounts` / `view_audit` before showing any of it."""
        return {"accounts": self.store.account_list(),
                "invites": self.store.live_invites(self._now()),
                "events": self.store.events(limit)}

    def revoke_listed_invite(self, by_id: str, invite_id: int, *,
                             via: Optional[str] = None, source: Optional[str] = None) -> None:
        """`revoke_invite` for a link named by its row id, as the Accounts page lists it."""
        token_hash = self.store.invite_hash(invite_id)
        if token_hash is None:
            raise AccountRefused("invalid_link")
        self.revoke_invite(by_id, token_hash, via=via, source=source)

    def invite_view(self, token: str) -> Optional[InviteView]:
        """What a live link is for, without spending it. For an enrolling link
        (join, reset_mfa, recover) every view carries a new TOTP secret, and
        nothing is stored: the page puts it in its form under a server MAC, and
        `accept_invite` enrols the secret the submitted form carried. So
        whatever fetched the link before the person (a mail scanner, a chat
        unfurler) saw a secret that is never enrolled. A link whose maker no
        longer has the authority to issue it is revoked and shows nothing."""
        if not isinstance(token, str) or not token:
            return None
        th = _token_hash(token)
        stamp = self.clock.now()
        voided = None
        with self.store.transaction() as cur:
            found = self._live(cur, th, self._now())
            if found is None:
                return None
            inv, acct = found
            voided = self._void_if_unauthorised(cur, inv, stamp)
        if voided is not None:
            _log("invite_revoked", None, inv["account_id"], None, voided)
            return None
        return InviteView(inv["kind"], acct["email"], acct["role"],
                          totp.new_secret() if inv["kind"] in _ENROLS else None)

    # --- mutations --------------------------------------------------------

    def setup_first(self, email: str, role: str, password: str, secret: str, code: str,
                    *, via: Optional[str] = None, source: Optional[str] = None,
                    start_session: bool = False) -> Any:
        """Create the first, active account; return its 10 recovery codes.

        `secret` is the TOTP secret the caller showed the person and `code`
        must match it. Refused once any account exists, invited or removed
        ones included. With `start_session` (the setup page) the account is
        also signed in, in the same transaction, and the return value is
        `(codes, session token)`."""
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
            token = (self._new_session(cur, account_id, self._now(), source, "setup", stamp)
                     if start_session else None)
        _log("setup", account_id, account_id, via, detail)
        if token is not None:
            _log("sign_in", account_id, account_id, _VIA, {"method": "setup"})
            return codes, token
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
                if existing["status"] == "active" or self._has_live_invite(
                        cur, existing["id"], now):
                    raise AccountRefused("email_taken")
                account_id = existing["id"]
                if existing["status"] == "removed":
                    # The same row and id come back, so records that name the person
                    # still resolve to them; removal already cleared its credentials.
                    detail["reason"] = "reinvited"
                cur.execute("UPDATE accounts SET role = ?, status = 'invited', "
                            "failed_count = 0, first_failed_at = NULL, locked_until = NULL, "
                            "updated_real_ts = ?, updated_sim_ts = ? WHERE id = ?",
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
            if row["role"] != "owner":
                # links the tech made were issued as a tech
                self._revoke_made_by(cur, row["id"])
            self._revoke_unauthorised_joins(cur)
            token = self._insert_invite(cur, "recover", email, "owner", row["id"], None,
                                        now, stamp)
            self._event(cur, "recover_owner", None, row["id"], via, source, detail, stamp)
        _log("recover_owner", None, row["id"], via, detail)
        return token

    def accept_invite(self, token: str, password: Optional[str], code: Optional[str], *,
                      secret: Optional[str] = None,
                      current_password: Optional[str] = None,
                      current_code: Optional[str] = None,
                      via: Optional[str] = None,
                      source: Optional[str] = None,
                      start_session: bool = False) -> tuple:
        """Use a link. Returns (account id, recovery codes or None), and with
        `start_session` (the invite page) also a new session token, created in
        the transaction that spends the link, after the account's other
        sessions end.

        - join, recover: `password` is the new password, `secret` is the new
          TOTP secret the page showed (the caller has verified the form's MAC
          over it; see scripts/local_auth.py) and `code` is from it.
        - reset_password: `password` is the new password, `current_code` is
          from the account's existing TOTP secret.
        - reset_mfa: `current_password` is the account's password, `secret`
          and `code` as for join.

        Everything is checked before the link is spent, and the spend commits
        with the account change, so a refused attempt leaves the link usable.
        Two exceptions, both deliberate: a link whose maker has lost the
        authority to issue it (removed, demoted, or a tech's owner invite once
        an owner has joined) is revoked and refused `invalid_link`; and every
        guess at a reset link's existing factor (current code or password) is
        reserved against the account's lockout before it is verified, as
        sign-in's will be. A locked account's reset links are refused `locked`
        and the guess is never verified.
        """
        if not isinstance(token, str) or not token:
            raise AccountRefused("invalid_link")
        th = _token_hash(token)
        now = self._now()
        stamp = self.clock.now()
        with self.store.transaction() as cur:
            found = self._live(cur, th, now)
            voided = self._void_if_unauthorised(cur, found[0], stamp) if found else None
        if voided is not None:
            _log("invite_revoked", None, found[0]["account_id"], None, voided)
        if found is None or voided is not None:
            raise AccountRefused("invalid_link")
        inv, acct = found
        kind = inv["kind"]
        if kind in RESET_KINDS and _is_locked(acct, now):
            raise AccountRefused("locked")

        # Checks that guess at no existing factor come first and are not counted:
        # the new password's policy and, for enrolling links, the code from the
        # link's own new secret.
        clean = (self._new_password(password)
                 if kind in ("join", "recover", "reset_password") else None)
        if kind == "reset_password":
            secret = acct["totp_secret"]
        else:
            # the secret the submitted page showed; never one stored on the link
            step = totp.match(secret, code, now, None) if _is_secret(secret) else None
            if step is None:
                raise AccountRefused("bad_code")
        if kind in RESET_KINDS:
            # Reserve-then-verify: the attempt is counted (and the account
            # locked at the cap) in a committed transaction before the existing
            # factor is checked, so parallel guesses cannot exceed LOCK_AFTER.
            if not self._reserve_attempt(acct["id"], now, via, source):
                raise AccountRefused("locked")
            if kind == "reset_mfa":
                if not isinstance(current_password, str) or not passwords.verify(
                        current_password, acct["password_hash"]):
                    raise AccountRefused("password", "incorrect")
            else:
                step = (totp.match(secret, current_code, now, acct["last_totp_step"])
                        if secret else None)
                if step is None:
                    raise AccountRefused("bad_code")
        pw_hash = passwords.hash_password(clean) if clean is not None else None
        codes = passwords.new_recovery_codes() if kind in _ENROLS else None

        stamp = self.clock.now()
        account_id = acct["id"]
        voided = None
        with self.store.transaction() as cur:
            current = self._live(cur, th, now)
            if current is None or current[1]["id"] != account_id:
                raise AccountRefused("invalid_link")
            voided = self._void_if_unauthorised(cur, current[0], stamp)
            session = None
            if voided is None:
                event, detail = self._apply_accept(cur, th, now, kind, current[1], acct, secret,
                                                   step, pw_hash, codes, via, source, stamp)
                if start_session:
                    session = self._new_session(cur, account_id, now, source, "invite", stamp)
        if voided is not None:
            _log("invite_revoked", None, account_id, None, voided)
            raise AccountRefused("invalid_link")
        _log(event, account_id, account_id, via, detail)
        if start_session:
            _log("sign_in", account_id, account_id, _VIA, {"method": "invite"})
            return account_id, codes, session
        return account_id, codes

    def _apply_accept(self, cur: sqlite3.Cursor, th: str, now: float, kind: str,
                      fresh: sqlite3.Row, seen: sqlite3.Row, secret: str, step: int,
                      pw_hash: Optional[str], codes: Optional[list[str]],
                      via: Optional[str], source: Optional[str],
                      stamp: Stamp) -> tuple[str, Optional[dict[str, Any]]]:
        """The write half of accept_invite, on its transaction's cursor."""
        account_id = fresh["id"]
        if self.store.spend_invite(th, now, cur=cur) is None:
            raise AccountRefused("invalid_link")
        # No lock check here: this attempt was reserved (and so is within the
        # cap) before its factor was verified. A lock set meanwhile by other,
        # later reservations is cleared by this success, as sign-in will do.
        if kind == "reset_password" and (
                fresh["totp_secret"] != secret or (fresh["last_totp_step"] is not None
                                                   and step <= fresh["last_totp_step"])):
            raise AccountRefused("bad_code")    # the code was used meanwhile
        if kind == "reset_mfa" and fresh["password_hash"] != seen["password_hash"]:
            raise AccountRefused("password", "incorrect")
        touch = (stamp.real_ts, stamp.sim_ts, account_id)
        if kind in ("join", "recover"):
            cur.execute("UPDATE accounts SET status = 'active', password_hash = ?, "
                        "totp_secret = ?, last_totp_step = ?, updated_real_ts = ?, "
                        "updated_sim_ts = ? WHERE id = ?", (pw_hash, secret, step, *touch))
        elif kind == "reset_password":
            cur.execute("UPDATE accounts SET password_hash = ?, last_totp_step = ?, "
                        "updated_real_ts = ?, updated_sim_ts = ? WHERE id = ?",
                        (pw_hash, step, *touch))
        else:
            cur.execute("UPDATE accounts SET totp_secret = ?, last_totp_step = ?, "
                        "updated_real_ts = ?, updated_sim_ts = ? WHERE id = ?",
                        (secret, step, *touch))
        self._clear_attempts(cur, account_id)
        if codes is not None:
            self._replace_codes(cur, account_id, codes)
        self._end_sessions(cur, account_id)
        detail: Optional[dict[str, Any]] = None
        if kind in ("join", "recover"):
            detail = {"invite_kind": kind, "role": fresh["role"]}
            if fresh["role"] == "owner":
                revoked = self._revoke_unauthorised_joins(cur)
                if revoked:
                    detail["count"] = revoked
        event = {"join": "invite_accepted", "recover": "owner_recovered",
                 "reset_password": "password_reset", "reset_mfa": "mfa_reset"}[kind]
        self._event(cur, event, account_id, account_id, via, source, detail, stamp)
        return event, detail

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
            # links the subject made were issued under the old role
            revoked = self._revoke_made_by(cur, account_id)
            if role == "owner":
                revoked += self._revoke_unauthorised_joins(cur)
            detail = {"from": target["role"], "to": role}
            if revoked:
                detail["count"] = revoked
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
            revoked = self._revoke_made_by(cur, account_id)
            detail = {"role": target["role"]}
            if revoked:
                detail["count"] = revoked
            self._event(cur, "removed", actor["id"], account_id, via, source, detail, stamp)
        _log("removed", actor["id"], account_id, via, detail)

    # --- sign-in and sessions ---------------------------------------------

    def sign_in(self, email: str, password: str, code: str,
                source: Optional[str]) -> Optional[str]:
        """Email, password and a TOTP code (or one unspent recovery code in its
        place). Returns a new raw session token, or None for every failure
        alike; see the module docstring for the single failure path."""
        pw = password if isinstance(password, str) else ""
        now = self._now()
        try:
            typed: Optional[str] = normalise_email(email)
        except ValueError:
            typed = None
        row = self.store.account_by_email(typed) if typed is not None else None
        account_id = row["id"] if row is not None else None
        usable = (row is not None and row["status"] == "active"
                  and row["password_hash"] is not None)
        if not usable or not self._reserve_attempt(account_id, now, _VIA, source,
                                                   method="sign_in"):
            # No attempt was written: commit a pad write instead, so this path
            # costs what a reservation costs. The same transaction reads the
            # email key, which only an unknown, well-formed email needs.
            with self.store.transaction() as cur:
                key = self.store.email_key(cur)
                self.store.pad_write(cur)
            passwords.verify(pw, None)           # the same one scrypt
            if row is not None or typed is None:
                key = None
            return self._sign_in_failed(account_id, typed, source, key)
        pw_ok = passwords.verify(pw, row["password_hash"])
        secret = row["totp_secret"]
        step = (totp.match(secret, code, now, row["last_totp_step"])
                if secret and isinstance(code, str) else None)
        code_hash = None
        if step is None and isinstance(code, str) and code.strip():
            code_hash = passwords.recovery_hash(code)
        if not pw_ok or (step is None and code_hash is None):
            return self._sign_in_failed(account_id, typed, source)

        token = secrets.token_urlsafe(32)            # 256 bits
        csrf = secrets.token_urlsafe(32)
        method = "totp" if step is not None else "recovery_code"
        detail = {"method": method}
        stamp = self.clock.now()
        try:
            with self.store.transaction() as cur:
                fresh = self._account(cur, account_id)
                if (fresh is None or fresh["status"] != "active"
                        or fresh["password_hash"] != row["password_hash"]
                        or fresh["totp_secret"] != secret):
                    raise _Failed
                if step is not None:
                    if fresh["last_totp_step"] is not None and step <= fresh["last_totp_step"]:
                        raise _Failed                 # the code was used meanwhile
                    cur.execute("UPDATE accounts SET last_totp_step = ? WHERE id = ?",
                                (step, account_id))
                elif not self.store.spend_recovery_code(account_id, code_hash, cur=cur):
                    raise _Failed
                self._clear_attempts(cur, account_id)
                self._insert_session(cur, account_id, token, csrf, now, source, detail, stamp)
        except _Failed:
            return self._sign_in_failed(account_id, typed, source)
        _log("sign_in", account_id, account_id, _VIA, detail)
        return token

    def _sign_in_failed(self, account_id: Optional[str], typed: Optional[str],
                        source: Optional[str], key: Optional[bytes] = None) -> None:
        """The one failure record. It names the account when one exists; for a
        well-formed unknown email (`key` given) it carries only the keyed
        `email_hmac`; for malformed input only `reason: malformed`. The log
        line never carries the HMAC or anything else derived from the email."""
        detail: Optional[dict[str, Any]] = None
        log_detail: Optional[dict[str, Any]] = None
        if account_id is None:
            if typed is None:
                detail = log_detail = {"reason": "malformed"}
            elif key is not None:
                detail = {"email_hmac": hmac.new(key, typed.encode("utf-8"),
                                                 hashlib.sha256).hexdigest()}
        stamp = self.clock.now()
        self.store.insert_event("sign_in_failed", None, account_id, _VIA, source, detail,
                                real_ts=stamp.real_ts, sim_ts=stamp.sim_ts)
        _log("sign_in_failed", None, account_id, _VIA, log_detail)
        return None

    def session(self, token: Optional[str]) -> Optional[Session]:
        """The live session for `token`, touching `last_seen`; else None.

        An idle, expired, or orphaned session (its account removed or no longer
        active) is deleted. The role is read from the account row now."""
        if not isinstance(token, str) or not token:
            return None
        th = _token_hash(token)
        now = self._now()
        with self.store.transaction() as cur:
            row = cur.execute("SELECT * FROM sessions WHERE token_hash = ?", (th,)).fetchone()
            if row is None:
                return None
            acct = self._account(cur, row["account_id"])
            if (now - row["last_seen"] >= IDLE_SECONDS
                    or now - row["created_at"] >= ABSOLUTE_SECONDS
                    or acct is None or acct["status"] != "active"):
                cur.execute("DELETE FROM sessions WHERE token_hash = ?", (th,))
                return None
            cur.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (now, th))
        until = row["confirmed_until"]
        return Session(acct["id"], acct["email"], acct["role"], row["csrf"],
                       until is not None and until > now)

    def sign_out(self, token: Optional[str], *, source: Optional[str] = None) -> None:
        """End this session. Unknown or already-ended tokens are ignored."""
        if not isinstance(token, str) or not token:
            return
        th = _token_hash(token)
        stamp = self.clock.now()
        with self.store.transaction() as cur:
            row = cur.execute("SELECT account_id FROM sessions WHERE token_hash = ?",
                              (th,)).fetchone()
            if row is None:
                return
            cur.execute("DELETE FROM sessions WHERE token_hash = ?", (th,))
            account_id = row["account_id"]
            self._event(cur, "sign_out", account_id, account_id, _VIA, source, None, stamp)
        _log("sign_out", account_id, account_id, _VIA, None)

    def confirm(self, token: Optional[str], password: Optional[str] = None,
                code: Optional[str] = None, *, source: Optional[str] = None) -> bool:
        """Re-confirm a live session with its password or a fresh TOTP code
        (exactly one); on success it is confirmed for CONFIRM_SECONDS.

        Each attempt is reserved against the account's lockout before it is
        verified, as sign-in's are; a locked account cannot confirm."""
        if (password is None) == (code is None):
            return False
        live = self.session(token)
        if live is None:
            return False
        now = self._now()
        row = self.store.account_by_id(live.account_id)
        if row is None or not self._reserve_attempt(row["id"], now, _VIA, source,
                                                    method="confirm"):
            if password is not None:
                passwords.verify(password if isinstance(password, str) else "", None)
            return False
        step = None
        if password is not None:
            ok = isinstance(password, str) and passwords.verify(password, row["password_hash"])
        else:
            step = (totp.match(row["totp_secret"], code, now, row["last_totp_step"])
                    if row["totp_secret"] and isinstance(code, str) else None)
            ok = step is not None
        if not ok:
            return False
        th = _token_hash(token)
        try:
            with self.store.transaction() as cur:
                sess = cur.execute("SELECT account_id FROM sessions WHERE token_hash = ?",
                                   (th,)).fetchone()
                fresh = self._account(cur, row["id"])
                if (sess is None or sess["account_id"] != row["id"] or fresh is None
                        or fresh["status"] != "active"
                        or fresh["password_hash"] != row["password_hash"]
                        or fresh["totp_secret"] != row["totp_secret"]):
                    raise _Failed
                if step is not None:
                    if fresh["last_totp_step"] is not None and step <= fresh["last_totp_step"]:
                        raise _Failed
                    cur.execute("UPDATE accounts SET last_totp_step = ? WHERE id = ?",
                                (step, row["id"]))
                self._clear_attempts(cur, row["id"])
                cur.execute("UPDATE sessions SET confirmed_until = ? WHERE token_hash = ?",
                            (now + CONFIRM_SECONDS, th))
        except _Failed:
            return False
        return True

    @staticmethod
    def actor_for(session: Session) -> dict[str, Any]:
        """The `actor` a browser action records: verified, via the dashboard."""
        return {"via": _VIA, "account_id": session.account_id, "verified": True}

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
    def _revoke_made_by(cur: sqlite3.Cursor, account_id: str) -> int:
        """Revoke every unused link `account_id` made; returns how many."""
        cur.execute("UPDATE invites SET revoked = 1 WHERE created_by = ? AND used = 0 "
                    "AND revoked = 0", (account_id,))
        return cur.rowcount

    @staticmethod
    def _revoke_unauthorised_joins(cur: sqlite3.Cursor) -> int:
        """Once an active owner exists, a join link made by anyone who is not
        an active owner (the bootstrap tech's owner invite) is void."""
        cur.execute("UPDATE invites SET revoked = 1 WHERE kind = 'join' AND used = 0 "
                    "AND revoked = 0 AND NOT EXISTS (SELECT 1 FROM accounts a WHERE "
                    "a.id = invites.created_by AND a.role = 'owner' AND a.status = 'active') "
                    "AND EXISTS (SELECT 1 FROM accounts WHERE role = 'owner' "
                    "AND status = 'active')")
        return cur.rowcount

    def _void_if_unauthorised(self, cur: sqlite3.Cursor, inv: sqlite3.Row,
                              stamp: Stamp) -> Optional[dict[str, Any]]:
        """Revoke a link whose maker could not issue it now; return the event
        detail when it did. `recover` links come from the server command and
        have no maker to check."""
        kind = inv["kind"]
        if kind == "recover":
            return None
        maker = self._account(cur, inv["created_by"])
        if maker is not None and maker["status"] == "active":
            if kind == "join" and access.may_invite(maker["role"], inv["role"],
                                                    self._owners(cur) > 0):
                return None
            if kind in RESET_KINDS and access.allowed(maker["role"], "manage_accounts"):
                return None
        cur.execute("UPDATE invites SET revoked = 1 WHERE token_hash = ?", (inv["token_hash"],))
        detail = {"invite_kind": kind, "reason": "maker_not_allowed"}
        self._event(cur, "invite_revoked", None, inv["account_id"], None, None, detail, stamp)
        return detail

    def _reserve_attempt(self, account_id: str, now: float, via: Optional[str],
                         source: Optional[str], method: str = "reset_link") -> bool:
        """Count one guess before it is verified; False if locked. Shared with sign-in (Task 5).

        One BEGIN IMMEDIATE transaction, committed before the caller verifies
        anything, so N parallel guesses are serialised here and at most
        LOCK_AFTER of them per LOCK_WINDOW are ever verified. The reservation
        that reaches LOCK_AFTER sets `locked_until` and writes the one `locked`
        event; it is itself still verified. A guess while locked is not
        counted, does not extend the lock, and is never verified. On success
        the caller clears the count with `_clear_attempts` in the transaction
        that applies the change; on failure there is nothing more to write.
        """
        stamp = self.clock.now()
        detail = None
        with self.store.transaction() as cur:
            row = self._account(cur, account_id)
            if row is None or _is_locked(row, now):
                return False
            first = row["first_failed_at"]
            if first is None or now - first >= LOCK_WINDOW:
                count, first = 1, now
            else:
                count = (row["failed_count"] or 0) + 1
            if count >= LOCK_AFTER:
                until = now + LOCK_SECONDS
                cur.execute("UPDATE accounts SET failed_count = 0, first_failed_at = NULL, "
                            "locked_until = ? WHERE id = ?", (until, account_id))
                detail = {"count": count, "locked_until": until, "method": method}
                self._event(cur, "locked", None, account_id, via, source, detail, stamp)
            else:
                cur.execute("UPDATE accounts SET failed_count = ?, first_failed_at = ? "
                            "WHERE id = ?", (count, first, account_id))
        if detail is not None:
            _log("locked", None, account_id, via, detail)
        return True

    @staticmethod
    def _clear_attempts(cur: sqlite3.Cursor, account_id: str) -> None:
        """Clear the guess count and any lock after a verified success. Shared with sign-in."""
        cur.execute("UPDATE accounts SET failed_count = 0, first_failed_at = NULL, "
                    "locked_until = NULL WHERE id = ?", (account_id,))

    def _insert_session(self, cur: sqlite3.Cursor, account_id: str, token: str, csrf: str,
                        now: float, source: Optional[str], detail: dict[str, Any],
                        stamp: Stamp) -> None:
        """A new session row and its `sign_in` event, on the caller's transaction."""
        cur.execute("INSERT INTO sessions (token_hash, account_id, csrf, created_at, "
                    "last_seen, confirmed_until) VALUES (?,?,?,?,?,NULL)",
                    (_token_hash(token), account_id, csrf, now, now))
        self._event(cur, "sign_in", account_id, account_id, _VIA, source, detail, stamp)

    def _new_session(self, cur: sqlite3.Cursor, account_id: str, now: float,
                     source: Optional[str], method: str, stamp: Stamp) -> str:
        """Sign in an account whose new password and new TOTP code the same request
        just verified (setup, an accepted link). Only `setup_first` and
        `accept_invite` call it, inside their own success transaction."""
        token = secrets.token_urlsafe(32)            # 256 bits, as sign_in
        self._insert_session(cur, account_id, token, secrets.token_urlsafe(32), now, source,
                             {"method": method}, stamp)
        return token

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


class RateLimiter:
    """Per-source sign-in attempts, in memory: `per_minute` in any sliding
    60 seconds. `hit(source)` returns None when allowed, else the Retry-After
    seconds. A refused hit is not counted. At most `max_sources` sources are
    kept; the least recently seen is evicted first. Thread-safe. `now` is a
    monotonic clock: this is a runtime timer and is never persisted."""

    WINDOW = 60.0

    def __init__(self, per_minute: int = 10, now: Callable[[], float] = time.monotonic,
                 max_sources: int = 10_000) -> None:
        self.per_minute = per_minute
        self.max_sources = max_sources
        self._now = now
        self._hits: "OrderedDict[str, deque[float]]" = OrderedDict()
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._hits)

    def hit(self, source: str) -> Optional[int]:
        with self._lock:
            t = self._now()
            q = self._hits.get(source)
            if q is None:
                q = self._hits[source] = deque()
                while len(self._hits) > self.max_sources:
                    self._hits.popitem(last=False)
            else:
                self._hits.move_to_end(source)
            while q and t - q[0] >= self.WINDOW:
                q.popleft()
            if len(q) >= self.per_minute:
                return max(1, math.ceil(q[0] + self.WINDOW - t))
            q.append(t)
            return None
