# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Sign-in: password + TOTP, lockout, sessions, re-confirm and the rate limiter."""
import contextlib
import hashlib
import hmac
import json
import logging
import sqlite3

import pytest

from tools import accounts as accounts_mod
from tools import passwords, totp
from tools.account_store import AccountStore
from tools.accounts import Accounts, RateLimiter, Session
from tools.clock import ClockMode, SimClock
from tests.test_accounts import (DAY, PW_OWNER, PW_TECH, T0, Now, code_for, join,
                                 setup_owner, wrong_code)

OWNER = "owner@client.example"
TECH = "tech@client.example"
SRC = "192.0.2.10"


@pytest.fixture
def now():
    return Now()


@pytest.fixture
def clock():
    c = SimClock(ClockMode.SIM, source=lambda: 1_700_000_000.0)
    c.advance(3 * DAY)
    return c


@pytest.fixture
def store(tmp_path):
    return AccountStore(tmp_path / "accounts.sqlite3")


@pytest.fixture
def accounts(store, clock, now):
    return Accounts(store, clock, now=now)


@pytest.fixture
def owner(accounts, now):
    account_id, secret, codes = setup_owner(accounts, now, email=OWNER)
    now.tick()
    return account_id, secret, codes


def events(store, name=None):
    rows = [dict(r) for r in reversed(store.events(1000))]
    return [r for r in rows if name is None or r["event"] == name]


def sign_in(accounts, now, secret, email=OWNER, password=PW_OWNER):
    now.tick()
    return accounts.sign_in(email, password, code_for(secret, now), SRC)


def count_scrypt(monkeypatch):
    calls = []
    real = passwords._scrypt

    def counted(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(passwords, "_scrypt", counted)
    return calls


def no_secrets_in_events(store, *secrets_):
    blob = json.dumps(events(store), default=str)
    for s in secrets_:
        assert s not in blob


# --- sign-in -----------------------------------------------------------------

def test_sign_in_needs_all_three(accounts, store, now, owner):
    account_id, secret, _ = owner
    now.tick()
    good = code_for(secret, now)
    assert accounts.sign_in(OWNER, PW_OWNER, wrong_code(secret, now), SRC) is None
    assert accounts.sign_in(OWNER, "not the password at all", good, SRC) is None
    assert accounts.sign_in("other@client.example", PW_OWNER, good, SRC) is None
    assert accounts.sign_in(OWNER, PW_OWNER, "", SRC) is None
    assert accounts.sign_in(OWNER, PW_OWNER, None, SRC) is None
    token = accounts.sign_in("  Owner@Client.Example ", PW_OWNER, good, SRC)
    assert isinstance(token, str) and len(token) >= 43
    s = accounts.session(token)
    assert s == Session(account_id, OWNER, "owner", s.csrf, False)
    assert len(s.csrf) >= 43
    # the same TOTP code is accepted once
    assert accounts.sign_in(OWNER, PW_OWNER, good, SRC) is None
    # stored hashed, never raw
    with sqlite3.connect(store.path) as c:
        hashes = [r[0] for r in c.execute("SELECT token_hash FROM sessions")]
    assert hashes == [hashlib.sha256(token.encode()).hexdigest()]
    ok = events(store, "sign_in")
    assert len(ok) == 1 and ok[0]["subject_id"] == account_id
    assert ok[0]["source"] == SRC and ok[0]["real_ts"] and ok[0]["sim_ts"]
    assert len(events(store, "sign_in_failed")) == 6
    no_secrets_in_events(store, token, s.csrf, good, PW_OWNER, OWNER, "Owner@Client")


def test_a_recovery_code_replaces_the_totp_code_once(accounts, store, now, owner):
    account_id, secret, codes = owner
    token = accounts.sign_in(OWNER, PW_OWNER, codes[0], SRC)
    assert token is not None
    assert accounts.session(token).account_id == account_id
    assert accounts.sign_in(OWNER, PW_OWNER, codes[0], SRC) is None
    # spaces and case are forgiven, as on the code sheet
    assert accounts.sign_in(OWNER, PW_OWNER, f" {codes[1].upper()} ", SRC) is not None
    # a recovery code still needs the password
    assert accounts.sign_in(OWNER, "not the password at all", codes[2], SRC) is None
    assert accounts.sign_in(OWNER, PW_OWNER, codes[2], SRC) is not None
    with sqlite3.connect(store.path) as c:
        spent = c.execute("SELECT COUNT(*) FROM recovery_codes WHERE account_id = ? "
                          "AND spent = 1", (account_id,)).fetchone()[0]
    assert spent == 3
    used = events(store, "sign_in")
    assert [json.loads(e["detail"])["method"] for e in used] == ["recovery_code"] * 3
    no_secrets_in_events(store, *codes)


def test_five_failures_lock_for_fifteen_minutes(accounts, store, now, owner):
    account_id, secret, _ = owner
    for _ in range(5):
        now.tick(10)
        assert accounts.sign_in(OWNER, "not the password at all", code_for(secret, now),
                                SRC) is None
    # a correct password and code now fail identically
    assert sign_in(accounts, now, secret) is None
    now.tick(accounts_mod.LOCK_SECONDS - 120)
    assert sign_in(accounts, now, secret) is None
    now.tick(120)
    token = sign_in(accounts, now, secret)
    assert token is not None
    row = store.account_by_id(account_id)
    assert row["failed_count"] == 0 and row["locked_until"] is None


def test_failures_outside_the_window_do_not_lock(accounts, now, owner):
    _, secret, _ = owner
    for _ in range(4):
        accounts.sign_in(OWNER, "not the password at all", "000000", SRC)
    now.tick(accounts_mod.LOCK_WINDOW)
    for _ in range(4):
        accounts.sign_in(OWNER, "not the password at all", "000000", SRC)
    assert sign_in(accounts, now, secret) is not None


def test_unknown_email_takes_the_same_path(accounts, store, now, owner, monkeypatch):
    account_id, secret, _ = owner
    calls = count_scrypt(monkeypatch)
    results = []
    now.tick()
    for email, pw in [("nobody@client.example", PW_OWNER),       # unknown
                      ("not an email", PW_OWNER),                 # not even an address
                      (OWNER, "not the password at all")]:        # known, wrong password
        calls.clear()
        results.append(accounts.sign_in(email, pw, code_for(secret, now), SRC))
        assert len(calls) == 1
    for _ in range(4):
        accounts.sign_in(OWNER, "not the password at all", "000000", SRC)
    calls.clear()                                                    # locked
    results.append(accounts.sign_in(OWNER, PW_OWNER, code_for(secret, now), SRC))
    assert len(calls) == 1
    assert results == [None, None, None, None]

    failed = events(store, "sign_in_failed")
    unknown = failed[0]
    assert unknown["subject_id"] is None
    assert json.loads(unknown["detail"]) == {
        "email_hmac": hmac.new(email_key(store), b"nobody@client.example",
                               hashlib.sha256).hexdigest()}
    assert json.loads(failed[1]["detail"]) == {"reason": "malformed"}
    assert {k for k in unknown} == {k for k in failed[2]}
    assert failed[2]["subject_id"] == account_id and failed[2]["detail"] is None
    assert failed[-1]["subject_id"] == account_id and failed[-1]["detail"] is None
    no_secrets_in_events(store, "nobody@client.example", OWNER)


def email_key(store):
    with sqlite3.connect(store.path) as c:
        return bytes.fromhex(c.execute("SELECT value FROM meta WHERE key = "
                                       "'email_hmac_key'").fetchone()[0])


def db_dump(store):
    with sqlite3.connect(store.path) as c:
        return "\n".join(c.iterdump())


def test_malformed_email_input_records_no_hash(accounts, store, now, owner, caplog):
    caplog.set_level(logging.INFO, logger="remediation_zero.accounts")
    typed = "violet tangerine harbour"            # a password typed into the email field
    assert accounts.sign_in(typed, PW_OWNER, "000000", SRC) is None
    failed = events(store, "sign_in_failed")
    assert len(failed) == 1
    assert failed[0]["subject_id"] is None
    assert json.loads(failed[0]["detail"]) == {"reason": "malformed"}
    key = email_key(store)
    blob = db_dump(store) + caplog.text
    for derived in (typed, typed.strip().lower(),
                    hashlib.sha256(typed.encode()).hexdigest(),
                    hmac.new(key, typed.encode(), hashlib.sha256).hexdigest()):
        assert derived not in blob


def test_unknown_email_hmac_is_keyed_and_never_logged(accounts, store, now, owner, caplog,
                                                     tmp_path, clock):
    caplog.set_level(logging.INFO, logger="remediation_zero.accounts")
    typed = "nobody@client.example"
    assert accounts.sign_in(typed, PW_OWNER, "000000", SRC) is None
    key = email_key(store)
    assert len(key) == 32
    mac = hmac.new(key, typed.encode(), hashlib.sha256).hexdigest()
    assert json.loads(events(store, "sign_in_failed")[0]["detail"]) == {"email_hmac": mac}
    assert hashlib.sha256(typed.encode()).hexdigest() not in db_dump(store) + caplog.text
    assert mac not in caplog.text and typed not in caplog.text
    assert "sign_in_failed" in caplog.text
    event_blob = json.dumps(events(store), default=str)
    assert key.hex() not in event_blob and key.hex() not in caplog.text
    # the same key is used next time; another workspace has its own
    accounts.sign_in(typed, PW_OWNER, "000000", SRC)
    assert json.loads(events(store, "sign_in_failed")[1]["detail"]) == {"email_hmac": mac}
    other = Accounts(AccountStore(tmp_path / "other.sqlite3"), clock, now=now)
    other.sign_in(typed, PW_OWNER, "000000", SRC)
    assert json.loads(events(other.store, "sign_in_failed")[0]["detail"])["email_hmac"] != mac


def test_unknown_and_known_failures_do_the_same_writes(accounts, store, now, owner,
                                                      monkeypatch):
    owner_id, secret, _ = owner
    tech_id, _, _ = join(accounts, now, owner_id, TECH, "tech")
    accounts.invite(owner_id, "pending@client.example", "tech")
    accounts.remove(owner_id, tech_id)
    writes = []
    original = store.transaction

    @contextlib.contextmanager
    def counted():
        with original() as cur:
            yield cur
            if cur.connection.total_changes:
                writes.append(1)

    monkeypatch.setattr(store, "transaction", counted)

    def count(email, password=PW_OWNER):
        writes.clear()
        now.tick()
        assert accounts.sign_in(email, password, wrong_code(secret, now), SRC) is None
        return len(writes)

    paths = {
        "unknown": count("nobody@client.example"),
        "malformed": count("not an email"),
        "invited": count("pending@client.example"),
        "removed": count(TECH),
        "wrong password": count(OWNER, "not the password at all"),
        "wrong code": count(OWNER),
    }
    for _ in range(3):
        count(OWNER)                                  # the fifth guess locks
    paths["locked"] = count(OWNER)
    assert set(paths.values()) == {2}, paths


def test_invited_and_removed_accounts_cannot_sign_in(accounts, store, now, owner,
                                                    monkeypatch):
    owner_id, _, _ = owner
    tech_id, tech_secret, _ = join(accounts, now, owner_id, TECH, "tech")
    accounts.invite(owner_id, "pending@client.example", "tech")
    accounts.remove(owner_id, tech_id)
    calls = count_scrypt(monkeypatch)
    for email in (TECH, "pending@client.example"):
        calls.clear()
        now.tick()
        assert accounts.sign_in(email, PW_TECH, code_for(tech_secret, now), SRC) is None
        assert len(calls) == 1


def test_sign_in_issues_a_new_token_each_time(accounts, store, now, owner):
    _, secret, _ = owner
    first = sign_in(accounts, now, secret)
    second = sign_in(accounts, now, secret)
    assert first and second and first != second
    a, b = accounts.session(first), accounts.session(second)
    assert a.csrf != b.csrf
    accounts.sign_out(first)
    assert accounts.session(first) is None
    assert accounts.session(second) is not None
    assert len(events(store, "sign_out")) == 1
    accounts.sign_out(first)                         # twice is harmless
    accounts.sign_out("never-issued")
    assert len(events(store, "sign_out")) == 1
    assert accounts.session("never-issued") is None
    assert accounts.session("") is None
    assert accounts.session(None) is None


# --- sessions ----------------------------------------------------------------

def test_idle_and_absolute_expiry(accounts, now, owner):
    _, secret, _ = owner
    token = sign_in(accounts, now, secret)
    now.tick(accounts_mod.IDLE_SECONDS - 1)
    assert accounts.session(token) is not None          # use resets the idle timer
    now.tick(accounts_mod.IDLE_SECONDS - 1)
    assert accounts.session(token) is not None
    now.tick(accounts_mod.IDLE_SECONDS)
    assert accounts.session(token) is None              # idle 30 minutes
    assert accounts.session(token) is None              # and it is gone

    token = sign_in(accounts, now, secret)
    start = now()
    while now() - start < accounts_mod.ABSOLUTE_SECONDS - 600:
        now.tick(600)
        assert accounts.session(token) is not None
    now.tick(start + accounts_mod.ABSOLUTE_SECONDS - now())
    assert accounts.session(token) is None              # 12 hours, however busy
    assert accounts_mod.IDLE_SECONDS == 1800
    assert accounts_mod.ABSOLUTE_SECONDS == 43200


def test_session_ends_when_the_account_is_removed_or_role_changes(accounts, store, now,
                                                                  owner):
    owner_id, _, _ = owner
    tech_id, tech_secret, _ = join(accounts, now, owner_id, TECH, "tech")
    token = sign_in(accounts, now, tech_secret, email=TECH, password=PW_TECH)
    assert accounts.session(token).role == "tech"
    accounts.set_role(owner_id, tech_id, "owner")
    assert accounts.session(token) is None

    token = sign_in(accounts, now, tech_secret, email=TECH, password=PW_TECH)
    assert accounts.session(token).role == "owner"
    # a role written by any path applies on the next request
    with store.transaction() as cur:
        cur.execute("UPDATE accounts SET role = 'tech' WHERE id = ?", (tech_id,))
    assert accounts.session(token).role == "tech"
    # and a status written by any path ends it
    with store.transaction() as cur:
        cur.execute("UPDATE accounts SET status = 'removed' WHERE id = ?", (tech_id,))
    assert accounts.session(token) is None
    with store.transaction() as cur:
        cur.execute("UPDATE accounts SET status = 'active' WHERE id = ?", (tech_id,))
    assert accounts.session(token) is None              # it was deleted, not hidden

    token = sign_in(accounts, now, tech_secret, email=TECH, password=PW_TECH)
    accounts.remove(owner_id, tech_id)
    assert accounts.session(token) is None


# --- lockout events ----------------------------------------------------------

def test_lockout_writes_a_locked_event(accounts, store, now, owner):
    account_id, secret, _ = owner
    for _ in range(7):
        accounts.sign_in(OWNER, "not the password at all", "000000", SRC)
    locked = events(store, "locked")
    assert len(locked) == 1
    assert locked[0]["subject_id"] == account_id and locked[0]["source"] == SRC
    detail = json.loads(locked[0]["detail"])
    assert detail["method"] == "sign_in" and detail["count"] == 5
    assert detail["locked_until"] == pytest.approx(now() + accounts_mod.LOCK_SECONDS)
    assert locked[0]["real_ts"] and locked[0]["sim_ts"]


def test_sign_in_and_reset_links_share_one_counter(accounts, store, now, owner):
    owner_id, _, _ = owner
    tech_id, tech_secret, _ = join(accounts, now, owner_id, TECH, "tech")
    link = accounts.reset_link(owner_id, tech_id, "reset_password")
    for _ in range(3):
        with pytest.raises(accounts_mod.AccountRefused):
            accounts.accept_invite(link, "a brand new passphrase", None,
                                   current_code=wrong_code(tech_secret, now))
    for _ in range(2):
        accounts.sign_in(TECH, "not the password at all", "000000", SRC)
    assert sign_in(accounts, now, tech_secret, email=TECH, password=PW_TECH) is None
    assert len(events(store, "locked")) == 1


def test_parallel_sign_in_guesses_cannot_pass_the_cap(accounts, now, owner, monkeypatch):
    import threading
    _, secret, _ = owner
    verified = []
    real = passwords.verify

    def counting(pw, stored):
        if stored is not None:
            verified.append(1)
        return real(pw, stored)

    monkeypatch.setattr(passwords, "verify", counting)
    barrier = threading.Barrier(8)

    def guess():
        barrier.wait()
        accounts.sign_in(OWNER, "not the password at all", "000000", SRC)

    threads = [threading.Thread(target=guess) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(verified) == accounts_mod.LOCK_AFTER


# --- re-confirm --------------------------------------------------------------

def test_confirm_lasts_five_minutes(accounts, store, now, owner):
    account_id, secret, _ = owner
    token = sign_in(accounts, now, secret)
    assert accounts.session(token).confirmed is False
    now.tick(30)
    code = code_for(secret, now)
    # with an authenticator set up, re-confirm takes the password and a fresh code together
    assert accounts.confirm(token, password="not the password at all", code=code) is False
    assert accounts.confirm(token, password=PW_OWNER) is False
    assert accounts.confirm(token, code=code) is False
    assert accounts.confirm(token) is False
    assert accounts.confirm("never-issued", password=PW_OWNER, code=code) is False
    assert accounts.confirm(token, password=PW_OWNER, code=code) is True
    assert accounts.session(token).confirmed is True
    now.tick(accounts_mod.CONFIRM_SECONDS - 1)
    assert accounts.session(token).confirmed is True
    now.tick(1)
    assert accounts.session(token).confirmed is False
    # the code is spent: the same one cannot confirm again
    assert accounts.confirm(token, password=PW_OWNER, code=code) is False
    now.tick(30)
    assert accounts.confirm(token, password=PW_OWNER, code=code_for(secret, now)) is True
    # confirming does not reach another session
    other = sign_in(accounts, now, secret)
    assert accounts.session(other).confirmed is False
    assert accounts_mod.CONFIRM_SECONDS == 300
    # wrong confirmations count towards the lockout
    now.tick(30)
    code = code_for(secret, now)
    for _ in range(5):
        accounts.confirm(other, password="not the password at all", code=code)
    assert accounts.confirm(other, password=PW_OWNER, code=code) is False
    assert json.loads(events(store, "locked")[0]["detail"])["method"] == "confirm"


def test_actor_for_a_session_is_verified_dashboard(accounts, now, owner):
    account_id, secret, _ = owner
    token = sign_in(accounts, now, secret)
    assert accounts.actor_for(accounts.session(token)) == {
        "via": "dashboard", "account_id": account_id, "verified": True}


# --- rate limiter ------------------------------------------------------------

def test_rate_limiter_returns_retry_after_and_evicts():
    clock = Now(100.0)
    limiter = RateLimiter(per_minute=10, now=clock)
    for _ in range(10):
        assert limiter.hit("198.51.100.1") is None
        clock.tick(1)
    retry = limiter.hit("198.51.100.1")
    assert retry == 50                                # the first hit leaves the window at 160
    assert limiter.hit("198.51.100.2") is None        # per source
    clock.tick(49)
    assert limiter.hit("198.51.100.1") == 1
    clock.tick(1)
    assert limiter.hit("198.51.100.1") is None        # a refused hit is not counted
    # bounded: the oldest source is evicted first
    small = RateLimiter(per_minute=1, now=clock, max_sources=3)
    for src in ("a", "b", "c"):
        assert small.hit(src) is None
    assert small.hit("a") is not None
    small.hit("d")                                    # evicts b, the least recently seen
    assert len(small) == 3
    assert small.hit("b") is None
    assert small.hit("a") is not None
    assert RateLimiter().max_sources == 10_000
