# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The account store: its own file, unreachable by every agent stage."""
import json
import os
import sqlite3
import stat

import pytest

from tools.account_store import AccountStore
from tools.local_layout import STAGE_WRITES, Workspace

ACCOUNT_COLLECTIONS = ("accounts", "recovery_codes", "invites", "sessions", "account_events")


@pytest.fixture
def ws(tmp_path):
    w = Workspace(tmp_path / "workspace")
    w.init()
    return w


@pytest.fixture
def store(ws):
    return AccountStore(ws.accounts_path())


def _add(store, id_, email, role="owner", status="active"):
    with store.transaction() as cur:
        cur.execute("INSERT INTO accounts (id, email, role, status, real_ts, sim_ts) "
                    "VALUES (?,?,?,?,1.0,1.0)", (id_, email, role, status))


def test_accounts_file_is_private_and_unreachable_by_every_stage(ws):
    path = ws.accounts_path()
    assert path == ws.root / "accounts.sqlite3"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    for stage in STAGE_WRITES:
        docs = ws.docs_for(stage)
        for name in ACCOUNT_COLLECTIONS:
            # what SQLiteDocStore raises for a collection it has no file for,
            # on the path both reads and writes start from
            with pytest.raises(KeyError):
                docs.collection(name)
            with pytest.raises(KeyError):
                docs.collection(name).document("x").set({"a": 1})
            with pytest.raises(KeyError):
                ws.file_for(name)
        docs.close()
    # init is safe to repeat and re-tightens the mode
    os.chmod(path, 0o644)
    ws.init()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_init_adds_accounts_file_to_an_existing_workspace(ws):
    ws.accounts_path().unlink()
    ws.init()
    assert ws.accounts_path().exists()


def test_tables_exist(store):
    with sqlite3.connect(store.path) as c:
        names = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert set(ACCOUNT_COLLECTIONS) <= names


def test_email_is_unique_case_insensitively(store):
    with store.transaction() as cur:
        cur.execute("INSERT INTO accounts (id, email, role, status) VALUES "
                    "('a1', 'a@example.com', 'owner', 'active')")
    assert store.account_by_email("A@Example.COM")["id"] == "a1"
    with pytest.raises(sqlite3.IntegrityError):
        with store.transaction() as cur:
            cur.execute("INSERT INTO accounts (id, email, role, status) VALUES "
                        "('a2', 'A@EXAMPLE.com', 'tech', 'active')")
    with sqlite3.connect(store.path) as c:
        assert c.execute("SELECT email FROM accounts").fetchall() == [("a@example.com",)]


def test_counts_and_lookup(store):
    assert store.count_accounts() == 0 and store.active_owner_count() == 0
    _add(store, "a1", "a@example.com")
    _add(store, "a2", "b@example.com", role="tech")
    _add(store, "a3", "c@example.com", status="removed")
    assert store.count_accounts() == 3
    assert store.active_owner_count() == 1
    assert store.account_by_id("a2")["email"] == "b@example.com"
    assert store.account_by_id("zz") is None and store.account_by_email("x@example.com") is None


def test_failed_transaction_rolls_back(store):
    with pytest.raises(RuntimeError):
        with store.transaction() as cur:
            cur.execute("INSERT INTO accounts (id, email, role, status) VALUES "
                        "('a1', 'a@example.com', 'owner', 'active')")
            raise RuntimeError("boom")
    assert store.count_accounts() == 0


@pytest.mark.parametrize("key", ["password", "code", "token", "secret", "totp_secret",
                                 "new_password", "Recovery_Code", "session_token"])
def test_event_detail_refuses_secret_keys(store, key):
    with pytest.raises(ValueError):
        store.insert_event("sign_in", None, None, "web", "127.0.0.1", {key: "x"},
                           real_ts=1.0, sim_ts=1.0)
    assert store.events() == []


def test_event_detail_allows_known_keys_and_lists_newest_first(store):
    store.insert_event("role_changed", "a1", "a2", "web", "127.0.0.1",
                       {"from": "tech", "to": "owner"}, real_ts=1.0, sim_ts=2.0)
    store.insert_event("sign_in", "a1", "a1", "web", "127.0.0.1", None, real_ts=3.0, sim_ts=4.0)
    ev = store.events(limit=10)
    assert [e["event"] for e in ev] == ["sign_in", "role_changed"]
    assert json.loads(ev[1]["detail"]) == {"from": "tech", "to": "owner"}
    assert len(store.events(limit=1)) == 1
    with pytest.raises(ValueError):
        store.insert_event("x", None, None, "web", "s", {"unlisted_key": 1}, real_ts=1, sim_ts=1)


def _invite(store, token_hash="h1", expires_at=100.0, revoked=0):
    with store.transaction() as cur:
        cur.execute("INSERT INTO invites (token_hash, kind, email, role, created_by, "
                    "expires_at, revoked, real_ts, sim_ts) VALUES (?, 'join', "
                    "'n@example.com', 'tech', 'a1', ?, ?, 1.0, 1.0)",
                    (token_hash, expires_at, revoked))


def test_spend_invite_once(store):
    _invite(store)
    row = store.spend_invite("h1", now=50.0)
    assert row["email"] == "n@example.com" and row["kind"] == "join"
    assert store.spend_invite("h1", now=50.0) is None
    assert store.spend_invite("missing", now=50.0) is None


def test_spend_invite_refuses_expired_and_revoked(store):
    _invite(store, "old", expires_at=100.0)
    _invite(store, "rev", expires_at=100.0, revoked=1)
    assert store.spend_invite("old", now=100.0) is None
    assert store.spend_invite("rev", now=50.0) is None
    assert store.spend_invite("old", now=99.0) is not None  # an expired attempt did not burn it


def test_spend_recovery_code_once(store):
    with store.transaction() as cur:
        cur.execute("INSERT INTO recovery_codes (account_id, code_hash) VALUES ('a1','c1')")
    assert store.spend_recovery_code("a1", "c1") is True
    assert store.spend_recovery_code("a1", "c1") is False
    assert store.spend_recovery_code("a2", "c1") is False
