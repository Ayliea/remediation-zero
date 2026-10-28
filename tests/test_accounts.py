# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Accounts: the permission table, invites, resets and the last-owner rule."""
import hashlib
import json
import sqlite3
import threading

import pytest

from tools import access, totp
from ui import account_views
from tools.account_store import AccountStore
from tools.accounts import AccountRefused, Accounts, InviteView
from tools.clock import ClockMode, SimClock
from tools.passwords import recovery_hash

T0 = 1_800_000_000.0          # injected wall time, seconds
DAY = 86400.0
PW_OWNER = "violet tangerine harbour"
PW_TECH = "copper lantern meadow"
PW_NEW = "quiet orchard sundial"


class Now:
    """A wall clock the test moves by hand."""

    def __init__(self, t: float = T0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def tick(self, seconds: float = 30.0) -> None:
        self.t += seconds


def code_for(secret: str, now: Now) -> str:
    return totp.code_at(secret, totp.step_for(now()))


def wrong_code(secret: str, now: Now) -> str:
    near = {totp.code_at(secret, totp.step_for(now()) + d) for d in (-1, 0, 1)}
    return next(c for c in ("000000", "111111", "222222", "333333") if c not in near)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@pytest.fixture
def now():
    return Now()


@pytest.fixture
def clock():
    c = SimClock(ClockMode.SIM, source=lambda: 1_700_000_000.0)
    c.advance(3 * DAY)   # sim time is fixed and differs from real time
    return c


@pytest.fixture
def store(tmp_path):
    return AccountStore(tmp_path / "accounts.sqlite3")


@pytest.fixture
def accounts(store, clock, now):
    return Accounts(store, clock, now=now)


def setup_owner(accounts, now, email="owner@client.example", role="owner"):
    secret = totp.new_secret()
    codes = accounts.setup_first(email, role, PW_OWNER, secret, code_for(secret, now))
    row = accounts.store.account_by_email(email)
    return row["id"], secret, codes


def join(accounts, now, by_id, email, role, password=PW_TECH):
    token = accounts.invite(by_id, email, role)
    view = accounts.invite_view(token)
    now.tick()
    account_id, codes = accounts.accept_invite(token, password, code_for(view.totp_secret, now), secret=view.totp_secret)
    return account_id, view.totp_secret, codes


def sessions_of(store, account_id):
    with sqlite3.connect(store.path) as c:
        return c.execute("SELECT COUNT(*) FROM sessions WHERE account_id = ?",
                         (account_id,)).fetchone()[0]


def add_session(store, account_id, name):
    with store.transaction() as cur:
        cur.execute("INSERT INTO sessions (token_hash, account_id, csrf, created_at, last_seen) "
                    "VALUES (?,?,?,?,?)", (name, account_id, "c", T0, T0))


def refused(code):
    return pytest.raises(AccountRefused, match=f"^{code}$")


# --- the permission table ---------------------------------------------------

SPEC_TABLE = {
    "owner": {"view", "settings", "upload", "approve", "accept_risk", "manage_accounts",
              "view_audit", "manage_connections"},
    "tech": {"view", "settings", "upload", "approve"},
    None: set(),
}


@pytest.mark.parametrize("role", ["owner", "tech", None])
@pytest.mark.parametrize("action", sorted(access.ACTIONS))
def test_permission_table_matches_the_spec(role, action):
    assert access.ACTIONS == SPEC_TABLE["owner"]
    assert access.allowed(role, action) is (action in SPEC_TABLE[role])


def test_unknown_action_is_denied():
    for role in ("owner", "tech", None):
        with pytest.raises(KeyError):
            access.allowed(role, "delete_everything")
    assert access.allowed("admin", "view") is False   # an unknown role gets nothing


# --- first account ----------------------------------------------------------

def test_first_account_only_once(accounts, store, now):
    secret = totp.new_secret()
    with refused("bad_code"):
        accounts.setup_first("owner@client.example", "owner", PW_OWNER, secret,
                             wrong_code(secret, now))
    assert store.count_accounts() == 0
    with refused("password"):
        accounts.setup_first("owner@client.example", "owner", "short", secret,
                             code_for(secret, now))
    assert store.count_accounts() == 0

    owner_id, _, codes = setup_owner(accounts, now, email="  Owner@Client.Example ")
    row = store.account_by_id(owner_id)
    assert row["email"] == "owner@client.example"
    assert (row["role"], row["status"]) == ("owner", "active")
    assert len(codes) == 10 and len(set(codes)) == 10
    with sqlite3.connect(store.path) as c:
        stored = {r[0] for r in c.execute("SELECT code_hash FROM recovery_codes")}
    assert stored == {recovery_hash(code) for code in codes}

    second = totp.new_secret()
    with refused("accounts_exist"):
        accounts.setup_first("tech@msp.example", "tech", PW_TECH, second, code_for(second, now))
    assert store.count_accounts() == 1


# --- invites ----------------------------------------------------------------

def test_tech_may_invite_only_an_owner_and_only_before_one_exists(accounts, store, now):
    assert access.may_invite("owner", "owner", True) and access.may_invite("owner", "tech", True)
    assert access.may_invite("owner", "tech", False)
    assert access.may_invite("tech", "owner", False)
    assert not access.may_invite("tech", "owner", True)
    assert not access.may_invite("tech", "tech", False)
    assert not access.may_invite(None, "owner", False)

    tech_id, _, _ = setup_owner(accounts, now, email="tech@msp.example", role="tech")
    with refused("not_allowed"):
        accounts.invite(tech_id, "helper@msp.example", "tech")
    token = accounts.invite(tech_id, "owner@client.example", "owner")
    assert accounts.invite_view(token).role == "owner"
    view = accounts.invite_view(token)
    now.tick()
    owner_id, _ = accounts.accept_invite(token, PW_OWNER, code_for(view.totp_secret, now), secret=view.totp_secret)
    assert accounts.owner_exists()
    with refused("not_allowed"):
        accounts.invite(tech_id, "second-owner@client.example", "owner")
    # the owner may invite either role
    accounts.invite(owner_id, "helper@msp.example", "tech")
    accounts.invite(owner_id, "partner@client.example", "owner")
    with refused("email_taken"):
        accounts.invite(owner_id, "HELPER@msp.example", "tech")
    with pytest.raises(ValueError):
        accounts.invite(owner_id, "not an email", "tech")
    with pytest.raises(ValueError):
        accounts.invite(owner_id, "x@client.example", "admin")


def test_pending_invite_is_not_an_owner(accounts, store, now):
    tech_id, _, _ = setup_owner(accounts, now, email="tech@msp.example", role="tech")
    token = accounts.invite(tech_id, "owner@client.example", "owner")
    assert store.account_by_email("owner@client.example")["status"] == "invited"
    assert not accounts.owner_exists() and store.active_owner_count() == 0
    accounts.invite_view(token)   # viewing is not joining
    assert not accounts.owner_exists()
    # and while no owner exists, the tech may still invite the owner again
    with refused("email_taken"):
        accounts.invite(tech_id, "owner@client.example", "owner")
    accounts.invite(tech_id, "other-owner@client.example", "owner")


def test_the_last_owner_cannot_be_removed_or_demoted(accounts, store, now, tmp_path, clock):
    a_id, _, _ = setup_owner(accounts, now)
    b_id, _, _ = join(accounts, now, a_id, "partner@client.example", "owner")
    tech_id, _, _ = join(accounts, now, a_id, "tech@msp.example", "tech")

    # two owners each try to remove the other at the same moment: one wins
    barrier = threading.Barrier(2)
    results = {}

    def remove(by, whom):
        acc = Accounts(AccountStore(tmp_path / "accounts.sqlite3"), clock, now=now)
        barrier.wait()
        try:
            acc.remove(by, whom)
            results[by] = "ok"
        except AccountRefused as exc:
            results[by] = exc.code

    threads = [threading.Thread(target=remove, args=(a_id, b_id)),
               threading.Thread(target=remove, args=(b_id, a_id))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results.values()) in (["last_owner", "ok"], ["not_allowed", "ok"])
    assert store.active_owner_count() == 1
    survivor = a_id if results[a_id] == "ok" else b_id

    with refused("last_owner"):
        accounts.remove(survivor, survivor)
    with refused("last_owner"):
        accounts.set_role(survivor, survivor, "tech")
    with refused("not_allowed"):
        accounts.remove(tech_id, survivor)
    with refused("not_allowed"):
        accounts.set_role(tech_id, survivor, "tech")
    assert store.account_by_id(survivor)["role"] == "owner"
    assert store.active_owner_count() == 1
    # promoting someone else makes the old last owner removable
    accounts.set_role(survivor, tech_id, "owner")
    accounts.remove(tech_id, survivor)
    assert store.account_by_id(survivor)["status"] == "removed"


def test_the_last_owner_cannot_demote_themself(accounts, store, now):
    a_id, _, _ = setup_owner(accounts, now)
    with refused("last_owner"):
        accounts.set_role(a_id, a_id, "tech")
    assert store.account_by_id(a_id)["role"] == "owner"
    b_id, _, _ = join(accounts, now, a_id, "partner@client.example", "owner")
    accounts.set_role(a_id, a_id, "tech")       # allowed once another owner exists
    assert store.account_by_id(a_id)["role"] == "tech"
    with refused("last_owner"):
        accounts.set_role(b_id, b_id, "tech")


def test_techs_cannot_reset_or_remove_anyone(accounts, store, now):
    owner_id, _, _ = setup_owner(accounts, now)
    t1, _, _ = join(accounts, now, owner_id, "tech1@msp.example", "tech")
    t2, _, _ = join(accounts, now, owner_id, "tech2@msp.example", "tech")
    for target in (owner_id, t2):
        for kind in ("reset_password", "reset_mfa"):
            with refused("not_allowed"):
                accounts.reset_link(t1, target, kind)
        with refused("not_allowed"):
            accounts.remove(t1, target)
        with refused("not_allowed"):
            accounts.set_role(t1, target, "owner")
    with refused("not_allowed"):
        accounts.set_role(t1, t1, "owner")
    with sqlite3.connect(store.path) as c:
        assert c.execute("SELECT COUNT(*) FROM invites WHERE kind != 'join'").fetchone()[0] == 0
    assert {store.account_by_id(i)["status"] for i in (owner_id, t1, t2)} == {"active"}
    # an owner can
    accounts.reset_link(owner_id, t2, "reset_password")
    accounts.remove(owner_id, t2)
    with refused("no_such_account"):
        accounts.reset_link(owner_id, t2, "reset_mfa")


def test_owner_cannot_reset_themself_by_link(accounts, now):
    owner_id, _, _ = setup_owner(accounts, now)
    for kind in ("reset_password", "reset_mfa"):
        with refused("not_allowed"):
            accounts.reset_link(owner_id, owner_id, kind)
    with pytest.raises(ValueError):
        accounts.reset_link(owner_id, "someone", "join")


def test_invite_expires_after_7_days(accounts, store, now):
    owner_id, _, _ = setup_owner(accounts, now)
    token = accounts.invite(owner_id, "tech@msp.example", "tech")
    view = accounts.invite_view(token)
    now.t = T0 + 7 * DAY - 1
    still = accounts.invite_view(token)                 # still valid; a new secret each view
    assert (still.kind, still.email, still.role) == (view.kind, view.email, view.role)
    now.t = T0 + 7 * DAY
    assert accounts.invite_view(token) is None
    with refused("invalid_link"):
        accounts.accept_invite(token, PW_TECH, code_for(view.totp_secret, now), secret=view.totp_secret)
    assert store.account_by_email("tech@msp.example")["status"] == "invited"
    # an expired invite does not block a fresh one for the same email
    fresh = accounts.invite(owner_id, "tech@msp.example", "tech")
    assert accounts.invite_view(fresh) is not None
    # without an injected `now`, expiry runs on wall time (real_ts), never sim time
    default = Accounts(store, accounts.clock)
    later = default.invite(owner_id, "later@msp.example", "tech")
    with sqlite3.connect(store.path) as c:
        expires = c.execute("SELECT expires_at FROM invites WHERE token_hash = ?",
                            (token_hash(later),)).fetchone()[0]
    assert expires == accounts.clock.now().real_ts + 7 * DAY


def test_revoked_invite_is_refused(accounts, store, now):
    owner_id, _, _ = setup_owner(accounts, now)
    token = accounts.invite(owner_id, "tech@msp.example", "tech")
    view = accounts.invite_view(token)
    accounts.revoke_invite(owner_id, token_hash(token))
    assert accounts.invite_view(token) is None
    now.tick()
    with refused("invalid_link"):
        accounts.accept_invite(token, PW_TECH, code_for(view.totp_secret, now), secret=view.totp_secret)
    with refused("invalid_link"):
        accounts.revoke_invite(owner_id, token_hash(token))
    assert store.account_by_email("tech@msp.example")["status"] == "invited"


def test_a_token_or_code_is_spent_exactly_once_under_concurrency(tmp_path, clock, now):
    path = tmp_path / "accounts.sqlite3"
    accounts = Accounts(AccountStore(path), clock, now=now)
    owner_id, _, _ = setup_owner(accounts, now)
    token = accounts.invite(owner_id, "tech@msp.example", "tech")
    view = accounts.invite_view(token)
    now.tick()
    code = code_for(view.totp_secret, now)

    # a failed attempt (weak password, wrong code) does not burn the link
    with refused("password"):
        accounts.accept_invite(token, "short", code, secret=view.totp_secret)
    with refused("bad_code"):
        accounts.accept_invite(token, PW_TECH, "abcdef", secret=view.totp_secret)
    assert accounts.invite_view(token) is not None

    barrier = threading.Barrier(2)
    outcomes = []

    def accept():
        mine = Accounts(AccountStore(path), clock, now=now)
        barrier.wait()
        try:
            outcomes.append(mine.accept_invite(token, PW_TECH, code, secret=view.totp_secret)[0])
        except AccountRefused as exc:
            outcomes.append(exc.code)

    threads = [threading.Thread(target=accept) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    tech_id = AccountStore(path).account_by_email("tech@msp.example")["id"]
    assert sorted(outcomes) == sorted([tech_id, "invalid_link"])
    assert AccountStore(path).account_by_id(tech_id)["status"] == "active"

    # a recovery code, raced, is also spent once
    with sqlite3.connect(path) as c:
        hashes = [r[0] for r in c.execute("SELECT code_hash FROM recovery_codes "
                                          "WHERE account_id = ?", (tech_id,))]
    assert len(hashes) == 10
    barrier2 = threading.Barrier(2)
    spent = []

    def spend():
        s = AccountStore(path)
        barrier2.wait()
        spent.append(s.spend_recovery_code(tech_id, hashes[0]))

    threads = [threading.Thread(target=spend) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(spent) == [False, True]


def test_reset_password_needs_the_current_code(accounts, store, now):
    owner_id, _, _ = setup_owner(accounts, now)
    tech_id, secret, _ = join(accounts, now, owner_id, "tech@msp.example", "tech")
    token = accounts.reset_link(owner_id, tech_id, "reset_password")
    view = accounts.invite_view(token)
    assert view == InviteView("reset_password", "tech@msp.example", "tech", None)
    with refused("bad_code"):
        accounts.accept_invite(token, PW_NEW, None)
    # the code already used to join is not accepted again
    with refused("bad_code"):
        accounts.accept_invite(token, PW_NEW, None, current_code=code_for(secret, now))
    now.tick()
    with refused("password"):
        accounts.accept_invite(token, "short", None, current_code=code_for(secret, now))
    account_id, codes = accounts.accept_invite(token, PW_NEW, None,
                                               current_code=code_for(secret, now))
    assert (account_id, codes) == (tech_id, None)
    from tools.passwords import verify
    row = store.account_by_id(tech_id)
    assert verify(PW_NEW, row["password_hash"]) and row["totp_secret"] == secret
    with refused("invalid_link"):
        accounts.accept_invite(token, PW_NEW, None, current_code=code_for(secret, now))


def test_reset_mfa_needs_the_current_password(accounts, store, now):
    owner_id, _, _ = setup_owner(accounts, now)
    tech_id, old_secret, old_codes = join(accounts, now, owner_id, "tech@msp.example", "tech")
    token = accounts.reset_link(owner_id, tech_id, "reset_mfa")
    view = accounts.invite_view(token)
    assert view.kind == "reset_mfa" and view.totp_secret and view.totp_secret != old_secret
    now.tick()
    new_code = code_for(view.totp_secret, now)
    with refused("password"):
        accounts.accept_invite(token, None, new_code, secret=view.totp_secret)
    with refused("password"):
        accounts.accept_invite(token, None, new_code, secret=view.totp_secret,
                               current_password="wrong password here")
    with refused("bad_code"):
        accounts.accept_invite(token, None, code_for(old_secret, now), secret=view.totp_secret,
                               current_password=PW_TECH)
    account_id, codes = accounts.accept_invite(token, None, new_code, secret=view.totp_secret,
                                               current_password=PW_TECH)
    assert account_id == tech_id and len(codes) == 10 and not set(codes) & set(old_codes)
    row = store.account_by_id(tech_id)
    assert row["totp_secret"] == view.totp_secret
    with sqlite3.connect(store.path) as c:
        stored = {r[0] for r in c.execute("SELECT code_hash FROM recovery_codes "
                                          "WHERE account_id = ?", (tech_id,))}
    assert stored == {recovery_hash(code) for code in codes}


def test_recover_owner_refuses_an_unknown_email_and_promotes_a_tech_only_with_promote(
        accounts, store, now):
    owner_id, _, _ = setup_owner(accounts, now)
    tech_id, _, _ = join(accounts, now, owner_id, "tech@msp.example", "tech")
    with refused("no_such_account"):
        accounts.recover_owner("nobody@client.example")
    assert store.count_accounts() == 2      # it never creates an account

    with refused("not_allowed"):
        accounts.recover_owner("tech@msp.example")
    assert store.account_by_id(tech_id)["role"] == "tech"
    assert store.account_by_id(tech_id)["password_hash"] is not None

    token = accounts.recover_owner("TECH@msp.example", promote=True)
    row = store.account_by_id(tech_id)
    assert (row["role"], row["status"]) == ("owner", "active")
    assert row["password_hash"] is None and row["totp_secret"] is None
    view = accounts.invite_view(token)
    assert view.kind == "recover" and view.role == "owner" and view.totp_secret
    now.tick()
    account_id, codes = accounts.accept_invite(token, PW_NEW, code_for(view.totp_secret, now), secret=view.totp_secret)
    assert account_id == tech_id and len(codes) == 10
    # using the recovery link is its own event, not an accepted invite
    ev = store.events(limit=1)[0]
    assert ev["event"] == "owner_recovered"
    assert json.loads(ev["detail"]) == {"invite_kind": "recover", "role": "owner"}
    assert account_views.event_columns(ev, {})["event"] == "Owner recovery completed"

    # an active owner: password and MFA cleared, a link to set new ones
    token = accounts.recover_owner("owner@client.example")
    assert store.account_by_id(owner_id)["password_hash"] is None
    assert accounts.invite_view(token).kind == "recover"
    ev = store.events(limit=1)[0]
    assert (ev["event"], ev["actor_id"], ev["via"]) == ("recover_owner", None, "command_line")

    # a removed account is not recovered
    accounts.remove(tech_id, owner_id)
    with refused("no_such_account"):
        accounts.recover_owner("owner@client.example")


def test_resets_and_removal_end_every_session(accounts, store, now):
    owner_id, _, _ = setup_owner(accounts, now)
    tech_id, secret, _ = join(accounts, now, owner_id, "tech@msp.example", "tech")
    other_id, _, _ = join(accounts, now, owner_id, "other@msp.example", "tech")
    add_session(store, owner_id, "s-owner")
    add_session(store, other_id, "s-other")

    def two_sessions():
        add_session(store, tech_id, f"s1-{now()}")
        add_session(store, tech_id, f"s2-{now()}")
        assert sessions_of(store, tech_id) == 2

    two_sessions()
    accounts.set_role(owner_id, tech_id, "owner")
    assert sessions_of(store, tech_id) == 0

    two_sessions()
    token = accounts.reset_link(owner_id, tech_id, "reset_password")
    assert sessions_of(store, tech_id) == 2           # making the link changes nothing yet
    now.tick()
    accounts.accept_invite(token, PW_NEW, None, current_code=code_for(secret, now))
    assert sessions_of(store, tech_id) == 0

    two_sessions()
    token = accounts.reset_link(owner_id, tech_id, "reset_mfa")
    view = accounts.invite_view(token)
    now.tick()
    accounts.accept_invite(token, None, code_for(view.totp_secret, now), secret=view.totp_secret, current_password=PW_NEW)
    assert sessions_of(store, tech_id) == 0

    two_sessions()
    accounts.recover_owner("tech@msp.example")
    assert sessions_of(store, tech_id) == 0

    two_sessions()
    accounts.remove(owner_id, tech_id)
    assert sessions_of(store, tech_id) == 0
    # nobody else's sessions were touched
    assert sessions_of(store, owner_id) == 1 and sessions_of(store, other_id) == 1


def test_every_mutation_writes_one_event_without_secrets(accounts, store, now, clock, caplog):
    caplog.set_level("INFO", logger="remediation_zero.accounts")
    secrets_seen = []

    def count():
        return len(store.events(limit=10_000))

    def step(expected_event, fn):
        before = count()
        result = fn()
        assert count() == before + 1, expected_event
        ev = store.events(limit=1)[0]
        assert ev["event"] == expected_event
        stamp = clock.now()
        assert (ev["real_ts"], ev["sim_ts"]) == (stamp.real_ts, stamp.sim_ts)
        return result

    secret = totp.new_secret()
    secrets_seen += [secret, PW_OWNER]
    codes = step("setup", lambda: accounts.setup_first(
        "owner@client.example", "owner", PW_OWNER, secret, code_for(secret, now)))
    secrets_seen += codes
    owner_id = store.account_by_email("owner@client.example")["id"]

    token = step("invite_created", lambda: accounts.invite(owner_id, "tech@msp.example", "tech"))
    view = accounts.invite_view(token)
    secrets_seen += [token, token_hash(token), view.totp_secret, PW_TECH]
    now.tick()
    tech_id, codes = step("invite_accepted", lambda: accounts.accept_invite(
        token, PW_TECH, code_for(view.totp_secret, now), secret=view.totp_secret))
    secrets_seen += codes
    tech_secret = view.totp_secret

    spare = step("invite_created", lambda: accounts.invite(owner_id, "spare@msp.example", "tech"))
    secrets_seen += [spare, token_hash(spare)]
    step("invite_revoked", lambda: accounts.revoke_invite(owner_id, token_hash(spare)))

    link = step("reset_link_created",
                lambda: accounts.reset_link(owner_id, tech_id, "reset_password"))
    secrets_seen += [link, token_hash(link), PW_NEW]
    now.tick()
    step("password_reset", lambda: accounts.accept_invite(
        link, PW_NEW, None, current_code=code_for(tech_secret, now)))

    link = step("reset_link_created", lambda: accounts.reset_link(owner_id, tech_id, "reset_mfa"))
    view = accounts.invite_view(link)
    secrets_seen += [link, token_hash(link), view.totp_secret]
    now.tick()
    _, codes = step("mfa_reset", lambda: accounts.accept_invite(
        link, None, code_for(view.totp_secret, now), secret=view.totp_secret, current_password=PW_NEW))
    secrets_seen += codes

    step("role_changed", lambda: accounts.set_role(owner_id, tech_id, "owner"))
    link = step("recover_owner", lambda: accounts.recover_owner("tech@msp.example"))
    secrets_seen += [link, token_hash(link)]
    step("removed", lambda: accounts.remove(owner_id, tech_id))

    # refusals write nothing
    before = count()
    with refused("last_owner"):
        accounts.remove(owner_id, owner_id)
    with refused("not_allowed"):
        accounts.reset_link(owner_id, owner_id, "reset_mfa")
    assert count() == before

    events = store.events(limit=10_000)
    assert {e["event"] for e in events} == {
        "setup", "invite_created", "invite_accepted", "invite_revoked", "reset_link_created",
        "password_reset", "mfa_reset", "role_changed", "removed", "recover_owner"}
    role_change = next(e for e in events if e["event"] == "role_changed")
    assert json.loads(role_change["detail"]) == {"from": "tech", "to": "owner"}
    assert (role_change["actor_id"], role_change["subject_id"]) == (owner_id, tech_id)

    with sqlite3.connect(store.path) as c:
        dump = json.dumps([list(r) for r in c.execute("SELECT * FROM account_events")])
    logs = "\n".join(r.getMessage() for r in caplog.records)
    assert len([r for r in caplog.records if r.name == "remediation_zero.accounts"]) == len(events)
    for line in logs.splitlines():
        json.loads(line)               # structured
    for value in secrets_seen:
        assert value not in dump, "secret in account_events"
        assert value not in logs, "secret in the log"
    for email in ("owner@client.example", "tech@msp.example", "spare@msp.example"):
        assert email not in dump and email not in logs


# --- a link is only as good as its maker's authority ------------------------

def invite_row(store, token):
    with sqlite3.connect(store.path) as c:
        c.row_factory = sqlite3.Row
        return c.execute("SELECT * FROM invites WHERE token_hash = ?",
                         (token_hash(token),)).fetchone()


def test_a_removed_inviters_link_is_refused(accounts, store, now):
    a_id, _, _ = setup_owner(accounts, now)
    b_id, _, _ = join(accounts, now, a_id, "partner@client.example", "owner")
    token = accounts.invite(b_id, "tech@msp.example", "tech")
    view = accounts.invite_view(token)
    accounts.remove(a_id, b_id)
    now.tick()
    with refused("invalid_link"):
        accounts.accept_invite(token, PW_TECH, code_for(view.totp_secret, now), secret=view.totp_secret)
    assert store.account_by_email("tech@msp.example")["status"] == "invited"

    # the check at use holds even if the maker lost authority some other way
    c_id, _, _ = join(accounts, now, a_id, "third@client.example", "owner")
    token = accounts.invite(c_id, "helper@msp.example", "tech")
    view = accounts.invite_view(token)
    with store.transaction() as cur:
        cur.execute("UPDATE accounts SET status = 'removed' WHERE id = ?", (c_id,))
    now.tick()
    with refused("invalid_link"):
        accounts.accept_invite(token, PW_TECH, code_for(view.totp_secret, now), secret=view.totp_secret)
    row = invite_row(store, token)
    assert (row["used"], row["revoked"]) == (0, 1)        # revoked, not spent
    ev = store.events(limit=1)[0]
    assert ev["event"] == "invite_revoked" and json.loads(ev["detail"]) == {
        "invite_kind": "join", "reason": "maker_not_allowed"}
    assert accounts.invite_view(token) is None


def test_a_demoted_owners_reset_link_is_refused(accounts, store, now):
    a_id, _, _ = setup_owner(accounts, now)
    b_id, _, _ = join(accounts, now, a_id, "partner@client.example", "owner")
    tech_id, secret, _ = join(accounts, now, a_id, "tech@msp.example", "tech")
    token = accounts.reset_link(b_id, tech_id, "reset_password")
    accounts.set_role(a_id, b_id, "tech")
    now.tick()
    with refused("invalid_link"):
        accounts.accept_invite(token, PW_NEW, None, current_code=code_for(secret, now))

    # and when the demotion bypassed set_role, the link is voided where it is used
    accounts.set_role(a_id, b_id, "owner")
    token = accounts.reset_link(b_id, tech_id, "reset_mfa")
    with store.transaction() as cur:
        cur.execute("UPDATE accounts SET role = 'tech' WHERE id = ?", (b_id,))
    assert accounts.invite_view(token) is None
    assert invite_row(store, token)["revoked"] == 1
    with refused("invalid_link"):
        accounts.accept_invite(token, None, "123456", current_password=PW_TECH)
    assert store.account_by_id(tech_id)["totp_secret"] == secret

    # a recover link has no maker and is not affected
    link = accounts.recover_owner("owner@client.example")
    assert accounts.invite_view(link).kind == "recover"


def test_tech_owner_invite_is_void_once_an_owner_joins(accounts, store, now):
    tech_id, _, _ = setup_owner(accounts, now, email="tech@msp.example", role="tech")
    first = accounts.invite(tech_id, "owner@client.example", "owner")
    second = accounts.invite(tech_id, "spouse@client.example", "owner")
    second_view = accounts.invite_view(second)
    view = accounts.invite_view(first)
    now.tick()
    owner_id, _ = accounts.accept_invite(first, PW_OWNER, code_for(view.totp_secret, now), secret=view.totp_secret)
    ev = store.events(limit=1)[0]
    assert ev["event"] == "invite_accepted"
    assert json.loads(ev["detail"]) == {"invite_kind": "join", "role": "owner", "count": 1}
    assert invite_row(store, second)["revoked"] == 1
    assert accounts.invite_view(second) is None
    with refused("invalid_link"):
        accounts.accept_invite(second, PW_NEW, code_for(second_view.totp_secret, now), secret=second_view.totp_secret)
    # the owner may invite that person again
    assert accounts.invite_view(accounts.invite(owner_id, "spouse@client.example", "owner"))

    # and if the cascade were missed, the check at use still refuses it
    tech2_id, _, _ = join(accounts, now, owner_id, "tech2@msp.example", "tech")
    with store.transaction() as cur:
        cur.execute("INSERT INTO invites (token_hash, kind, email, role, account_id, "
                    "created_by, expires_at, real_ts, sim_ts) VALUES (?, 'join', "
                    "'late@client.example', 'owner', 'acct-late', ?, ?, 1.0, 1.0)",
                    (token_hash("stale-tech-link"), tech2_id, now() + DAY))
        cur.execute("INSERT INTO accounts (id, email, role, status) VALUES "
                    "('acct-late', 'late@client.example', 'owner', 'invited')")
    assert accounts.invite_view("stale-tech-link") is None
    assert invite_row(store, "stale-tech-link")["revoked"] == 1


def test_remove_and_demotion_revoke_the_subjects_unused_links(accounts, store, now):
    a_id, _, _ = setup_owner(accounts, now)
    b_id, _, _ = join(accounts, now, a_id, "partner@client.example", "owner")
    tech_id, _, _ = join(accounts, now, b_id, "tech@msp.example", "tech")   # B's used link
    pending = accounts.invite(b_id, "tech2@msp.example", "tech")
    reset = accounts.reset_link(b_id, tech_id, "reset_password")
    mine = accounts.invite(a_id, "tech3@msp.example", "tech")

    accounts.set_role(a_id, b_id, "tech")
    assert invite_row(store, pending)["revoked"] == 1
    assert invite_row(store, reset)["revoked"] == 1
    assert invite_row(store, mine)["revoked"] == 0                # not B's
    with sqlite3.connect(store.path) as c:
        used = c.execute("SELECT used, revoked FROM invites WHERE created_by = ? AND used = 1",
                         (b_id,)).fetchall()
    assert used == [(1, 0)]                                       # history left alone
    ev = store.events(limit=1)[0]
    assert json.loads(ev["detail"]) == {"from": "owner", "to": "tech", "count": 2}

    accounts.set_role(a_id, b_id, "owner")
    later = accounts.invite(b_id, "tech4@msp.example", "tech")
    accounts.remove(a_id, b_id)
    assert invite_row(store, later)["revoked"] == 1
    ev = store.events(limit=1)[0]
    assert (ev["event"], json.loads(ev["detail"])) == ("removed", {"role": "owner", "count": 1})


# --- reset links' second factor is rate limited -----------------------------

def test_reset_link_second_factor_failures_lock_the_account(accounts, store, now):
    from tools.accounts import LOCK_AFTER, LOCK_SECONDS, LOCK_WINDOW
    assert (LOCK_AFTER, LOCK_WINDOW, LOCK_SECONDS) == (5, 900, 900)
    owner_id, _, _ = setup_owner(accounts, now)
    tech_id, secret, _ = join(accounts, now, owner_id, "tech@msp.example", "tech")
    token = accounts.reset_link(owner_id, tech_id, "reset_password")

    for _ in range(LOCK_AFTER - 1):
        with refused("bad_code"):
            accounts.accept_invite(token, PW_NEW, None, current_code=wrong_code(secret, now))
    row = store.account_by_id(tech_id)
    assert row["failed_count"] == LOCK_AFTER - 1 and row["locked_until"] is None
    # failures older than the window no longer count
    now.tick(LOCK_WINDOW)
    with refused("bad_code"):
        accounts.accept_invite(token, PW_NEW, None, current_code=wrong_code(secret, now))
    assert store.account_by_id(tech_id)["failed_count"] == 1
    for _ in range(LOCK_AFTER - 2):
        with refused("bad_code"):
            accounts.accept_invite(token, PW_NEW, None, current_code=wrong_code(secret, now))
    assert store.events(limit=1)[0]["event"] != "locked"
    with refused("bad_code"):
        accounts.accept_invite(token, PW_NEW, None, current_code=wrong_code(secret, now))
    row = store.account_by_id(tech_id)
    assert row["locked_until"] == now() + LOCK_SECONDS
    ev = store.events(limit=1)[0]
    assert (ev["event"], ev["subject_id"]) == ("locked", tech_id)
    assert json.loads(ev["detail"])["count"] == LOCK_AFTER
    inv = invite_row(store, token)
    assert (inv["used"], inv["revoked"]) == (0, 0)                # the link is not burnt

    # a wrong current password on a reset_mfa link counts the same way
    other_id, _, _ = join(accounts, now, owner_id, "other@msp.example", "tech")
    link = accounts.reset_link(owner_id, other_id, "reset_mfa")
    view = accounts.invite_view(link)
    for _ in range(LOCK_AFTER):
        with refused("password"):
            accounts.accept_invite(link, None, code_for(view.totp_secret, now), secret=view.totp_secret,
                                   current_password="not the password at all")
    assert store.account_by_id(other_id)["locked_until"] == now() + LOCK_SECONDS
    assert store.events(limit=1)[0]["event"] == "locked"

    # a wrong code from the link's *new* secret is not a guess at an existing factor
    third_id, _, _ = join(accounts, now, owner_id, "third@msp.example", "tech")
    link = accounts.reset_link(owner_id, third_id, "reset_mfa")
    view = accounts.invite_view(link)
    with refused("bad_code"):
        accounts.accept_invite(link, None, wrong_code(view.totp_secret, now), secret=view.totp_secret,
                               current_password=PW_TECH)
    assert (store.account_by_id(third_id)["failed_count"] or 0) == 0


def test_a_locked_account_cannot_use_a_reset_link(accounts, store, now):
    from tools.accounts import LOCK_AFTER, LOCK_SECONDS
    owner_id, _, _ = setup_owner(accounts, now)
    tech_id, secret, _ = join(accounts, now, owner_id, "tech@msp.example", "tech")
    token = accounts.reset_link(owner_id, tech_id, "reset_password")
    for _ in range(LOCK_AFTER):
        with refused("bad_code"):
            accounts.accept_invite(token, PW_NEW, None, current_code=wrong_code(secret, now))
    locked_until = store.account_by_id(tech_id)["locked_until"]
    events_then = len(store.events(limit=10_000))
    now.tick()
    # locked: even the right code is refused, and a wrong one is not counted
    with refused("locked"):
        accounts.accept_invite(token, PW_NEW, None, current_code=code_for(secret, now))
    with refused("locked"):
        accounts.accept_invite(token, PW_NEW, None, current_code=wrong_code(secret, now))
    mfa = accounts.reset_link(owner_id, tech_id, "reset_mfa")
    view = accounts.invite_view(mfa)
    with refused("locked"):
        accounts.accept_invite(mfa, None, code_for(view.totp_secret, now), secret=view.totp_secret,
                               current_password=PW_TECH)
    row = store.account_by_id(tech_id)
    assert row["locked_until"] == locked_until and row["failed_count"] == 0
    assert len(store.events(limit=10_000)) == events_then + 1     # just the reset_link
    assert invite_row(store, token)["used"] == 0
    # once the lock lapses the same link works, and the counters are cleared
    now.tick(LOCK_SECONDS)
    accounts.accept_invite(token, PW_NEW, None, current_code=code_for(secret, now))
    row = store.account_by_id(tech_id)
    assert row["locked_until"] is None and row["failed_count"] == 0


def _counting(monkeypatch, module, name, watched):
    """Wrap module.name so calls whose first argument is in `watched` are counted."""
    real = getattr(module, name)
    calls = []
    guard = threading.Lock()

    def wrapper(first, *args, **kwargs):
        if first in watched:
            with guard:
                calls.append(first)
        return real(first, *args, **kwargs)

    monkeypatch.setattr(module, name, wrapper)
    return calls


def test_concurrent_reset_guesses_cannot_exceed_the_cap(tmp_path, clock, now, monkeypatch):
    from tools import passwords
    from tools.accounts import LOCK_AFTER, LOCK_SECONDS
    path = tmp_path / "accounts.sqlite3"
    accounts = Accounts(AccountStore(path), clock, now=now)
    owner_id, _, _ = setup_owner(accounts, now)
    tech_id, secret, _ = join(accounts, now, owner_id, "tech@msp.example", "tech")
    other_id, _, _ = join(accounts, now, owner_id, "other@msp.example", "tech")
    code_link = accounts.reset_link(owner_id, tech_id, "reset_password")
    pw_link = accounts.reset_link(owner_id, other_id, "reset_mfa")
    new_secret = accounts.invite_view(pw_link).totp_secret
    other_hash = AccountStore(path).account_by_id(other_id)["password_hash"]
    now.tick()
    code_checks = _counting(monkeypatch, totp, "match", {secret})
    password_checks = _counting(monkeypatch, passwords, "verify", {"wrong guess, in parallel"})

    def burst(attempt, n=20):
        barrier = threading.Barrier(n)
        outcomes = []
        guard = threading.Lock()

        def run():
            mine = Accounts(AccountStore(path), clock, now=now)
            barrier.wait()
            try:
                attempt(mine)
                result = "accepted"
            except AccountRefused as exc:
                result = exc.code
            with guard:
                outcomes.append(result)

        threads = [threading.Thread(target=run) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return outcomes

    outcomes = burst(lambda acc: acc.accept_invite(
        code_link, PW_NEW, None, current_code=wrong_code(secret, now)))
    assert len(code_checks) == LOCK_AFTER                 # verified at most the cap
    assert sorted(set(outcomes)) == ["bad_code", "locked"]
    assert outcomes.count("bad_code") == LOCK_AFTER
    assert outcomes.count("locked") == 20 - LOCK_AFTER
    store = AccountStore(path)
    assert store.account_by_id(tech_id)["locked_until"] == now() + LOCK_SECONDS
    assert [e["subject_id"] for e in store.events(limit=10_000)
            if e["event"] == "locked"] == [tech_id]

    assert password_checks == []
    outcomes = burst(lambda acc: acc.accept_invite(
        pw_link, None, code_for(new_secret, now), secret=new_secret, current_password="wrong guess, in parallel"))
    assert len(password_checks) == LOCK_AFTER
    assert outcomes.count("password") == LOCK_AFTER and outcomes.count("locked") == 15
    assert store.account_by_id(other_id)["locked_until"] == now() + LOCK_SECONDS
    assert store.account_by_id(other_id)["password_hash"] == other_hash
    inv = invite_row(store, code_link)
    assert (inv["used"], inv["revoked"]) == (0, 0)


def test_a_correct_guess_after_the_cap_is_refused(accounts, store, now, monkeypatch):
    from tools import passwords
    from tools.accounts import LOCK_AFTER
    owner_id, _, _ = setup_owner(accounts, now)
    tech_id, secret, _ = join(accounts, now, owner_id, "tech@msp.example", "tech")
    token = accounts.reset_link(owner_id, tech_id, "reset_password")
    mfa = accounts.reset_link(owner_id, tech_id, "reset_mfa")
    new_secret = accounts.invite_view(mfa).totp_secret
    for _ in range(LOCK_AFTER):
        with refused("bad_code"):
            accounts.accept_invite(token, PW_NEW, None, current_code=wrong_code(secret, now))
    now.tick()
    code_checks = _counting(monkeypatch, totp, "match", {secret})
    password_checks = _counting(monkeypatch, passwords, "verify", {PW_TECH})
    with refused("locked"):
        accounts.accept_invite(token, PW_NEW, None, current_code=code_for(secret, now))
    with refused("locked"):
        accounts.accept_invite(mfa, None, code_for(new_secret, now), secret=new_secret, current_password=PW_TECH)
    assert code_checks == [] and password_checks == []     # never verified while locked
    row = store.account_by_id(tech_id)
    assert row["totp_secret"] == secret
    assert passwords.verify(PW_TECH, row["password_hash"])
    # the fifth reservation is itself verified: a right guess there succeeds
    now.tick(15 * 60)
    for _ in range(LOCK_AFTER - 1):
        with refused("bad_code"):
            accounts.accept_invite(token, PW_NEW, None, current_code=wrong_code(secret, now))
    accounts.accept_invite(token, PW_NEW, None, current_code=code_for(secret, now))
    row = store.account_by_id(tech_id)
    assert row["locked_until"] is None and row["failed_count"] == 0


# --- final round: no TOTP secret is kept for a link (I4), a removed email comes back (I5) ---


def test_each_view_of_an_enrolling_link_shows_a_new_secret_and_stores_none(accounts, store, now):
    owner_id, _, _ = setup_owner(accounts, now)
    tech_id, _, _ = join(accounts, now, owner_id, "tech@msp.example", "tech")
    links = [accounts.invite(owner_id, "new@msp.example", "tech"),
             accounts.reset_link(owner_id, tech_id, "reset_mfa"),
             accounts.recover_owner("owner@client.example")]
    for token in links:
        first, second = accounts.invite_view(token), accounts.invite_view(token)
        assert first.totp_secret and second.totp_secret and first.totp_secret != second.totp_secret
        assert invite_row(store, token)["totp_secret"] is None


def test_accepting_enrols_the_secret_given_and_needs_one(accounts, store, now):
    owner_id, _, _ = setup_owner(accounts, now)
    token = accounts.invite(owner_id, "tech@msp.example", "tech")
    shown, later = accounts.invite_view(token), accounts.invite_view(token)
    now.tick()
    with refused("bad_code"):        # no secret: nothing to check the code against
        accounts.accept_invite(token, PW_TECH, code_for(shown.totp_secret, now))
    with refused("bad_code"):        # not a secret at all
        accounts.accept_invite(token, PW_TECH, code_for(shown.totp_secret, now), secret="not-base32!")
    account_id, codes = accounts.accept_invite(token, PW_TECH, code_for(shown.totp_secret, now),
                                               secret=shown.totp_secret)
    row = store.account_by_id(account_id)
    assert row["totp_secret"] == shown.totp_secret != later.totp_secret
    assert len(codes) == 10


def test_a_removed_account_can_be_invited_again_keeping_its_id(accounts, store, now):
    owner_id, _, _ = setup_owner(accounts, now)
    tech_id, _, _ = join(accounts, now, owner_id, "tech@msp.example", "tech")
    accounts.remove(owner_id, tech_id)
    token = accounts.invite(owner_id, "Tech@MSP.example", "owner")
    row = store.account_by_id(tech_id)
    assert (row["status"], row["role"], row["password_hash"], row["totp_secret"]) == (
        "invited", "owner", None, None)
    created = [dict(r) for r in store.events(50) if r["event"] == "invite_created"][0]
    assert created["subject_id"] == tech_id
    assert json.loads(created["detail"]) == {"invite_kind": "join", "role": "owner", "reason": "reinvited"}
    # a second invite while that one is live is still refused
    with refused("email_taken"):
        accounts.invite(owner_id, "tech@msp.example", "tech")
    view = accounts.invite_view(token)
    now.tick()
    account_id, _ = accounts.accept_invite(token, PW_NEW, code_for(view.totp_secret, now),
                                           secret=view.totp_secret)
    assert account_id == tech_id            # old records still name the same person
    assert store.account_by_id(tech_id)["status"] == "active"
    assert store.count_accounts() == 2
