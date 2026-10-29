# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Signed-in accounts for the dashboard server's tests.

Every dashboard page and form needs a session, so the tests that drive the
handler need one too. Building accounts costs several scrypt runs, so one
accounts file is built once per test session and copied into each test's own
directory: the copy holds an owner and a tech, each with a live, re-confirmed
session, and an owner session that is not re-confirmed. Synthetic data only."""
import shutil
from dataclasses import dataclass
from pathlib import Path

from tests.test_accounts import PW_OWNER, PW_TECH, T0, Now, code_for, join, setup_owner
from tools.account_store import AccountStore
from tools.accounts import Accounts
from tools.clock import ClockMode, SimClock

OWNER = 'owner@client.example'
TECH = 'tech@client.example'
SOURCE = '192.0.2.10'


def clock():
    c = SimClock(ClockMode.SIM, source=lambda: 1_700_000_000.0)
    c.advance(3 * 86400.0)
    return c


@dataclass
class Site:
    """An accounts file and the wall clock its Accounts reads."""
    accounts: Accounts
    now: Now
    owner_token: str
    tech_token: str
    unconfirmed_token: str
    owner_secret: str
    tech_secret: str
    owner_codes: list

    def cookie(self, who='owner'):
        token = {'owner': self.owner_token, 'tech': self.tech_token,
                 'unconfirmed': self.unconfirmed_token}[who]
        return f'rz_session={token}'


_TEMPLATE = {}


def _build(path):
    now = Now(T0)
    accounts = Accounts(AccountStore(path), clock(), now=now)
    owner_id, owner_secret, owner_codes = setup_owner(accounts, now, email=OWNER)
    _, tech_secret, _ = join(accounts, now, owner_id, TECH, 'tech')
    now.tick()
    owner_token = accounts.sign_in(OWNER, PW_OWNER, code_for(owner_secret, now), SOURCE)
    tech_token = accounts.sign_in(TECH, PW_TECH, code_for(tech_secret, now), SOURCE)
    now.tick()
    unconfirmed = accounts.sign_in(OWNER, PW_OWNER, code_for(owner_secret, now), SOURCE)
    assert owner_token and tech_token and unconfirmed
    now.tick()
    assert accounts.confirm(owner_token, password=PW_OWNER, code=code_for(owner_secret, now))
    assert accounts.confirm(tech_token, password=PW_TECH, code=code_for(tech_secret, now))
    return dict(end=now(), owner_token=owner_token, tech_token=tech_token, unconfirmed_token=unconfirmed,
                owner_secret=owner_secret, tech_secret=tech_secret, owner_codes=owner_codes)


def site(directory, template_dir):
    """A fresh copy of the signed-in accounts file in `directory`."""
    template = Path(template_dir) / 'accounts-template.sqlite3'
    if str(template) not in _TEMPLATE:
        _TEMPLATE[str(template)] = _build(template)
    built = _TEMPLATE[str(template)]
    path = Path(directory) / 'accounts.sqlite3'
    shutil.copyfile(template, path)
    now = Now(built['end'])
    return Site(Accounts(AccountStore(path), clock(), now=now), now,
                **{k: v for k, v in built.items() if k != 'end'})


def empty(directory):
    """An accounts file with no accounts, and its clock."""
    now = Now(T0)
    return Accounts(AccountStore(Path(directory) / 'accounts.sqlite3'), clock(), now=now), now
