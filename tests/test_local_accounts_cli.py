# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The account and settings commands (scripts/local_accounts.py, scripts/local.py).

Run in-process through scripts.local.main, so the accounts file can be the signed-in
template (tests/signed_in.py) rather than paying for scrypt in every test. Synthetic
data only: client.example accounts, .test server names, TEST-NET addresses."""
import json
import os
import re

import pytest

from scripts import local
from tests.signed_in import OWNER, TECH, site
from tools import local_settings, totp
from tools.account_store import AccountStore
from tools.accounts import Accounts
from tools.clock import ClockMode, SimClock
from tools.local_layout import Workspace
from ui.account_views import REFUSALS

PASSWORD = 'quiet orchard sundial lantern'  # synthetic
CODE = re.compile(r'\b[a-z2-7]{5}-[a-z2-7]{5}\b')
AS_REFUSED = '--as must name an active account. Nothing was changed.'


def cli(capsys, database, *argv):
    """(exit code, stdout, stderr) of one command, run in this process."""
    try:
        local.main(['--database', str(database), *argv])
        code = 0
    except SystemExit as exit_:
        code = exit_.code if isinstance(exit_.code, int) else (0 if exit_.code is None else 1)
    out, err = capsys.readouterr()
    return code, out, err


@pytest.fixture
def db(tmp_path):
    root = tmp_path / 'w'
    Workspace(root).init()
    return root


@pytest.fixture
def people(db, tmp_path_factory):
    """The workspace's accounts file holds an active owner and an active tech."""
    return site(db, tmp_path_factory.getbasetemp())


def store(db):
    return AccountStore(Workspace(db).accounts_path())


def link(db, token):
    """What a printed link is for, read on the wall clock the command used."""
    return Accounts(store(db), SimClock(ClockMode.REAL)).invite_view(token)


def events(db):
    return [dict(row) for row in store(db).events(1000)]


# --- account setup -------------------------------------------------------------


def test_setup_creates_the_first_account_and_prints_recovery_codes(db, capsys, monkeypatch):
    prompts, answers = [], iter(['Owner@Client.example', 'owner'])

    def fake_input(prompt=''):
        prompts.append(prompt)
        if 'code' in prompt.lower():
            shown = capsys.readouterr().out
            print(shown, end='')  # keep it for the assertions below
            secret = re.search(r'Key: ([A-Z2-7]+)', shown)[1]
            return totp.code_at(secret, totp.step_for(SimClock(ClockMode.REAL).now().real_ts))
        return next(answers)

    secrets_asked = []
    monkeypatch.setattr('builtins.input', fake_input)
    monkeypatch.setattr('getpass.getpass', lambda prompt='': secrets_asked.append(prompt) or PASSWORD)
    code, out, err = cli(capsys, db, 'account', 'setup')
    assert code == 0, err
    assert len(secrets_asked) == 2  # the password, twice
    assert 'otpauth://totp/' in out and re.search(r'Key: [A-Z2-7]{16,}', out)
    assert len(set(CODE.findall(out))) == 10
    assert PASSWORD not in out + err
    row = store(db).account_by_email(OWNER)
    assert (row['role'], row['status']) == ('owner', 'active')
    setup = [e for e in events(db) if e['event'] == 'setup']
    assert len(setup) == 1 and setup[0]['via'] == 'command_line'


def test_setup_refuses_when_an_account_exists(db, people, capsys, monkeypatch):
    def never(*args, **kwargs):
        raise AssertionError('nothing is asked once an account exists')

    monkeypatch.setattr('builtins.input', never)
    monkeypatch.setattr('getpass.getpass', never)
    before = len(events(db))
    code, out, err = cli(capsys, db, 'account', 'setup')
    assert code == 1
    assert err == REFUSALS['accounts_exist'] + '\n' and out == ''
    assert len(events(db)) == before


def test_setup_refuses_passwords_that_differ(db, capsys, monkeypatch):
    answers = iter([PASSWORD, PASSWORD + ' and more'])
    emails = iter(['owner@client.example', 'owner'])
    monkeypatch.setattr('builtins.input', lambda prompt='': next(emails))
    monkeypatch.setattr('getpass.getpass', lambda prompt='': next(answers))
    code, out, err = cli(capsys, db, 'account', 'setup')
    assert code == 1 and 'did not match' in err and len(err.splitlines()) == 1
    assert store(db).count_accounts() == 0


# --- --as ------------------------------------------------------------------------


def test_as_must_name_an_active_account(db, people, capsys):
    before = len(events(db))
    for name in ('nobody@client.example', 'not an email'):
        code, out, err = cli(capsys, db, 'account', 'invite', '--email', 'new@client.example',
                             '--role', 'tech', '--as', name)
        assert (code, out, err) == (1, '', AS_REFUSED + '\n')
    # an invited (not yet joined) account is not active either
    code, out, _ = cli(capsys, db, 'account', 'invite', '--email', 'new@client.example', '--role', 'tech',
                       '--as', OWNER)
    assert code == 0 and '/invite/' in out
    code, _, err = cli(capsys, db, 'account', 'remove', TECH, '--as', 'new@client.example')
    assert (code, err) == (1, AS_REFUSED + '\n')
    assert len(events(db)) == before + 1  # only the invite


def test_account_commands_act_as_the_named_account(db, people, capsys):
    owner_id = store(db).account_by_email(OWNER)['id']
    tech_id = store(db).account_by_email(TECH)['id']
    before = len(events(db))
    # a tech is refused what only an owner may do, with the page's sentence
    code, _, err = cli(capsys, db, 'account', 'remove', OWNER, '--as', TECH)
    assert (code, err) == (1, REFUSALS['not_allowed'] + '\n')
    code, _, err = cli(capsys, db, 'account', 'invite', '--email', 'x@client.example', '--role', 'tech',
                       '--as', TECH)
    assert (code, err) == (1, REFUSALS['not_allowed'] + '\n')

    code, out, err = cli(capsys, db, 'account', 'invite', '--email', 'new@client.example', '--role', 'tech',
                         '--as', OWNER)
    assert code == 0, err
    found = re.search(r'http://127\.0\.0\.1:8081/invite/(\S+)', out)
    assert found and link(db, found[1]).email == 'new@client.example'

    code, out, err = cli(capsys, db, 'account', 'reset-password', TECH, '--as', OWNER)
    assert code == 0, err
    assert link(db, re.search(r'/invite/(\S+)', out)[1]).kind == 'reset_password'
    code, out, _ = cli(capsys, db, 'account', 'reset-mfa', TECH, '--as', OWNER)
    assert code == 0 and link(db, re.search(r'/invite/(\S+)', out)[1]).kind == 'reset_mfa'

    code, _, err = cli(capsys, db, 'account', 'set-role', TECH, 'owner', '--as', OWNER)
    assert code == 0, err
    assert store(db).account_by_id(tech_id)['role'] == 'owner'
    code, _, err = cli(capsys, db, 'account', 'remove', TECH, '--as', OWNER)
    assert code == 0, err
    assert store(db).account_by_id(tech_id)['status'] == 'removed'
    code, _, err = cli(capsys, db, 'account', 'remove', OWNER, '--as', OWNER)
    assert (code, err) == (1, REFUSALS['last_owner'] + '\n')
    code, _, err = cli(capsys, db, 'account', 'set-role', TECH, 'chief', '--as', OWNER)
    assert code == 2  # argparse: not a role

    code, out, _ = cli(capsys, db, 'account', 'list')
    listed = [json.loads(line) for line in out.splitlines()]
    assert {(r['email'], r['role'], r['status']) for r in listed} >= {
        (OWNER, 'owner', 'active'), (TECH, 'owner', 'removed'), ('new@client.example', 'tech', 'invited')}
    assert all(set(r) == {'email', 'role', 'status'} for r in listed)

    made = events(db)[:len(events(db)) - before]
    assert [e['event'] for e in made] == ['removed', 'role_changed', 'reset_link_created', 'reset_link_created',
                                          'invite_created']
    assert all((e['actor_id'], e['via']) == (owner_id, 'command_line') for e in made)
    code, out, _ = cli(capsys, db, 'account', 'events', '--limit', '3')
    shown = [json.loads(line) for line in out.splitlines()]
    assert len(shown) == 3
    assert all(set(r) == {'time', 'event', 'by', 'account', 'via', 'note'} for r in shown)
    assert shown[0] == {'time': shown[0]['time'], 'event': 'Account removed', 'by': OWNER, 'account': TECH,
                        'via': 'command_line', 'note': ''}
    for bad in ('0', '1001', 'many'):
        assert cli(capsys, db, 'account', 'events', '--limit', bad)[0] == 2


def test_events_never_show_email_hmac(db, people, capsys):
    assert people.accounts.sign_in('nobody@client.example', PASSWORD, '000000', '192.0.2.10') is None
    raw = events(db)[0]
    assert raw['event'] == 'sign_in_failed' and 'email_hmac' in (raw['detail'] or '')
    code, out, _ = cli(capsys, db, 'account', 'events', '--limit', '1')
    assert code == 0
    assert json.loads(out) ['account'] == 'no such account'
    assert 'email_hmac' not in out and json.loads(raw['detail'])['email_hmac'] not in out


# --- recover-owner -----------------------------------------------------------------


def test_recover_owner_prints_a_link_and_records_the_event(db, people, capsys):
    owner_id = store(db).account_by_email(OWNER)['id']
    code, out, err = cli(capsys, db, 'account', 'recover-owner', '--email', OWNER)
    assert code == 0, err
    token = re.search(r'^http://127\.0\.0\.1:8081/invite/(\S+)$', out, re.M)[1]
    assert link(db, token).kind == 'recover'
    recovered = [e for e in events(db) if e['event'] == 'recover_owner']
    assert len(recovered) == 1
    assert (recovered[0]['subject_id'], recovered[0]['via'], recovered[0]['actor_id']) == (
        owner_id, 'command_line', None)
    assert token not in json.dumps(events(db))

    # a tech needs --promote; an unknown email is refused; nothing is created
    code, _, err = cli(capsys, db, 'account', 'recover-owner', '--email', TECH)
    assert code == 1 and len(err.splitlines()) == 1 and '--promote' in err
    code, _, err = cli(capsys, db, 'account', 'recover-owner', '--email', 'nobody@client.example')
    assert (code, err) == (1, REFUSALS['no_such_account'] + '\n')
    code, out, _ = cli(capsys, db, 'account', 'recover-owner', '--email', TECH, '--promote')
    assert code == 0 and '/invite/' in out
    assert store(db).account_by_email(TECH)['role'] == 'owner'
    assert store(db).count_accounts() == 2


def test_links_use_the_first_server_name_when_exposed(db, people, capsys):
    path = local_settings.settings_path(db)
    local_settings.save(path, dict(local_settings.DEFAULTS, listen_address='0.0.0.0', port=8443,
                                   server_names=['rz.example.test', '192.0.2.10']))
    code, out, err = cli(capsys, db, 'account', 'recover-owner', '--email', OWNER)
    assert code == 0, err
    assert re.search(r'^https://rz\.example\.test:8443/invite/\S+$', out, re.M)


# --- settings ------------------------------------------------------------------------


def test_settings_show_prints_the_settings_file(db, capsys):
    code, out, _ = cli(capsys, db, 'settings', 'show')
    assert code == 0 and json.loads(out) == local_settings.load(local_settings.settings_path(db))


def test_settings_set_validates_like_the_page(db, capsys, monkeypatch, tmp_path):
    path = local_settings.settings_path(db)
    calls = []
    real = local.apply_settings_form
    monkeypatch.setattr(local, 'apply_settings_form', lambda *a, **k: calls.append(a[1]) or real(*a, **k))
    not_pem = tmp_path / 'not.pem'
    not_pem.write_text('not a certificate')
    refused = {
        ('application', 'port=80'): 'Choose a port from 1024 to 65535. Nothing was saved.',
        ('application', 'port=eighty'): 'A value is not valid. Nothing was saved.',
        ('application', 'server_names=bad_name!'): 'A server name must be a host name or an IP address. '
                                                    'Nothing was saved.',
        ('application', 'listen_address=192.0.2.1'): 'This machine cannot listen on 192.0.2.1. '
                                                      'Nothing was saved.',
        ('application', 'certificate.mode=own'): 'Your own certificate needs two absolute paths: the '
                                                 'certificate and its key. Nothing was saved.',
        ('application', f'certificate.mode=own certificate.cert_file={not_pem} certificate.key_file={not_pem}'):
            'The certificate and key could not be loaded as a matching PEM pair. Nothing was saved.',
        ('application', 'open_browser=maybe'): 'open_browser takes true or false. Nothing was saved.',
        ('application', 'colour=blue'): 'colour is not a field of the application section; write FIELD=VALUE. '
                                        'Nothing was saved.',
        ('application', 'certificate_mode=own'): 'certificate_mode is not a field of the application section; '
                                                 'write FIELD=VALUE. Nothing was saved.',
        ('model', f'proposer.endpoint=https://models.example.test/v1 proposer.model=m proposer.ca_file={not_pem}'):
            'The proposer CA certificate file could not be read as a PEM certificate. Nothing was saved.',
        ('scanner', 'username=someone'): 'username is not a field of the scanner section; write FIELD=VALUE. '
                                         'Nothing was saved.',
        ('scanner', 'task_ids=not-a-uuid'): 'Task IDs must be lowercase UUIDs. Nothing was saved.',
        ('greenbone', 'host=x'): 'The section must be application, model or scanner. Nothing was saved.',
    }
    for (section, assignments), sentence in refused.items():
        code, out, err = cli(capsys, db, 'settings', 'set', section, *assignments.split(' '))
        assert (code, out, err) == (1, '', sentence + '\n'), (section, assignments)
        assert not path.exists()
    assert calls  # the page's own function did the checking
    code, out, err = cli(capsys, db, 'settings', 'set', 'scanner', 'transport=tls', 'host=gvm.example.test',
                         'task_ids=00000000-0000-4000-8000-000000000001,00000000-0000-4000-8000-000000000002',
                         'auto_enrichment=true')
    assert (code, out) == (0, 'Saved.\n'), err
    scanner = local_settings.load(path)['scanner']
    assert scanner['task_ids'] == ['00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002']
    assert scanner['auto_enrichment'] is True and scanner['host'] == 'gvm.example.test'
    code, out, err = cli(capsys, db, 'settings', 'set', 'model', 'proposer.endpoint=http://127.0.0.1:9/v1',
                         'proposer.model=gpt-test')
    assert (code, out) == (0, 'Saved.\n'), err
    assert local_settings.load(path)['roles']['proposer']['family'] == 'gpt'
    assert cli(capsys, db, 'settings', 'set', 'application')[0] == 2  # nothing to set


def test_settings_set_says_restart_required(db, capsys):
    path = local_settings.settings_path(db)
    code, out, err = cli(capsys, db, 'settings', 'set', 'application', 'server_names=rz.example.test,192.0.2.10')
    assert (code, out) == (0, local.SAVED_RESTART + '\n'), err
    assert out == ('Saved. Restart Remediation Zero for listen address, names or certificate changes '
                   'to take effect.\n')
    assert local_settings.load(path)['server_names'] == ['rz.example.test', '192.0.2.10']
    code, out, _ = cli(capsys, db, 'settings', 'set', 'application', 'cycle_interval_minutes=5', 'open_browser=false')
    assert (code, out) == (0, 'Saved.\n')
    saved = local_settings.load(path)
    assert saved['cycle_interval_minutes'] == 5 and saved['open_browser'] is False
    assert saved['server_names'] == ['rz.example.test', '192.0.2.10']  # untouched fields are kept
    code, out, _ = cli(capsys, db, 'settings', 'set', 'application', 'listen_address=127.0.0.2')
    assert (code, out) == (0, local.SAVED_RESTART + '\n')


# --- final round: an unreadable accounts file is one sentence, never a traceback (I2) ------

UNREADABLE = 'The accounts file could not be read or written. Nothing was changed.\n'
needs_non_root = pytest.mark.skipif(hasattr(os, 'geteuid') and os.geteuid() == 0,
                                    reason='root reads a mode-000 file')


@pytest.fixture
def unreadable(db, people):
    path = Workspace(db).accounts_path()
    os.chmod(path, 0)
    yield path
    os.chmod(path, 0o600)


@needs_non_root
@pytest.mark.parametrize('argv', [
    ('account', 'list'),
    ('account', 'invite', '--email', 'new@client.example', '--role', 'tech', '--as', OWNER),
    ('account', 'recover-owner', '--email', OWNER),
    ('approve', 'RZ-0001', '--cycle', '1', '--as', OWNER),
    ('exception', 'accept', 'RZ-0001', '--ttl', '7', '--reason', 'Synthetic', '--cycle', '1', '--as', OWNER),
    ('serve', '--port', '0'),
])
def test_an_unreadable_accounts_file_is_one_sentence(db, unreadable, capsys, argv):
    code, out, err = cli(capsys, db, *argv)
    assert (code, err) == (1, UNREADABLE)
    assert 'Traceback' not in out + err


# --- final round: a removed person can be invited again (I5) -----------------------------


def test_a_removed_account_is_invited_again_with_the_same_id(db, people, capsys):
    tech_id = store(db).account_by_email(TECH)['id']
    assert cli(capsys, db, 'account', 'remove', TECH, '--as', OWNER)[0] == 0
    code, out, err = cli(capsys, db, 'account', 'invite', '--email', TECH, '--role', 'owner', '--as', OWNER)
    assert code == 0, err
    token = re.search(r'/invite/(\S+)', out)[1]
    view = link(db, token)
    assert (view.email, view.role, view.kind) == (TECH, 'owner', 'join')
    assert store(db).account_by_email(TECH)['id'] == tech_id
    code, out, _ = cli(capsys, db, 'account', 'events', '--limit', '1')
    shown = json.loads(out)
    assert (shown['event'], shown['account'], shown['note']) == (
        'Invite created', TECH, 'invited again after being removed')
