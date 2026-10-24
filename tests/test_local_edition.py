# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
import io
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from scripts.local import suggest
from tools.adjudication import CapacityError, Proposal, Verdict
from tools.idempotency import CompletedCall, IdempotencyInProgress, derive_record
from tools.inference_journal import InferenceJournal
from tools.model_endpoint import ModelEndpoint
from tools.sqlite_store import SQLiteStore


def test_real_sqlite_reservation_race_and_restart(tmp_path):
    path = tmp_path / 'local.sqlite3'
    SQLiteStore(path)
    record = derive_record('A', 'attempt', 1)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: SQLiteStore(path).reserve_once(record), range(8)))
    assert results.count(True) == 1
    assert SQLiteStore(path).reserve_once(record) is False


def test_claims_and_stale_completion(tmp_path):
    store = SQLiteStore(tmp_path / 'local.sqlite3')
    record = derive_record('A', 'review', 1)
    old = store.acquire(record)
    assert not store.acquire(record).acquired
    store.abandon(old)
    new = store.acquire(record)
    with pytest.raises(IdempotencyInProgress):
        store.complete(old, CompletedCall(record, 'stale'))
    store.abandon(old)
    store.complete(new, CompletedCall(record, 'valid'))
    assert store.get(record.key).result == 'valid'


def test_outage_budget_and_rejection_survive_reopen(tmp_path):
    path = tmp_path / 'local.sqlite3'
    def journal():
        return InferenceJournal(SQLiteStore(path), 'A', 1, pause=lambda _: None)
    rejection = Verdict(False, 'evidence missing')
    journal().call('review_1', Verdict, lambda: rejection)
    calls = []
    def outage():
        calls.append(1)
        raise CapacityError('outage')
    for _ in range(2):
        with pytest.raises(CapacityError):
            journal().call('review_2', Verdict, outage)
    assert len(calls) == 4
    assert journal().call('review_1', Verdict, lambda: pytest.fail('replayed model')) == rejection


class Endpoint:
    url = 'http://localhost:11434/v1/chat/completions'
    model = 'test'
    calls = 0

    def propose(self, prompt, finding_id):
        self.calls += 1
        return Proposal(finding_id, 'medium', 14, 'Verify version first', ('synthetic evidence',), 'Exposure is unknown')


def test_suggestion_replay_context_and_no_duplicate_record(tmp_path):
    path = tmp_path / 'local.sqlite3'
    endpoint = Endpoint()
    assert suggest(SQLiteStore(path), endpoint, 1) == 'unreviewed'
    assert suggest(SQLiteStore(path), endpoint, 1) == 'unreviewed'
    assert endpoint.calls == 1
    assert len(SQLiteStore(path).snapshot()['decisions']) == 1
    endpoint.model = 'changed'
    with pytest.raises(ValueError, match='changed'):
        suggest(SQLiteStore(path), endpoint, 1)
    assert endpoint.calls == 1


@pytest.mark.parametrize('url', ['http://example.com/v1', 'https://user:pass@example.com/v1',
                               'file:///tmp/key', 'https://example.com/v1?key=secret'])
def test_unsafe_endpoint_config_rejected(url):
    with pytest.raises(ValueError):
        ModelEndpoint(url, 'model')


def test_endpoint_contract_and_no_secret_in_errors(monkeypatch):
    import tools.model_transport as module
    requests = []
    payload = {'finding_id': 'A', 'severity': 'high', 'sla_days': 7,
               'remediation': 'Verify first', 'evidence': ['example'], 'rationale': 'Example only'}
    class Opener:
        def open(self, req, timeout):
            requests.append((req, timeout))
            return io.BytesIO(json.dumps({'choices': [{'finish_reason': 'stop', 'message': {'content': json.dumps(payload)}}]}).encode())
    monkeypatch.setattr(module, 'build_opener', lambda *args: Opener())
    endpoint = ModelEndpoint('https://example.invalid/v1/chat/completions', 'test', 'secret')
    assert endpoint.propose('example', 'A').finding_id == 'A'
    req, timeout = requests[0]
    assert timeout == 60
    assert json.loads(req.data)['max_tokens'] == 2048
    assert req.headers['Authorization'] == 'Bearer secret'
    payload['sla_days'] = True
    with pytest.raises(ValueError, match='invalid proposal'):
        endpoint.propose('example', 'A')


def test_no_third_party_packages_needed(tmp_path):
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, '-S', '-m', 'scripts.local', '--database',
                             str(tmp_path / 'fresh.sqlite3'), 'init'], cwd=root, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert 'No model calls made' in result.stdout


def _roles(**models):
    from tools.model_roles import ModelRoles, RoleConfig
    local = 'http://localhost:11434/v1/chat/completions'
    return ModelRoles(**{r: RoleConfig(r, 'openai_chat', local, 'm-' + r, 'other') for r in models})


class _Adapter:
    def __init__(self, reply):
        self.reply = reply

    def complete(self, system, user, json_output=False):
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


def test_check_models_reports_each_role(tmp_path, monkeypatch, capsys):
    import sys
    import types
    from scripts import local
    from tools import local_settings
    from tools.model_check import SAMPLE_PROPOSAL
    from tools.model_roles import ModelRoles
    database = tmp_path / 'w.sqlite3'
    roles = {r: dict(format='openai_chat', endpoint='http://localhost:1/v1/chat/completions', model='m-' + r, family='other')
             for r in ('proposer', 'reviewer', 'summarizer')}
    roles['guard'] = None
    local_settings.save(local_settings.settings_path(database), dict(local_settings.DEFAULTS, roles=roles))
    replies = {'proposer': json.dumps(SAMPLE_PROPOSAL), 'reviewer': CapacityError('queue full at http://secret.invalid'),
               'summarizer': 'Three findings are open.'}
    monkeypatch.setattr(ModelRoles, 'adapter', lambda self, role, **kw: _Adapter(replies[role]))
    monkeypatch.setitem(sys.modules, 'tools.reports', types.SimpleNamespace(write_summary=lambda m, a: a.complete('', '')))
    before = sorted(p.name for p in tmp_path.iterdir())
    monkeypatch.setattr('sys.argv', ['local', '--database', str(database), 'check-models'])
    with pytest.raises(SystemExit) as stop:
        local.main()
    out = capsys.readouterr().out.splitlines()
    assert stop.value.code == 1
    assert out == ['proposer: ok', 'reviewer: failed (CapacityError)', 'summarizer: ok', 'guard: not configured']
    assert 'secret.invalid' not in ''.join(out)
    assert sorted(p.name for p in tmp_path.iterdir()) == before  # nothing written, no database created


def test_check_models_guard_outcomes_and_role_filter(monkeypatch):
    from tools.model_check import check_models
    lines = []
    roles = _roles(guard=1)
    cases = [('VERDICT: SAFE\nREASON:', 0, 'guard: ok'), ('garbage', 1, 'guard: failed (GuardUnusable)'),
             ('VERDICT: UNSAFE\nREASON: looks hostile', 1, 'guard: failed (GuardBlockedBenign)')]
    for reply, code, line in cases:
        lines.clear()
        monkeypatch.setattr(type(roles), 'adapter', lambda self, role, reply=reply, **kw: _Adapter(reply))
        assert check_models(roles, 'guard', out=lines.append) == code
        assert lines == [line]
    lines.clear()
    assert check_models(roles, 'reviewer', out=lines.append) == 0
    assert lines == ['reviewer: not configured']
