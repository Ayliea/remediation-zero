# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
import stat

import pytest

from tools.local_secrets import Overlay, SecretsFile, SecretsFileUnsafe, secrets_path
from tools.local_settings import settings_path
from tools.secrets_port import check_key

KEY = 'sk-test-ABCD1234'


def test_put_get_hint_delete(tmp_path):
    s = SecretsFile(tmp_path / 'ws.secrets.json')
    s.put('conn-1', KEY)
    assert s.get('conn-1') == KEY and s.hint('conn-1') == '1234'
    s.delete('conn-1')
    assert s.get('conn-1') is None and s.hint('conn-1') is None


def test_a_short_key_stores_no_hint(tmp_path):
    s = SecretsFile(tmp_path / 'ws.secrets.json')
    s.put('conn-1', 'sk-short-12')  # 11 characters: four would be a third of it
    s.put('conn-2', 'sk-test-1234')  # 12 characters
    assert s.get('conn-1') == 'sk-short-12' and s.hint('conn-1') == ''
    assert s.hint('conn-2') == '1234'
    assert Overlay(None, {'d': 'sk-short-12'}).hint('d') == ''


def test_file_is_created_0600(tmp_path):
    path = tmp_path / 'ws.secrets.json'
    SecretsFile(path).put('conn-1', KEY)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_loosened_file_is_refused_naming_the_fix(tmp_path):
    path = tmp_path / 'ws.secrets.json'
    s = SecretsFile(path)
    s.put('conn-1', KEY)
    path.chmod(0o644)
    for call in (lambda: s.get('conn-1'), lambda: s.hint('conn-1'), lambda: s.put('c2', KEY)):
        with pytest.raises(SecretsFileUnsafe) as exc:
            call()
        assert 'chmod 600' in str(exc.value) and str(path) in str(exc.value)
        assert KEY not in str(exc.value)


def test_symlinked_file_is_refused(tmp_path):
    target = tmp_path / 'target.json'
    target.write_text('{"version": 1, "keys": {}}')
    target.chmod(0o600)
    link = tmp_path / 'ws.secrets.json'
    link.symlink_to(target)
    s = SecretsFile(link)
    with pytest.raises((OSError, SecretsFileUnsafe)):
        s.get('conn-1')
    with pytest.raises((OSError, SecretsFileUnsafe)):
        s.put('conn-1', KEY)
    assert target.read_text() == '{"version": 1, "keys": {}}'


def test_broken_json_reads_empty_and_is_not_overwritten(tmp_path):
    path = tmp_path / 'ws.secrets.json'
    path.write_text('{not json')
    path.chmod(0o600)
    s = SecretsFile(path)
    assert s.get('conn-1') is None and s.hint('conn-1') is None
    with pytest.raises(ValueError) as exc:
        s.put('conn-1', KEY)
    assert KEY not in str(exc.value)
    with pytest.raises(ValueError):
        s.delete('conn-1')
    assert path.read_text() == '{not json'


def test_no_temp_file_is_left_behind(tmp_path):
    s = SecretsFile(tmp_path / 'ws.secrets.json')
    s.put('a', KEY)
    s.put('b', KEY)
    s.delete('a')
    assert [p.name for p in tmp_path.iterdir()] == ['ws.secrets.json']


def test_repr_shows_only_the_path(tmp_path):
    s = SecretsFile(tmp_path / 'ws.secrets.json')
    s.put('conn-1', KEY)
    assert KEY not in repr(s) and 'ws.secrets.json' in repr(s)


def test_check_key_refuses_unusable_keys():
    for bad in ('', '   ', 'a b', 'a\nb', 'kéy', 'x' * 4097):
        with pytest.raises(ValueError):
            check_key(bad)
    assert check_key('  sk-abc  ') == 'sk-abc'


def test_put_refuses_an_unusable_key(tmp_path):
    with pytest.raises(ValueError):
        SecretsFile(tmp_path / 'ws.secrets.json').put('conn-1', 'a b')


def test_secrets_path_sits_beside_settings(tmp_path):
    assert secrets_path(tmp_path / 'ws') == settings_path(tmp_path / 'ws').with_name('ws.secrets.json')


def test_overlay_answers_pending_first_and_refuses_writes(tmp_path):
    base = SecretsFile(tmp_path / 'ws.secrets.json')
    base.put('stored', 'sk-test-STORED99')
    base.put('both', 'sk-test-OLDOLD11')
    o = Overlay(base, {'both': 'sk-test-NEWNEW22', 'draft': 'sk-test-DRAFT33'})
    assert o.get('both') == 'sk-test-NEWNEW22' and o.hint('both') == 'EW22'
    assert o.get('draft') == 'sk-test-DRAFT33' and o.hint('draft') == 'FT33'
    assert o.get('stored') == 'sk-test-STORED99' and o.hint('stored') == 'ED99'
    assert o.get('nope') is None and o.hint('nope') is None
    with pytest.raises(TypeError):
        o.put('x', KEY)
    with pytest.raises(TypeError):
        o.delete('x')
    assert Overlay(None, {'d': KEY}).get('other') is None
    assert base.get('both') == 'sk-test-OLDOLD11'
    assert KEY not in repr(Overlay(None, {'d': KEY}))
