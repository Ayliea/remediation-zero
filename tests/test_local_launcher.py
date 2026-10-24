# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
import io
from pathlib import Path
from types import SimpleNamespace
import pytest
from scripts import local_launcher
from tools import local_settings


def test_source_launcher_resolves_root_and_preferences(tmp_path, monkeypatch):
    database = tmp_path / 'custom.sqlite3'
    local_settings.save(local_settings.settings_path(database), dict(local_settings.DEFAULTS,
        mode='saved', open_browser=False, port=8083))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('sys.argv', ['start', '--database', str(database)])
    calls = []
    def start(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(stdout=io.StringIO('Local synthetic preview: http://127.0.0.1:8083\n'),
                               wait=lambda **kw: 0, poll=lambda: 0)
    monkeypatch.setattr(local_launcher.subprocess, 'Popen', start)
    monkeypatch.setattr(local_launcher.webbrowser, 'open', lambda *a: pytest.fail('Browser should be disabled'))
    local_launcher.main()
    command, kwargs = calls[-1]
    assert kwargs['cwd'] == Path(local_launcher.__file__).resolve().parents[1]
    assert command[command.index('--database') + 1] == str(database)
    assert command[-1] == '8083'
    assert '--demo' not in command
    monkeypatch.setattr('sys.argv', ['start', '--database', str(database), '--demo', '--port', '8084'])
    local_launcher.main()
    assert calls[-1][0][-1] == '--demo'
    assert '8084' in calls[-1][0]


@pytest.mark.parametrize('args', [['--port','0'], ['--port','65536'], ['--demo','--saved']])
def test_invalid_launcher_flags_never_start(args, monkeypatch):
    monkeypatch.setattr('sys.argv', ['start', *args])
    monkeypatch.setattr(local_launcher.subprocess, 'Popen', lambda *a, **kw: pytest.fail('Unexpected process'))
    with pytest.raises(SystemExit) as error:
        local_launcher.main()
    assert error.value.code == 2
