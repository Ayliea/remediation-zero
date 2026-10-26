# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
import importlib.util
import subprocess
import sys
from scripts.build_local_installer import build


def run(installer, destination, *args, answer=None):
    return subprocess.run([sys.executable, '-S', str(installer), '--directory', str(destination), *args],
                          input=answer, capture_output=True, text=True, timeout=20)


def test_install_cancel_and_existing_directory(tmp_path):
    installer = build(tmp_path / 'install.py')
    destination = tmp_path / 'app'
    cancelled = run(installer, destination, '--no-start', answer='n\n')
    assert cancelled.returncode == 0 and not destination.exists()
    installed = run(installer, destination, '--yes', '--no-start')
    assert installed.returncode == 0, installed.stderr
    assert (destination / 'start-remediation-zero.py').exists()
    assert not (destination / 'remediation-zero.sqlite3').exists()
    existing = run(installer, destination, '--yes', '--no-start')
    assert existing.returncode == 1
    assert 'Nothing was overwritten' in existing.stderr
    initialized = subprocess.run([sys.executable, '-S', '-m', 'scripts.local', 'init'],
                                 cwd=destination, capture_output=True, text=True, timeout=10)
    assert initialized.returncode == 0, initialized.stderr


def test_checksums_before_writes_and_reproducible_build(tmp_path):
    first = build(tmp_path / 'first.py')
    second = build(tmp_path / 'second.py')
    assert first.read_bytes() == second.read_bytes()
    spec = importlib.util.spec_from_file_location('generated_installer', first)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert 'tools/sqlite_store.py' in module.unpack()
    module.DIGEST = '0' * 64
    import pytest
    with pytest.raises(ValueError, match='damaged'):
        module.unpack()


def test_installer_bundle_runs_account_setup(tmp_path):
    """The installed tree imports what sign-in needs with -S, carries the notices, and runs
    `account setup` end to end with nothing but the standard library."""
    import re
    from tools.clock import ClockMode, SimClock
    from tools import totp
    installer = build(tmp_path / 'install.py')
    destination = tmp_path / 'app'
    installed = run(installer, destination, '--yes', '--no-start')
    assert installed.returncode == 0, installed.stderr
    for name in ('THIRD_PARTY_NOTICES.md', 'NOTICE', 'tools/vendor/QRCODEGEN_LICENSE.txt'):
        assert (destination / name).is_file(), name
    probe = subprocess.run([sys.executable, '-S', '-c',
                            'import tools.accounts, tools.vendor.qrcodegen, tools.server_tls, scripts.local_accounts'],
                           cwd=destination, capture_output=True, text=True, timeout=20)
    assert probe.returncode == 0, probe.stderr
    # No controlling terminal (a new session), so getpass reads the piped stdin.
    setup = subprocess.Popen([sys.executable, '-S', '-m', 'scripts.local', '--database', str(tmp_path / 'w'),
                              'account', 'setup'], cwd=destination, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        password = 'quiet orchard sundial lantern'  # synthetic
        setup.stdin.write(f'owner@client.example\nowner\n{password}\n{password}\n')
        setup.stdin.flush()
        shown = ''
        while 'Key: ' not in shown or not shown.endswith('\n'):
            line = setup.stdout.readline()
            assert line, setup.stderr.read()
            shown += line
        secret = re.search(r'Key: ([A-Z2-7]+)', shown)[1]
        out, err = setup.communicate(totp.code_at(secret, totp.step_for(SimClock(ClockMode.REAL).now().real_ts)) + '\n', timeout=60)
    finally:
        if setup.poll() is None:
            setup.kill()
    assert setup.returncode == 0, err
    assert len(set(re.findall(r'\b[a-z2-7]{5}-[a-z2-7]{5}\b', out))) == 10
    assert password not in shown + out + err
