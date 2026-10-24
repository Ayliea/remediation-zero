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
