# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
import re
import shutil
import ssl
import subprocess

import pytest

from tools import local_settings, server_tls

needs_openssl = pytest.mark.skipif(shutil.which('openssl') is None, reason='openssl is not installed')


def sans(cert):
    return set(ssl._ssl._test_decode_cert(str(cert))['subjectAltName'])


@needs_openssl
def test_self_signed_names_every_server_name_and_ip(tmp_path):
    cert, key = server_tls.ensure_self_signed(tmp_path, ['rz.example.test', '192.0.2.10', '2001:db8::1'])
    assert (cert.name, key.name) == ('server-cert.pem', 'server-key.pem')
    assert sans(cert) == {('DNS', 'rz.example.test'), ('IP Address', '192.0.2.10'),
                          ('IP Address', '2001:DB8:0:0:0:0:0:1')}
    assert cert.stat().st_mode & 0o777 == 0o600 and key.stat().st_mode & 0o777 == 0o600
    assert not [p for p in tmp_path.iterdir() if p not in (cert, key)]
    local_settings.check_certificate(cert, key)
    server_tls.server_context(cert, key)


@needs_openssl
def test_self_signed_is_reused_and_renewed_when_names_change(tmp_path):
    cert, key = server_tls.ensure_self_signed(tmp_path, ['a.example.test'])
    first = cert.read_bytes()
    assert server_tls.ensure_self_signed(tmp_path, ['A.example.test']) == (cert, key)
    assert cert.read_bytes() == first
    server_tls.ensure_self_signed(tmp_path, ['a.example.test', '192.0.2.10'])
    assert cert.read_bytes() != first
    assert sans(cert) == {('DNS', 'a.example.test'), ('IP Address', '192.0.2.10')}
    assert key.stat().st_mode & 0o777 == 0o600


@needs_openssl
def test_self_signed_is_renewed_when_nearly_expired(tmp_path):
    cert, key = server_tls.ensure_self_signed(tmp_path, ['a.example.test'])
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
                    '-days', '10', '-subj', '/CN=a.example.test', '-addext', 'subjectAltName=DNS:a.example.test',
                    '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
    short = cert.read_bytes()
    server_tls.ensure_self_signed(tmp_path, ['a.example.test'])
    assert cert.read_bytes() != short  # 10 days left is under the 30-day window
    renewed = cert.read_bytes()
    server_tls.ensure_self_signed(tmp_path, ['a.example.test'])
    assert cert.read_bytes() == renewed


def test_names_that_are_not_hosts_never_reach_openssl(tmp_path, monkeypatch):
    monkeypatch.setattr(server_tls.subprocess, 'run', lambda *a, **k: pytest.fail('openssl ran'))
    for bad in (['x.test,DNS:evil.test'], ['bad name'], ['x.test\nIP:1.2.3.4'], []):
        with pytest.raises(ValueError):
            server_tls.ensure_self_signed(tmp_path, bad)


@needs_openssl
def test_fingerprint_format(tmp_path):
    cert, _ = server_tls.ensure_self_signed(tmp_path, ['a.example.test'])
    value = server_tls.fingerprint(cert)
    assert re.fullmatch(r'([0-9A-F]{2}:){31}[0-9A-F]{2}', value)
    out = subprocess.run(['openssl', 'x509', '-in', str(cert), '-noout', '-fingerprint', '-sha256'],
                         capture_output=True, text=True, check=True).stdout
    assert out.strip().split('=', 1)[1].upper() == value


def test_no_openssl_raises_NoOpenssl(tmp_path, monkeypatch):
    monkeypatch.setattr(server_tls.shutil, 'which', lambda name: None)
    with pytest.raises(server_tls.NoOpenssl):
        server_tls.ensure_self_signed(tmp_path, ['a.example.test'])
    assert list(tmp_path.iterdir()) == []


@needs_openssl
def test_check_certificate_refuses_a_mismatched_key(tmp_path):
    one, other = tmp_path / 'one', tmp_path / 'other'
    one.mkdir()
    other.mkdir()
    cert, key = server_tls.ensure_self_signed(one, ['a.example.test'])
    _, other_key = server_tls.ensure_self_signed(other, ['b.example.test'])
    local_settings.check_certificate(cert, key)
    with pytest.raises(ValueError):
        local_settings.check_certificate(cert, other_key)
    with pytest.raises(ValueError):
        local_settings.check_certificate(tmp_path / 'missing.pem', key)


@needs_openssl
def test_server_context_has_a_tls_1_2_minimum(tmp_path):
    cert, key = server_tls.ensure_self_signed(tmp_path, ['a.example.test'])
    assert server_tls.server_context(cert, key).minimum_version == ssl.TLSVersion.TLSv1_2
