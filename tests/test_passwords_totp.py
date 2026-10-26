# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Passwords, TOTP and recovery codes for local sign-in."""
import base64
import hashlib
import re

import pytest

from tools import passwords, totp

RFC_SECRET = base64.b32encode(b'12345678901234567890').decode()


@pytest.mark.parametrize('ts, eight', [(59, '94287082'), (1111111109, '07081804'),
    (1111111111, '14050471'), (1234567890, '89005924'), (2000000000, '69279037')])
def test_rfc6238_sha1_vectors(ts, eight):
    assert totp.code_at(RFC_SECRET, totp.step_for(ts), digits=8) == eight


def test_a_code_from_the_next_or_previous_step_matches_once():
    step = totp.step_for(1_000_000)
    code = totp.code_at(RFC_SECRET, step + 1)
    assert totp.match(RFC_SECRET, code, 1_000_000, None) == step + 1
    assert totp.match(RFC_SECRET, code, 1_000_000, step + 1) is None   # replay
    assert totp.match(RFC_SECRET, totp.code_at(RFC_SECRET, step + 2), 1_000_000, None) is None
    assert totp.match(RFC_SECRET, totp.code_at(RFC_SECRET, step - 1), 1_000_000, None) == step - 1


def test_new_secret_is_20_bytes_unpadded_base32():
    s = totp.new_secret()
    assert '=' not in s and len(base64.b32decode(s + '=' * (-len(s) % 8))) == 20
    assert totp.new_secret() != s


def test_otpauth_uri():
    uri = totp.otpauth_uri('ABC', 'a@example.com')
    assert uri.startswith('otpauth://totp/Remediation%20Zero:a%40example.com?')
    assert 'secret=ABC' in uri and 'issuer=Remediation%20Zero' in uri


@pytest.mark.parametrize('pw, reason', [('a' * 11, 'too_short'), ('a' * 129, 'too_long')])
def test_length_rules(pw, reason):
    with pytest.raises(passwords.PasswordRefused) as exc:
        passwords.check_new(pw)
    assert exc.value.reason == reason


def test_length_is_counted_after_nfkc():
    # 12 fullwidth letters normalise to 12 ascii letters; 11 + a combining pair stays short
    assert passwords.check_new('ｈｏｒｓｅｂａｔｔｅｒｙ') == 'horsebattery'


def test_twelve_plain_lowercase_letters_are_fine():
    assert passwords.check_new('horsebattery') == 'horsebattery'


def test_a_listed_password_is_refused():
    first = open(passwords.BREACHED_PATH, encoding='utf-8').readline().strip()
    assert len(first) >= 12
    for variant in (first, first.upper()):
        with pytest.raises(passwords.PasswordRefused) as exc:
            passwords.check_new(variant)
        assert exc.value.reason == 'breached'


def test_hash_round_trip_and_format():
    stored = passwords.hash_password('correct horse battery')
    assert stored.startswith('scrypt$32768$8$1$') and passwords.verify('correct horse battery', stored)
    assert not passwords.verify('correct horse batterz', stored)
    assert passwords.hash_password('correct horse battery') != stored   # fresh salt


def test_unknown_account_still_runs_scrypt(monkeypatch):
    calls = []
    real = hashlib.scrypt
    monkeypatch.setattr(hashlib, 'scrypt', lambda *a, **k: calls.append(1) or real(*a, **k))
    assert passwords.verify('whatever password', None) is False
    assert len(calls) == 1


def test_malformed_stored_hash_is_false():
    assert passwords.verify('x' * 12, 'nonsense') is False


def test_recovery_codes_are_ten_distinct_and_hash_ignores_format():
    codes = passwords.new_recovery_codes()
    assert len(set(codes)) == 10 and all(re.fullmatch(r'[a-z2-7]{5}-[a-z2-7]{5}', c) for c in codes)
    assert passwords.recovery_hash(codes[0].upper().replace('-', ' ')) == passwords.recovery_hash(codes[0])
    assert re.fullmatch(r'[0-9a-f]{64}', passwords.recovery_hash(codes[0]))


@pytest.mark.parametrize('bad', ['12345é', '１２３４５６', '12345', '1234567', 'abcdef', '', None])
def test_malformed_codes_never_match_or_raise(bad):
    assert totp.match(RFC_SECRET, bad, 1_000_000, None) is None
