# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Password rules, scrypt hashing and recovery codes for local sign-in.

Standard library only. Passwords are 12 to 128 characters after NFKC
normalisation, with no character-class rules, and are refused when they are on
the bundled breached list. Nothing here logs a password, hash or code.
"""
import base64
import functools
import hashlib
import hmac
import os
import secrets
import unicodedata

MIN_LENGTH = 12
MAX_LENGTH = 128
BREACHED_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             'vendor', 'breached_passwords.txt')

_N, _R, _P = 32768, 8, 1
_MAXMEM = 64 * 1024 * 1024
_SALT_BYTES = 16
_KEY_BYTES = 32


class PasswordRefused(Exception):
    """reason is one of 'too_short', 'too_long', 'breached'."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@functools.lru_cache(maxsize=1)
def _breached() -> frozenset:
    with open(BREACHED_PATH, encoding='utf-8') as fh:
        return frozenset(line.strip() for line in fh if line.strip())


def check_new(password: str) -> str:
    """Return the NFKC-normalised password, or raise PasswordRefused."""
    normalised = unicodedata.normalize('NFKC', password)
    if len(normalised) < MIN_LENGTH:
        raise PasswordRefused('too_short')
    if len(normalised) > MAX_LENGTH:
        raise PasswordRefused('too_long')
    if normalised.lower() in _breached():
        raise PasswordRefused('breached')
    return normalised


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(unicodedata.normalize('NFKC', password).encode(), salt=salt,
                          n=n, r=r, p=p, maxmem=_MAXMEM, dklen=_KEY_BYTES)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(_SALT_BYTES)
    key = _scrypt(password, salt, _N, _R, _P)
    return '$'.join(['scrypt', str(_N), str(_R), str(_P),
                     base64.b64encode(salt).decode(), base64.b64encode(key).decode()])


def verify(password: str, stored: str | None) -> bool:
    """Check a password; with stored=None run one scrypt anyway and return False."""
    if stored is None:
        _scrypt(password, b'\0' * _SALT_BYTES, _N, _R, _P)
        return False
    try:
        scheme, n, r, p, salt, key = stored.split('$')
        if scheme != 'scrypt':
            return False
        expected = base64.b64decode(key)
        actual = _scrypt(password, base64.b64decode(salt), int(n), int(r), int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def new_recovery_codes() -> list[str]:
    """Ten distinct codes, xxxxx-xxxxx, lowercase base32."""
    codes: set[str] = set()
    while len(codes) < 10:
        raw = base64.b32encode(secrets.token_bytes(7)).decode().lower()[:10]
        codes.add(f'{raw[:5]}-{raw[5:]}')
    return sorted(codes, key=lambda _: secrets.randbelow(1 << 30))


def recovery_hash(code: str) -> str:
    cleaned = code.replace('-', '').replace(' ', '').lower()
    return hashlib.sha256(cleaned.encode()).hexdigest()
