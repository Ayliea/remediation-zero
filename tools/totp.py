# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""TOTP (RFC 6238) for local sign-in. Standard library only.

HMAC-SHA1 is used deliberately: it is what every authenticator app implements
by default, and RFC 6238 SHA-1 is not weakened by the known collision attacks
because HMAC does not rely on collision resistance. This is the deviation from
"no SHA-1 anywhere" that the design spec words explicitly.
"""
import base64
import hmac
import secrets
import struct
from urllib.parse import quote

PERIOD = 30


def new_secret() -> str:
    """20 random bytes as unpadded base32."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')


def step_for(ts: float) -> int:
    return int(ts // PERIOD)


def code_at(secret: str, step: int, digits: int = 6) -> str:
    key = base64.b32decode(secret.upper() + '=' * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack('>Q', step), 'sha1').digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack('>I', mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


def match(secret: str, code: str, now: float, last_step: int | None) -> int | None:
    """Return the step `code` matches within +-1 step, if later than `last_step`."""
    current = step_for(now)
    code = (code or '').strip().replace(' ', '')
    if not (code.isascii() and code.isdigit() and len(code) == 6):
        return None   # also keeps compare_digest from raising on non-ASCII text
    found = None
    for step in (current - 1, current, current + 1):
        # constant-time compare, and no early exit on the first hit
        if hmac.compare_digest(code_at(secret, step), code) and found is None:
            found = step
    if found is None or (last_step is not None and found <= last_step):
        return None
    return found


def otpauth_uri(secret: str, email: str, issuer: str = 'Remediation Zero') -> str:
    label = quote(issuer, safe='') + ':' + quote(email, safe='')
    return (f'otpauth://totp/{label}?secret={secret}&issuer={quote(issuer, safe="")}'
            f'&algorithm=SHA1&digits=6&period={PERIOD}')
