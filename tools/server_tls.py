# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The dashboard's own HTTPS certificate: made with openssl, checked, fingerprinted."""
import hashlib
import ipaddress
import os
import re
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile

from tools.local_settings import normalize_server_name

CERT_NAME, KEY_NAME = 'server-cert.pem', 'server-key.pem'
VALID_DAYS = 825
RENEW_WITHIN_DAYS = 30


class NoOpenssl(Exception):
    """openssl is not installed, so no self-signed certificate can be made."""


def _san(names):
    entries = []
    for raw in names:
        name = normalize_server_name(raw)  # only validated names ever reach -addext
        try:
            entries.append(f'IP:{ipaddress.ip_address(name)}')
        except ValueError:
            entries.append(f'DNS:{name}')
    return entries


def _wanted(entries):
    return {('IP Address', e[3:]) if e.startswith('IP:') else ('DNS', e[4:]) for e in entries}


def _sans(cert):
    """The set of SAN pairs of an existing certificate, or None if it cannot be read."""
    try:
        info = ssl._ssl._test_decode_cert(str(cert))
        return {(kind, str(ipaddress.ip_address(value)) if kind == 'IP Address' else value.lower())
                for kind, value in info.get('subjectAltName', ())}
    except (ssl.SSLError, OSError, ValueError, KeyError):
        return None


def _valid_for_a_while(exe, cert):
    """openssl itself answers whether the certificate outlives the renewal window, so this module
    reads no clock (the repository allows only tools/clock.py to)."""
    done = subprocess.run([exe, 'x509', '-in', str(cert), '-noout', '-checkend', str(RENEW_WITHIN_DAYS * 86400)],
                          capture_output=True, timeout=30, stdin=subprocess.DEVNULL)
    return done.returncode == 0


def _pair_loads(cert, key):
    """True when the key loads and belongs to the certificate (load_cert_chain checks both)."""
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(str(cert), str(key))
        return True
    except (ssl.SSLError, OSError, ValueError):
        return False


def ensure_self_signed(root, names, *, renew=False):
    """Create or renew server-cert.pem and server-key.pem (0600) in `root`; return (cert, key).

    Renews with under 30 days left, when the certificate's names differ from `names`, when the
    key does not load or does not match the certificate (a corrupt file, or a key replaced
    without its certificate), or with `renew`. The pair is ours, so remaking it loses nothing.
    The first name is the subject CN; every name is in the SAN."""
    root = Path(root)
    entries = _san(names)
    if not entries:
        raise ValueError('At least one server name is needed')
    cert, key = root / CERT_NAME, root / KEY_NAME
    exe = shutil.which('openssl')
    if exe is None:
        raise NoOpenssl()
    if (not renew and cert.is_file() and key.is_file() and _sans(cert) == _wanted(entries)
            and _pair_loads(cert, key)):
        try:
            if _valid_for_a_while(exe, cert):
                return cert, key
        except (subprocess.TimeoutExpired, OSError):
            pass  # cannot tell: make a new one
    cn = normalize_server_name(names[0])
    # openssl writes into a private temporary directory beside the target (mkdtemp makes it 0700),
    # so the key is never readable by others, even briefly; both files are then set 0600 and moved in.
    with tempfile.TemporaryDirectory(prefix='.rz-tls-', dir=root) as tmp:
        tmp_cert, tmp_key = Path(tmp) / CERT_NAME, Path(tmp) / KEY_NAME
        try:
            subprocess.run([exe, 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                            '-nodes', '-days', str(VALID_DAYS), '-subj', f'/CN={cn}',
                            '-addext', 'subjectAltName=' + ','.join(entries),
                            '-keyout', str(tmp_key), '-out', str(tmp_cert)],
                           check=True, capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as error:
            raise RuntimeError(f'openssl could not make the certificate ({type(error).__name__})') from None
        for path in (tmp_key, tmp_cert):
            os.chmod(path, 0o600)
        os.replace(tmp_key, key)
        os.replace(tmp_cert, cert)
    return cert, key


_PEM_CERT = re.compile(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.S)


def fingerprint(cert_path):
    """SHA-256 of the certificate's DER, as colon-separated upper-case hex. For a chain file,
    the first certificate's: the server's own, which is what a browser shows."""
    first = _PEM_CERT.search(Path(cert_path).read_text())
    if first is None:
        raise ValueError('No PEM certificate found')
    der = ssl.PEM_cert_to_DER_cert(first.group(0))
    digest = hashlib.sha256(der).hexdigest().upper()
    return ':'.join(digest[i:i + 2] for i in range(0, len(digest), 2))


def server_context(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert), str(key))
    return context
