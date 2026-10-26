# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Shared transport rules for every explicitly configured model endpoint.

HTTPS unless the host is loopback; no redirects; no inherited proxies; no URL
credentials, query or fragment; bounded response; fixed socket timeout.
An endpoint with its own certificate is trusted through a CA file, and then
only through that file; the name check always stays on.
Standard library only.
"""
import ipaddress
import json
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from tools.adjudication import CapacityError

MAX_INPUT_BYTES = 32768
MAX_RESPONSE_BYTES = 65536
MAX_OUTPUT_TOKENS = 2048
TIMEOUT_SECONDS = 60


# Load, not a verdict: request timeout, rate limit, and every server error
# (500-599, including vendor overload codes such as 529).
def _is_capacity_code(code):
    return code in (408, 429) or 500 <= code <= 599


class CertificateProblem(CapacityError):
    """The endpoint's certificate could not be verified.

    A CapacityError on purpose: like an unreachable model it means no model answered,
    so a reviewer's certificate problem is recorded unavailable and retried next cycle,
    never read as a verdict. It is not load, so it is not backed off and retried in place.
    """


class CertificateNotTrusted(CertificateProblem):
    """Not signed by anything trusted: the system's list, or the role's CA file when set."""


class CertificateNameMismatch(CertificateProblem):
    """Trusted, but issued for another name than the endpoint URL's host."""


class CertificateExpired(CertificateProblem):
    """Outside its validity period."""


class CertificateFileUnreadable(CertificateProblem):
    """The role's CA file is missing or holds no certificate."""


class TLSRefused(CertificateProblem):
    """The server ended the TLS handshake itself, e.g. it serves no certificate for this name."""


class ModelTimedOut(CapacityError):
    """No answer within the role's timeout. Load, or a model still loading: retried as before."""


_EXPIRED = {9, 10}           # X509_V_ERR_CERT_NOT_YET_VALID, _CERT_HAS_EXPIRED
_NAME_MISMATCH = {62, 64}    # X509_V_ERR_HOSTNAME_MISMATCH, _IP_ADDRESS_MISMATCH


def tls_context(ca_file):
    """Verification against `ca_file` alone: create_default_context loads no system
    certificates when a cafile is given."""
    try:
        context = ssl.create_default_context(cafile=ca_file)
    except (OSError, ssl.SSLError):
        raise CertificateFileUnreadable('The CA certificate file could not be read') from None
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _certificate_problem(reason):
    """The CertificateProblem for a urlopen failure reason, or None if it is not one."""
    if isinstance(reason, ssl.SSLError) and not isinstance(reason, ssl.SSLCertVerificationError):
        # An alert from the server (handshake failure, unrecognised name, internal error).
        # Our own EOF or a reset mid-handshake are not refusals: they stay "could not be reached".
        # OpenSSL's reason code, e.g. TLSV1_ALERT_INTERNAL_ERROR or SSLV3_ALERT_HANDSHAKE_FAILURE.
        if (isinstance(reason, (ssl.SSLEOFError, ssl.SSLZeroReturnError))
                or '_ALERT_' not in (getattr(reason, 'reason', None) or '')):
            return None
        return TLSRefused('The server refused the TLS connection')
    if not isinstance(reason, ssl.SSLCertVerificationError):
        return None
    if reason.verify_code in _EXPIRED:
        return CertificateExpired('The endpoint certificate is expired or not yet valid')
    if reason.verify_code in _NAME_MISMATCH:
        return CertificateNameMismatch('The endpoint certificate is for another name')
    return CertificateNotTrusted('The endpoint certificate is not trusted')


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_endpoint(url):
    if not isinstance(url, str) or any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise ValueError('Invalid endpoint URL')
    parsed = urlsplit(url)
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError('Invalid endpoint port')
    try:
        local = ipaddress.ip_address(parsed.hostname or '').is_loopback
    except ValueError:
        local = parsed.hostname == 'localhost'
    if (parsed.scheme not in {'http', 'https'} or not parsed.hostname or
            (parsed.scheme == 'http' and not local) or parsed.username or
            parsed.password or parsed.query or parsed.fragment):
        raise ValueError('Use an HTTPS endpoint, or HTTP on loopback; no URL credentials, query or fragment')
    return url.rstrip('/')


def _build_opener(ca_file=None):
    # Avoid forwarding credentials via redirects or inherited proxy settings.
    handlers = [ProxyHandler({}), NoRedirects()]
    if ca_file:
        handlers.append(HTTPSHandler(context=tls_context(ca_file)))
    return build_opener(*handlers)


def _open(request, timeout, ca_file=None):
    return _build_opener(ca_file).open(request, timeout=timeout)


def post_json(url, body, headers, *, ca_file=None, timeout=None):
    """`timeout`: the role's seconds (Settings, 5-600); None is TIMEOUT_SECONDS."""
    if ca_file and urlsplit(url).scheme != 'https':
        raise ValueError('A CA file applies only to an HTTPS endpoint')
    seconds = TIMEOUT_SECONDS if timeout is None else timeout
    data = json.dumps(body).encode()
    try:
        with _open(Request(url, data=data, headers=headers), timeout=seconds, ca_file=ca_file) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        if _is_capacity_code(exc.code):
            raise CapacityError('Model endpoint temporarily unavailable') from None
        raise ValueError('Model endpoint rejected request') from None
    except ssl.SSLCertVerificationError as exc:  # raised during the read on some paths
        raise _certificate_problem(exc) from None
    except URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise ModelTimedOut(f'No answer within {seconds:g} s') from None
        problem = _certificate_problem(exc.reason)
        if problem is not None:
            raise problem from None
        raise CapacityError('Model endpoint could not be reached') from None
    except TimeoutError:  # socket.timeout is TimeoutError: the read, after connecting
        raise ModelTimedOut(f'No answer within {seconds:g} s') from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError('Model response exceeds limit')
    try:
        return json.loads(raw)
    except ValueError:
        raise ValueError('Model returned an invalid proposal') from None
