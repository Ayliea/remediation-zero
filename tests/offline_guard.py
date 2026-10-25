# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Deny network, credential discovery and inference before test collection."""
import sys
import traceback

violations = []


def forbidden(*args, **kwargs):
    violations.append("".join(traceback.format_stack(limit=14)))
    raise AssertionError("Offline tests forbid network, credentials, and live inference")


_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def _local_only(event, args):
    """True for a Unix-socket connect or a loopback connect/lookup, which never leave the machine.

    Fakes that serve a protocol from a thread inside a test (the GMP client's fake gvmd) need
    these. Anything else, and any call with unparseable arguments, stays forbidden.
    """
    try:
        if event == "socket.connect":
            address = args[1]
            if isinstance(address, (str, bytes)):
                return True
            return isinstance(address, tuple) and address[0] in _LOOPBACK
        if event == "socket.getaddrinfo":
            return args[0] in _LOOPBACK
    except (IndexError, TypeError):
        return False
    return False


def _audit(event, args):
    if event in {"socket.connect", "socket.getaddrinfo", "socket.gethostbyname",
                 "socket.gethostbyaddr", "socket.sendto"}:
        if _local_only(event, args):
            return
        forbidden()


sys.addaudithook(_audit)
import urllib.request
import requests
import httpx
import google.auth
from google.auth.compute_engine import _metadata

urllib.request.urlopen = forbidden
requests.sessions.Session.request = forbidden
httpx.HTTPTransport.handle_request = forbidden
httpx.AsyncHTTPTransport.handle_async_request = forbidden
google.auth.default = forbidden
_metadata.get = forbidden
_metadata.ping = forbidden
from google.genai.models import AsyncModels, Models
Models.generate_content = forbidden
AsyncModels.generate_content = forbidden
