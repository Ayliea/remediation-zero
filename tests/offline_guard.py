# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Deny network, credential discovery and inference before test collection."""
import os
import sys
import traceback

violations = []


def forbidden(*args, **kwargs):
    violations.append("".join(traceback.format_stack(limit=14)))
    raise AssertionError("Offline tests forbid network, credentials, and live inference")


# Endpoints a test's own fake server bound. Nothing else is reachable: not a real gvmd socket,
# not docker.sock, not a dev server on a loopback port, not a local model endpoint.
allowed_unix = set()   # os.path.realpath of a socket under pytest's base temp dir
allowed_tcp = set()    # ("127.0.0.1", port) as returned by getsockname()
_LOOPBACK_HOSTS = {"127.0.0.1", "::1"}  # ::1 only so "localhost" may try IPv6 first, on the same port
_LOOKUP_HOSTS = {"localhost", "127.0.0.1"}


def register_unix(path, basetemp):
    real = os.path.realpath(path)
    base = os.path.realpath(str(basetemp))
    if os.path.commonpath([real, base]) != base:
        raise ValueError("a fake Unix socket must live under pytest's base temp dir")
    allowed_unix.add(real)
    return real


def register_tcp(host, port):
    if host != "127.0.0.1":
        raise ValueError("a fake TCP server must be bound to 127.0.0.1")
    allowed_tcp.add((host, port))
    return (host, port)


def deregister(entry):
    allowed_unix.discard(entry)
    allowed_tcp.discard(entry)


def _local_only(event, args):
    """True only for a connect/lookup that a test's fake server registered."""
    try:
        if event == "socket.connect":
            address = args[1]
            if isinstance(address, str):
                return os.path.realpath(address) in allowed_unix
            if isinstance(address, tuple) and address[0] in _LOOPBACK_HOSTS:
                return ("127.0.0.1", address[1]) in allowed_tcp
            return False
        if event == "socket.getaddrinfo":
            host, port = args[0], args[1]
            return host in _LOOKUP_HOSTS and isinstance(port, int) and ("127.0.0.1", port) in allowed_tcp
    except (IndexError, TypeError, ValueError):
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
