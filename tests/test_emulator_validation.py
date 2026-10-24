# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
import pytest
from scripts.verify_recovery_emulator import emulator_endpoint, make_client


@pytest.mark.parametrize("host", [None, "", "localhost:8080", "example.invalid:8080",
                                 "127.0.0.1:443", "127.0.0.1:65536", "127.0.0.1:0",
                                 "http://127.0.0.1:8080", "127.0.0.1:8080/path"])
def test_reject_host(host):
    with pytest.raises(ValueError, match="cloud fallback is forbidden"):
        emulator_endpoint({} if host is None else {"FIRESTORE_EMULATOR_HOST": host})


def test_accept_loopback():
    assert emulator_endpoint({"FIRESTORE_EMULATOR_HOST": "127.0.0.1:8787"}) == "127.0.0.1:8787"


def test_missing_host_refuses_before_client(monkeypatch):
    from google.cloud import firestore
    monkeypatch.delenv("FIRESTORE_EMULATOR_HOST", raising=False)
    monkeypatch.setattr(firestore, "Client", lambda **_: pytest.fail("client constructed"))
    with pytest.raises(ValueError):
        make_client()


def test_anonymous_unique_projects(monkeypatch):
    from google.auth.credentials import AnonymousCredentials
    monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:8787")
    clients = [make_client(), make_client()]
    try:
        assert clients[0].project != clients[1].project
        for client in clients:
            assert client.project.startswith("demo-rz-")
            assert client._emulator_host == "127.0.0.1:8787"
            assert isinstance(client._credentials, AnonymousCredentials)
    finally:
        for client in clients:
            client.close()
