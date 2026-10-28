# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The plug-in point for model API keys typed in the browser.

The local edition keeps them in an owner-only file (`tools.local_secrets`); the cloud edition
will implement the same four methods over its secret store. A key is never returned except by
`get`, and never appears in an exception message, repr or log line. Standard library only.
"""
from typing import Protocol

MAX_KEY_LENGTH = 4096
KEY_MESSAGE = 'An API key is one line of letters, digits and symbols'


class SecretsPort(Protocol):
    def put(self, connection_id: str, key: str) -> None: ...

    def get(self, connection_id: str) -> str | None: ...

    def delete(self, connection_id: str) -> None: ...

    def hint(self, connection_id: str) -> str | None: ...


def check_key(key: str) -> str:
    """Strip surrounding whitespace and refuse a key that cannot be sent in a header."""
    if not isinstance(key, str):
        raise ValueError(KEY_MESSAGE)
    key = key.strip()
    if not key or len(key) > MAX_KEY_LENGTH or any(not 0x21 <= ord(c) <= 0x7E for c in key):
        raise ValueError(KEY_MESSAGE)
    return key
