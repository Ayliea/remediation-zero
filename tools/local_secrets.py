# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The owner-only key file: the local edition's `SecretsPort`.

`<database>.secrets.json`, beside the settings file. Created 0600 with O_NOFOLLOW and written
atomically (temp file in the same directory, fsync, rename). Every read opens with O_NOFOLLOW
and refuses a file that is group- or world-accessible or owned by someone else, naming the
`chmod 600` fix. Nothing is cached, so a loosened file is caught on the next call. Protection at
rest is the file mode plus full-disk encryption of the host; there is no encryption with a
co-located key. On Windows the mode and owner check is skipped: the file relies on the user
profile directory's ACL. A key never appears in an exception message or repr.
Standard library only.
"""
import json
import os
from pathlib import Path

from tools.secrets_port import SecretsPort, check_key

_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)
_WINDOWS = os.name == 'nt'


def secrets_path(database):
    return Path(database).resolve().with_suffix('.secrets.json')


class SecretsFileUnsafe(Exception):
    def __init__(self, path):
        super().__init__(f'{path} must be readable only by its owner. Run: chmod 600 {path}')


class StoredKeyMissing(Exception):
    """A connection says its key is stored, but the key file has none for it."""


class SecretsFile:
    def __init__(self, path):
        self.path = Path(path)

    def __repr__(self):
        return f'SecretsFile({str(self.path)!r})'

    def _load(self):
        """The keys map, or None when the file is absent or not valid. Refuses an unsafe file."""
        try:
            fd = os.open(self.path, os.O_RDONLY | _NOFOLLOW)
        except FileNotFoundError:
            return {}
        try:
            st = os.fstat(fd)
            if not _WINDOWS and (st.st_mode & 0o077 or st.st_uid != os.getuid()):
                raise SecretsFileUnsafe(self.path)
            with os.fdopen(fd, 'rb') as handle:
                fd = -1
                raw = handle.read()
        finally:
            if fd >= 0:
                os.close(fd)
        try:
            data = json.loads(raw)
        except ValueError:
            return None
        keys = data.get('keys') if isinstance(data, dict) and data.get('version') == 1 else None
        if not isinstance(keys, dict) or not all(
                isinstance(e, dict) and isinstance(e.get('key'), str) and isinstance(e.get('hint'), str)
                for e in keys.values()):
            return None
        return keys

    def _editable(self):
        keys = self._load()
        if keys is None:
            raise ValueError(f'{self.path} is not a valid key file; it was left unchanged')
        return keys

    def _write(self, keys):
        body = json.dumps({'version': 1, 'keys': keys}).encode()
        tmp = self.path.with_name(f'{self.path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp')
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as handle:
                fd = -1
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise

    def put(self, connection_id, key):
        key = check_key(key)
        keys = self._editable()
        keys[connection_id] = {'key': key, 'hint': key[-4:]}
        self._write(keys)

    def get(self, connection_id):
        entry = (self._load() or {}).get(connection_id)
        return entry['key'] if entry else None

    def hint(self, connection_id):
        entry = (self._load() or {}).get(connection_id)
        return entry['hint'] if entry else None

    def delete(self, connection_id):
        keys = self._editable()
        if keys.pop(connection_id, None) is not None:
            self._write(keys)


class Overlay:
    """Read-only: answers from `pending` first, then `base`. Tests a draft's key before it is stored."""

    def __init__(self, base: SecretsPort | None, pending: dict[str, str]):
        self._base = base
        self._pending = dict(pending)

    def __repr__(self):
        return 'Overlay()'

    def get(self, connection_id):
        if connection_id in self._pending:
            return self._pending[connection_id]
        return self._base.get(connection_id) if self._base else None

    def hint(self, connection_id):
        if connection_id in self._pending:
            return self._pending[connection_id][-4:]
        return self._base.hint(connection_id) if self._base else None

    def put(self, connection_id, key):
        raise TypeError('An overlay is read-only')

    def delete(self, connection_id):
        raise TypeError('An overlay is read-only')
