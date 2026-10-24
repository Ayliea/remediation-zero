# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Non-secret local preferences, validated before atomic persistence."""
import json
import os
from pathlib import Path
import tempfile
from tools.model_endpoint import ModelEndpoint

DEFAULTS = {'endpoint': '', 'model': '', 'mode': 'demo', 'open_browser': True, 'port': 8081}


def settings_path(database):
    return Path(database).resolve().with_suffix('.settings.json')


def validate(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULTS):
        raise ValueError('Unexpected settings fields')
    if not all(isinstance(value[k], str) for k in ('endpoint', 'model', 'mode')):
        raise ValueError('Invalid text settings')
    if len(value['endpoint']) > 2048:
        raise ValueError('Endpoint is too long')
    if value['endpoint'] or value['model']:
        ModelEndpoint(value['endpoint'], value['model'])
    if value['mode'] not in {'demo', 'saved'} or type(value['open_browser']) is not bool:
        raise ValueError('Invalid startup preferences')
    if type(value['port']) is not int or not 1024 <= value['port'] <= 65535:
        raise ValueError('Choose a port from 1024 to 65535')
    return dict(value)


def load(path):
    try:
        return validate(json.loads(Path(path).read_text()))
    except FileNotFoundError:
        return dict(DEFAULTS)


def save(path, value):
    value = validate(value)
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix='.rz-settings-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)
