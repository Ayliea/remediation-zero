# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Build an offline single-file installer from explicit source files."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FILES = ('LICENSE', 'start-remediation-zero.py', 'scripts/local_launcher.py', 'scripts/__init__.py', 'scripts/local.py', 'tools/__init__.py',
         'tools/clock.py', 'tools/idempotency.py', 'tools/adjudication.py',
         'tools/inference_journal.py', 'tools/sqlite_store.py', 'tools/model_endpoint.py', 'tools/model_transport.py', 'tools/model_roles.py',
         'tools/models/__init__.py', 'tools/models/_common.py', 'tools/models/openai_chat.py',
         'tools/models/anthropic_messages.py', 'tools/models/gemini_api.py',
         'tools/local_settings.py', 'ui/settings_view.py', 'ui/dashboard_view.py', 'ui/theme.css', 'ui/assets/remediation-zero-logo.png',
         'prompts/local_suggestion_v1.txt')


def build(destination):
    files = {name: (ROOT / name).read_bytes() for name in FILES}
    files['README.md'] = (ROOT / 'docs/development/local-edition.md').read_bytes()
    files['install-manifest.json'] = json.dumps({name: hashlib.sha256(content).hexdigest()
                                                for name, content in files.items()}, sort_keys=True).encode()
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(files.items()):
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)
    raw = payload.getvalue()
    template = (ROOT / 'scripts/installer_template.py').read_text()
    script = template.replace('__PAYLOAD__', base64.b85encode(raw).decode()).replace('__DIGEST__', hashlib.sha256(raw).hexdigest())
    destination.write_text(script)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    print(build(args.output))


if __name__ == '__main__':
    main()
