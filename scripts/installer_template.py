# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Build template: distribute the generated install-remediation-zero.py file."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import zipfile

PAYLOAD = '__PAYLOAD__'
DIGEST = '__DIGEST__'


def unpack():
    raw = base64.b85decode(PAYLOAD)
    if hashlib.sha256(raw).hexdigest() != DIGEST:
        raise ValueError('Installer payload is damaged')
    files = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if sum(info.file_size for info in archive.infolist()) > 5_000_000:
            raise ValueError('Installer payload exceeds size limit')
        for info in archive.infolist():
            name = PurePosixPath(info.filename)
            if (name.is_absolute() or '..' in name.parts or '\\' in info.filename or
                    ':' in info.filename or info.filename in files or info.is_dir()):
                raise ValueError('Invalid installer payload path')
            files[info.filename] = archive.read(info)
    manifest = json.loads(files.pop('install-manifest.json'))
    if set(manifest) != set(files):
        raise ValueError('Installer file manifest differs from payload')
    for name, content in files.items():
        if hashlib.sha256(content).hexdigest() != manifest[name]:
            raise ValueError('Installer file checksum failed')
    return files


def main():
    parser = argparse.ArgumentParser(description='Install the Remediation Zero local synthetic preview')
    parser.add_argument('--directory', type=Path, default=Path.home() / 'RemediationZero')
    parser.add_argument('--yes', action='store_true', help='Accept the displayed installation plan without prompting')
    parser.add_argument('--no-start', action='store_true', help='Install without starting the dashboard or opening a browser')
    args = parser.parse_args()
    if sys.version_info < (3, 12):
        parser.exit(1, 'Python 3.12 or newer is required. Install Python from python.org, then run this script again. No files were installed.\n')
    destination = args.directory.expanduser().absolute()
    print(f'''Remediation Zero — local synthetic preview

Install location: {destination}
Contents: Python application, license, setup guide and local launchers.
Storage: SQLite database inside this directory, created on first launch.
Network: dashboard listens only on 127.0.0.1:8081. Installation downloads nothing.
Your browser will open unless --no-start is set. No telemetry or model calls.
No administrator rights, background services, PATH changes or automatic updates.
No Python packages or models will be installed. No API keys will be requested.
This preview uses synthetic examples. It does not scan or secure your devices.
Model use is optional and explicit; hosted model requests may incur charges.
Stop: press Ctrl+C in the launch terminal. Restart: run start-remediation-zero.py.
Removal: stop the app, back up the database if wanted, then remove this directory.
Existing directories will not be overwritten; this installer does not upgrade.
Checksums detect damaged files. This installer is not digitally signed.
''', flush=True)
    if destination.exists() or destination.is_symlink():
        parser.exit(1, 'Destination already exists. Use its launcher or choose a new directory. Nothing was overwritten.\n')
    try:
        files = unpack()
        if not args.yes and input('Install this preview? [y/N] ').strip().lower() not in {'y', 'yes'}:
            print('Cancelled. No files installed.')
            return
        os.umask(0o077)
        destination.mkdir(mode=0o700, parents=False, exist_ok=False)
        for name, content in files.items():
            target = destination.joinpath(*PurePosixPath(name).parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with target.open('xb') as output:
                output.write(content)
        print(f'Installed in {destination}', flush=True)
        if not args.no_start:
            subprocess.run([sys.executable, '-S', str(destination / 'start-remediation-zero.py')], check=True)
    except (ValueError, OSError, EOFError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f'Installation or launch stopped: {exc}\nNo existing installation was replaced. Check the install directory before retrying.\n')


if __name__ == '__main__':
    main()
