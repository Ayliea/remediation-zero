# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Installed entry point; safe to restart without resetting stored records."""
import argparse
from pathlib import Path
import subprocess
import sys
import webbrowser
from tools import local_settings


def main():
    parser = argparse.ArgumentParser(description='Start the local Remediation Zero dashboard; Ctrl+C stops it')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--saved', action='store_true', help='Show saved model suggestions instead of demo fixtures')
    mode.add_argument('--demo', action='store_true', help='Show synthetic examples instead of saved records')
    parser.add_argument('--database', type=Path, help='Use a specific database; defaults to the installation folder')
    parser.add_argument('--no-browser', action='store_true')
    parser.add_argument('--port', type=int)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    database = args.database.expanduser().resolve() if args.database else root / 'remediation-zero.sqlite3'
    if args.port is not None and not 1024 <= args.port <= 65535:
        parser.error('Choose a port from 1024 to 65535')
    try:
        preferences = local_settings.load(local_settings.settings_path(database))
    except (ValueError, OSError):
        raise SystemExit('Could not read local preferences. Check the settings file before restarting.')
    command = [sys.executable, '-S', '-m', 'scripts.local', '--database',
               str(database), 'serve', '--port', str(args.port if args.port is not None else preferences['port'])]
    if args.demo or (not args.saved and preferences['mode'] == 'demo'):
        command.append('--demo')
    process = subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, text=True)
    try:
        ready = process.stdout.readline().strip()
        if not ready.startswith('Local synthetic preview: http://127.0.0.1:'):
            raise SystemExit('Dashboard did not start. Check the error above; port 8081 may already be in use. Try --port 8082.')
        print(ready, flush=True)
        print('Synthetic preview only. Press Ctrl+C here to stop. No model calls are made by this launcher.', flush=True)
        if not args.no_browser and preferences['open_browser']:
            webbrowser.open(ready.split()[-1])
        return_code = process.wait()
        if return_code:
            raise SystemExit(return_code)
    except KeyboardInterrupt:
        pass
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=10)


if __name__ == '__main__':
    main()
