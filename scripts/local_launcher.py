# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Installed entry point; safe to restart without resetting stored records.

With `cycle_interval_minutes` above 0 in the settings, one daemon thread here
also runs the `cycle` command's function every interval. Each run opens its
own workspace stores (SQLite connections are never shared across threads),
takes the next cycle number from the `cycles` collection, and is skipped,
not queued, while an earlier run in this process still holds the lock. A
second process running `cycle` by hand is covered by the idempotency journal
and SQLite's busy timeout, not by this lock.
"""
import argparse
import json
import logging
from pathlib import Path
import subprocess
import sys
import threading
import webbrowser
from tools import local_settings

logger = logging.getLogger('remediation_zero.launcher')


def default_database(root):
    """The default workspace directory beside the application files."""
    return Path(root) / 'remediation-zero'


def _log(event, **fields):
    logger.info(json.dumps({'event': event, 'cycle_id': fields.pop('cycle_id', '-'),
                            'finding_id': '-', **fields}, sort_keys=True))


class IntervalRunner:
    """Runs `run(workspace, cycle)` every `minutes`; overlap is skipped and logged."""

    def __init__(self, database, minutes, *, run=None, wait=None):
        self.database = Path(database)
        self.minutes = minutes
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        self._run = run
        self._wait = wait or self.stopping.wait  # returns True once stopping

    def tick(self):
        if not self.lock.acquire(blocking=False):
            _log('cycle_skipped', reason='previous run still active')
            return
        cycle = None
        try:
            from scripts.local import next_cycle, open_workspace, run_local_cycle
            workspace = open_workspace(self.database)
            cycle = next_cycle(workspace)
            (self._run or run_local_cycle)(workspace, cycle)
            _log('interval_cycle_finished', cycle_id=f'cycle-{cycle:03d}')
        except Exception as exc:  # noqa: BLE001 - logged by class only; the runner keeps going
            _log('cycle_failed', cycle_id='-' if cycle is None else f'cycle-{cycle:03d}',
                 error=type(exc).__name__)
        finally:
            self.lock.release()

    def loop(self):
        while not self._wait(self.minutes * 60):
            self.tick()

    def start(self):
        thread = threading.Thread(target=self.loop, name='rz-interval-cycle', daemon=True)
        thread.start()
        return thread


def start_interval_runner(database, minutes, **kwargs):
    """Start the runner's one daemon thread, or nothing when the interval is 0 (off)."""
    if minutes <= 0:
        return None
    runner = IntervalRunner(database, minutes, **kwargs)
    runner.start()
    return runner


def main():
    parser = argparse.ArgumentParser(description='Start the local Remediation Zero dashboard; Ctrl+C stops it')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--saved', action='store_true', help='Show saved records instead of demo fixtures')
    mode.add_argument('--demo', action='store_true', help='Show synthetic examples instead of saved records')
    parser.add_argument('--database', type=Path, metavar='DIR',
                        help='Use a specific workspace directory; defaults to one in the installation folder')
    parser.add_argument('--no-browser', action='store_true')
    parser.add_argument('--port', type=int)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    database = args.database.expanduser().resolve() if args.database else default_database(root)
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
        minutes = preferences['cycle_interval_minutes']
        if minutes > 0:
            logging.basicConfig(level=logging.INFO, stream=sys.stderr, format='%(message)s')
            start_interval_runner(database, minutes)
            print(f'Press Ctrl+C here to stop. A cycle runs every {minutes} minutes and calls your configured models.', flush=True)
        else:
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
