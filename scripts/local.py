# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The local edition's command line: python3 -S -m scripts.local --help.

Standard library only. Every command takes --database DIR, the workspace
root (one SQLite file per agent; see tools/local_layout.py). Only `cycle` and
`check-models` call a model; `update-enrichment` is the one command that reaches the
internet (CISA, EPSS, NVD); `greenbone` reads from your Greenbone server
(credentials only from RZ_GREENBONE_USERNAME and RZ_GREENBONE_PASSWORD); `seed`, `rescan`, `exception` and `approve` work
with no model configured. API keys come only from the environment
(RZ_<ROLE>_API_KEY, or RZ_MODEL_API_KEY for the proposer) and are never
printed, logged or written to settings.
"""
import argparse
import json
import logging
import os
import re
import secrets
import shlex
import sys
import unicodedata
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from engine.approve import ApprovalRefused, InvalidFindingId, approve, assign_approved
from engine.chase import run_chase
from engine.ports import NoDelivery, NoTelemetry, Ports
from engine.report import run_report
from engine.rescan import load_scan, run_rescan
from engine.scanner_import import GreenboneSource, ImportRefused, import_upload, pull
from engine.seed import SeedRefused, seed
from engine.snapshot import snapshot
from engine.sweep import NoSuchFinding, accept, run_sweep
from engine.triage_cycle import NO_PROPOSER, build_adapters, pending_findings, run_triage_cycle
from tools import local_settings
from tools.adjudication import RetryStateError
from tools.clock import SimClock
from tools.delivery import GitHubDelivery
from tools.enrichment import EnrichmentCache, finding_cves
from tools.enrichment_fetch import refresh, urllib_get, workspace_cache_dir
from tools.github_tickets import GitHubTickets, GitHubUnavailable
from tools.gmp import GmpAuthError, GmpClient, GmpError, credentials_from_env
from tools.greenbone_report import MAX_REPORT_BYTES, parse_report
from tools.guardrail import NoGuard, guard_for
from tools.local_layout import Workspace
from tools.local_memory import LocalMemory
from tools.model_check import check_models
from tools.model_roles import ModelRoles, ROLES, key_present, suggest_family
from ui.dashboard_view import VIEWS, demo_snapshot, render
from ui.settings_view import SECTIONS, render_settings
from worker.envelope import cycle_for_day

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = 'remediation-zero'
DEFAULT_CORPUS = ROOT / 'data'
CORPUS_FILES = ('findings.json', 'assets.json', 'owners.json')
NO_CORPUS = 'no corpus: pass --corpus DIR (findings.json, assets.json, owners.json)'
MODEL_FIELDS = {'same_family_policy'} | {f'{role}_{part}' for role in ROLES for part in ('format', 'endpoint', 'model', 'family')}
# mode and port are required; the checkbox and the interval may be absent.
APPLICATION_FIELDS = {'mode', 'port', 'open_browser', 'cycle_interval_minutes'}
SCANNER_REQUIRED = {'transport', 'socket_path', 'host', 'port', 'ca_file', 'task_ids', 'qod_floor'}
SCANNER_FIELDS = SCANNER_REQUIRED | {'auto_enrichment'}
SCANNER_PAGE_TIMEOUT = 5.0  # the settings page must stay responsive when Greenbone is not
NOT_A_WORKSPACE = ('{} is not a Remediation Zero workspace directory (a single-file database from an earlier '
                   'version, or a non-empty folder). Choose a new or empty directory with --database DIR; '
                   'nothing was changed.')

logger = logging.getLogger('remediation_zero.local')

_ANSI = re.compile(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|[@-Z\\-_])')
NO_TASKS = 'No tasks are chosen. Nothing was pulled. Choose tasks in Settings, or run: greenbone tasks'
NOT_SET_UP = ('The Greenbone connection is not set up. Save a socket path (Unix) or host (TLS) in Settings. '
              'No connection was attempted.')


class NotAWorkspace(Exception):
    """--database names something that is not, and cannot become, a workspace."""


def _log(event, cycle_id='-', finding_id='-', **fields):
    logger.info(json.dumps({'event': event, 'cycle_id': cycle_id, 'finding_id': finding_id, **fields},
                           sort_keys=True))


def refuse_non_directory(database):
    """Refuse an existing non-directory (an earlier version's single-file database). Reads only."""
    path = Path(database)
    if path.exists() and not path.is_dir():
        raise NotAWorkspace(str(database))


def open_workspace(database):
    """The workspace at `database`, created if new. Never migrates or touches anything else."""
    refuse_non_directory(database)
    workspace = Workspace(Path(database))
    try:
        workspace.init()
    except (ValueError, NotADirectoryError):
        raise NotAWorkspace(str(database)) from None
    return workspace


def load_roles(database, environ):
    """Roles from the workspace's settings; RZ_MODEL_ENDPOINT / RZ_MODEL override the proposer."""
    return ModelRoles.from_settings(local_settings.load(local_settings.settings_path(database)), environ)


def _ports(docs, journal, clock, *, roles=None, delivery=None, memory=None, guard=None,
           record_failed_runs=False):
    return Ports(docs=docs, journal=journal, clock=clock, roles=roles, guard=guard or NoGuard(),
                 delivery=delivery or NoDelivery(), memory=memory, telemetry=NoTelemetry(),
                 record_failed_runs=record_failed_runs)


def chase_delivery(docs, environ):
    """GitHub issues only when both variables are set; otherwise the dashboard is the delivery."""
    repo = environ.get('GITHUB_TICKET_REPO', '').strip()
    token = environ.get('GITHUB_TOKEN', '').strip()
    if repo and token:
        try:
            delivery = GitHubDelivery(GitHubTickets(repo=repo, token=token), client=docs)
        except GitHubUnavailable as exc:
            _log('delivery_unavailable', error=type(exc).__name__)
            return NoDelivery()
        _log('delivery_enabled', tracker=repo)
        return delivery
    _log('delivery_disabled', reason='GITHUB_TICKET_REPO and GITHUB_TOKEN are not both set')
    return NoDelivery()


def approval_ports(ws, clock):
    """The approve stage: it may write `approvals` and nothing else."""
    return _ports(ws.docs_for('approve'), ws.journal(), clock)


def run_local_cycle(ws, cycle, *, roles=None, clock=None, environ=None):
    """Triage, chase, sweep and report, in that order, each with its own stage's store.

    Triage and report use `cycle`; chase and sweep use the day's cycle number,
    as the cloud worker does. Approved decisions not yet assigned are assigned
    first. With no proposer configured this raises ValueError(NO_PROPOSER)
    before anything is opened or written. `roles` is for tests; production
    builds them from the workspace settings and the environment's keys.
    """
    environ = os.environ if environ is None else environ
    if roles is None:
        roles = load_roles(ws.root, environ)
    if roles.proposer is None:
        raise ValueError(NO_PROPOSER)
    clock = clock or SimClock.from_env(environ)
    guard = guard_for(roles)  # the guard model, or none: then untrusted text is withheld
    journal = ws.journal()
    stores = []

    def docs_for(stage):
        stores.append(ws.docs_for(stage))
        return stores[-1]

    try:
        triage_docs = docs_for('triage_cycle')
        triage = _ports(triage_docs, journal, clock, roles=roles, guard=guard,
                        memory=LocalMemory(triage_docs), record_failed_runs=True)
        build_adapters(triage)  # a broken model configuration fails before any write
        approved = assign_approved(triage)
        # Only pending findings (Ruling 29): re-triaging a decided one would
        # pay for the models again and restart its SLA clock. The cache is the
        # workspace's enrichment folder (filled by update-enrichment), read only
        # and offline; absent, enrichment is empty.
        cache_dir = workspace_cache_dir(ws.root)
        enrichment = EnrichmentCache(cache_dir)
        missing = [name for name, present in (('kev', enrichment.has_kev), ('epss', enrichment.has_epss),
                                              ('nvd', enrichment.has_nvd)) if not present]
        if missing:
            _log('enrichment_absent', f'cycle-{cycle:03d}', sources=missing)
            print(f'warning: enrichment cache not found at {cache_dir}: '
                  f'{", ".join(missing)} were not checked', file=sys.stderr, flush=True)
        # A finding that raises stops triage, not the lifecycle: chase, the
        # sweep and the report read only what is stored, so they still run,
        # and the triage error is raised afterwards (exit 1, class only).
        triage_error = None
        try:
            record = run_triage_cycle(triage, cycle, finding_ids=pending_findings(triage_docs),
                                      enrichment=enrichment)
        except Exception as exc:  # noqa: BLE001 - re-raised below, after the other stages
            triage_error = exc

        day = cycle_for_day(clock.now().real_ts)
        try:
            chase_docs = docs_for('chase')
            chased = run_chase(_ports(chase_docs, journal, clock,
                                      delivery=chase_delivery(chase_docs, environ)), day)
            swept = run_sweep(_ports(docs_for('sweep'), journal, clock), day)
            run_report(_ports(docs_for('report'), journal, clock, roles=roles), cycle)
        except Exception:
            # The triage failure is the first cause; never let a later one hide it.
            if triage_error is not None:
                raise triage_error
            raise
    finally:
        for store in stores:
            store.close()
    if triage_error is not None:
        raise triage_error
    return {'cycle': record['cycle_id'], 'outcomes': record['outcomes'], 'approved': approved,
            'chase_cycle': day, 'chase': chased, 'sweep': swept}


def update_enrichment(ws, environ, *, cves=None, get=None, clock=None):
    """Refresh the workspace's enrichment cache; the one thing that reaches the internet.

    `cves` None means every CVE on the workspace's findings. `get` None is the
    real https fetcher; tests inject one. The NVD key comes only from
    `NVD_API_KEY` in `environ` and is passed to the fetcher, never stored. The
    status document `scanner_state/enrichment` is written through the
    enrichment_refresh stage with the SimClock's stamps.
    """
    get = get or urllib_get
    clock = clock or SimClock.from_env(environ)
    docs = ws.docs_for('enrichment_refresh')
    try:
        if cves is None:
            found = set()
            for snapshot in docs.collection('findings').stream():
                found.update(finding_cves(snapshot.to_dict()))
            cves = sorted(found)
        result = refresh(cves, workspace_cache_dir(ws.root), get=get,
                         nvd_api_key=environ.get('NVD_API_KEY') or None)
        failed = [name for name in ('kev', 'epss') if result[name] != 'ok'] + list(result['nvd_failed'])
        stamp = clock.now()
        docs.collection('scanner_state').document('enrichment').set({
            'last_run_real_ts': stamp.real_ts, 'last_run_sim_ts': stamp.sim_ts,
            'kev': result['kev'], 'epss': result['epss'], 'nvd_fetched': result['nvd_fetched'],
            'failed': failed})
        _log('enrichment_refreshed', kev=result['kev'], epss=result['epss'],
             nvd_fetched=result['nvd_fetched'], nvd_failed=len(result['nvd_failed']))
        return result
    finally:
        docs.close()


def next_cycle(ws):
    """One more than the highest recorded cycle, or 1 when there are none."""
    docs = ws.docs_for('report')
    try:
        numbers = [int((s.to_dict() or {}).get('cycle') or 0) for s in docs.collection('cycles').stream()]
    finally:
        docs.close()
    return max(numbers, default=0) + 1


class _View:
    """What the dashboard handler reads: the full local snapshot."""

    def __init__(self, docs):
        self._docs = docs

    def snapshot(self):
        return snapshot(self._docs)


def scanner_probe(settings, *, test=False):
    """What the Scanner section learns from Greenbone, from the saved settings. Only the
    token-protected scanner_test POST calls this with test=True; a GET never contacts Greenbone.

    Never raises, never returns server text: a failure is reported as its class name only.
    With credentials unset or no connection saved, no connection is attempted. The whole
    session (connect, sign-in, task list) is bounded by one deadline, because this server
    handles one request at a time."""
    try:
        username, password = credentials_from_env(os.environ)
    except GmpError:
        return {'state': 'unset', 'test': test}
    if not test:
        return {'state': 'idle'}
    try:
        target = local_settings.gmp_target(settings, timeout=SCANNER_PAGE_TIMEOUT)
    except ValueError:
        return {'state': 'unconfigured', 'test': test}
    try:
        with GmpClient(target, username, password, total_timeout=SCANNER_PAGE_TIMEOUT) as client:
            tasks = client.list_tasks()
    except GmpAuthError:
        return {'state': 'auth', 'test': test}
    except Exception as error:  # GmpError, OSError or anything else: the class name only
        return {'state': 'error', 'error': type(error).__name__, 'test': test}
    return {'state': 'ok', 'tasks': tasks, 'test': test}


def terminal_safe(text, limit=80):
    """Text from Greenbone or a report, safe to print: no escape sequences, no control or
    format characters, at most `limit` characters."""
    text = _ANSI.sub('', str(text))
    kept = ''.join(c for c in text if unicodedata.category(c)[0] != 'C' and unicodedata.category(c) not in ('Zl', 'Zp'))
    return kept.strip()[:limit]


def gmp_client_factory(preferences, environ, *, timeout=30.0):
    """A callable that returns an unopened GmpClient for the saved connection.

    Raises GmpAuthError (naming the two variables, never a value) when the credentials are
    not in `environ`, and ValueError when no connection is saved."""
    username, password = credentials_from_env(environ)
    target = local_settings.gmp_target(preferences, timeout=timeout)
    return lambda: GmpClient(target, username, password)


def probe_lines(probe):
    """The three lines the Scanner page shows after a test, for the terminal."""
    state = probe.get('state')
    yes = lambda ok: 'yes' if ok else 'no'
    count = f' ({len(probe.get("tasks") or [])})' if state == 'ok' else ''
    return [f'Connected: {yes(state in {"ok", "auth"})}', f'Signed in: {yes(state == "ok")}',
            f'Tasks listed: {yes(state == "ok")}{count}']


def _credentials_error(environ):
    """The missing-credentials message (variable names only), or None when both are set."""
    try:
        credentials_from_env(environ)
    except GmpAuthError as exc:
        return str(exc)
    return None


def greenbone_tasks(preferences, environ):
    """Print `task_id  name` for each task the account can see. Returns the exit code."""
    try:
        factory = gmp_client_factory(preferences, environ)
    except GmpAuthError as exc:
        print(exc, file=sys.stderr)
        return 2
    except ValueError:
        print(NOT_SET_UP, file=sys.stderr)
        return 1
    try:
        with factory() as client:
            tasks = client.list_tasks()
    except GmpAuthError:
        print('Greenbone did not accept the credentials in RZ_GREENBONE_USERNAME and RZ_GREENBONE_PASSWORD.',
              file=sys.stderr)
        return 1
    except Exception as error:  # the class only: a message can carry server text
        print(f'Could not list tasks ({type(error).__name__}).', file=sys.stderr)
        return 1
    for task in tasks:
        print(f'{terminal_safe(task["task_id"])}  {terminal_safe(task["name"])}')
    return 0


def greenbone_test(preferences, environ):
    """Connect, sign in, list tasks: the page's three lines. Returns the exit code."""
    missing = _credentials_error(environ)
    if missing:
        print(missing, file=sys.stderr)
        return 2
    probe = scanner_probe(preferences, test=True)
    if probe['state'] == 'unconfigured':
        print(NOT_SET_UP, file=sys.stderr)
        return 1
    print('\n'.join(probe_lines(probe)))
    if probe['state'] == 'error':
        print(f'Could not reach Greenbone: {terminal_safe(probe.get("error", "Error"))}.', file=sys.stderr)
    return 0 if probe['state'] == 'ok' else 1


def greenbone_pull(ws, preferences, environ, cycle, *, client_factory=None, clock=None):
    """Pull the chosen tasks through the import path; the result of `engine.scanner_import.pull`."""
    scanner = preferences['scanner']
    factory = client_factory or gmp_client_factory(preferences, environ)
    source = GreenboneSource(factory, qod_floor=scanner['qod_floor'])
    ports = _ports(ws.docs_for('scanner_import'), ws.journal(), clock or SimClock.from_env(environ))
    try:
        return pull(ports, cycle, source, chosen_task_ids=scanner['task_ids'])
    finally:
        ports.docs.close()


def pull_line(outcome):
    task, result = terminal_safe(outcome['task_id']), outcome['result']
    if result == 'failed':
        return f'{task} failed {terminal_safe(outcome.get("error_class", "Error"))}'
    counts = outcome.get('counts') or {}
    skipped = outcome.get('skipped')
    skipped = sum(skipped.values()) if isinstance(skipped, dict) else outcome.get('skipped_reports', 0)
    return (f'{task} {result} findings={counts.get("new", 0)} resolved={counts.get("resolved", 0)} '
            f'skipped={skipped} refused={outcome.get("refused", 0)} deferred={outcome.get("deferred", 0)}')


def greenbone_pull_command(ws, preferences, environ, cycle):
    """`greenbone pull`: one line per task. 0 when every task imported or had nothing new."""
    if not preferences['scanner']['task_ids']:
        print(NO_TASKS)
        return 0
    try:
        result = greenbone_pull(ws, preferences, environ, cycle)
    except GmpAuthError as exc:  # only the missing-credentials check raises it here, before any connection
        print(exc, file=sys.stderr)
        return 2
    except ImportRefused as exc:
        print(f'Refused: {terminal_safe(exc, 200)} Nothing was written.', file=sys.stderr)
        return 1
    except ValueError:
        print(NOT_SET_UP, file=sys.stderr)
        return 1
    for outcome in result['pulled']:
        print(pull_line(outcome))
    return 0 if all(o['result'] in {'imported', 'nothing_new'} for o in result['pulled']) else 1


def _read_capped(path):
    """The file's bytes, or None when it is larger than the parser's cap (never read in full)."""
    if path.stat().st_size > MAX_REPORT_BYTES:
        return None
    with path.open('rb') as stream:
        data = stream.read(MAX_REPORT_BYTES + 1)
    return data if len(data) <= MAX_REPORT_BYTES else None


def greenbone_upload(ws, preferences, environ, path, cycle, *, add_task=False, clock=None):
    """`greenbone upload FILE`: one report through the same checks as a pulled one.

    The report's own task decides. An unchosen task needs --add-task, and is saved to the
    settings only after the report parses and the import succeeds."""
    scanner = preferences['scanner']
    try:
        data = _read_capped(Path(path))
    except OSError as error:
        print(f'Could not read the file ({type(error).__name__}). Nothing was written.', file=sys.stderr)
        return 1
    if data is None:
        print(f'The report is larger than {MAX_REPORT_BYTES} bytes. It was not read. Nothing was written.',
              file=sys.stderr)
        return 1
    try:
        report = parse_report(data)
    except Exception as error:  # a refused or malformed document: the closed reason or the class
        reason = getattr(error, 'reason', None) or type(error).__name__
        print(f'The report was refused ({terminal_safe(reason)}). Nothing was written.', file=sys.stderr)
        return 1
    chosen = list(scanner['task_ids'])
    if report.task_id not in chosen:
        if not add_task:
            print(f'Task {terminal_safe(report.task_id)} is not chosen for this install. '
                  'Re-run with --add-task to add it.', file=sys.stderr)
            return 1
        if not local_settings.TASK_ID_RE.fullmatch(report.task_id or ''):
            print('The report names a task id that is not a lowercase UUID. Nothing was written.', file=sys.stderr)
            return 1
    ports = _ports(ws.docs_for('scanner_import'), ws.journal(), clock or SimClock.from_env(environ))
    try:
        result = import_upload(ports, cycle, data, chosen_task_ids=chosen,
                               qod_floor=scanner['qod_floor'], add_task=add_task)
    except ImportRefused as exc:
        reason = f' ({exc.reason})' if exc.reason else ''
        print(f'Refused{reason}: {terminal_safe(exc, 200)} Nothing was written.', file=sys.stderr)
        return 1
    finally:
        ports.docs.close()
    if result['task_added']:
        print(f'Adding task {terminal_safe(report.task_name) or "(unnamed)"} ({report.task_id}) to this install.')
        settings_file = local_settings.settings_path(ws.root)
        saved = local_settings.load(settings_file)
        saved['scanner']['task_ids'].append(report.task_id)
        local_settings.save(settings_file, saved)
    _print({'cycle': result['cycle'], 'scan_id': result['scan_id'], 'task_id': result['task_id'],
            'counts': result['counts'], 'newly_ingested': result['newly_ingested'],
            'newly_resolved': result['newly_resolved'], 'task_added': result['task_added']})
    return 0


def scanner_tick(ws, cycle, environ=None, *, client_factory=None, clock=None):
    """The timer's Greenbone step, before the cycle: pull, then enrich what the pull added.

    Never raises: the cycle must still run. A failure is logged as its class only. With no
    task chosen nothing is contacted and nothing is logged; with tasks chosen and no
    credentials, `greenbone_credentials_missing` is logged once."""
    environ = os.environ if environ is None else environ
    cycle_id = f'cycle-{cycle:03d}'
    try:
        preferences = local_settings.load(local_settings.settings_path(ws.root))
        scanner = preferences['scanner']
        if not scanner['task_ids']:
            return
        if client_factory is None and _credentials_error(environ):
            _log('greenbone_credentials_missing', cycle_id)
            return
        result = greenbone_pull(ws, preferences, environ, cycle, client_factory=client_factory, clock=clock)
    except Exception as exc:  # noqa: BLE001 - class only; the cycle still runs
        _log('greenbone_pull_failed', cycle_id, error=type(exc).__name__)
        return
    new_cves = result.get('new_cves') or []
    if scanner['auto_enrichment'] and new_cves:
        try:
            update_enrichment(ws, environ, cves=new_cves, clock=clock)
        except Exception as exc:  # noqa: BLE001 - class only; the cycle still runs
            _log('greenbone_enrichment_failed', cycle_id, error=type(exc).__name__)


MAX_CHOSEN_TASKS = 500


class TooManyTasks(ValueError):
    pass


def _scanner_values(fields, values):
    """The scanner settings a posted form describes: the union of the typed and ticked task IDs."""
    ints = {}
    for name in ('port', 'qod_floor'):
        text = fields[name]
        if not (text.isascii() and text.isdigit()):  # ASCII digits only; validate checks the range
            raise ValueError()
        ints[name] = int(text)
    if fields.get('auto_enrichment', 'yes') != 'yes':
        raise ValueError()
    task_ids = []
    for line in fields['task_ids'].splitlines():
        line = line.strip().lower()
        if line and line not in task_ids:
            task_ids.append(line)
    if len(task_ids) > MAX_CHOSEN_TASKS:
        raise TooManyTasks()
    return dict(transport=fields['transport'], socket_path=fields['socket_path'], host=fields['host'],
                ca_file=fields['ca_file'], task_ids=task_ids, auto_enrichment='auto_enrichment' in fields, **ints)


def handler(store, demo, config_path=None, approve_command=None):
    token = secrets.token_urlsafe(32)
    class DashboardHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Avoid recording URL parameters or request headers.

        def do_GET(self):
            if self.headers.get('Host') not in {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}:
                self.send_error(403)
                return
            parsed = urlsplit(self.path)
            view = parse_qs(parsed.query).get('view', ['overview'])[0]
            section = parse_qs(parsed.query).get('section', ['model'])[0]
            if parsed.path != '/' or (view not in VIEWS and not (config_path and view == 'settings')) or (view == 'settings' and section not in SECTIONS):
                self.send_error(404)
                return
            try:
                settings_html = None
                if config_path:
                    saved = local_settings.load(config_path)
                    settings_html = self._settings_html(saved, section if section in SECTIONS else 'model',
                        message='Preferences saved. No model calls were made.' if parse_qs(parsed.query).get('saved') == ['1'] else '',
                        scanner=scanner_probe(saved) if view == 'settings' and section == 'scanner' else None)
                body = render(demo_snapshot() if demo else store.snapshot(), view, demo=demo, settings_html=settings_html,
                              approve_command=None if demo else approve_command)
                status = 200
            except Exception:
                body, status = render({}, view, unavailable=True, settings_html="" if config_path else None), 503
            self._send_html(body, status)

        def _settings_html(self, values, section, *, message='', scanner=None):
            return render_settings(values, section, token, message=message,
                keys={role: key_present(role, os.environ) for role in ROLES},
                overrides=bool(os.environ.get('RZ_MODEL_ENDPOINT') or os.environ.get('RZ_MODEL')), scanner=scanner)

        def _send_html(self, body, status):
            encoded = body.encode()
            self.send_response(status)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(encoded)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Security-Policy', "default-src 'none'; img-src data:; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.end_headers()
            self.wfile.write(encoded)
        def do_POST(self):
            host = self.headers.get('Host')
            allowed = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
            if (not config_path or host not in allowed or self.path != '/settings'
                    or self.headers.get('Origin') != f'http://{host}'
                    or self.headers.get('Sec-Fetch-Site') not in {None, 'same-origin'}):
                self.send_error(403)
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if (not 0 < length <= 65536 or self.headers.get('Transfer-Encoding')
                        or self.headers.get('Content-Type') != 'application/x-www-form-urlencoded'):
                    raise ValueError()
                raw = self.rfile.read(length).decode('utf-8')
                # Only the Scanner form repeats a field (one task_ids per ticked task) and may be longer.
                scanner_form = 'section=scanner' in raw.split('&')
                if length > 8192 and not scanner_form:
                    raise ValueError()
                fields = parse_qs(raw, keep_blank_values=True, strict_parsing=True, max_num_fields=1100 if scanner_form else 20)
                if any(len(v) != 1 for k, v in fields.items() if not (scanner_form and k == 'task_ids')):
                    raise ValueError()
                fields = {k: '\n'.join(v) if k == 'task_ids' else v[0] for k, v in fields.items()}
                if not secrets.compare_digest(fields.pop('token', '').encode(), token.encode()):
                    self.send_error(403)
                    return
                section = fields.pop('section', '')
                values = local_settings.load(config_path)
                if section == 'scanner_test' and not fields:
                    # Tests the saved settings. Never saves, so nothing below runs.
                    self._send_html(render(demo_snapshot() if demo else store.snapshot(), 'settings', demo=demo,
                                           settings_html=self._settings_html(values, 'scanner', scanner=scanner_probe(values, test=True)),
                                           approve_command=None if demo else approve_command), 200)
                    return
                if section == 'scanner':
                    # A credential is never accepted, whatever the field is called or how it is cased.
                    if any(k.lower() in {'username', 'password'} for k in fields) or not SCANNER_REQUIRED <= set(fields) <= SCANNER_FIELDS:
                        raise ValueError()
                    values['scanner'] = _scanner_values(fields, values)
                elif section == 'model' and set(fields) == MODEL_FIELDS:
                    for role in ROLES:
                        endpoint, model = fields[role + '_endpoint'], fields[role + '_model']
                        values['roles'][role] = None if not (endpoint or model) else {
                            'format': fields[role + '_format'], 'endpoint': endpoint, 'model': model,
                            'family': fields[role + '_family'] or suggest_family(model)}
                    values['same_family_policy'] = fields['same_family_policy']
                elif section == 'application' and {'mode', 'port'} <= set(fields) <= APPLICATION_FIELDS:
                    if fields.get('open_browser', 'yes') != 'yes':
                        raise ValueError()
                    values.update(mode=fields['mode'], port=int(fields['port']), open_browser='open_browser' in fields)
                    if 'cycle_interval_minutes' in fields:
                        # ASCII digits only; local_settings.validate checks 0-1440 on save.
                        minutes = fields['cycle_interval_minutes']
                        if not (minutes.isascii() and minutes.isdigit()):
                            raise ValueError()
                        values['cycle_interval_minutes'] = int(minutes)
                else:
                    raise ValueError()
                local_settings.save(config_path, values)
            except TooManyTasks:
                self.send_error(400, 'At most 500 scan tasks can be chosen. Nothing was saved.')
                return
            except (ValueError, UnicodeError):
                self.send_error(400, 'Invalid preferences. Nothing was saved. Check the endpoint, model, port, and interval.')
                return
            except OSError:
                self.send_error(503, 'Preferences could not be saved. Check local file permissions.')
                return
            self.send_response(303)
            self.send_header('Location', f'/?view=settings&section={section}&saved=1')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', '0')
            self.end_headers()

    return DashboardHandler


def _cycle(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError('a cycle number is 0 or more')
    return number


def _parser():
    parser = argparse.ArgumentParser(description='Remediation Zero local edition (no cloud setup required)')
    parser.add_argument('--database', default=DEFAULT_DATABASE, metavar='DIR',
                        help='Workspace directory (default: %(default)s)')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('init', help='Create the workspace; no model calls')
    seeding = commands.add_parser('seed', help='Load findings, assets and owners from a corpus; no model calls')
    seeding.add_argument('--corpus', type=Path, metavar='DIR',
                         help="Folder holding findings.json, assets.json and owners.json (default: the repository's data/)")
    cycle = commands.add_parser('cycle', help='Run triage, chase, sweep and report once; calls your models')
    cycle.add_argument('--cycle', type=_cycle, required=True)
    rescan = commands.add_parser('rescan', help='Apply a follow-up scan; the only way a finding is resolved')
    rescan.add_argument('--cycle', type=_cycle, required=True)
    rescan.add_argument('--scan', type=Path, required=True, metavar='PATH')
    rescan.add_argument('--dry-run', action='store_true', help='Show what would close; write nothing')
    exception = commands.add_parser('exception', help='Accept a risk, or list acceptances')
    actions = exception.add_subparsers(dest='action', required=True)
    accepting = actions.add_parser('accept', help='Record a risk acceptance that expires')
    accepting.add_argument('finding')
    accepting.add_argument('--ttl', type=int, required=True, metavar='DAYS')
    accepting.add_argument('--by', required=True, metavar='OWNER_ID')
    accepting.add_argument('--reason', required=True, metavar='TEXT')
    accepting.add_argument('--cycle', type=_cycle, required=True)
    accepting.add_argument('--approved-by-person', action='store_true',
                           help='A person has approved this acceptance; required for a KEV CVE, '
                                'or when the KEV list is not available')
    actions.add_parser('list', help='List recorded risk acceptances')
    approving = commands.add_parser('approve', help='Approve an unreviewed or held decision as a person')
    approving.add_argument('finding')
    approving.add_argument('--cycle', type=_cycle, required=True)
    approving.add_argument('--by', default='local user', metavar='NAME')
    serve = commands.add_parser('serve', help='Serve the dashboard and preferences on loopback')
    serve.add_argument('--demo', action='store_true', help='Show illustrative fixtures instead of saved records')
    serve.add_argument('--port', type=int, default=8081)
    greenbone = commands.add_parser('greenbone', help='Read tasks and finished reports from Greenbone; never changes anything there')
    gb_actions = greenbone.add_subparsers(dest='gb_action', required=True)
    gb_actions.add_parser('tasks', help='List the tasks the account can see: task_id  name')
    gb_actions.add_parser('test', help='Connect, sign in and list tasks, one line each')
    gb_pull = gb_actions.add_parser('pull', help='Import the newest finished report of each chosen task')
    gb_pull.add_argument('--cycle', type=_cycle, help='Default: the next cycle number')
    gb_upload = gb_actions.add_parser('upload', help='Import one exported report file')
    gb_upload.add_argument('file', metavar='FILE')
    gb_upload.add_argument('--add-task', action='store_true',
                           help="Also choose the report's task for this install, if the import succeeds")
    gb_upload.add_argument('--cycle', type=_cycle, help='Default: the next cycle number')
    commands.add_parser('update-enrichment', help='Download CISA KEV, FIRST EPSS and NVD data into the workspace cache; reaches the internet')
    check = commands.add_parser('check-models', help='Explicitly send the bundled synthetic example to each configured model role')
    check.add_argument('--role', choices=ROLES, help='Check only this role')
    return parser


def _print(value):
    print(json.dumps(value, sort_keys=True, default=str), flush=True)


def main():
    parser = _parser()
    args = parser.parse_args()
    os.umask(0o077)
    try:
        refuse_non_directory(args.database)
        config_path = local_settings.settings_path(args.database)
        preferences = local_settings.load(config_path)
        if args.command == 'check-models':
            # Reads settings only; writes nothing to the workspace.
            raise SystemExit(check_models(ModelRoles.from_settings(preferences, os.environ), args.role))
        if args.command == 'greenbone' and args.gb_action in {'tasks', 'test'}:
            # Reads settings and the environment only; writes nothing to the workspace.
            run_greenbone = greenbone_tasks if args.gb_action == 'tasks' else greenbone_test
            raise SystemExit(run_greenbone(preferences, os.environ))
        if args.command == 'cycle':
            roles = ModelRoles.from_settings(preferences, os.environ)
            if roles.proposer is None:
                parser.exit(1, NO_PROPOSER + '\n')  # Ruling 21: before anything is created
            ws = open_workspace(args.database)
            try:
                _print(run_local_cycle(ws, args.cycle, roles=roles))
            except (ValueError, RetryStateError):
                raise
            except Exception as exc:  # noqa: BLE001 - the class only: a message can carry an endpoint
                parser.exit(1, f'The cycle stopped ({type(exc).__name__}); see failed runs on the dashboard. '
                               'Run the cycle again to retry.\n')
            return
        if args.command == 'seed':
            # Ruling 33: check the corpus before the workspace exists, so a
            # refusal creates nothing.
            corpus = args.corpus or DEFAULT_CORPUS
            if args.corpus is None and not DEFAULT_CORPUS.is_dir():
                parser.exit(1, NO_CORPUS + '\n')
            if not all((corpus / name).is_file() for name in CORPUS_FILES):
                parser.exit(1, f'No corpus found in {corpus}. Nothing was loaded.\n')
        ws = open_workspace(args.database)
        clock = SimClock.from_env()
        if args.command == 'seed':
            docs = ws.docs_for('seed')
            try:
                _print(seed(_ports(docs, None, clock), corpus))
            except SeedRefused as exc:
                parser.exit(1, f'{exc}\n')
            except FileNotFoundError:
                parser.exit(1, f'No corpus found in {corpus}. Nothing was loaded.\n')
            finally:
                docs.close()
        elif args.command == 'rescan':
            scan = load_scan(args.scan)
            docs = ws.docs_for('rescan')
            try:
                _print(run_rescan(_ports(docs, None if args.dry_run else ws.journal(), clock),
                                  args.cycle, scan, args.dry_run))
            finally:
                docs.close()
        elif args.command == 'exception' and args.action == 'accept':
            docs = ws.docs_for('exception_accept')
            try:
                result = accept(_ports(docs, ws.journal(), clock), args.finding, args.ttl,
                                args.by, args.reason, args.cycle,
                                approved_by_human=args.approved_by_person)
            except NoSuchFinding:
                parser.exit(1, f'No such finding: {args.finding}. Nothing was written.\n')
            except ValueError:
                parser.exit(2, 'The acceptance was refused and routed to the human queue.\n')
            finally:
                docs.close()
            _print({'finding_id': args.finding, 'result': result})
        elif args.command == 'exception':
            docs = ws.docs_for('report')  # read only: listing writes nothing
            try:
                for row in sorted((s.to_dict() for s in docs.collection('exceptions').stream()),
                                  key=lambda r: str(r.get('finding_id'))):
                    _print(row)
            finally:
                docs.close()
        elif args.command == 'approve':
            ports = approval_ports(ws, clock)
            try:
                _print({'approval_id': approve(ports, args.finding, args.cycle, args.by),
                        'finding_id': args.finding, 'cycle': args.cycle})
            except InvalidFindingId as exc:
                parser.exit(1, f'{exc}\n')
            except ApprovalRefused as exc:
                parser.exit(1, f'{exc}. Nothing was written.\n')
            finally:
                ports.docs.close()
        elif args.command == 'greenbone':
            cycle = args.cycle if args.cycle is not None else next_cycle(ws)
            if args.gb_action == 'pull':
                code = greenbone_pull_command(ws, preferences, os.environ, cycle)
            else:
                code = greenbone_upload(ws, preferences, os.environ, args.file, cycle, add_task=args.add_task)
            if code:
                raise SystemExit(code)
        elif args.command == 'update-enrichment':
            print('This reaches the internet: CISA, FIRST EPSS and NVD.', flush=True)
            result = update_enrichment(ws, os.environ)
            _print(result)
            if result['kev'] != 'ok' or result['epss'] != 'ok' or result['nvd_failed']:
                raise SystemExit(1)
        elif args.command == 'serve':
            docs = ws.docs_for('dashboard')  # reads only: no collection is writable
            command = f'python3 -S -m scripts.local --database {shlex.quote(str(ws.root.resolve()))}'
            with HTTPServer(('127.0.0.1', args.port), handler(_View(docs), args.demo, config_path, command)) as server:
                print(f'Local synthetic preview: http://127.0.0.1:{server.server_port}', flush=True)
                server.serve_forever()
        else:
            print('Local workspace ready. No model calls made.')
    except NotAWorkspace as exc:
        parser.exit(1, NOT_A_WORKSPACE.format(exc) + '\n')
    except (ValueError, RetryStateError):
        parser.exit(1, 'Configuration, model context or journal state is invalid. Check settings; do not reset the database to bypass request limits.\n')


if __name__ == '__main__':
    # Structured log lines go to stderr; stdout carries each command's result.
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format='%(message)s')
    main()


