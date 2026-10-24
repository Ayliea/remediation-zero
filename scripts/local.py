# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The local edition's command line: python3 -S -m scripts.local --help.

Standard library only. Every command takes --database DIR, the workspace
root (one SQLite file per agent; see tools/local_layout.py). Only `cycle` and
`check-models` call a model; `seed`, `rescan`, `exception` and `approve` work
with no model configured. API keys come only from the environment
(RZ_<ROLE>_API_KEY, or RZ_MODEL_API_KEY for the proposer) and are never
printed, logged or written to settings.
"""
import argparse
import json
import logging
import os
import secrets
import shlex
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from engine.approve import ApprovalRefused, InvalidFindingId, approve, assign_approved
from engine.chase import run_chase
from engine.ports import NoDelivery, NoTelemetry, Ports
from engine.report import run_report
from engine.rescan import load_scan, run_rescan
from engine.seed import seed
from engine.snapshot import snapshot
from engine.sweep import NoSuchFinding, accept, run_sweep
from engine.triage_cycle import NO_PROPOSER, build_adapters, pending_findings, run_triage_cycle
from tools import local_settings
from tools.adjudication import RetryStateError
from tools.clock import SimClock
from tools.delivery import GitHubDelivery
from tools import enrichment as enrichment_module
from tools.enrichment import EnrichmentCache
from tools.github_tickets import GitHubTickets, GitHubUnavailable
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
NOT_A_WORKSPACE = ('{} is not a Remediation Zero workspace directory (a single-file database from an earlier '
                   'version, or a non-empty folder). Choose a new or empty directory with --database DIR; '
                   'nothing was changed.')

logger = logging.getLogger('remediation_zero.local')


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
        # repo's data/cache, read only and offline; absent, enrichment is empty.
        enrichment = EnrichmentCache()
        missing = [name for name, present in (('kev', enrichment.has_kev), ('epss', enrichment.has_epss),
                                              ('nvd', enrichment.has_nvd)) if not present]
        if missing:
            _log('enrichment_absent', f'cycle-{cycle:03d}', sources=missing)
            print(f'warning: enrichment cache not found at {enrichment_module.DEFAULT_CACHE_DIR}: '
                  f'{", ".join(missing)} were not checked', file=sys.stderr, flush=True)
        record = run_triage_cycle(triage, cycle, finding_ids=pending_findings(triage_docs),
                                  enrichment=enrichment)

        day = cycle_for_day(clock.now().real_ts)
        chase_docs = docs_for('chase')
        chased = run_chase(_ports(chase_docs, journal, clock,
                                  delivery=chase_delivery(chase_docs, environ)), day)
        swept = run_sweep(_ports(docs_for('sweep'), journal, clock), day)
        run_report(_ports(docs_for('report'), journal, clock, roles=roles), cycle)
    finally:
        for store in stores:
            store.close()
    return {'cycle': record['cycle_id'], 'outcomes': record['outcomes'], 'approved': approved,
            'chase_cycle': day, 'chase': chased, 'sweep': swept}


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
                    settings_html = render_settings(local_settings.load(config_path), section if section in SECTIONS else 'model', token,
                        message='Preferences saved. No model calls were made.' if parse_qs(parsed.query).get('saved') == ['1'] else '',
                        keys={role: key_present(role, os.environ) for role in ROLES},
                        overrides=bool(os.environ.get('RZ_MODEL_ENDPOINT') or os.environ.get('RZ_MODEL')))
                body = render(demo_snapshot() if demo else store.snapshot(), view, demo=demo, settings_html=settings_html,
                              approve_command=None if demo else approve_command)
                status = 200
            except Exception:
                body, status = render({}, view, unavailable=True, settings_html="" if config_path else None), 503
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
                if (not 0 < length <= 8192 or self.headers.get('Transfer-Encoding')
                        or self.headers.get('Content-Type') != 'application/x-www-form-urlencoded'):
                    raise ValueError()
                fields = parse_qs(self.rfile.read(length).decode('utf-8'), keep_blank_values=True, strict_parsing=True, max_num_fields=20)
                if any(len(v) != 1 for v in fields.values()):
                    raise ValueError()
                fields = {k: v[0] for k, v in fields.items()}
                if not secrets.compare_digest(fields.pop('token', '').encode(), token.encode()):
                    self.send_error(403)
                    return
                section = fields.pop('section', '')
                values = local_settings.load(config_path)
                if section == 'model' and set(fields) == MODEL_FIELDS:
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
        elif args.command == 'serve':
            docs = ws.docs_for('report')  # the dashboard reads; it writes no record
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


