# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The local edition's command line: python3 -S -m scripts.local --help.

Standard library only. Every command takes --database DIR, the workspace
root (one SQLite file per agent; see tools/local_layout.py). Only `cycle` and
`check-models` call a model; `update-enrichment` is the one command that reaches the
internet (CISA, EPSS, NVD); `greenbone` reads from your Greenbone server
(credentials only from RZ_GREENBONE_USERNAME and RZ_GREENBONE_PASSWORD); `seed`, `rescan`, `exception` and `approve` work
with no model configured. API keys come from the environment
(RZ_<ROLE>_API_KEY, or RZ_MODEL_API_KEY for the proposer) or from the owner-only
key file (`connection add`, never a command-line argument) and are never
printed, logged or written to settings.

`account` (scripts/local_accounts.py) does on the server what the Accounts page
does, `settings show` / `settings set` what the Settings page does, through
the page's own validation (apply_settings_form), and `connection` what Settings ->
Models does (scripts/local_connection_cli.py). `approve` and `exception accept`
name the person with `--as EMAIL`, an active account (an owner, to accept a
risk); the record carries `actor = {'via': 'command_line', 'account_id': ...,
'verified': False}`.
"""
import argparse
import copy
import errno
import io
import ipaddress
import json
import logging
import os
import re
import secrets
import shlex
import socket
import socketserver
import sqlite3
import ssl
import sys
import unicodedata
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from engine.approve import ApprovalRefused, InvalidFindingId, approve, assign_approved
from engine.chase import run_chase
from engine.ports import NoDelivery, NoTelemetry, Ports
from engine.report import run_report
from engine.rescan import holds_greenbone_findings, load_scan, run_rescan
from engine.scanner_import import WAITING_FOR_CYCLE, GreenboneSource, ImportRefused, import_upload, pull
from engine.seed import SeedRefused, seed
from engine.snapshot import snapshot
from engine.sweep import NoSuchFinding, accept, run_sweep
from engine.triage_cycle import NO_PROPOSER, build_adapters, pending_findings, run_triage_cycle
from scripts import local_accounts, local_auth, local_connection_cli, local_connections
from tools import access, connections, local_settings, server_tls
from tools.account_store import AccountStore
from tools.accounts import RESET_KINDS, AccountRefused, Accounts, RateLimiter
from tools.adjudication import RetryStateError
from tools.clock import SimClock
from tools.delivery import GitHubDelivery
from tools.enrichment import DEFAULT_CACHE_DIR as DEMO_CACHE_DIR, EnrichmentCache, finding_cves
from tools.enrichment_fetch import refresh, urllib_get, workspace_cache_dir
from tools.github_tickets import GitHubTickets, GitHubUnavailable
from tools.gmp import GmpAuthError, GmpClient, GmpError, credentials_from_env
from tools.greenbone_report import MAX_REPORT_BYTES, parse_report
from tools.guardrail import NoGuard, guard_for
from tools.local_layout import Workspace
from tools.local_memory import LocalMemory
from tools.local_secrets import SecretsFile, secrets_path
from tools.model_check import check_models
from tools.model_endpoints import split_endpoint
from tools.model_roles import ModelRoles, ROLES, suggest_family
from tools.models import FORMATS
from ui import account_views
from ui.dashboard_view import REFUSAL_WORDS, UPLOAD_MESSAGES, VIEWS, demo_snapshot, render
from ui.connections_view import SCRIPT_HASH
from ui.settings_view import NO_VISIBLE_TASKS, SECTIONS, render_settings
from worker.envelope import cycle_for_day

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = 'remediation-zero'
DEFAULT_CORPUS = ROOT / 'data'
CORPUS_FILES = ('findings.json', 'assets.json', 'owners.json')
NO_CORPUS = 'no corpus: pass --corpus DIR (findings.json, assets.json, owners.json)'
MODEL_FIELDS = {'same_family_policy'} | {f'{role}_{part}' for role in ROLES
                                         for part in ('format', 'endpoint', 'model', 'family', 'ca_file',
                                                      'timeout_seconds')}
# mode and port are required; the checkbox and the interval may be absent.
APPLICATION_FIELDS = {'mode', 'port', 'open_browser', 'cycle_interval_minutes', 'listen_address', 'server_names',
                      'certificate_mode', 'cert_file', 'key_file'}
SCANNER_REQUIRED = {'transport', 'socket_path', 'host', 'port', 'ca_file', 'task_ids', 'qod_floor'}
SCANNER_FIELDS = SCANNER_REQUIRED | {'auto_enrichment'}
SCANNER_PAGE_TIMEOUT = 5.0  # the settings page must stay responsive when Greenbone is not
NOT_A_WORKSPACE = ('{} is not a Remediation Zero workspace directory (a single-file database from an earlier '
                   'version, or a non-empty folder). Choose a new or empty directory with --database DIR; '
                   'nothing was changed.')

logger = logging.getLogger('remediation_zero.local')

_ANSI = re.compile(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|[@-Z\\-_])')
NO_TASKS = 'No tasks are chosen. Nothing was pulled. Choose tasks in Settings, or run: greenbone tasks'
GREENBONE_RESCAN = 'This install imports from Greenbone; use greenbone pull or greenbone upload.'
NOT_SET_UP = ('The Greenbone connection is not set up. Save a socket path (Unix) or host (TLS) in Settings. '
              'No connection was attempted.')


class NotAWorkspace(Exception):
    """--database names something that is not, and cannot become, a workspace."""


def _log(event, cycle_id='-', finding_id='-', *, level=logging.INFO, **fields):
    logger.log(level, json.dumps({'event': event, 'cycle_id': cycle_id, 'finding_id': finding_id, **fields},
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
    """Roles from the workspace's settings; RZ_MODEL_ENDPOINT / RZ_MODEL override the proposer.
    A key comes from the environment first, else from the workspace's key file."""
    return ModelRoles.from_settings(local_settings.load(local_settings.settings_path(database)), environ,
                                    SecretsFile(secrets_path(database)))


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
        # and offline. When it is empty and the workspace holds seeded demo
        # findings, the bundled data/cache is read instead, as before Greenbone.
        # A Greenbone workspace never reads data/cache; absent, enrichment is empty.
        cache_dir = workspace_cache_dir(ws.root)
        enrichment = EnrichmentCache(cache_dir)
        if (not (enrichment.has_kev or enrichment.has_epss or enrichment.has_nvd)
                and not holds_greenbone_findings(triage_docs)):
            cache_dir = DEMO_CACHE_DIR
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

    def records(self):
        return records_kind(self._docs)


def records_kind(docs):
    """'synthetic' for a workspace holding only seeded demo findings; 'saved' otherwise,
    including an empty one, which is waiting for its first Greenbone import."""
    sources = [(snap.to_dict() or {}).get('source') for snap in docs.collection('findings').stream()]
    return 'synthetic' if sources and 'greenbone' not in sources else 'saved'


#: Seconds a connection may sit between two reads. Browsers open spare connections they may
#: never use; this closes them instead of holding a thread.
IDLE_TIMEOUT = 15
#: Seconds from accepting a connection to the end of its request headers, TLS handshake
#: included, however the bytes are spread out (a per-read timeout alone lets a client send a
#: byte every few seconds for ever). Each later request on the connection gets as long from
#: the end of the one before. Bodies have their own deadline (BODY_SECONDS).
HEADER_SECONDS = 15
#: Sent on the TLS listener with your own certificate: a year, no includeSubDomains, no preload.
HSTS_VALUE = 'max-age=31536000'
#: Connections served at once, on every listener (loopback too: a proxy brings everyone
#: through loopback). One over a cap is closed as soon as it is accepted.
MAX_CONNECTIONS = 64
#: Of those, kept for loopback peers (the server itself, and a proxy such as Tailscale Serve),
#: so peers on the network together hold at most MAX_CONNECTIONS - LOOPBACK_RESERVED.
LOOPBACK_RESERVED = 16
#: At once from any one non-loopback address. Loopback has no per-address cap: a proxy funnels
#: everyone through 127.0.0.1. Each connection carries one request (the handler speaks
#: HTTP/1.0, so the server closes after each response): there is no keep-alive to bound.
MAX_PEER_CONNECTIONS = 16


def _peer_key(address):
    """What a connection is counted under: an IPv4 address (IPv4-mapped IPv6 included) or a
    loopback address as itself, any other IPv6 address as its /64, since one host can rotate
    through the addresses of its /64 at will. No scope ID."""
    text = str(address).split('%', 1)[0]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return text
    mapped = getattr(ip, 'ipv4_mapped', None)
    if mapped is not None:
        return str(mapped)
    if ip.version == 6 and not ip.is_loopback:
        return str(ipaddress.ip_network(f'{ip}/64', strict=False))
    return str(ip)


def _is_loopback_peer(peer):
    """`peer` is a `_peer_key`: an address, or an IPv6 /64 (never loopback)."""
    try:
        return ipaddress.ip_address(peer).is_loopback
    except ValueError:
        return False


class _ConnectionSlots:
    """Who holds the server's connections: at most `total` at once, at most
    `total - loopback_reserved` from non-loopback peers together, and at most `per_peer` from
    any one non-loopback peer. Every count changes under one lock. `take` answers False, and
    counts nothing, when a cap is reached; `give` returns exactly what one `take` counted."""

    def __init__(self, total, loopback_reserved, per_peer):
        self.total, self.remote_limit, self.per_peer = total, max(total - loopback_reserved, 0), per_peer
        self._lock = threading.Lock()
        self._all = self._remote = 0
        self._by_peer = {}
        self.refusal = None     # why the last take failed: a reason, never an address

    def take(self, peer):
        peer = _peer_key(peer)
        remote = not _is_loopback_peer(peer)
        with self._lock:
            if self._all >= self.total:
                self.refusal = 'too_many_connections'
                return False
            if remote and self._remote >= self.remote_limit:
                self.refusal = 'too_many_connections'
                return False
            if remote and self._by_peer.get(peer, 0) >= self.per_peer:
                self.refusal = 'too_many_from_one_address'
                return False
            self._all += 1
            if remote:
                self._remote += 1
                self._by_peer[peer] = self._by_peer.get(peer, 0) + 1
            return True

    def give(self, peer):
        peer = _peer_key(peer)
        remote = not _is_loopback_peer(peer)
        with self._lock:
            self._all -= 1
            if remote:
                self._remote -= 1
                left = self._by_peer.get(peer, 1) - 1
                if left:
                    self._by_peer[peer] = left
                else:
                    self._by_peer.pop(peer, None)


class _DeadlineReader(io.RawIOBase):
    """The connection's reads, for the handler's rfile. While `deadline` is set (the request
    line and headers), each read waits at most until it, and no longer than `idle` per read;
    past it, TimeoutError. With no deadline (the body), the socket's own timeout applies."""

    def __init__(self, sock, idle):
        self.sock, self.idle, self.deadline = sock, idle, None

    def readable(self):
        return True

    def readinto(self, buffer):
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            self.sock.settimeout(min(remaining, self.idle))
        return self.sock.recv_into(buffer)


class DashboardServer(ThreadingHTTPServer):
    """One thread per connection, so an idle connection holds only its own thread.
    The handler still runs requests one at a time.

    At most MAX_CONNECTIONS connections at once, LOOPBACK_RESERVED of them kept for loopback
    peers, and at most MAX_PEER_CONNECTIONS from any one network address (an IPv6 /64): a slot
    is taken when a connection is accepted and given back exactly once when its thread ends;
    one over a cap is closed at once, unread. Each
    connection has HEADER_SECONDS from accept to the end of its request headers, the TLS
    handshake included (`connection_deadline`).

    With `tls_context`, the listener accepts plain sockets and each connection's TLS handshake
    runs in its own thread under that deadline, so a client that connects and stalls (or sends
    plain HTTP) holds only that thread, never the accept loop. A failed handshake is closed
    quietly: one log line with the error class, nothing about the peer or what it sent."""
    daemon_threads = True

    def __init__(self, address, handler_class, tls_context=None):
        self.tls_context = tls_context
        self._slots = _ConnectionSlots(MAX_CONNECTIONS, LOOPBACK_RESERVED, MAX_PEER_CONNECTIONS)
        self._connection = threading.local()   # each connection has its own thread
        try:
            if ipaddress.ip_address(address[0]).version == 6:
                self.address_family = socket.AF_INET6
        except ValueError:
            pass  # a host name: the default family
        super().__init__(address, handler_class)

    def server_bind(self):
        # http.server would name itself with socket.getfqdn, a reverse DNS lookup that can stall
        # startup for many seconds (seen on macOS); nothing here uses that name.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def process_request(self, request, client_address):
        peer = client_address[0] if client_address else ''
        # The global cap, the loopback reserve and the per-address cap (_ConnectionSlots).
        if not self._slots.take(peer):
            _log('connection_refused', reason=self._slots.refusal)   # the reason only, never the address
            self.close_request(request)          # never counted, so nothing is given back
            return
        # The counted peer travels with the connection to its thread, which gives the slot back
        # in a `finally` whatever state the socket is in (a reset during the TLS wrap leaves it
        # detached, fileno() -1). Nothing is looked up by descriptor at teardown.
        try:
            super().process_request((request, peer), client_address)
        except BaseException:
            self._slots.give(peer)               # the thread never started: give it back here
            raise                                # _handle_request_noblock shuts the socket down

    def process_request_thread(self, counted, client_address):
        request, peer = counted
        try:
            self._connection.deadline = time.monotonic() + HEADER_SECONDS   # the thread starts at accept
            if self.tls_context is not None:
                request = self._handshake(request)
                if request is None:
                    return
            super().process_request_thread(request, client_address)
        finally:
            self._slots.give(peer)               # exactly once per counted connection

    def connection_deadline(self):
        """The monotonic time this thread's connection must have sent its headers by; None once
        the first request has used it (later requests start their own)."""
        deadline, self._connection.deadline = getattr(self._connection, 'deadline', None), None
        return deadline

    def _handshake(self, raw):
        """The TLS socket, or None after shutting the connection down. The slot is given back by
        process_request_thread, not here."""
        try:
            wrapped = self.tls_context.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
        except (OSError, ValueError) as error:
            _log('tls_handshake_failed', error=type(error).__name__)
            self.shutdown_request(raw)
            return None
        try:
            remaining = self._connection.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            # CPython's do_handshake treats the socket timeout as one deadline for the whole
            # handshake, not per read, so a trickled ClientHello cannot stretch it.
            wrapped.settimeout(remaining)
            wrapped.do_handshake()
        except (OSError, ValueError) as error:  # ssl.SSLError and timeouts are OSErrors
            _log('tls_handshake_failed', error=type(error).__name__)
            self.shutdown_request(wrapped)
            return None
        return wrapped

    def handle_error(self, request, client_address):
        # A TLS connection that breaks mid-request is the client's doing: the class only, no traceback.
        error = sys.exc_info()[1]
        if self.tls_context is not None and isinstance(error, (ssl.SSLError, ConnectionError, TimeoutError)):
            _log('tls_connection_failed', error=type(error).__name__)
            return
        super().handle_error(request, client_address)


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
    if not tasks:
        print(NO_VISIBLE_TASKS, file=sys.stderr)  # stdout stays one task per line
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


def _listing_words(outcome):
    """Plain-word counts of what gvmd's listing held that could not be read; empty when none."""
    words = ''
    if outcome.get('listing_refused'):
        words += f'; {int(outcome["listing_refused"])} listed reports could not be read'
    if outcome.get('skipped_tasks'):
        words += f'; {int(outcome["skipped_tasks"])} listed tasks could not be read'
    return words


def pull_line(outcome):
    task, result = terminal_safe(outcome['task_id']), outcome['result']
    if result == 'failed':
        return f'{task} failed {terminal_safe(outcome.get("error_class", "Error"))}' + _listing_words(outcome)
    if result == WAITING_FOR_CYCLE:
        return f'{task} waiting for the previous cycle to finish'
    counts = outcome.get('counts') or {}
    skipped = outcome.get('skipped')
    hidden = skipped.get('host_uncovered', 0) if isinstance(skipped, dict) else 0
    skipped = sum(skipped.values()) if isinstance(skipped, dict) else outcome.get('skipped_reports', 0)
    line = (f'{task} {result} findings={counts.get("new", 0)} resolved={counts.get("resolved", 0)} '
            f'skipped={skipped} refused={outcome.get("refused", 0)} deferred={outcome.get("deferred", 0)}')
    if hidden:
        hosts = outcome.get('host_uncovered_hosts') or 0
        on = f' on {int(hosts)} hosts' if hosts else ''
        line += (f'; {int(hidden)} results{on} were not imported because another result on that host '
                 'could not be read')
    missing = outcome.get('results_not_returned') or 0
    if missing:
        line += f'; {int(missing)} results counted in the report are missing from it, so it closed nothing'
    if not outcome.get('uncovered_all') and outcome.get('hosts_in_report') == 0:
        line += '; the report scanned no hosts, so nothing could be confirmed'
    elif not outcome.get('uncovered_all') and outcome.get('hosts_covered') == 0:
        line += '; no host in the report finished its scan, so nothing could be confirmed'
    unfinished = outcome.get('unfinished_checks') or 0
    if unfinished:
        line += f'; {int(unfinished)} checks did not finish; findings from them on those hosts stay open'
    return line + _listing_words(outcome)


def greenbone_pull_command(ws, preferences, environ, cycle):
    """`greenbone pull`: one line per task. 0 when every task imported, had nothing new, had
    already imported in this cycle, or is waiting for that cycle to finish (a frequent cron pull
    is not an error)."""
    if not preferences['scanner']['task_ids']:
        print(NO_TASKS)
        return 0
    try:
        factory = gmp_client_factory(preferences, environ)
    except GmpAuthError as exc:  # the missing-credentials check, before any connection
        print(exc, file=sys.stderr)
        return 2
    except ValueError:  # no connection saved
        print(NOT_SET_UP, file=sys.stderr)
        return 1
    try:
        result = greenbone_pull(ws, preferences, environ, cycle, client_factory=factory)
    except ImportRefused as exc:
        print(f'Refused: {terminal_safe(exc, 200)} Nothing was written.', file=sys.stderr)
        return 1
    for outcome in result['pulled']:
        print(pull_line(outcome))
    ok = {'imported', 'nothing_new', 'already_imported_this_cycle', WAITING_FOR_CYCLE}
    return 0 if all(o['result'] in ok for o in result['pulled']) else 1


def _read_capped(path):
    """The file's bytes, or None when it is larger than the parser's cap (never read in full)."""
    if path.stat().st_size > MAX_REPORT_BYTES:
        return None
    with path.open('rb') as stream:
        data = stream.read(MAX_REPORT_BYTES + 1)
    return data if len(data) <= MAX_REPORT_BYTES else None


def upload_report(ws, preferences, environ, data, cycle, *, add_task=False, clock=None):
    """One report's bytes through the same checks as a pulled one: the command and the page both call this.

    The report's own task decides. An unchosen task needs `add_task`, and is saved to the settings
    only after the report parses and the import succeeds. Returns `code` (a closed set: imported,
    refused_<reason or kind>, not_chosen, too_many_tasks, saved_failed, parse_refused, bad_request), the
    report and result when there are ones, and `detail`, text only the command prints."""
    scanner = preferences['scanner']
    try:
        report = parse_report(data)
    except Exception as error:  # a refused or malformed document: the closed reason or the class
        return {'code': 'parse_refused', 'detail': getattr(error, 'reason', None) or type(error).__name__}
    chosen = list(scanner['task_ids'])
    if report.task_id not in chosen:
        if not add_task:
            return {'code': 'not_chosen', 'report': report}
        if not local_settings.TASK_ID_RE.fullmatch(report.task_id or ''):
            return {'code': 'bad_request', 'report': report}
        if len(chosen) >= MAX_CHOSEN_TASKS:  # before the import, so no findings are left without their task
            return {'code': 'too_many_tasks', 'report': report}
    ports = _ports(ws.docs_for('scanner_import'), ws.journal(), clock or SimClock.from_env(environ))
    try:
        result = import_upload(ports, cycle, data, chosen_task_ids=chosen,
                               qod_floor=scanner['qod_floor'], add_task=add_task)
    except ImportRefused as exc:
        reason = exc.reason if exc.reason in REFUSAL_WORDS else None
        kind = exc.kind if f'refused_{exc.kind}' in UPLOAD_MESSAGES else None
        return {'code': 'refused_' + (reason or kind or 'other'), 'report': report, 'refusal': exc}
    finally:
        ports.docs.close()
    if result['task_added']:
        settings_file = local_settings.settings_path(ws.root)
        try:
            saved = local_settings.load(settings_file)
            saved['scanner']['task_ids'].append(report.task_id)
            local_settings.save(settings_file, saved)
        except (OSError, ValueError):
            return {'code': 'saved_failed', 'report': report, 'result': result}
    return {'code': 'imported', 'report': report, 'result': result}


def greenbone_upload(ws, preferences, environ, path, cycle, *, add_task=False, clock=None):
    """`greenbone upload FILE`: read the file (capped), then `upload_report`, then say what happened."""
    try:
        data = _read_capped(Path(path))
    except OSError as error:
        print(f'Could not read the file ({type(error).__name__}). Nothing was written.', file=sys.stderr)
        return 1
    if data is None:
        print(f'The report is larger than {MAX_REPORT_BYTES} bytes. It was not read. Nothing was written.',
              file=sys.stderr)
        return 1
    outcome = upload_report(ws, preferences, environ, data, cycle, add_task=add_task, clock=clock)
    code, report = outcome['code'], outcome.get('report')
    if code == 'parse_refused':
        print(f'The report was refused ({terminal_safe(outcome["detail"])}). Nothing was written.', file=sys.stderr)
    elif code == 'not_chosen':
        print(f'Task {terminal_safe(report.task_id)} is not chosen for this install. '
              'Re-run with --add-task to add it.', file=sys.stderr)
    elif code == 'bad_request':
        print('The report names a task id that is not a lowercase UUID. Nothing was written.', file=sys.stderr)
    elif code == 'too_many_tasks':
        print(f'At most {MAX_CHOSEN_TASKS} scan tasks can be chosen. Nothing was saved or imported.',
              file=sys.stderr)
    elif code.startswith('refused_'):
        exc = outcome['refusal']
        reason = f' ({exc.reason})' if exc.reason else ''
        print(f'Refused{reason}: {terminal_safe(exc, 200)} Nothing was written.', file=sys.stderr)
    elif code == 'saved_failed':
        print(f'Imported, but task {report.task_id} was not saved; add it in Settings.', file=sys.stderr)
    else:
        result = outcome['result']
        if result['task_added']:
            print(f'Adding task {terminal_safe(report.task_name) or "(unnamed)"} ({report.task_id}) to this install.')
        _print({'cycle': result['cycle'], 'scan_id': result['scan_id'], 'task_id': result['task_id'],
                'counts': result['counts'], 'newly_ingested': result['newly_ingested'],
                'newly_resolved': result['newly_resolved'], 'task_added': result['task_added']})
        return 0
    return 1


def page_upload(ws, config_path, environ):
    """The page's upload, bound to a workspace: `(bytes, add_task) -> closed code`, the same call the command makes."""
    def upload(data, add_task):
        outcome = upload_report(ws, local_settings.load(config_path), environ, data, next_cycle(ws), add_task=add_task)
        return outcome['code']
    return upload


def _uncached_cves(ws, cves):
    """The CVEs the workspace's NVD cache has no good entry for (a missing or errored one counts)."""
    try:
        cached = json.loads((workspace_cache_dir(ws.root) / 'nvd.json').read_text())
    except (OSError, ValueError):
        cached = {}
    cached = cached if isinstance(cached, dict) else {}
    return [c for c in cves if not (isinstance(cached.get(c), dict) and not cached[c].get('_error'))]


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
    # Every CVE in the imported reports that the NVD cache holds no good entry for: new findings
    # and earlier failed fetches alike. From the pull's result, never from all findings.
    wanted = _uncached_cves(ws, result.get('scan_cves') or [])
    if scanner['auto_enrichment'] and wanted:
        try:
            update_enrichment(ws, environ, cves=wanted, clock=clock)
        except Exception as exc:  # noqa: BLE001 - class only; the cycle still runs
            _log('greenbone_enrichment_failed', cycle_id, error=type(exc).__name__)


MAX_CHOSEN_TASKS = 500
UPLOAD_OVERHEAD = 64 * 1024  # multipart framing and the other two fields


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


TOO_MANY_TASKS = f'At most {MAX_CHOSEN_TASKS} scan tasks can be chosen. Nothing was saved.'


class SettingsRefused(ValueError):
    """A settings change refused with its own sentence (the message is shown as is)."""


def apply_settings_form(values, section, fields, *, running_port=None):
    """`values` (the saved settings) with one Settings section's form fields applied, validated
    as for saving. The Settings page and `settings set` both call this, so a value one refuses
    the other refuses too.

    `fields` are the section's form fields as the page posts them (strings; a ticked checkbox is
    'yes', an unticked one is absent). Raises SettingsRefused with the sentence to show,
    TooManyTasks, or ValueError for anything else. `running_port`: the port this server already
    holds on loopback, which makes a bind to the same port fail; then only the address is checked."""
    values = copy.deepcopy(values)
    if section == 'scanner':
        # A credential is never accepted, whatever the field is called or how it is cased.
        if any(k.lower() in {'username', 'password'} for k in fields) or not SCANNER_REQUIRED <= set(fields) <= SCANNER_FIELDS:
            raise ValueError()
        values['scanner'] = _scanner_values(fields, values)
    elif section == 'model' and set(fields) == {'same_family_policy'}:
        values['same_family_policy'] = fields['same_family_policy']  # jobs change through /connections
    elif section == 'model' and set(fields) == MODEL_FIELDS:
        for role in ROLES:
            endpoint, model = fields[role + '_endpoint'], fields[role + '_model']
            ca_file = fields[role + '_ca_file'].strip()
            if ca_file and (endpoint or model):
                try:
                    local_settings.check_ca_file(ca_file)
                except ValueError:
                    raise SettingsRefused(f'The {role} CA certificate file could not be read as a PEM '
                                          'certificate. Nothing was saved.') from None
            timeout = fields[role + '_timeout_seconds'].strip() or '60'
            if not (timeout.isascii() and timeout.isdigit()):
                raise ValueError()  # 5-600 is checked by local_settings on save
            if not (endpoint or model):
                values['roles'][role] = None  # its connection stays
                continue
            values['roles'][role] = {
                'connection': _connection_for(values, role, fields[role + '_format'], endpoint, model, ca_file),
                'model': model, 'family': fields[role + '_family'] or suggest_family(model),
                'timeout_seconds': int(timeout)}
        values['same_family_policy'] = fields['same_family_policy']
    elif section == 'application' and {'mode', 'port'} <= set(fields) <= APPLICATION_FIELDS:
        if fields.get('open_browser', 'yes') != 'yes':
            raise ValueError()
        try:
            port = int(fields['port'])
        except ValueError:
            raise ValueError() from None  # no message: int()'s own is not a sentence for a person
        values.update(mode=fields['mode'], port=port, open_browser='open_browser' in fields)
        if 'cycle_interval_minutes' in fields:
            # ASCII digits only; local_settings.validate checks 0-1440 on save.
            minutes = fields['cycle_interval_minutes']
            if not (minutes.isascii() and minutes.isdigit()):
                raise ValueError()
            values['cycle_interval_minutes'] = int(minutes)
        if 'listen_address' in fields:
            values['listen_address'] = fields['listen_address'].strip()
        if 'server_names' in fields:
            values['server_names'] = local_settings.parse_server_names(fields['server_names'])
        if 'certificate_mode' in fields:
            values['certificate'] = {'mode': fields['certificate_mode'], 'cert_file': fields.get('cert_file', '').strip(),
                                     'key_file': fields.get('key_file', '').strip()}
        values = local_settings.validate(values)
        try:
            if local_settings.exposed(values):
                same_port = values['port'] == running_port
                local_settings.check_bindable(values['listen_address'], 0 if same_port else values['port'])
            if values['certificate']['mode'] == 'own':
                local_settings.check_certificate(values['certificate']['cert_file'], values['certificate']['key_file'])
        except ValueError as refusal:
            raise SettingsRefused(f'{refusal}. Nothing was saved.') from None
    else:
        raise ValueError()
    return values


def _connection_for(values, role, format, endpoint, model, ca_file):
    """The id of the connection a job's call goes through: one with the same format, address and
    CA file (the job's own first), else a new one named for the job. Changes `values`."""
    if format not in FORMATS:
        raise ValueError('The local edition has no cloud model format' if format == 'vertex' else
                         'Unknown model format')
    base_url, style = split_endpoint(format, endpoint, model)
    current = (values['roles'][role] or {}).get('connection')
    order = sorted(values['connections'], key=lambda cid: cid != current)
    for cid in order:
        conn = values['connections'][cid]
        if (conn['format'], conn['base_url'], conn['endpoint_style'], conn['ca_file']) == (format, base_url, style, ca_file):
            return cid
    made = local_settings.new_connection(format, endpoint, model, ca_file, role)
    taken = {c['name'].casefold() for c in values['connections'].values()}
    name, number = made['name'], 2
    while name.casefold() in taken:
        name, number = f"{made['name']} {number}", number + 1
    cid = local_settings.new_connection_id()
    values['connections'][cid] = dict(made, name=name)
    return cid


def settings_form(values, section):
    """The form fields the Settings page shows for `section`, filled from `values`: what it
    posts when nothing is changed (a ticked checkbox is 'yes'; an unticked one is absent)."""
    if section == 'model':
        fields = {'same_family_policy': values['same_family_policy']}
        for role in ROLES:
            cfg = local_settings.role_settings(values, role) or {
                'format': 'openai_chat', 'endpoint': '', 'model': '', 'family': '', 'ca_file': '', 'timeout_seconds': 60}
            fields.update({f'{role}_{part}': str(cfg[part]) for part in
                           ('format', 'endpoint', 'model', 'family', 'ca_file', 'timeout_seconds')})
        return fields
    if section == 'scanner':
        cfg = values['scanner']
        fields = {name: str(cfg[name]) for name in ('transport', 'socket_path', 'host', 'port', 'ca_file', 'qod_floor')}
        fields['task_ids'] = '\n'.join(cfg['task_ids'])
        if cfg['auto_enrichment']:
            fields['auto_enrichment'] = 'yes'
        return fields
    if section == 'application':
        cert = values['certificate']
        fields = {'mode': values['mode'], 'port': str(values['port']),
                  'cycle_interval_minutes': str(values['cycle_interval_minutes']),
                  'listen_address': values['listen_address'], 'server_names': ', '.join(values['server_names']),
                  'certificate_mode': cert['mode'], 'cert_file': cert['cert_file'], 'key_file': cert['key_file']}
        if values['open_browser']:
            fields['open_browser'] = 'yes'
        return fields
    raise ValueError(section)


#: `settings set` field names that differ from the page's form names: nested values are dotted.
_CLI_FIELD_NAMES = {
    'application': {'certificate.mode': 'certificate_mode', 'certificate.cert_file': 'cert_file',
                    'certificate.key_file': 'key_file'},
    'model': {f'{role}.{part}': f'{role}_{part}' for role in ROLES
              for part in ('format', 'endpoint', 'model', 'family', 'ca_file', 'timeout_seconds')},
    'scanner': {},
}
_CLI_CHECKBOXES = {'application': 'open_browser', 'scanner': 'auto_enrichment'}
#: Changes that take effect only when serve starts again.
RESTART_FIELDS = ('listen_address', 'server_names', 'certificate')
SAVED = 'Saved.'
SAVED_RESTART = 'Saved. Restart Remediation Zero for listen address, names or certificate changes to take effect.'


class SettingsCommandRefused(Exception):
    """`settings set` was refused; the message is the one sentence printed."""


def settings_set(config_path, section, assignments, *, running_port=None):
    """Apply `FIELD=VALUE` assignments to one Settings section through the page's own validation
    (apply_settings_form) and save. Returns the sentence to print; SettingsCommandRefused otherwise.

    Field names are the page's, with nested values dotted (`certificate.mode`, `proposer.endpoint`);
    lists are comma-separated (`server_names`, `task_ids`); a checkbox takes true or false."""
    if section not in _CLI_FIELD_NAMES:
        raise SettingsCommandRefused('The section must be application, model or scanner. Nothing was saved.')
    saved = local_settings.load(config_path)
    fields = settings_form(saved, section)
    names = _CLI_FIELD_NAMES[section]
    checkbox = _CLI_CHECKBOXES.get(section)
    allowed = (set(fields) - set(names.values())) | set(names) | ({checkbox} if checkbox else set())
    for assignment in assignments:
        name, equals, value = assignment.partition('=')
        if not equals or name not in allowed:
            raise SettingsCommandRefused(f'{terminal_safe(name)} is not a field of the {section} section; '
                                         'write FIELD=VALUE. Nothing was saved.')
        if name == checkbox:
            if value.lower() not in {'true', 'false', 'yes', 'no'}:
                raise SettingsCommandRefused(f'{name} takes true or false. Nothing was saved.')
            fields.pop(name, None)
            if value.lower() in {'true', 'yes'}:
                fields[name] = 'yes'
            continue
        if name == 'task_ids':
            value = '\n'.join(part.strip() for part in value.split(','))
        fields[names.get(name, name)] = value
    if running_port is None:
        # A dashboard may be running on the saved port (on loopback), and a bind to that port would
        # then fail although the address is fine. As on the page, an unchanged port checks only the
        # address; serve says so in one sentence at start if the port really cannot be used.
        running_port = saved['port']
    try:
        values = apply_settings_form(saved, section, fields, running_port=running_port)
        local_settings.save(config_path, values)
    except SettingsRefused as refusal:
        raise SettingsCommandRefused(str(refusal)) from None
    except TooManyTasks:
        raise SettingsCommandRefused(TOO_MANY_TASKS) from None
    except (ValueError, TypeError, KeyError) as error:
        # local_settings' own sentences say what is wrong; a bare parse error does not.
        reason = str(error) if type(error) is ValueError and str(error) else 'A value is not valid'
        raise SettingsCommandRefused(f'{terminal_safe(reason, 200)}. Nothing was saved.') from None
    except OSError:
        raise SettingsCommandRefused('The settings could not be saved. Check local file permissions.') from None
    changed = any(values[name] != saved[name] for name in RESTART_FIELDS)
    return SAVED_RESTART if changed else SAVED


#: A field name that would hold a secret. No settings field does (API keys live in the environment
#: or the key file, scanner credentials in the environment); `settings show` masks any that ever
#: appears. A `*_file` field is a path to a file, not its contents, so it is shown, as is a
#: connection's `key_source` (where its key comes from: stored, environment or none).
_SECRET_NAME = re.compile(r'key|secret|password|token', re.I)
_NOT_SECRET = {'key_source'}


def settings_shown(config_path):
    """The saved settings as `settings show` prints them. Reads the settings file only, never the
    key file."""
    def masked(value):
        if isinstance(value, dict):
            return {k: '(hidden)' if _SECRET_NAME.search(k) and not k.endswith('_file') and k not in _NOT_SECRET
                    else masked(v)
                    for k, v in value.items()}
        if isinstance(value, list):
            return [masked(v) for v in value]
        return value
    return masked(local_settings.load(config_path))


_BCHARS = r"[0-9A-Za-z'()+_,\-./:=? ]"
_UPLOAD_TYPE = re.compile(r'multipart/form-data; ?boundary=(?:"(%s{1,70})"|(%s{1,70}))' % (_BCHARS, _BCHARS), re.I | re.A)
_UPLOAD_DISPOSITION = re.compile(rb'form-data; ?name="(token|report|add_task)"(; ?filename="[^"\r\n]*")?')
UPLOAD_HEADER_LIMIT = 1024
UPLOAD_TOKEN_LIMIT = 128


def _read_upload_form(content_type, body):
    """The fields of one multipart/form-data upload: `{'token': bytes, 'report': bytes, 'add_task': bool}`.

    A strict, non-recursive reader for exactly the form the dashboard sends, deliberately not the stdlib
    email parser (which accepts LF-only and CR-only line endings, folded headers, comments, nested
    multiparts, and boundary spellings this reader never reads differently). Anything else is a ValueError.
    The report is opaque bytes, never interpreted here; a nested multipart is just report bytes that
    then fail XML parsing."""
    match = _UPLOAD_TYPE.fullmatch(content_type)
    if match is None:
        raise ValueError('content type')
    boundary = (match.group(1) if match.group(1) is not None else match.group(2)).encode('ascii')
    if boundary.endswith(b' '):
        raise ValueError('boundary')
    delimiter = b'--' + boundary
    if body.count(delimiter) > 4:  # counted before anything is sliced: 3 parts and the close at most
        raise ValueError('too many parts')
    opening, closing = delimiter + b'\r\n', b'\r\n' + delimiter + b'--'
    if body.endswith(closing + b'\r\n'):
        body = body[:-2]
    if not (body.startswith(opening) and body.endswith(closing)) or len(body) < len(opening) + len(closing):
        raise ValueError('framing')
    parts = body[len(opening):-len(closing)].split(b'\r\n' + delimiter + b'\r\n')
    if not 2 <= len(parts) <= 3:
        raise ValueError('part count')
    found = {}
    for part in parts:
        head, split, content = part.partition(b'\r\n\r\n')
        if not split or len(head) > UPLOAD_HEADER_LIMIT or b'\0' in head:
            raise ValueError('header block')
        headers = {}
        for line in head.split(b'\r\n'):
            if line[:1] in (b' ', b'\t') or b'\r' in line or b'\n' in line:
                raise ValueError('folded header')
            name, colon, value = line.partition(b':')
            name = name.lower()
            if not colon or name not in (b'content-disposition', b'content-type') or name in headers:
                raise ValueError('header')
            headers[name] = value.strip(b' \t')
        shown = _UPLOAD_DISPOSITION.fullmatch(headers.get(b'content-disposition', b''))
        if shown is None:
            raise ValueError('disposition')
        name, filename = shown.group(1).decode(), shown.group(2)
        if name in found or (name == 'report') != (filename is not None):
            raise ValueError('field')
        if b'content-type' in headers and name != 'report':
            raise ValueError('header')
        found[name] = content
    if not {'token', 'report'} <= set(found) or len(found['token']) > UPLOAD_TOKEN_LIMIT:
        raise ValueError('fields')
    if 'add_task' in found and found['add_task'] != b'yes':
        raise ValueError('add_task')
    if len(found['report']) > MAX_REPORT_BYTES:
        raise ValueError('report size')
    return {'token': found['token'], 'report': found['report'], 'add_task': 'add_task' in found}


#: Each existing dashboard route and the one permission it needs (tools.access). The one
#: widening is /accounts/invite: a tech may post it while no owner has joined (_may_post), and
#: Accounts.invite then allows only an owner invite.
GET_ACTIONS = dict({view: 'view' for view in VIEWS}, settings='settings', accounts='manage_accounts')
POST_ACTIONS = {'/settings': 'settings', '/upload': 'upload', '/accounts/invite': 'manage_accounts',
                '/accounts/revoke': 'manage_accounts', '/accounts/role': 'manage_accounts',
                '/accounts/remove': 'manage_accounts', '/accounts/reset': 'manage_accounts',
                **{path: local_connections.ACTION for path in local_connections.PATHS}}
#: The fields each account form carries besides `token`: (required, optional). Anything else is a 400.
ACCOUNT_FORMS = {'/accounts/invite': ({'email'}, {'role'}), '/accounts/revoke': ({'invite'}, set()),
                 '/accounts/role': ({'account', 'role'}, set()), '/accounts/remove': ({'account'}, set()),
                 '/accounts/reset': ({'account', 'kind'}, set())}
#: An account id is 32 hex characters (tools.accounts); a listed link id is a rowid.
_ACCOUNT_ID = re.compile(r'[0-9a-f]{32}')
_INVITE_ID = re.compile(r'[1-9][0-9]{0,17}')
SETTINGS_BODY_LIMIT = 65536
#: One deadline for a whole POST body, plus a second per BODY_MIN_RATE bytes for a large upload.
BODY_SECONDS = 15
BODY_MIN_RATE = 256 * 1024
#: Body bytes that signed-in requests (settings, uploads, account forms) may hold at once, counted
#: as received: two full uploads. An upload's peak memory is about twice its size while the
#: buffer becomes bytes for the parser, then its parsed parts.
INFLIGHT_BODY_LIMIT = 2 * (MAX_REPORT_BYTES + UPLOAD_OVERHEAD)
#: Sign-in forms (no session yet) have their own budget, so neither kind can starve the other.
FORM_BUDGET_LIMIT = 64 * local_auth.FORM_LIMIT
BUSY_RETRY_SECONDS = 5


class _BodyBudget:
    """A thread-safe count of request-body bytes being held; `take` refuses past the limit."""

    def __init__(self, limit):
        self.limit = limit
        self.held = 0
        self._lock = threading.Lock()

    def take(self, size):
        with self._lock:
            if self.held + size > self.limit:
                return False
            self.held += size
            return True

    def give(self, size):
        with self._lock:
            self.held -= size


def handler(store, demo, config_path=None, approve_command=None, upload=None, records=None,
            public_origin=None, *, accounts, settings_exposed=False, server_names=(), scheme='http',
            limiter=None, workspace_root=None, hsts=False, connection_limiter=None):
    # records: returns 'saved' or 'synthetic' for the page banner; None keeps 'synthetic'.
    # public_origin: from public_origin(); the one name an HTTPS proxy in front may forward.
    # accounts: tools.accounts.Accounts on the workspace's accounts file, opened by serve
    # (never by an agent stage). Every page and form needs a session from it, and the
    # signed-in role must be allowed the route's action; see scripts/local_auth.py for how
    # each request is classified (local, proxied, direct) and what that changes.
    # settings_exposed: the saved listen address is a network one, so no request is local.
    # server_names, scheme: the names a 'direct' request may use, over the TLS listener ('https').
    # workspace_root: where serve keeps the self-signed certificate, for the Settings fingerprint.
    # hsts: send Strict-Transport-Security on every response (the TLS listener with your own
    # certificate only; see build_server for why not with the self-signed one).
    # connection_limiter: for the /connections/* routes that call a provider (default 6 a minute).
    public_host = public_origin.split('://', 1)[1] if public_origin else None
    limiter = limiter if limiter is not None else RateLimiter()
    auth = local_auth.AuthRoutes(accounts, limiter)
    # Two budgets per server (serve runs one server per process): sign-in forms, and bodies of
    # requests already authorised. At most one upload per session is in flight.
    form_budget = _BodyBudget(FORM_BUDGET_LIMIT)
    body_budget = _BodyBudget(INFLIGHT_BODY_LIMIT)
    # At most one upload, and one /connections/* request, per session in flight (in memory only).
    uploading, connecting, uploading_lock = set(), set(), threading.Lock()
    server_names = tuple(server_names)
    # Connections are threaded; requests are not. The scanner probe's deadline and the
    # settings read-modify-write both assume one request at a time.
    serial = threading.Lock()
    # The Models page's JSON routes take `serial` themselves, and never across a model call.
    connection_routes = (local_connections.ConnectionRoutes(accounts, config_path, serial, limiter, log=_log,
                                                            limiter=connection_limiter)
                         if config_path else None)

    class DashboardHandler(BaseHTTPRequestHandler):
        timeout = IDLE_TIMEOUT

        def log_message(self, *args):
            pass  # Never record request lines or headers: invite tokens are in paths.

        def setup(self):
            super().setup()
            # The request line and headers are read under one deadline (HEADER_SECONDS),
            # not just a per-read timeout; see _DeadlineReader and DashboardServer.
            self._reader = _DeadlineReader(self.connection, self.timeout)
            self.rfile = io.BufferedReader(self._reader)

        def end_headers(self):
            if hsts:
                self.send_header('Strict-Transport-Security', HSTS_VALUE)
            super().end_headers()

        def handle_one_request(self):
            first = getattr(self.server, 'connection_deadline', lambda: None)()
            self._reader.deadline = first if first is not None else time.monotonic() + HEADER_SECONDS
            try:
                super().handle_one_request()
            finally:
                self._reader.deadline = None

        def parse_request(self):
            ok = super().parse_request()
            # The headers are in: from here the body's own deadline (_read_body) applies.
            self._reader.deadline = None
            self.connection.settimeout(self.timeout)
            return ok

        # `serial` is held only for the work on records, settings and imports. Classifying a
        # request, reading its body (under BODY_SECONDS) and the sign-in pages (scrypt, and the
        # accounts file, whose writes AccountStore serialises with BEGIN IMMEDIATE) all run
        # outside it, so a slow client or a slow password check never stops anyone else.

        def do_GET(self):
            self._guarded(self._route_get)

        def do_POST(self):
            self._guarded(self._route_post)

        def _route_get(self):
            parsed = urlsplit(self.path)
            if auth.handles(parsed.path):
                req = self._request()
                if req is not None:
                    auth.get(self, req, parsed.path, parsed.query)
                return
            with serial:
                req = self._request()  # the session is read under the lock, just before it is used
                if req is not None:
                    self._get(req, parsed)

        def _route_post(self):
            parsed = urlsplit(self.path)
            req = self._request(session=False)
            if req is None:
                return
            # The Origin must be the scheme and Host this request came in on (local_auth.classify).
            if (self.headers.get('Origin') != req.origin
                    or self.headers.get('Sec-Fetch-Site') not in {None, 'same-origin'}):
                self.send_error(403)
                return
            path = parsed.path
            if auth.handles(path):
                # Sign-in forms work without a session, so they are small: FORM_LIMIT at most.
                try:
                    if self._read_body(local_auth.FORM_LIMIT, form_budget):
                        req = self._request()
                        if req is not None:
                            auth.post(self, req, path, parsed.query)
                finally:
                    self._release_body()
                return
            # Every other POST is authorised before a byte of its body is read: no session, no
            # permission, or a route that is not there is refused on its headers alone.
            req = self._request()
            if req is None or self._refuse_post(req, path):
                return
            connection = path in local_connections.PATHS
            limit = (MAX_REPORT_BYTES + UPLOAD_OVERHEAD if path == '/upload' else
                     SETTINGS_BODY_LIMIT if path == '/settings' else
                     local_auth.FORM_LIMIT if path.startswith('/accounts/') or connection else 0)
            slot = None
            held = uploading if path == '/upload' else connecting if connection else None
            if held is not None:
                slot = req.session.csrf             # one per session; in memory only
                with uploading_lock:
                    busy = slot in held
                    if not busy:
                        held.add(slot)
                if busy:
                    slot = None
                    self._busy(409)
                    return
            try:
                if not self._read_body(limit, body_budget):
                    return
                if connection:
                    # Not under `serial`: a model list or test can take minutes, and the
                    # routes take the lock only for the settings work around it.
                    req = self._request()
                    if req is not None:
                        connection_routes.post(self, req, path)
                    return
                with serial:
                    req = self._request()  # read again under the lock, just before it is used
                    if req is not None:
                        self._post(req, path)
            finally:
                self._release_body()
                if slot is not None:
                    with uploading_lock:
                        held.discard(slot)

        def _guarded(self, route):
            """A read or write the server cannot complete is a 503, never a dropped connection.
            Only the error class is logged: never a path, header, password, code or token."""
            self._responded = False
            try:
                route()
            except Exception as error:
                _log('request_failed', error=type(error).__name__)
                if getattr(self, '_responded', False):
                    self.close_connection = True
                else:
                    self.send_error(503, 'This could not be checked or completed. Try again.')

        def send_response(self, code, message=None):
            self._responded = True
            super().send_response(code, message)

        def _refuse_post(self, req, path):
            """Answer and return True when a dashboard POST may not proceed; nothing is read.
            The same checks run again in _post, under `serial`."""
            action = POST_ACTIONS.get(path)
            if action is None:
                self.send_error(404)
                return True
            session = req.session
            if (session is None or not config_path or (path == '/upload' and not upload)
                    or not self._may_post(session, path, action)):
                self.send_error(403)
                return True
            return False

        def _busy(self, status):
            """Refuse before reading the body, asking the client to try again shortly."""
            self.close_connection = True
            self.send_response(status)
            self.send_header('Retry-After', str(BUSY_RETRY_SECONDS))
            self.send_header('Content-Length', '0')
            self.send_header('Connection', 'close')
            self.end_headers()

        @property
        def body_file(self):
            """The body as a file, for the small forms (sign-in forms are at most FORM_LIMIT)."""
            return io.BytesIO(self.body)

        def _read_body(self, limit, budget):
            """Read a POST body before `serial` is taken, under one deadline for the whole body
            (per-recv timeouts alone let a client trickle a byte at a time for hours), into one
            preallocated buffer counted against `budget` until _release_body. A body with no
            usable Content-Length, or larger than `limit`, is not read: the route then refuses it
            on its headers. False after answering 408, or 503 when the budget is spent."""
            length = self.headers.get('Content-Length')
            self.body = b''
            self._held = (None, 0)
            if (length is None or not (length.isascii() and length.isdigit()) or self.headers.get('Transfer-Encoding')
                    or not 0 < int(length) <= limit):
                return True
            size = int(length)
            if not budget.take(size):
                self._busy(503)
                return False
            self._held = (budget, size)
            deadline = time.monotonic() + BODY_SECONDS + size / BODY_MIN_RATE
            sock = getattr(self, 'connection', None)
            buffer = bytearray(size)
            view = memoryview(buffer)
            got = 0
            try:
                while got < size:
                    if sock is not None:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError()
                        sock.settimeout(remaining)
                    count = self.rfile.readinto1(view[got:])
                    if not count:
                        break
                    got += count
            except (TimeoutError, OSError):
                self.close_connection = True
                if sock is not None:
                    sock.settimeout(self.timeout)
                self.send_error(408, 'The request body did not arrive in time.')
                return False
            finally:
                view.release()
            if sock is not None:
                sock.settimeout(self.timeout)
            del buffer[got:]                       # a short body stays short; the route refuses it
            self.body = buffer                     # no copy: the routes read it in place
            return True

        def _take_body(self):
            """The body as bytes for a parser, dropping the buffer so only one copy stays."""
            body, self.body = bytes(self.body), b''
            return body

        def _release_body(self):
            budget, size = getattr(self, '_held', (None, 0))
            if budget is not None:
                budget.give(size)
            self._held = (None, 0)
            self.body = b''

        def _request(self, session=True):
            """Classify the request and resolve its session; None after refusing it with 403."""
            peer = (getattr(self, 'client_address', None) or ('',))[0]
            found = local_auth.classify(peer, self.headers.get('Host'), port=self.server.server_port,
                                        public_host=public_host, exposed=settings_exposed,
                                        server_names=server_names, scheme=scheme)
            if found is None:
                self.send_error(403)
                return None
            kind, origin = found
            cookies = local_auth.read_cookies(self.headers.get('Cookie'))
            token = cookies.get(local_auth.SESSION_COOKIE) or None
            get_all = getattr(self.headers, 'get_all', None)
            forwarded = get_all('X-Forwarded-For') if get_all else (
                [self.headers['X-Forwarded-For']] if self.headers.get('X-Forwarded-For') else None)
            # An unreadable accounts file raises here, and _guarded answers 503: unknown, never
            # signed out or in.
            live = accounts.session(token) if session and token else None
            return local_auth.Request(kind, origin, local_auth.client_address(kind, peer, forwarded), token,
                                      live, cookies)

        def send_page(self, body, status, headers=()):
            self._send_html(body, status, headers)

        def redirect(self, location, headers=()):
            self.send_response(303)
            self.send_header('Location', location)
            self.send_header('Cache-Control', 'no-store')
            for name, value in headers:
                self.send_header(name, value)
            self.send_header('Content-Length', '0')
            self.end_headers()

        def _get(self, req, parsed):
            query = parse_qs(parsed.query)
            view = query.get('view', ['overview'])[0]
            section = query.get('section', ['model'])[0]
            if (parsed.path != '/' or view not in GET_ACTIONS or (view == 'settings' and not config_path)
                    or (view == 'settings' and section not in SECTIONS)):
                self.send_error(404)
                return
            if req.session is None and auth.no_accounts():
                if req.kind == 'local':
                    self.redirect('/setup')
                else:
                    self.send_page(account_views.first_account_page(local_auth.SETUP_COMMAND), 200)
                return
            session = req.session
            if session is None:
                self.redirect('/signin')
                return
            if not access.allowed(session.role, GET_ACTIONS[view]):
                self.send_error(403)
                return
            if view == 'accounts':
                self._send_html(self._accounts_html(session), 200)
                return
            self.csrf = session.csrf
            owner_missing = not accounts.owner_exists()
            account = self._account(session, owner_missing)
            try:
                settings_html = None
                chosen = None
                if config_path:
                    saved = local_settings.load(config_path)
                    chosen = saved['scanner']['task_ids']
                    # Only the Settings view shows it (others need only its nav link), so only that view
                    # reads the key file and builds the Models data.
                    settings_html = self._settings_html(saved, section if section in SECTIONS else 'model',
                        message='Preferences saved. No model calls were made.' if query.get('saved') == ['1'] else '',
                        scanner=scanner_probe(saved) if view == 'settings' and section == 'scanner' else None,
                        session=session) if view == 'settings' else ''
                body = render(demo_snapshot() if demo else store.snapshot(), view, demo=demo, settings_html=settings_html,
                              approve_command=None if demo else approve_command,
                              upload_token=session.csrf if upload and not demo else None,
                              upload_code=query.get('upload', [None])[0],
                              chosen_tasks=chosen, records=records() if records and not demo else 'synthetic',
                              account=account, owner_missing=owner_missing)
                status = 200
            except Exception:
                body, status = render({}, view, unavailable=True, settings_html="" if config_path else None,
                                      account=account), 503
            # Settings -> Models, for an owner, is the one page that runs a script: its popup.
            scripted = (status == 200 and view == 'settings' and section == 'model'
                        and access.allowed(session.role, local_connections.ACTION))
            self._send_html(body, status, script_hash=SCRIPT_HASH if scripted else None)

        def _may_post(self, session, path, action):
            if path == '/accounts/invite':
                # An owner may invite; a tech only an owner, and only while no owner has joined.
                return (access.allowed(session.role, action)
                        or access.may_invite(session.role, 'owner', accounts.owner_exists()))
            return access.allowed(session.role, action)

        @staticmethod
        def _account(session, owner_missing):
            """The signed-in header's values for render(), with the two flags it may show."""
            return {'email': session.email, 'role': session.role, 'token': session.csrf,
                    'manage_accounts': access.allowed(session.role, 'manage_accounts'),
                    'invite_owner': (not access.allowed(session.role, 'manage_accounts')
                                     and access.may_invite(session.role, 'owner', not owner_missing))}

        def _accounts_html(self, session, message=''):
            # GET_ACTIONS already required manage_accounts; the audit trail needs view_audit too.
            overview = accounts.overview(200)
            if not access.allowed(session.role, 'view_audit'):
                overview = dict(overview, events=[])
            return account_views.accounts_page(overview, session.csrf, email=session.email, message=message)

        def _account_form(self, path):
            """The body of an account form as one value per field; ValueError if it is not one."""
            length = self.headers.get('Content-Length')
            if (length is None or not (length.isascii() and length.isdigit())
                    or not 0 < int(length) <= local_auth.FORM_LIMIT or self.headers.get('Transfer-Encoding')
                    or self.headers.get('Content-Type') != 'application/x-www-form-urlencoded'):
                raise ValueError()
            raw = self._take_body()
            if len(raw) != int(length):
                raise ValueError()
            fields = parse_qs(raw.decode('utf-8'), keep_blank_values=True, strict_parsing=True,
                              max_num_fields=local_auth.FORM_FIELDS)
            if any(len(v) != 1 for v in fields.values()):
                raise ValueError()
            fields = {k: v[0] for k, v in fields.items()}
            required, optional = ACCOUNT_FORMS[path]
            if not required | {'token'} <= set(fields) <= required | optional | {'token'}:
                raise ValueError()
            return fields

        def _accounts_post(self, req, session, path):
            """POST /accounts/*, under `serial`, after the route's permission was checked. The form
            token, then a recent re-confirm, then Accounts itself, which is the authority on who
            may do what. A link is shown once, on this response, and never logged."""
            manager = access.allowed(session.role, 'manage_accounts')
            back = '/?view=accounts' if manager else '/'
            try:
                fields = self._account_form(path)
            except (ValueError, UnicodeError):
                self.send_error(400, account_views.INVALID_FORM)
                return
            if not secrets.compare_digest(fields.pop('token').encode(), session.csrf.encode()):
                self.send_error(403)
                return
            if not session.confirmed:
                # Nothing is done; after re-confirm the person comes back and submits again.
                self.redirect(local_auth.confirm_location(back))
                return
            by = dict(via='dashboard', source=req.client)
            link = kind = None
            try:
                if path == '/accounts/invite':
                    # The installing tech's form sends no role: theirs is fixed to owner here, and
                    # Accounts.invite refuses anything else from a tech.
                    role = fields.get('role', None if manager else 'owner')
                    if role is None:
                        raise ValueError()
                    link, kind = accounts.invite(session.account_id, fields['email'], role, **by), 'join'
                elif path == '/accounts/reset':
                    if not _ACCOUNT_ID.fullmatch(fields['account']) or fields['kind'] not in RESET_KINDS:
                        raise ValueError()
                    kind = fields['kind']
                    link = accounts.reset_link(session.account_id, fields['account'], kind, **by)
                elif path == '/accounts/revoke':
                    if not _INVITE_ID.fullmatch(fields['invite']):
                        raise ValueError()
                    accounts.revoke_listed_invite(session.account_id, int(fields['invite']), **by)
                elif not _ACCOUNT_ID.fullmatch(fields['account']):
                    raise ValueError()
                elif path == '/accounts/role':
                    accounts.set_role(session.account_id, fields['account'], fields['role'], **by)
                else:
                    accounts.remove(session.account_id, fields['account'], **by)
            except AccountRefused as refusal:
                message = account_views.refusal_sentence(refusal.code)
                status = 403 if refusal.code == 'not_allowed' else 400
                # The page is drawn for the account as it is now: a refusal may follow a change.
                now = accounts.session(req.token)
                if now is not None and access.allowed(now.role, 'manage_accounts'):
                    self._send_html(self._accounts_html(now, message), status)
                else:
                    self._send_html(account_views.refusal_page(message, back), status)
                return
            except ValueError:
                self.send_error(400, account_views.INVALID_FORM)
                return
            if link is not None:
                self._send_html(account_views.link_page(f'{req.origin}/invite/{link}', kind, back), 200)
                return
            self.redirect('/?view=accounts')

        def _settings_html(self, values, section, *, message='', scanner=None, session=None):
            return render_settings(values, section, self.csrf, message=message,
                                   fingerprint=_certificate_fingerprint(values, workspace_root),
                                   models=self._models(values, session) if section == 'model' else None,
                                   scanner=scanner)

        @staticmethod
        def _models(values, session):
            """What the Models section shows: never a key, only its last characters (rows).
            The SimClock's real_ts only words "Tested n min ago"; it is never stored."""
            keys = SecretsFile(local_connections.secrets_beside(config_path))
            return {'rows': connections.rows(values, os.environ, keys, now_real_ts=accounts.clock.now().real_ts),
                    'coverage': connections.coverage(values, os.environ),
                    'owner': session is not None and access.allowed(session.role, local_connections.ACTION),
                    'confirmed': bool(session is not None and session.confirmed),
                    'deletions': {cid: connections.deletion_consequences(values, cid) for cid in values['connections']}}

        def _send_html(self, body, status, headers=(), script_hash=None):
            encoded = body.encode()
            self.send_response(status)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(encoded)))
            self.send_header('Cache-Control', 'no-store')
            # Inline <svg> (the QR code) is markup, not a loaded image: img-src is unchanged.
            # `script_hash` (the Models page, for an owner only) allows that one inline script, and
            # its requests to this server; every other page runs no script at all.
            scripted = f"script-src '{script_hash}'; connect-src 'self'; " if script_hash else ''
            self.send_header('Content-Security-Policy', f"default-src 'none'; {scripted}img-src data:; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.send_header('X-Content-Type-Options', 'nosniff')
            # Not no-referrer: under it a browser sends "Origin: null" on this page's own form
            # posts, which do_POST refuses. same-origin still sends nothing to other sites,
            # so an invite token in this page's URL never leaves in a Referer.
            self.send_header('Referrer-Policy', 'same-origin')
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(encoded)
        def _upload(self, session):
            """POST /upload. Host, Origin, Sec-Fetch-Site, the session and its role were checked before
            this; the session's form token is in the body, so it is checked after parsing and before
            anything is imported, and then the session must be re-confirmed. Nothing from the request
            or the report reaches the redirect: only a code from a closed set."""
            try:
                length = self.headers.get('Content-Length')
                if length is None or not (length.isascii() and length.isdigit()) or self.headers.get('Transfer-Encoding'):
                    self.send_error(400, 'Content-Length is required.')
                    return
                length = int(length)
                if length > MAX_REPORT_BYTES + UPLOAD_OVERHEAD:
                    self.send_error(413, 'The upload is too large. Nothing was read.')
                    return
                content_type = self.headers.get('Content-Type') or ''
                if not 0 < length:
                    raise ValueError()
                body = self._take_body()
                if len(body) != length:
                    raise ValueError()
                form = _read_upload_form(content_type, body)
                supplied, data, add_task = form['token'], form['report'], form['add_task']
            except Exception as error:  # a 400, never a traceback
                if not isinstance(error, (ValueError, UnicodeError, OSError, LookupError)):
                    _log('upload_parse_failed', error=type(error).__name__)
                self.send_error(400, 'Invalid upload. Nothing was imported.')
                return
            if not secrets.compare_digest(supplied, session.csrf.encode()):
                self.send_error(403)
                return
            if not session.confirmed:
                self.redirect(local_auth.confirm_location('/?view=infrastructure'))
                return
            if not data or len(data) > MAX_REPORT_BYTES:
                code = 'refused_too_large' if data else 'bad_request'
            else:
                try:
                    code = upload(data, add_task)
                except Exception as error:  # class only; the page says the upload was not accepted
                    _log('upload_failed', error=type(error).__name__)
                    code = 'bad_request'
            self.send_response(303)
            self.send_header('Location', f'/?view=infrastructure&upload={code}')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', '0')
            self.end_headers()

        def _post(self, req, path):
            """A dashboard POST, under `serial`. Origin, Sec-Fetch-Site and the body were handled
            in _route_post; `path` is the parsed path."""
            action = POST_ACTIONS.get(path)
            session = req.session
            if action is None:
                self.send_error(404)
                return
            if (session is None or not config_path or (path == '/upload' and not upload)
                    or not self._may_post(session, path, action)):
                self.send_error(403)
                return
            if path in ACCOUNT_FORMS:
                self._accounts_post(req, session, path)
                return
            if path == '/upload':
                self._upload(session)
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if (not 0 < length <= SETTINGS_BODY_LIMIT or self.headers.get('Transfer-Encoding')
                        or self.headers.get('Content-Type') != 'application/x-www-form-urlencoded'):
                    raise ValueError()
                raw = self._take_body()
                if len(raw) != length:
                    raise ValueError()
                raw = raw.decode('utf-8')
                # Only the Scanner form repeats a field (one task_ids per ticked task) and may be longer.
                scanner_form = 'section=scanner' in raw.split('&')
                if length > 8192 and not scanner_form:
                    raise ValueError()
                fields = parse_qs(raw, keep_blank_values=True, strict_parsing=True, max_num_fields=1100 if scanner_form else 40)
                if any(len(v) != 1 for k, v in fields.items() if not (scanner_form and k == 'task_ids')):
                    raise ValueError()
                fields = {k: '\n'.join(v) if k == 'task_ids' else v[0] for k, v in fields.items()}
                if not secrets.compare_digest(fields.pop('token', '').encode(), session.csrf.encode()):
                    self.send_error(403)
                    return
                self.csrf = session.csrf
                section = fields.pop('section', '')
                if section == 'model' and set(fields) != {'same_family_policy'}:
                    # The page posts the same-family policy only. Jobs and models change through the
                    # owner-only /connections/* routes; the per-role fields stay for `settings set`.
                    raise ValueError()
                values = local_settings.load(config_path)
                if section == 'scanner_test' and not fields:
                    # Tests the saved settings. Never saves, so nothing below runs and no re-confirm is asked.
                    self._send_html(render(demo_snapshot() if demo else store.snapshot(), 'settings', demo=demo,
                                           settings_html=self._settings_html(values, 'scanner', scanner=scanner_probe(values, test=True)),
                                           approve_command=None if demo else approve_command,
                                           records=records() if records and not demo else 'synthetic',
                                           account=self._account(session, not accounts.owner_exists()),
                                           owner_missing=not accounts.owner_exists()), 200)
                    return
                if not session.confirmed:
                    # A save needs a recent re-confirm. Nothing is saved; the person comes back to this section.
                    shown = section if section in SECTIONS else 'model'
                    self.redirect(local_auth.confirm_location(f'/?view=settings&section={shown}'))
                    return
                values = apply_settings_form(values, section, fields,
                                             running_port=getattr(self.server, 'server_port', None))
                local_settings.save(config_path, values)
            except SettingsRefused as refusal:
                self.send_error(400, str(refusal))
                return
            except TooManyTasks:
                self.send_error(400, TOO_MANY_TASKS)
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


#: The first line `serve` prints. The launcher and the install check match on it.
DEMO_BANNER = 'Local synthetic preview: '
SAVED_BANNER = 'Local dashboard: '


_PUBLIC_HOST_RE = local_settings.PUBLIC_HOST_RE  # one host rule, shared with the server names setting
PUBLIC_URL_RULE = 'an https:// address with a host name and an optional port, and nothing after it'
PROXY_SIGN_IN = 'Every page there asks for sign-in; the first account is created on the server itself.'


def public_origin(url):
    """The origin a browser uses for `url`, the address of an HTTPS proxy in front (Tailscale
    Serve, nginx, Caddy): `https://host[:port]`, lower case, with :443 dropped as browsers drop it.

    The server itself still listens only on 127.0.0.1; this only names the one extra Host the
    proxy forwards, so the DNS-rebinding check stays a closed list.
    """
    parts = urlsplit(url.strip())
    port = parts.port  # ValueError for a non-number or out of range
    host = (parts.hostname or '')
    if (parts.scheme != 'https' or parts.path not in ('', '/') or parts.query or parts.fragment
            or parts.username is not None or parts.password is not None or port == 0
            or not _PUBLIC_HOST_RE.fullmatch(host) or parts.netloc.lower().rstrip(':') not in (
                host, f'{host}:{port}')):
        raise ValueError(f'The public URL must be {PUBLIC_URL_RULE}.')
    return f'https://{host}' if port in (None, 443) else f'https://{host}:{port}'


def _certificate_fingerprint(values, workspace_root):
    """The fingerprint of the certificate that would be served, or None if there is none yet.
    The self-signed one is in the workspace, where serve makes it."""
    cert = values['certificate']
    if cert['mode'] == 'own':
        path = cert['cert_file']
    elif workspace_root is not None:
        path = Path(workspace_root) / server_tls.CERT_NAME
    else:
        return None
    try:
        return server_tls.fingerprint(path)
    except (OSError, ValueError):
        return None


class ServeRefused(Exception):
    """serve cannot start; the message is the one sentence printed."""


NO_SERVER_NAME = ('No server name is set, so a certificate cannot be made. Set the names people use to reach '
                  'this server: settings set application server_names=NAME')
NO_SERVER_NAME_OWN = ('No server name is set, so the server would refuse every name people use to reach it. '
                      'Set them: settings set application server_names=NAME')
NO_OPENSSL = ('No openssl command was found, so a certificate cannot be made. Set your own certificate '
              '(settings set application certificate.mode=own …) or use a proxy.')
FINGERPRINT_LINE = 'Certificate fingerprint (SHA-256): '
#: The banner's second line on a network listener: every name and address it answers to.
ANSWERS_TO = 'Answers to: '
NO_ACCOUNTS_LINE = 'No accounts yet. Create the first one on this server: '


def _machine_addresses():
    """This machine's own addresses, as its host name resolves: never loopback or unspecified,
    never one with an IPv6 scope ID (a browser cannot use it in a URL), each once."""
    try:
        found = socket.getaddrinfo(socket.gethostname(), None)
    except (OSError, UnicodeError, ValueError):
        return []
    addresses = []
    for *_, sockaddr in found:
        text = str(sockaddr[0])
        if '%' in text:
            continue
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            continue
        if address.is_loopback or address.is_unspecified or str(address) in addresses:
            continue
        addresses.append(str(address))
    return addresses


def default_server_names(settings):
    """The names a network listener answers to and its certificate carries, and the banner's
    `Answers to:` line: the saved server_names, or else this machine's host name (when it is a
    valid one) and then the listen address when it is a specific IP, or, for 0.0.0.0 or ::,
    this machine's own addresses (`_machine_addresses`), so typing the server's IP works.
    Possibly empty."""
    names = list(settings['server_names'])
    if names:
        return names
    try:
        names.append(local_settings.normalize_server_name(socket.gethostname()))
    except (ValueError, OSError):
        pass
    address = ipaddress.ip_address(settings['listen_address'])
    for name in (_machine_addresses() if address.is_unspecified else [str(address)]):
        if name not in names:
            names.append(name)
    return names


def _host_port(host, port):
    return f'[{host}]:{port}' if ':' in host else f'{host}:{port}'


def bind_refusal(address, port, error):
    """The one sentence for a listener that could not bind."""
    reasons = {errno.EADDRINUSE: 'the port is already in use',
               errno.EADDRNOTAVAIL: "that address is not one of this machine's",
               errno.EACCES: 'permission was refused'}
    reason = reasons.get(getattr(error, 'errno', None), f'the system refused ({type(error).__name__})')
    return f'This machine cannot listen on {_host_port(address, port)}: {reason}.'


def _tls_context(ws, settings, names):
    """(context, certificate path) for the network listener; ServeRefused with one sentence."""
    cert = settings['certificate']
    if cert['mode'] == 'own':
        if not names:
            raise ServeRefused(NO_SERVER_NAME_OWN)
        cert_file, key_file = cert['cert_file'], cert['key_file']
        try:
            server_tls.fingerprint(cert_file)
        except (OSError, ValueError):
            raise ServeRefused(f'Your certificate file {cert_file} could not be read as a PEM certificate.') from None
        try:
            return server_tls.server_context(cert_file, key_file), cert_file
        except (ssl.SSLError, OSError, ValueError):
            # The key's contents are never part of the message, only its path.
            raise ServeRefused(f'Your key file {key_file} could not be loaded, or it does not match the '
                               f'certificate {cert_file}.') from None
    if not names:
        raise ServeRefused(NO_SERVER_NAME)
    # The self-signed pair is ours: one that will not load (a corrupt file, or a key and
    # certificate changed apart) is made again once; if that does not help, both files are named.
    for renew in (False, True):
        try:
            cert_path, key_path = server_tls.ensure_self_signed(ws.root, names, renew=renew)
        except server_tls.NoOpenssl:
            raise ServeRefused(NO_OPENSSL) from None
        except RuntimeError as error:  # openssl failed; the message names its error class only
            raise ServeRefused(f'{error}. Set your own certificate (settings set application '
                               'certificate.mode=own …) or use a proxy.') from None
        try:
            return server_tls.server_context(cert_path, key_path), cert_path
        except (ssl.SSLError, OSError, ValueError):
            pass
    raise ServeRefused(f'The certificate {cert_path} and key {key_path} in the workspace could not be loaded, '
                       'even after making them again. Set your own certificate (settings set application '
                       'certificate.mode=own …) or use a proxy.')


def build_server(ws, preferences, config_path, *, demo=False, public_url=None, port=None, clock=None):
    """(server, banner lines) for `serve`; ServeRefused, before anything listens, when it cannot start.

    Loopback settings (the default): plain HTTP on 127.0.0.1, as before. A network listen
    address: TLS only, with the self-signed certificate (made or renewed in the workspace) or
    your own, and the request kinds of scripts/local_auth.py's 'direct' over https."""
    exposed = local_settings.exposed(preferences)
    port = preferences['port'] if port is None else port
    command = f'python3 -S -m scripts.local --database {shlex.quote(str(ws.root.resolve()))}'
    # Everything that can fail is read before anything listens, so a refusal is one sentence
    # and never leaves a socket open. The accounts file is opened here, by the dashboard server,
    # and by the account commands; never through docs_for, so no agent stage can reach it.
    try:
        accounts = Accounts(AccountStore(ws.accounts_path()), clock or SimClock.from_env())
        no_accounts = accounts.store.count_accounts() == 0
    except (sqlite3.Error, OSError):
        raise ServeRefused(ACCOUNTS_UNREADABLE) from None
    if exposed:
        names = default_server_names(preferences)
        context, cert_path = _tls_context(ws, preferences, names)
        address = preferences['listen_address']
        try:
            fingerprint = server_tls.fingerprint(cert_path)
        except (OSError, ValueError):
            raise ServeRefused(f'The certificate file {cert_path} could not be read as a PEM certificate.') from None
    else:
        names, context, cert_path, address = list(preferences['server_names']), None, None, '127.0.0.1'
    docs = ws.docs_for('dashboard')  # reads only: no collection is writable
    upload = None if demo else page_upload(ws, config_path, os.environ)
    view = _View(docs)
    # HSTS only with your own certificate. Deviation from the web baseline for the self-signed
    # one: a browser that has seen HSTS refuses the certificate warning's click-through, so the
    # self-signed install (checked by its printed fingerprint) would lock everyone out at the
    # first renewal or name change. Loopback is plain HTTP and never sends it.
    hsts = exposed and preferences['certificate']['mode'] == 'own'
    handler_class = handler(view, demo, config_path, command, upload, records=view.records,
                            public_origin=public_url, accounts=accounts, settings_exposed=exposed,
                            server_names=tuple(names), scheme='https' if exposed else 'http',
                            workspace_root=ws.root, hsts=hsts)
    try:
        server = DashboardServer((address, port), handler_class, tls_context=context)
    except OSError as error:
        docs.close()
        raise ServeRefused(bind_refusal(address, port, error)) from None
    if not exposed:
        lines = [serve_banner(demo, server.server_port)]
    else:
        lines = [f'{DEMO_BANNER if demo else SAVED_BANNER}https://{_host_port(names[0], server.server_port)}/',
                 ANSWERS_TO + ', '.join(names), FINGERPRINT_LINE + fingerprint]
    # Setup is offered in the browser only to a local visit (loopback, no proxy); otherwise
    # the first account is made with this command, on the server.
    if no_accounts and (exposed or public_url):
        lines.append(f'{NO_ACCOUNTS_LINE}{command} account setup')
    return server, lines


def serve_banner(demo, port):
    """"Local synthetic preview" only when serving demo fixtures; saved records are not synthetic."""
    return f'{DEMO_BANNER if demo else SAVED_BANNER}http://127.0.0.1:{port}'


def _public_url(value):
    try:
        return public_origin(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f'use {PUBLIC_URL_RULE}') from None


def _cycle(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError('a cycle number is 0 or more')
    return number


class _Parser(argparse.ArgumentParser):
    """argparse echoes unrecognised arguments and rejected values in its errors; for the
    `connection` commands one of those could be a key typed by mistake, so they get a fixed
    sentence instead. Other commands are unchanged."""

    def parse_args(self, args=None, namespace=None):
        self._argv = list(sys.argv[1:] if args is None else args)
        return super().parse_args(args, namespace)

    def error(self, message):
        in_connection = ' connection' in self.prog or 'connection' in getattr(self, '_argv', ())
        if in_connection and not message.startswith(('the following arguments are required',
                                                     'expected one argument')):
            self.exit(2, local_connection_cli.BAD_ARGUMENTS + '\n')
        super().error(message)


def _parser():
    parser = _Parser(description='Remediation Zero local edition (no cloud setup required)')
    parser.add_argument('--database', default=DEFAULT_DATABASE, metavar='DIR',
                        help='Workspace directory (default: %(default)s)')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('init', help='Create the workspace; no model calls')
    seeding = commands.add_parser('seed', help='Load findings, assets and owners from a corpus; no model calls')
    seeding.add_argument('--corpus', type=Path, metavar='DIR',
                         help="Folder holding findings.json, assets.json and owners.json (default: the repository's data/)")
    cycle = commands.add_parser('cycle', help='Run triage, chase, sweep and report once; calls your models')
    cycle.add_argument('--cycle', type=_cycle, required=True)
    rescan = commands.add_parser('rescan', help='Apply a follow-up scan to a demo workspace; Greenbone workspaces resolve through greenbone pull or upload')
    rescan.add_argument('--cycle', type=_cycle, required=True)
    rescan.add_argument('--scan', type=Path, required=True, metavar='PATH')
    rescan.add_argument('--dry-run', action='store_true', help='Show what would close; write nothing')
    exception = commands.add_parser('exception', help='Accept a risk, or list acceptances')
    actions = exception.add_subparsers(dest='action', required=True)
    accepting = actions.add_parser('accept', help='Record a risk acceptance that expires')
    accepting.add_argument('finding')
    accepting.add_argument('--ttl', type=int, required=True, metavar='DAYS')
    accepting.add_argument('--as', dest='as_email', required=True, metavar='EMAIL',
                           help='The owner accepting the risk: an active owner account')
    accepting.add_argument('--by', action=_ByReplaced, help=argparse.SUPPRESS)
    accepting.add_argument('--reason', required=True, metavar='TEXT')
    accepting.add_argument('--cycle', type=_cycle, required=True)
    accepting.add_argument('--approved-by-person', action='store_true',
                           help='A person has approved this acceptance; required for a KEV CVE, '
                                'or when the KEV list is not available')
    actions.add_parser('list', help='List recorded risk acceptances')
    approving = commands.add_parser('approve', help='Approve an unreviewed or held decision as a person')
    approving.add_argument('finding')
    approving.add_argument('--cycle', type=_cycle, required=True)
    approving.add_argument('--as', dest='as_email', required=True, metavar='EMAIL',
                           help='The person approving: an active account')
    approving.add_argument('--by', action=_ByReplaced, help=argparse.SUPPRESS)
    serve = commands.add_parser('serve', help='Serve the dashboard and preferences: on loopback, or over HTTPS '
                                              'on the saved listen address')
    serve.add_argument('--demo', action='store_true', help='Show illustrative fixtures instead of saved records')
    serve.add_argument('--port', type=int, help='Default: the saved port (8081 unless set)')
    serve.add_argument('--public-url', type=_public_url, metavar='URL',
                       help='The https:// address of a proxy in front, such as Tailscale Serve')
    greenbone = commands.add_parser('greenbone', help='Read tasks and finished reports from Greenbone; never changes anything there')
    gb_actions = greenbone.add_subparsers(dest='gb_action', required=True)
    gb_actions.add_parser('tasks', help='List the tasks the account can see: task_id  name')
    gb_actions.add_parser('test', help='Connect, sign in and list tasks, one line each')
    gb_pull = gb_actions.add_parser('pull', help='Import the next finished report of each chosen task (the newest one the first time)')
    gb_pull.add_argument('--cycle', type=_cycle, help='Default: the next cycle number')
    gb_upload = gb_actions.add_parser('upload', help='Import one exported report file')
    gb_upload.add_argument('file', metavar='FILE')
    gb_upload.add_argument('--add-task', action='store_true',
                           help="Also choose the report's task for this install, if the import succeeds")
    gb_upload.add_argument('--cycle', type=_cycle, help='Default: the next cycle number')
    commands.add_parser('update-enrichment', help='Download CISA KEV, FIRST EPSS and NVD data into the workspace cache; reaches the internet')
    check = commands.add_parser('check-models', help='Explicitly send the bundled synthetic example to each configured model role')
    check.add_argument('--role', choices=ROLES, help='Check only this role')
    local_accounts.add_parsers(commands, _public_url)
    settings = commands.add_parser('settings', help='Show or change the Settings page values from the server')
    settings_actions = settings.add_subparsers(dest='settings_action', required=True)
    settings_actions.add_parser('show', help='Print the settings file as JSON')
    setting = settings_actions.add_parser(
        'set', help='Change one section, validated as the Settings page does',
        description='Nested fields are dotted (certificate.mode=own, proposer.endpoint=URL); lists are '
                    'comma-separated (server_names=a.example,192.0.2.10); a checkbox takes true or false.')
    setting.add_argument('section', metavar='SECTION', help='application, model or scanner')
    setting.add_argument('assignments', nargs='+', metavar='FIELD=VALUE')
    local_connection_cli.add_parsers(commands)
    return parser


BY_REPLACED = '--by was replaced by --as EMAIL, which must name an account.'


class _ByReplaced(argparse.Action):
    """`--by` is gone from approve and exception accept: name an account with --as instead."""

    def __init__(self, option_strings, dest, **kwargs):
        kwargs.pop('nargs', None)
        super().__init__(option_strings, dest, nargs='?', **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        parser.exit(2, BY_REPLACED + '\n')


def link_origin(preferences):
    """Where the links the account commands print start: the first server name over HTTPS when
    the saved listen address is a network one, else this machine's loopback address."""
    port = preferences['port']
    if local_settings.exposed(preferences):
        names = default_server_names(preferences)
        if names:
            return f'https://{_host_port(names[0], port)}'
    return f'http://127.0.0.1:{port}'


def _print(value):
    print(json.dumps(value, sort_keys=True, default=str), flush=True)


ACCOUNTS_UNREADABLE = 'The accounts file could not be read or written. Nothing was changed.'


def command_line_account(ws, email, action=None):
    """The active account `--as` names, allowed `action` (tools.access), as (row, actor);
    local_accounts.CommandRefused otherwise. Opens the accounts file, as serve does, never
    through docs_for."""
    try:
        row = local_accounts.resolve_as(AccountStore(ws.accounts_path()), email)
    except (sqlite3.Error, OSError):  # OSError: the file cannot be opened (_private_file)
        raise local_accounts.CommandRefused(ACCOUNTS_UNREADABLE) from None
    if action == 'accept_risk' and not access.allowed(row['role'], action):
        raise local_accounts.CommandRefused(f'Only an owner can accept a risk; {row["email"]} is a {row["role"]}.')
    if action is not None and not access.allowed(row['role'], action):
        raise local_accounts.CommandRefused(account_views.refusal_sentence('not_allowed'))
    return row, local_accounts.command_line_actor(row)


def main(argv=None):
    parser = _parser()
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        refuse_non_directory(args.database)
        config_path = local_settings.settings_path(args.database)
        if args.command == 'settings':
            # The settings file only: the workspace is neither opened nor created.
            if args.settings_action == 'show':
                print(json.dumps(settings_shown(config_path), indent=2, sort_keys=True), flush=True)
                return
            try:
                print(settings_set(config_path, args.section, args.assignments), flush=True)
            except SettingsCommandRefused as refusal:
                parser.exit(1, f'{refusal}\n')
            return
        if args.command == 'connection':
            # Settings and the key file; the workspace is opened only to name and audit the acting account.
            def acting(email):
                ws = open_workspace(args.database)
                person, _ = command_line_account(ws, email, 'manage_connections')
                return person, Accounts(AccountStore(ws.accounts_path()), SimClock.from_env())
            raise SystemExit(local_connection_cli.run(args, config_path, SecretsFile(secrets_path(args.database)),
                                                      os.environ, acting=acting, clock=SimClock.from_env(),
                                                      log=_log))
        preferences = local_settings.load(config_path)
        if args.command == 'check-models':
            # Reads settings only; writes nothing to the workspace.
            raise SystemExit(check_models(ModelRoles.from_settings(preferences, os.environ,
                                                                   SecretsFile(secrets_path(args.database))),
                                          args.role))
        if args.command == 'greenbone' and args.gb_action in {'tasks', 'test'}:
            # Reads settings and the environment only; writes nothing to the workspace.
            run_greenbone = greenbone_tasks if args.gb_action == 'tasks' else greenbone_test
            raise SystemExit(run_greenbone(preferences, os.environ))
        if args.command == 'cycle':
            roles = ModelRoles.from_settings(preferences, os.environ, SecretsFile(secrets_path(args.database)))
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
            docs = ws.docs_for('rescan')
            try:
                # Before the scan is read: a Greenbone workspace is reconciled only by its imports.
                if holds_greenbone_findings(docs):
                    parser.exit(1, GREENBONE_RESCAN + '\n')
                scan = load_scan(args.scan)
                # A scan that claims a scanner task enters only through greenbone pull/upload,
                # which check the report itself; a hand-made one must not seed fake findings.
                if scan.get('source') or scan.get('task_id'):
                    parser.exit(1, GREENBONE_RESCAN + '\n')
                _print(run_rescan(_ports(docs, None if args.dry_run else ws.journal(), clock),
                                  args.cycle, scan, args.dry_run))
            finally:
                docs.close()
        elif args.command == 'exception' and args.action == 'accept':
            try:
                person, actor = command_line_account(ws, args.as_email, 'accept_risk')
            except local_accounts.CommandRefused as refusal:
                parser.exit(1, f'{refusal}\n')
            docs = ws.docs_for('exception_accept')
            try:
                result = accept(_ports(docs, ws.journal(), clock), args.finding, args.ttl,
                                person['email'], args.reason, args.cycle,
                                approved_by_human=args.approved_by_person, actor=actor)
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
            try:
                person, actor = command_line_account(ws, args.as_email, 'approve')
            except local_accounts.CommandRefused as refusal:
                parser.exit(1, f'{refusal}\n')
            ports = approval_ports(ws, clock)
            try:
                _print({'approval_id': approve(ports, args.finding, args.cycle, person['email'], actor=actor),
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
        elif args.command == 'account':
            # Opened here, as serve opens it: never through docs_for, so no agent stage reaches it.
            try:
                accounts = Accounts(AccountStore(ws.accounts_path()), clock)
                origin = getattr(args, 'public_url', None) or link_origin(preferences)
                lines = local_accounts.run(args, accounts, origin)
            except local_accounts.CommandRefused as refusal:
                parser.exit(1, f'{refusal}\n')
            except KeyboardInterrupt:
                parser.exit(1, 'Cancelled. Nothing was changed.\n')
            except (sqlite3.Error, OSError):  # OSError: the file cannot be opened (_private_file)
                parser.exit(1, ACCOUNTS_UNREADABLE + '\n')
            for line in lines:
                print(line, flush=True)
        elif args.command == 'update-enrichment':
            print('This reaches the internet: CISA, FIRST EPSS and NVD.', flush=True)
            result = update_enrichment(ws, os.environ)
            _print(result)
            if result['kev'] != 'ok' or result['epss'] != 'ok' or result['nvd_failed']:
                raise SystemExit(1)
        elif args.command == 'serve':
            try:
                server, lines = build_server(ws, preferences, config_path, demo=args.demo,
                                             public_url=args.public_url, port=args.port, clock=clock)
            except ServeRefused as refusal:
                parser.exit(1, f'{refusal}\n')
            with server:
                print('\n'.join(lines), flush=True)
                if args.public_url:
                    print(f'Also at {args.public_url} through your HTTPS proxy. {PROXY_SIGN_IN}', flush=True)
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
