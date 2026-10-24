# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Dependency-free synthetic local edition: python -m scripts.local --help."""
import argparse
import hashlib
import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from tools.adjudication import CapacityError, Proposal, RetryStateError
from tools.idempotency import derive_record
from tools.inference_journal import InferenceJournal
from tools.model_endpoint import ModelEndpoint
from tools import local_settings
from tools.model_roles import suggest_family
from ui.settings_view import SECTIONS, render_settings
from tools.sqlite_store import SQLiteStore
from ui.dashboard_view import VIEWS, demo_snapshot, render

PROMPT = Path(__file__).resolve().parents[1] / 'prompts/local_suggestion_v1.txt'


def suggest(store, endpoint, cycle, *, pause=None):
    # Validate cycle and configuration before reserving or invoking a model.
    key = derive_record('DEMO-WEB-01', 'local_suggestion', cycle)
    prompt = PROMPT.read_text()
    context = hashlib.sha256(json.dumps([endpoint.url, endpoint.model, prompt]).encode()).hexdigest()
    journal = InferenceJournal(store, 'DEMO-WEB-01', cycle, context=context, pause=pause)
    journal._ensure_context()  # also validate configuration before replay
    try:
        proposal = journal.call('triage_1', Proposal, lambda: endpoint.propose(prompt, 'DEMO-WEB-01'))
        document = {'finding_id': proposal.finding_id, 'cycle': cycle, 'outcome': 'unreviewed',
                    'proposed_severity': proposal.severity, 'proposed_remediation': proposal.remediation,
                    'rationale': proposal.rationale, 'cited_evidence': list(proposal.evidence),
                    'note': 'Model suggestion only. No independent review or infrastructure verification.'}
    except (CapacityError, ValueError):
        document = {'finding_id': 'DEMO-WEB-01', 'cycle': cycle, 'outcome': 'unavailable',
                    'note': 'The model check did not produce a valid suggestion. No security conclusion is available.'}
    store.record_suggestion(key.key, document)
    return document['outcome']


def handler(store, demo, config_path=None):
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
                        key_present=bool(os.environ.get('RZ_MODEL_API_KEY')),
                        overrides=bool(os.environ.get('RZ_MODEL_ENDPOINT') or os.environ.get('RZ_MODEL')))
                body = render(demo_snapshot() if demo else store.snapshot(), view, demo=demo, settings_html=settings_html)
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
                fields = parse_qs(self.rfile.read(length).decode('utf-8'), keep_blank_values=True, strict_parsing=True, max_num_fields=10)
                if any(len(v) != 1 for v in fields.values()):
                    raise ValueError()
                fields = {k: v[0] for k, v in fields.items()}
                if not secrets.compare_digest(fields.pop('token', '').encode(), token.encode()):
                    self.send_error(403)
                    return
                section = fields.pop('section', '')
                values = local_settings.load(config_path)
                if section == 'model' and set(fields) == {'endpoint', 'model'}:
                    # The existing form edits the proposer only; other v2 fields stay as saved.
                    values['roles']['proposer'] = None if not (fields['endpoint'] or fields['model']) else {
                        'format': 'openai_chat', 'endpoint': fields['endpoint'], 'model': fields['model'],
                        'family': suggest_family(fields['model'])}
                elif section == 'application' and set(fields) in ({'mode', 'port'}, {'mode', 'port', 'open_browser'}):
                    if fields.get('open_browser', 'yes') != 'yes':
                        raise ValueError()
                    values.update(mode=fields['mode'], port=int(fields['port']), open_browser='open_browser' in fields)
                else:
                    raise ValueError()
                local_settings.save(config_path, values)
            except (ValueError, UnicodeError):
                self.send_error(400, 'Invalid preferences. Nothing was saved. Check the endpoint, model, and port.')
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


def main():
    parser = argparse.ArgumentParser(description='Remediation Zero local synthetic preview (no cloud setup required)')
    parser.add_argument('--database', default='remediation-zero.sqlite3')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('init', help='Create local storage; no model calls')
    serve = commands.add_parser('serve', help='Serve local dashboard and preferences on loopback')
    serve.add_argument('--demo', action='store_true', help='Show illustrative fixtures instead of saved records')
    serve.add_argument('--port', type=int, default=8081)
    run = commands.add_parser('suggest-demo', help='Explicitly call your configured endpoint with the bundled synthetic example')
    run.add_argument('--cycle', type=int, default=1)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        config_path = local_settings.settings_path(args.database)
        preferences = local_settings.load(config_path)
        if args.command == 'suggest-demo':
            saved = preferences['roles']['proposer'] or {'endpoint': '', 'model': ''}
            endpoint = ModelEndpoint(os.environ.get('RZ_MODEL_ENDPOINT', saved['endpoint']), os.environ.get('RZ_MODEL', saved['model']), os.environ.get('RZ_MODEL_API_KEY'))
            derive_record('DEMO-WEB-01', 'local_suggestion', args.cycle)
        store = SQLiteStore(args.database)
        if args.command == 'suggest-demo':
            print(json.dumps({'finding_id': 'DEMO-WEB-01', 'cycle_id': args.cycle, 'outcome': suggest(store, endpoint, args.cycle)}))
        elif args.command == 'serve':
            with HTTPServer(('127.0.0.1', args.port), handler(store, args.demo, config_path)) as server:
                print(f'Local synthetic preview: http://127.0.0.1:{server.server_port}', flush=True)
                server.serve_forever()
        else:
            print('Local database ready. No model calls made.')
    except (ValueError, RetryStateError):
        parser.exit(1, 'Configuration, model context or journal state is invalid. Check settings; do not reset the database to bypass request limits.\n')


if __name__ == '__main__':
    main()
