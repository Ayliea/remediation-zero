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
FILES = ('LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md', 'start-remediation-zero.py', 'scripts/local_launcher.py', 'scripts/__init__.py',
         'scripts/local.py', 'scripts/local_auth.py', 'scripts/local_accounts.py', 'scripts/local_connections.py', 'scripts/local_connection_cli.py', 'scripts/local_context.py', 'tools/__init__.py',
         'tools/accounts.py', 'tools/access.py', 'tools/passwords.py', 'tools/totp.py', 'tools/qr_svg.py',
         'tools/vendor/__init__.py', 'tools/vendor/qrcodegen.py', 'tools/vendor/QRCODEGEN_LICENSE.txt',
         'tools/vendor/breached_passwords.txt', 'tools/vendor/BREACHED_PASSWORDS_SOURCE.md', 'ui/account_views.py',
         'tools/clock.py', 'tools/idempotency.py', 'tools/adjudication.py',
         'tools/inference_journal.py', 'tools/sqlite_store.py', 'tools/docstore.py', 'tools/sqlite_docstore.py', 'tools/local_layout.py', 'tools/account_store.py', 'tools/local_memory.py', 'tools/fleet_memory.py', 'engine/__init__.py', 'engine/ports.py', 'engine/triage_cycle.py',
         'engine/chase.py', 'engine/sweep.py', 'engine/report.py', 'engine/rescan.py', 'engine/seed.py',
         'engine/scanner_source.py', 'engine/scanner_import.py',
         'engine/approve.py', 'engine/snapshot.py', 'worker/__init__.py', 'worker/envelope.py',
         'tools/delivery.py', 'tools/github_tickets.py',
         'tools/chase.py', 'tools/tickets.py', 'tools/telemetry.py', 'tools/exceptions.py', 'tools/exception_store.py',
         'tools/metrics.py', 'tools/reports.py', 'tools/rescan.py', 'tools/scan_store.py', 'tools/ingest.py',
         'tools/decisions.py', 'tools/assignments.py', 'tools/ownership.py', 'tools/cycles.py', 'tools/model_endpoint.py', 'tools/model_transport.py', 'tools/model_endpoints.py', 'tools/model_roles.py', 'tools/model_catalogue.py', 'tools/model_catalogue.json',
         'tools/secrets_port.py', 'tools/local_secrets.py', 'tools/connections.py', 'tools/connection_advice.py',
         'tools/context.py', 'tools/context_store.py', 'tools/context_import.py', 'tools/context_rules.py', 'tools/context_floor.py',
         'tools/guardrail.py', 'tools/model_armor.py', 'tools/inference.py', 'tools/enrichment.py', 'tools/enrichment_fetch.py', 'tools/greenbone_report.py', 'tools/gmp.py',
         'tools/models/__init__.py', 'tools/models/_common.py', 'tools/models/openai_chat.py',
         'tools/models/anthropic_messages.py', 'tools/models/gemini_api.py',
         'tools/local_settings.py', 'tools/server_tls.py', 'tools/model_check.py', 'ui/settings_view.py', 'ui/connections_view.py', 'ui/context_view.py', 'ui/assets/connections.js', 'ui/assets/connections.css', 'ui/dashboard_view.py', 'ui/theme.css', 'ui/assets/remediation-zero-logo.png',
         'prompts/guard_v1.md',
         'prompts/triage.md', 'prompts/triage_no_cve.md', 'prompts/triage_context.md', 'prompts/reviewer.md', 'prompts/reporting.md')


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
