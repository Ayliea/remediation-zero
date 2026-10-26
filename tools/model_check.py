# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Explicit sample check for each configured model role. Standard library only.

Sends bundled synthetic examples only. Failure lines carry the exception class
name and nothing else, because a message could contain an endpoint.
"""
import json

from tools.enrichment import Enrichment
from tools.guardrail import GuardModelScreen
from tools.inference import parse_review_strict, propose, render_finding, review
from tools.model_roles import ROLES

SAMPLE_FINDING = {'finding_id': 'DEMO-WEB-01', 'cve_id': 'CVE-2021-44228', 'scanner_severity': 'high',
                  'scanner_cvss': 9.8, 'port': 8080,
                  'scanner_comment': 'Synthetic example: an outdated logging component was detected.'}
SAMPLE_ASSET = {'hostname': 'demo-web-01.example.invalid', 'environment': 'demo',
                'criticality': 'medium', 'internet_facing': True}
SAMPLE_PROPOSAL = {'finding_id': 'DEMO-WEB-01', 'severity': 'high', 'sla_days': 14,
                   'remediation': 'Verify the component version with the hosting provider, then update it.',
                   'evidence': ['Synthetic scanner finding for CVE-2021-44228; version not yet confirmed.'],
                   'rationale': 'Exposure and exploitability have not been established; verification comes first.'}
SAMPLE_METRICS = {'period': 'demo', 'open_findings': 3, 'closed_findings': 1, 'overdue_findings': 0}
SAMPLE_GUARD_TEXT = 'The web server reports an outdated component version on port 8080.'


class _Recorder:
    """Passes calls through and keeps the last raw reply."""

    def __init__(self, adapter):
        self._adapter = adapter
        self.reply = None

    def complete(self, *args, **kwargs):
        self.reply = self._adapter.complete(*args, **kwargs)
        return self.reply


def _finding_text():
    return render_finding(SAMPLE_FINDING, SAMPLE_ASSET, Enrichment(cve_id=SAMPLE_FINDING['cve_id']))


def _run(role, adapter):
    """Return None when the role is ok, else a short failure name."""
    if role == 'proposer':
        propose(_finding_text(), adapter, finding_id='DEMO-WEB-01', retry=False, legacy=True)
        return None
    if role == 'reviewer':
        recorder = _Recorder(adapter)
        review(_finding_text() + '\n\nPROPOSAL\n' + json.dumps(SAMPLE_PROPOSAL, sort_keys=True), recorder, retry=False)
        # review() fails closed to a rejecting Verdict on any reply; ok means the reply matched the format.
        parse_review_strict(recorder.reply or '')
        return None
    if role == 'summarizer':
        from tools.reports import write_summary  # standard library only; imported when needed
        return None if write_summary(SAMPLE_METRICS, adapter) else 'EmptySummary'
    verdict = GuardModelScreen(adapter).screen(SAMPLE_GUARD_TEXT)
    if not verdict.screened:
        return 'GuardUnusable'
    return 'GuardBlockedBenign' if verdict.blocked else None


#: Fixed advice per failure the user can act on; the line still carries no exception text.
PROBLEM_HINTS = {
    'ModelTimedOut': "no answer within this role's timeout; raise this role's timeout in Settings "
                     '(a CPU-only or just-loaded local model can need minutes)',
    'TLSRefused': 'the server refused the TLS connection; check the host name and port in the endpoint URL',
    'CertificateNotTrusted': "set this role's CA certificate file to the model server's certificate "
                             "or the CA that signed it",
    'CertificateNameMismatch': 'the certificate does not name the host in the endpoint URL; '
                               'use the name it was issued for, or reissue it',
    'CertificateExpired': 'the model server\'s certificate is expired or not yet valid; renew it',
    'CertificateFileUnreadable': "this role's CA certificate file is missing or is not a PEM certificate",
}


def check_models(roles, only=None, *, out=print):
    """Print one line per role; return 0 if every configured role is ok, else 1."""
    failed = False
    for role in ROLES:
        if only and role != only:
            continue
        if getattr(roles, role) is None:
            out('%s: not configured' % role)
            continue
        try:
            problem = _run(role, roles.adapter(role))
        except Exception as exc:
            problem = type(exc).__name__
            if problem in PROBLEM_HINTS:
                problem = f'{problem}: {PROBLEM_HINTS[problem]}'
        if problem:
            failed = True
            out('%s: failed (%s)' % (role, problem))
        else:
            out('%s: ok' % role)
    return 1 if failed else 0
