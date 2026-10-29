# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The /context/* form routes of the local dashboard server: business context, owner only.

scripts/local.py has already checked the Host, Origin and Sec-Fetch-Site, that the session's
role may `manage_context`, and the body's size. Here: the form token, then a recent re-confirm
(else a redirect to the confirm page and nothing is done), then the change through
tools.context_store and its audit row. Every route but /context/label runs under `serial`.

/context/label screens a new custom label's name with the configured guard, which can take as
long as a model call, so it runs with `serial` released: the form is checked under `serial`,
the name is screened, then `serial` is taken again, the session resolved again (an account
demoted or removed meanwhile gets 403), and the label written.

A spreadsheet is read once, on /context/upload, and held in memory for this session for ten
minutes (PREVIEW_SECONDS) under a random id, so the column mapping and the preview never post
the file again. The id is bound to the session's form token. Nothing from a spreadsheet is
logged; pages escape it. Log lines carry the route and the error class only. Standard library only.
"""
import secrets
import threading
import time
from urllib.parse import parse_qs

from scripts import local_auth
from tools import access, context
from tools.accounts import AccountRefused
from tools.context_import import ColumnMapping, preview, read_csv
from tools.context_store import ContextWriter
from ui import context_view

ACTION = 'manage_context'
PATHS = frozenset({'/context/facts', '/context/questions', '/context/label', '/context/label-remove',
                   '/context/tag', '/context/upload', '/context/preview', '/context/upload-apply',
                   '/context/rule', '/context/rule-remove', '/context/decide'})
#: Routes that run with `serial` released (a guard call); scripts/local.py checks this.
UNSERIAL = frozenset({'/context/label'})
BACK = '/?view=settings&section=context'
FORM_LIMIT = 65536
FORM_FIELDS = 1100
PREVIEW_SECONDS = 600
MAX_PREVIEWS = 8
INVALID = 'That form could not be used. Nothing was changed.'
_FACT_WORDS = {'criticality': {'high': 'high', 'medium': 'medium', 'low': 'low'},
               'environment': {'production': 'production', 'development': 'development'},
               'internet_facing': {'yes': True, 'no': False},
               'sensitive_data': {'yes': True, 'no': False}}


def _facts(fields: dict, *, allow_unknown: bool) -> dict:
    """The fact changes a form asks for: '' leaves a fact, 'unknown' clears it (when allowed)."""
    changes = {}
    for fact, words in _FACT_WORDS.items():
        word = fields.get(fact, '')
        if word == '':
            continue
        if word == 'unknown' and allow_unknown:
            changes[fact] = None
        elif word in words:
            changes[fact] = words[word]
        else:
            raise ValueError(INVALID)
    return changes


class ContextRoutes:
    def __init__(self, workspace, accounts, serial, *, guard, read_upload, log):
        # guard: () -> the configured tools.guardrail guard, or None when there is none.
        # read_upload: scripts.local._read_upload_form, the strict multipart reader.
        self._ws, self._accounts, self._serial = workspace, accounts, serial
        self._guard, self._read_upload, self._log = guard, read_upload, log
        self._previews: dict = {}
        self._previews_lock = threading.Lock()

    # --- reading --------------------------------------------------------------------------

    def _writer(self):
        docs = self._ws.docs_for('context')
        return docs, ContextWriter(docs, self._accounts.clock)

    def state(self) -> dict:
        """What the Context section shows."""
        docs, writer = self._writer()
        try:
            labels = writer.labels()
            custom = {k: v.get('effect') for k, v in labels.items()}
            assets = [{**(s.to_dict() or {}), 'asset_id': s.id} for s in docs.collection('assets').stream()]
            names = {a['asset_id']: a.get('hostname') or a.get('ip') or a.get('ip_address') or a['asset_id']
                     for a in assets}
            hosts = []
            for a in assets:
                facts = context.effective_facts(a, custom)
                hosts.append({'asset_id': a['asset_id'], 'name': names[a['asset_id']], 'facts': facts,
                          'direct': context.direct_facts(a),
                              'labels': [labels[x]['name'] for x in a.get('context_labels') or () if x in labels],
                              'provenance': dict(a.get('context_provenance') or {}),
                              'unknown': all(v is None for v in facts.values())})
            hosts.sort(key=lambda h: (not h['unknown'], h['name']))
            rules = writer.rules()
            rule_names = {r.rule_id: r.pattern for r in rules}
            found = [{'source_id': s.source_id, 'asset_id': s.asset_id, 'facts': s.facts,
                      'name': names.get(s.asset_id, s.asset_id),
                      'from': f'rule {rule_names[s.source_id]}' if s.source_id in rule_names else 'spreadsheet row'}
                     for s in writer.suggestions(self._accounts.clock.now().sim_ts)]
            return {'hosts': hosts, 'suggestions': found, 'unknown': sum(h['unknown'] for h in hosts),
                    'rules': [{'rule_id': r.rule_id, 'kind': r.kind, 'pattern': r.pattern, 'facts': r.facts}
                              for r in rules],
                    'labels': [{'label_id': k, 'name': v.get('name'), 'effect': v.get('effect'),
                                'count': sum(1 for a in assets if k in (a.get('context_labels') or ()))}
                               for k, v in sorted(labels.items(), key=lambda kv: kv[1].get('name', '').lower())]}
        finally:
            docs.close()

    def section(self, session, message='') -> str:
        return context_view.render_context(self.state(), session.csrf,
                                           owner=access.allowed(session.role, ACTION), message=message)

    # --- forms ----------------------------------------------------------------------------

    @staticmethod
    def _form(handler) -> dict:
        """A url-encoded body as {name: value}, `asset` as a list; ValueError if it is not one."""
        length = handler.headers.get('Content-Length')
        if (length is None or not (length.isascii() and length.isdigit()) or not 0 < int(length) <= FORM_LIMIT
                or handler.headers.get('Transfer-Encoding')
                or handler.headers.get('Content-Type') != 'application/x-www-form-urlencoded'):
            raise ValueError(INVALID)
        raw = handler._take_body()
        if len(raw) != int(length):
            raise ValueError(INVALID)
        fields = parse_qs(raw.decode('utf-8'), keep_blank_values=True, strict_parsing=True,
                          max_num_fields=FORM_FIELDS)
        if any(len(v) != 1 for k, v in fields.items() if k != 'asset'):
            raise ValueError(INVALID)
        return {k: (v if k == 'asset' else v[0]) for k, v in fields.items()}

    def _checked(self, handler, req, session, path):
        """The form's fields once the token and a recent re-confirm are good, else None (answered)."""
        try:
            if path == '/context/upload':
                form = self._read_upload(handler.headers.get('Content-Type') or '', handler._take_body())
                if form['add_task']:
                    raise ValueError(INVALID)
                fields = {'token': form['token'].decode('ascii'), 'file': form['report']}
            else:
                fields = self._form(handler)
        except (ValueError, UnicodeError, LookupError):
            handler.send_error(400, INVALID)
            return None
        if not secrets.compare_digest(str(fields.pop('token', '')).encode(), session.csrf.encode()):
            handler.send_error(403)
            return None
        if not session.confirmed:
            handler.redirect(local_auth.confirm_location(BACK))
            return None
        return fields

    def post(self, handler, req, session, path):
        """Every /context/* route but /context/label, under `serial`."""
        fields = self._checked(handler, req, session, path)
        if fields is None:
            return
        by = dict(via='dashboard', source=req.client)
        actor = session.account_id
        docs, writer = self._writer()
        try:
            done = self._dispatch(handler, session, path, fields, docs, writer, actor, by)
        except AccountRefused:
            handler.send_error(403)
            return
        except (ValueError, KeyError) as error:
            message = str(error) if isinstance(error, ValueError) and str(error) else INVALID
            handler._send_html(handler._context_page(session, self.section(session, message)), 400)
            return
        finally:
            docs.close()
        if done is not None:
            handler.redirect(f'{BACK}&done={done}')

    def _dispatch(self, handler, session, path, fields, docs, writer, actor, by):
        record = self._accounts.record_context_change
        email = session.email
        if path == '/context/facts':
            changes = _facts(fields, allow_unknown=True)
            if not changes or set(fields) - {'asset', *_FACT_WORDS}:
                raise ValueError(INVALID)
            (asset,) = fields['asset']
            changed = writer.set_facts([asset], changes, source='direct', account=email)
            record(actor, 'context_facts_set', detail={'assets': len(changed), 'facts': sorted(changes)}, **by)
            return 'saved'
        if path == '/context/questions':
            number = fields.get('question', '')
            if number not in ('1', '2', '3', '4') or set(fields) - {'asset', 'question'}:
                raise ValueError(INVALID)
            _, fact, value = context_view.QUESTIONS[int(number) - 1]
            changed = writer.set_facts(list(fields.get('asset', [])), {fact: value},
                                       source='questions', account=email)
            record(actor, 'context_facts_set', detail={'assets': len(changed), 'facts': [fact]}, **by)
            return 'saved'
        if path == '/context/tag':
            (asset,) = fields['asset']
            label, action = fields.get('label', ''), fields.get('action')
            if action not in ('add', 'remove'):
                raise ValueError(INVALID)
            changed = (writer.tag if action == 'add' else writer.untag)([asset], label, account=email)
            record(actor, 'context_facts_set', detail={'assets': len(changed)}, **by)
            return 'saved'
        if path == '/context/label-remove':
            changed = writer.remove_label(fields.get('label', ''), account=email)
            record(actor, 'context_label_removed', detail={'assets': len(changed)}, **by)
            return 'removed'
        if path == '/context/rule':
            rule_id = writer.save_rule(fields.get('kind', ''), fields.get('pattern', ''),
                                       _facts(fields, allow_unknown=False), account=email)
            record(actor, 'context_rule_saved', detail={'rule': rule_id}, **by)
            return 'saved'
        if path == '/context/rule-remove':
            rule_id = fields.get('rule', '')
            if rule_id not in {r.rule_id for r in writer.rules()}:
                raise KeyError(rule_id)
            writer.remove_rule(rule_id, account=email)
            record(actor, 'context_rule_removed', detail={'rule': rule_id}, **by)
            return 'removed'
        if path == '/context/decide':
            decision = fields.get('decision')
            (asset,) = fields['asset']
            if decision not in ('approve', 'deny') or len(fields.get('source', '')) > 64:
                raise ValueError(INVALID)
            changed = writer.decide(fields['source'], asset, decision == 'approve', account=email)
            record(actor, 'context_suggestion_decided',
                   detail={'decision': 'approved' if decision == 'approve' else 'denied',
                           'rule': fields['source'], 'assets': len(changed)}, **by)
            return 'decided'
        if path == '/context/upload':
            header, rows = read_csv(fields['file'])
            preview_id = self._hold(session, header, rows)
            page = context_view.render_mapping(header, writer.saved_mapping(), preview_id, session.csrf)
            handler._send_html(handler._context_page(session, page), 200)
            return None
        held = self._held(session, fields.get('preview', ''))
        mapping = ColumnMapping(fields.get('host_column', ''),
                                {f: fields[f'col_{f}'] for f in _FACT_WORDS if fields.get(f'col_{f}')})
        hosts = [{**(s.to_dict() or {}), 'asset_id': s.id}
                 for s in docs.collection('assets').stream()]
        result = preview(held['header'], held['rows'], mapping, hosts)
        if path == '/context/preview':
            names = {h['asset_id']: h.get('hostname') or h['asset_id'] for h in hosts}
            page = context_view.render_preview(result, names, fields['preview'], mapping, session.csrf)
            handler._send_html(handler._context_page(session, page), 200)
            return None
        changed = writer.apply_upload(result, mapping, account=email)
        self._drop(fields['preview'])
        record(actor, 'context_upload_applied', detail={'assets': changed}, **by)
        return 'applied'

    # --- the held spreadsheet ---------------------------------------------------------------

    def _hold(self, session, header, rows) -> str:
        preview_id = secrets.token_urlsafe(16)
        now = time.monotonic()  # runtime expiry only; never persisted
        with self._previews_lock:
            for key in [k for k, v in self._previews.items() if v['expires'] <= now]:
                del self._previews[key]
            while len(self._previews) >= MAX_PREVIEWS:
                del self._previews[min(self._previews, key=lambda k: self._previews[k]['expires'])]
            self._previews[preview_id] = {'csrf': session.csrf, 'expires': now + PREVIEW_SECONDS,
                                          'header': header, 'rows': rows}
        return preview_id

    def _held(self, session, preview_id) -> dict:
        with self._previews_lock:
            held = self._previews.get(preview_id)
            if (held is None or held['expires'] <= time.monotonic()
                    or not secrets.compare_digest(held['csrf'].encode(), session.csrf.encode())):
                raise ValueError('That upload has expired. Upload the file again.')
            return held

    def _drop(self, preview_id) -> None:
        with self._previews_lock:
            self._previews.pop(preview_id, None)

    # --- /context/label: screened with `serial` released ----------------------------------------

    def post_label(self, handler, req):
        """POST /context/label. The body was read by scripts/local.py; `serial` is not held."""
        with self._serial:
            session = self._accounts.session(req.token)
            if session is None or not access.allowed(session.role, ACTION):
                handler.send_error(403)
                return
            fields = self._checked(handler, req, session, '/context/label')
            if fields is None:
                return
            try:
                name = context.validate_label_name(fields.get('name', ''))
                effect = fields.get('effect', '')
                if effect not in context.EFFECTS or set(fields) - {'name', 'effect'}:
                    raise ValueError(INVALID)
            except ValueError as error:
                handler._send_html(handler._context_page(session, self.section(session, str(error))), 400)
                return
        # Without a configured guard the strict name rule alone applies (design 2026-10-29).
        refused = False
        try:
            guard = self._guard()
            if guard is not None:
                refused = bool(guard.screen(name).blocked)
        except Exception as error:  # a guard that cannot answer is not a pass
            self._log('context_label_screen_failed', error=type(error).__name__)
            refused = True
        with self._serial:
            session = self._accounts.session(req.token)
            if session is None or not access.allowed(session.role, ACTION):
                handler.send_error(403)
                return
            if refused:
                message = 'That label name was refused by the safety check. Choose another.'
                handler._send_html(handler._context_page(session, self.section(session, message)), 400)
                return
            docs, writer = self._writer()
            try:
                writer.add_label(name, effect, account=session.email)
                self._accounts.record_context_change(session.account_id, 'context_label_added',
                                                     detail={'label': name}, via='dashboard',
                                                     source=req.client)
            except AccountRefused:
                handler.send_error(403)
                return
            except ValueError as error:
                handler._send_html(handler._context_page(session, self.section(session, str(error))), 400)
                return
            finally:
                docs.close()
            handler.redirect(f'{BACK}&done=saved')
