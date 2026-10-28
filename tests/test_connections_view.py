# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Settings -> Models: the connections list, the coverage strip, and the one page that runs a script.

The page is served over a real socket by the dashboard server with the signed-in owner and tech
from tests/signed_in.py. No model is called: the page makes no call when it is rendered. Synthetic
data only: `.invalid` hosts, invented keys."""
import base64
import copy
import hashlib
import html
import http.client
import json
import re
import socket
import threading
from pathlib import Path
from urllib.parse import urlencode

import pytest

from scripts import build_local_installer, local, local_connections
from tools import connections, local_settings, model_catalogue, model_endpoints
from tools.local_secrets import SecretsFile
from tools.model_catalogue import Preset, presets
from ui import connections_view
from ui.connections_view import SCRIPT, SCRIPT_HASH, models_section

KEY = 'sk-test-viewQX7Z1234'
BASE = 'https://api.example.invalid/v1'
OPENAI = 'conn-00000000000a'
OLLAMA = 'conn-00000000000b'
EXPECTED_CSP = (f"default-src 'none'; script-src '{SCRIPT_HASH}'; connect-src 'self'; img-src data:; "
                "style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


@pytest.fixture(autouse=True)
def no_reverse_lookup(monkeypatch):
    monkeypatch.setattr(socket, 'getfqdn', lambda name='': name)


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    for name in ('RZ_MODEL', 'RZ_MODEL_ENDPOINT', 'RZ_MODEL_API_KEY', 'RZ_PROPOSER_API_KEY',
                 'RZ_REVIEWER_API_KEY', 'RZ_SUMMARIZER_API_KEY', 'RZ_GUARD_API_KEY'):
        monkeypatch.delenv(name, raising=False)


def settings_with_connections(name='OpenAI'):
    value = copy.deepcopy(local_settings.DEFAULTS)
    value['connections'][OPENAI] = {'name': name, 'provider': 'openai', 'format': 'openai_chat',
                                    'base_url': BASE, 'endpoint_style': 'base', 'ca_file': '',
                                    'key_source': 'stored', 'last_test': None}
    value['connections'][OLLAMA] = {'name': 'Ollama', 'provider': 'ollama', 'format': 'openai_chat',
                                    'base_url': 'http://127.0.0.1:11434/v1', 'endpoint_style': 'base',
                                    'ca_file': '', 'key_source': 'none', 'last_test': None}
    value['roles']['proposer'] = {'connection': OPENAI, 'model': 'gpt-x', 'family': 'gpt', 'timeout_seconds': 60}
    value['roles']['guard'] = {'connection': OLLAMA, 'model': 'llama3.1:8b', 'family': 'llama',
                               'timeout_seconds': 300}
    return value


class Client:
    def __init__(self, port, site, who, config_path):
        self.port, self.site, self.who, self.config_path = port, site, who, config_path

    @property
    def csrf(self):
        token = {'owner': self.site.owner_token, 'tech': self.site.tech_token,
                 'unconfirmed': self.site.unconfirmed_token}[self.who]
        return self.site.accounts.session(token).csrf

    def _send(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        host = f'127.0.0.1:{self.port}'
        sent = {'Host': host, 'Cookie': self.site.cookie(self.who)}
        sent.update(headers or {})
        conn.request(method, path, body=body, headers=sent)
        response = conn.getresponse()
        response.text = response.read().decode()
        conn.close()
        return response

    def get(self, path):
        return self._send('GET', path)

    def post_form(self, path, fields):
        host = f'127.0.0.1:{self.port}'
        return self._send('POST', path, urlencode(fields), {
            'Origin': f'http://{host}', 'Sec-Fetch-Site': 'same-origin',
            'Content-Type': 'application/x-www-form-urlencoded'})


@pytest.fixture
def served(tmp_path, fake_endpoints, signed_in, monkeypatch):
    monkeypatch.setattr(connections, 'test_jobs', lambda *a, **k: pytest.fail('a model was tested'))
    monkeypatch.setattr(model_endpoints, 'list_models', lambda *a, **k: pytest.fail('a model list was fetched'))
    ws = local.open_workspace(tmp_path / 'ws')
    config_path = local_settings.settings_path(ws.root)
    docs = ws.docs_for('dashboard')
    cls = local.handler(local._View(docs), False, config_path, 'python3 -S -m scripts.local --database /srv/rz',
                        None, accounts=signed_in.accounts)
    httpd = local.DashboardServer(('127.0.0.1', 0), cls)
    fake_endpoints.tcp(httpd.socket)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_port, config_path, signed_in
    httpd.shutdown()
    httpd.server_close()
    docs.close()


@pytest.fixture
def owner_client(served):
    port, config_path, site = served
    return Client(port, site, 'owner', config_path)


@pytest.fixture
def tech_client(served):
    port, config_path, site = served
    return Client(port, site, 'tech', config_path)


def data_block(text):
    found = re.search(r'<script type="application/json" id="rz-connections">(.*?)</script>', text, re.S)
    assert found, 'no data block'
    return json.loads(found[1])


def section(**changes):
    settings = settings_with_connections(changes.pop('name', 'OpenAI'))
    kwargs = dict(rows=connections.rows(settings, {}, None, now_real_ts=0.0),
                  coverage=connections.coverage(settings, {}), presets=presets(), policy='wait',
                  token='form-token', owner=True, confirmed=False,
                  deletions={cid: connections.deletion_consequences(settings, cid) for cid in settings['connections']})
    kwargs.update(changes)
    return models_section(**kwargs)


# --- the script and its hash ------------------------------------------------------

def test_the_script_hash_is_the_sha256_of_the_exact_script():
    assert SCRIPT == (Path(connections_view.__file__).parent / 'assets' / 'connections.js').read_text(encoding='utf-8')
    assert SCRIPT_HASH.startswith('sha256-')
    assert hashlib.sha256(SCRIPT.encode()).digest() == base64.b64decode(SCRIPT_HASH.split('-', 1)[1])


def test_models_page_csp_allows_exactly_the_script_hash(owner_client):
    r = owner_client.get('/?view=settings&section=model')
    assert r.status == 200
    csp = r.headers['Content-Security-Policy']
    assert csp == EXPECTED_CSP
    assert f"script-src '{SCRIPT_HASH}'" in csp and "connect-src 'self'" in csp
    assert hashlib.sha256(SCRIPT.encode()).digest() == base64.b64decode(SCRIPT_HASH.split('-', 1)[1])
    assert f'<script>{SCRIPT}</script>' in r.text
    # One executable script, and the data block, and nothing else that could run.
    assert r.text.count('<script') == 2
    assert 'src=' not in re.sub(r'<script type="application/json".*?</script>', '', r.text, flags=re.S).split('<script>')[1]


def test_no_other_page_allows_a_script(owner_client):
    for path in ('/', '/?view=actions', '/?view=settings&section=scanner', '/?view=settings&section=application',
                 '/?view=accounts', '/signin', '/confirm?next=/'):
        r = owner_client.get(path)
        assert 'script-src' not in r.headers.get('Content-Security-Policy', ''), path
        assert '<script' not in r.text, path


def test_no_inline_event_handlers_or_eval(owner_client):
    for text in (section(), section(owner=False), owner_client.get('/?view=settings&section=model').text):
        assert not re.search(r'\son[a-z]+\s*=', text, re.I)
        assert 'javascript:' not in text.lower()
    for banned in ('eval(', 'new Function', 'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write',
                   'setTimeout("', "setTimeout('", 'localStorage', 'sessionStorage'):
        assert banned not in SCRIPT, banned


def test_the_script_calls_only_the_connection_routes():
    called = set(re.findall(r"'(/[a-z/-]*)'", SCRIPT))
    assert called <= set(local_connections.PATHS) | {'/?view=settings&section=model'}, called
    assert not re.search(r'https?://[A-Za-z0-9]', SCRIPT)   # no address of its own: key pages come as data


# --- who sees what --------------------------------------------------------------

def test_tech_sees_list_and_coverage_without_controls_or_script(tech_client):
    local_settings.save(tech_client.config_path, settings_with_connections())
    r = tech_client.get('/?view=settings&section=model')
    assert r.status == 200
    assert 'script-src' not in r.headers['Content-Security-Policy']
    assert '<script' not in r.text and '<dialog' not in r.text
    assert 'data-action' not in r.text and 'Add a connection' not in r.text
    for word in ('Edit', 'Replace key', 'Test again', 'Delete'):
        assert f'>{word}<' not in r.text
    assert 'OpenAI' in r.text and 'gpt-x' in r.text and 'llama3.1:8b' in r.text
    assert 'Review' in r.text and 'nobody' in r.text
    assert 'name="same_family_policy"' in r.text      # the policy stays a Settings write, as today


def test_owner_sees_every_control_for_each_connection():
    text = section()
    assert 'data-action="add"' in text
    for action in ('edit', 'test', 'delete'):
        assert f'data-action="{action}" data-connection="{OPENAI}"' in text
        assert f'data-action="{action}" data-connection="{OLLAMA}"' in text
    # Replace key: only where there is a key to replace (Ollama needs none).
    assert f'data-action="replace" data-connection="{OPENAI}"' in text
    assert f'data-action="replace" data-connection="{OLLAMA}"' not in text
    assert '<dialog' in text and f'<script>{SCRIPT}</script>' in text


def test_test_again_is_offered_only_for_a_connection_with_jobs():
    settings = settings_with_connections()
    settings['roles']['guard'] = None
    text = section(rows=connections.rows(settings, {}, None, now_real_ts=0.0),
                   coverage=connections.coverage(settings, {}))
    assert f'data-action="test" data-connection="{OPENAI}"' in text
    assert f'data-action="test" data-connection="{OLLAMA}"' not in text


def test_the_data_block_tells_the_script_only_what_it_needs():
    data = data_block(section(confirmed=True))
    assert data['token'] == 'form-token' and data['confirmed'] is True
    assert [p['id'] for p in data['presets']] == [p.id for p in presets()]
    by_id = {c['id']: c for c in data['connections']}
    assert by_id[OPENAI]['jobs'] == [{'role': 'proposer', 'job': 'Triage', 'model': 'gpt-x', 'family': 'gpt',
                                      'timeout_seconds': 60}]
    assert by_id[OLLAMA]['jobs'][0]['timeout_seconds'] == 300
    assert set(data['families']) and 'openai_chat' in data['formats']
    assert 'key' not in json.dumps(data['connections']).replace('"can_replace_key"', '')


# --- what is shown, and how ------------------------------------------------------

def test_names_and_models_are_escaped():
    settings = settings_with_connections(name='<img src=x>')
    settings['roles']['proposer']['model'] = '</script><script>alert(1)</script>'
    text = section(rows=connections.rows(settings, {}, None, now_real_ts=0.0),
                   coverage=connections.coverage(settings, {}),
                   deletions={cid: connections.deletion_consequences(settings, cid) for cid in settings['connections']})
    assert '<img src=x>' not in text
    assert '&lt;img src=x&gt;' in text
    assert text.count('<script') == 2 and text.count('</script>') == 2
    data = data_block(text)
    assert data['connections'][0]['name'] == '<img src=x>'
    assert data['connections'][0]['jobs'][0]['model'] == '</script><script>alert(1)</script>'


def test_the_token_is_escaped_where_it_is_written():
    text = section(token='a"b<c')
    assert 'value="a&quot;b&lt;c"' in text and 'a"b<c"' not in text
    assert data_block(text)['token'] == 'a"b<c'


def test_list_shows_hint_never_key(owner_client):
    local_settings.save(owner_client.config_path, settings_with_connections())
    SecretsFile(local_connections.secrets_beside(owner_client.config_path)).put(OPENAI, KEY)
    r = owner_client.get('/?view=settings&section=model')
    assert 'ends in …1234' in r.text
    assert KEY not in r.text and 'sk-test' not in r.text
    assert 'no key needed' in r.text


def test_the_page_says_when_a_key_is_set_on_the_server(owner_client, monkeypatch):
    settings = settings_with_connections()
    settings['connections'][OPENAI]['key_source'] = 'environment'
    local_settings.save(owner_client.config_path, settings)
    monkeypatch.setenv('RZ_PROPOSER_API_KEY', KEY)
    r = owner_client.get('/?view=settings&section=model')
    assert 'set on the server' in r.text and KEY not in r.text
    assert f'data-action="replace" data-connection="{OPENAI}"' not in r.text


def test_an_environment_connection_whose_variable_is_unset_says_key_missing_and_offers_replace_key(owner_client):
    settings = settings_with_connections()
    settings['connections'][OPENAI]['key_source'] = 'environment'
    local_settings.save(owner_client.config_path, settings)
    r = owner_client.get('/?view=settings&section=model')
    assert 'Key: key missing' in r.text and 'Key: set on the server' not in r.text
    assert f'data-action="replace" data-connection="{OPENAI}"' in r.text


@pytest.mark.parametrize('owner', [True, False])
def test_each_row_shows_where_it_calls_and_each_job_its_family_and_timeout(owner):
    settings = settings_with_connections()
    settings['connections'][OPENAI]['ca_file'] = '/etc/rz/model-ca.pem'
    text = section(rows=connections.rows(settings, {}, None, now_real_ts=0.0), owner=owner)
    assert f'Address: {BASE} · CA file: /etc/rz/model-ca.pem' in text
    assert 'Address: http://127.0.0.1:11434/v1</p>' in text          # no CA file, none shown
    assert '<strong>Triage</strong> gpt-x <span class="rz-muted">(family gpt · timeout 60 s)</span>' in text
    assert ('<strong>Screening</strong> llama3.1:8b <span class="rz-muted">(family llama · timeout 300 s)</span>'
            in text)


def test_the_address_and_ca_file_are_escaped():
    settings = settings_with_connections()
    settings['connections'][OPENAI]['base_url'] = 'https://x.example.invalid/<b>"v1'
    settings['connections'][OPENAI]['ca_file'] = '/etc/<i>ca.pem'
    settings['roles']['proposer']['family'] = '<u>'
    text = section(rows=connections.rows(settings, {}, None, now_real_ts=0.0))
    assert '<b>' not in text and '<i>' not in text and '<u>' not in text
    assert 'https://x.example.invalid/&lt;b&gt;&quot;v1' in text and '/etc/&lt;i&gt;ca.pem' in text


def test_replace_key_shows_the_address_it_keeps():
    by_id = {c['id']: c for c in data_block(section())['connections']}
    assert by_id[OPENAI]['base_url'] == BASE
    prepare = SCRIPT[SCRIPT.index('function prepareKey()'):SCRIPT.index('function keyDone()')]
    assert "'Leave blank to keep ' + (state.conn.base_url || 'the current address')" in prepare


def test_coverage_shows_nobody_and_family_note():
    settings = settings_with_connections()
    text = section(coverage=connections.coverage(settings, {}))
    assert re.search(r'class="rz-pill rz-gap"[^>]*>\s*<strong>Review</strong>\s*nobody', text)
    assert re.search(r'class="rz-pill rz-gap"[^>]*>\s*<strong>Summaries</strong>\s*nobody', text)
    assert re.search(r'class="rz-pill rz-ok"[^>]*>\s*<strong>Triage</strong>\s*OpenAI · gpt-x', text)
    settings['roles']['reviewer'] = {'connection': OPENAI, 'model': 'gpt-y', 'family': 'gpt', 'timeout_seconds': 60}
    text = section(coverage=connections.coverage(settings, {}))
    assert 'same family' in text
    settings['roles']['reviewer']['family'] = 'claude'
    text = section(coverage=connections.coverage(settings, {}))
    assert 'different family' in text


def test_coverage_says_when_triage_is_set_on_the_server():
    settings = settings_with_connections()
    text = section(coverage=connections.coverage(settings, {'RZ_MODEL': 'override-model'}))
    assert 'set on the server' in text


def test_last_test_is_shown():
    settings = settings_with_connections()
    settings['connections'][OPENAI]['last_test'] = {'ok': False, 'error': 'ModelTimedOut', 'seconds': 1.0,
                                                    'jobs': ['proposer'], 'real_ts': 0.0, 'sim_ts': 0.0}
    text = section(rows=connections.rows(settings, {}, None, now_real_ts=0.0))
    assert 'Failed: ModelTimedOut' in text and 'Not tested' in text


def test_delete_dialog_text_is_the_consequence_sentence(owner_client):
    settings = settings_with_connections()
    local_settings.save(owner_client.config_path, settings)
    data = data_block(owner_client.get('/?view=settings&section=model').text)
    assert data['deletions'][OPENAI] == connections.deletion_consequences(settings, OPENAI)
    assert data['deletions'][OPENAI] == 'OpenAI does Triage. After deleting, nobody triages, so no cycle runs.'


def test_the_page_carries_the_confirmed_flag(served):
    port, config_path, site = served
    assert data_block(Client(port, site, 'owner', config_path).get('/?view=settings&section=model').text)['confirmed'] is True
    assert data_block(Client(port, site, 'unconfirmed', config_path).get('/?view=settings&section=model').text)[
        'confirmed'] is False


def test_the_tab_is_called_models():
    from ui.settings_view import SECTIONS
    assert SECTIONS['model'] == 'Models'


def test_the_provider_key_page_link_opens_safely():
    text = section()
    links = re.findall(r'<a [^>]*target="_blank"[^>]*>', text)
    assert links and all('rel="noopener noreferrer"' in a for a in links)


def test_the_key_field_asks_password_managers_to_keep_out():
    # What the markup can say. Whether a real password manager obeys was not checked (see the report).
    field = re.search(r'<input [^>]*id="rz-key"[^>]*>', section())[0]
    assert 'type="password"' in field and 'autocomplete="new-password"' in field and 'spellcheck="false"' in field
    assert 'data-1p-ignore' in field and 'data-lpignore="true"' in field
    assert 'value=' not in field and 'name=' not in field


def test_the_script_empties_the_key_box_before_leaving_step_2():
    # keyDone moves the key to memory and empties the box before the card is hidden; requests send
    # the held key, never the box; the model list is signed with an epoch, not the key.
    done = SCRIPT[SCRIPT.index('function keyDone()'):SCRIPT.index('function baseUrl()')]
    assert done.index("heldKey = fields.key.value;") < done.index("fields.key.value = '';") < done.index('enter(')
    assert SCRIPT.count('key: heldKey') == 3 and 'key: fields.key.value' not in SCRIPT
    assert "{ key: 'epoch ' + keyEpoch }" in SCRIPT


def test_every_answer_is_dropped_when_its_popup_is_gone():
    # Each awaited request checks the popup that asked is still the open one.
    assert SCRIPT.count('const mine = state;') == SCRIPT.count('await post(') == 4
    assert SCRIPT.count('if (state !== mine)') == 4
    begin = SCRIPT[SCRIPT.index('function begin('):SCRIPT.index('function whenConfirmed(')]
    assert 'button.disabled = false' in begin


def test_only_the_settings_view_builds_the_models_data(owner_client, monkeypatch):
    local_settings.save(owner_client.config_path, settings_with_connections())
    monkeypatch.setattr(connections, 'rows', lambda *a, **k: pytest.fail('the key file was read'))
    for path in ('/', '/?view=actions', '/?view=infrastructure'):
        r = owner_client.get(path)
        assert r.status == 200 and '?view=settings' in r.text


def test_every_control_in_the_dialog_is_a_real_button_or_input():
    dialog = re.search(r'<dialog.*?</dialog>', section(), re.S)[0]
    assert 'tabindex' not in dialog
    assert not re.search(r'<(div|span)[^>]*role="button"', dialog)
    assert dialog.count('type="button"') >= 10


# --- colours and links from the catalogue ----------------------------------------

def test_a_preset_colour_that_is_not_hex_never_reaches_a_style():
    bad = Preset('anthropic', 'Anthropic', 'A', 'red;background:url(https://x.invalid)', 'anthropic_messages',
                 'https://api.anthropic.com/v1', True, 'javascript:alert(1)')
    text = section(presets=(bad,) + presets()[1:])
    assert 'url(' not in text and 'red;' not in text and 'javascript:' not in text
    assert data_block(text)['presets'][0]['colour'] == connections_view.NEUTRAL
    assert data_block(text)['presets'][0]['key_page'] == ''


@pytest.mark.parametrize('field, value', [('colour', 'red'), ('colour', '#12345'), ('colour', '#1234567'),
                                          ('colour', '#12345g'), ('key_page', 'http://keys.example.invalid'),
                                          ('key_page', 'javascript:alert(1)')])
def test_the_catalogue_refuses_a_bad_colour_or_key_page(tmp_path, field, value):
    data = json.loads(Path(model_catalogue.__file__).with_name('model_catalogue.json').read_text())
    data['providers'][0][field] = value
    path = tmp_path / 'catalogue.json'
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        model_catalogue.load_presets(path)


def test_every_preset_colour_is_hex():
    assert all(re.fullmatch(r'#[0-9a-f]{6}', p.colour) for p in presets())


# --- the Models section posts only the policy ---------------------------------------

def model_form(token):
    fields = {'token': token, 'section': 'model', 'same_family_policy': 'wait'}
    for role in ('proposer', 'reviewer', 'summarizer', 'guard'):
        fields.update({role + '_format': 'openai_chat', role + '_endpoint': '', role + '_model': '',
                       role + '_family': '', role + '_ca_file': '', role + '_timeout_seconds': ''})
    fields.update(proposer_endpoint='http://127.0.0.1:11434/v1/chat/completions', proposer_model='m')
    return fields


@pytest.mark.parametrize('who', ['owner', 'tech'])
def test_the_page_may_not_post_the_per_role_model_fields(served, who):
    port, config_path, site = served
    client = Client(port, site, who, config_path)
    local_settings.save(config_path, settings_with_connections())
    before = config_path.read_bytes()
    r = client.post_form('/settings', model_form(client.csrf))
    assert r.status == 400
    assert config_path.read_bytes() == before


@pytest.mark.parametrize('who', ['owner', 'tech'])
def test_the_page_still_saves_the_same_family_policy(served, who):
    port, config_path, site = served
    client = Client(port, site, who, config_path)
    local_settings.save(config_path, settings_with_connections())
    page = client.get('/?view=settings&section=model').text
    form = re.search(r'<form method="post" action="/settings".*?</form>', page, re.S)[0]
    assert set(re.findall(r'name="([a-z_]+)"', form)) == {'token', 'section', 'same_family_policy'}
    r = client.post_form('/settings', {'token': client.csrf, 'section': 'model', 'same_family_policy': 'proceed'})
    assert r.status == 303
    after = local_settings.load(config_path)
    assert after['same_family_policy'] == 'proceed'
    assert after['roles'] == settings_with_connections()['roles']


def test_the_command_line_still_sets_the_role_fields(tmp_path):
    path = tmp_path / 'ws.settings.json'
    local_settings.save(path, local_settings.DEFAULTS)
    local.settings_set(path, 'model', ['proposer.endpoint=http://127.0.0.1:11434/v1/chat/completions',
                                       'proposer.model=m'])
    assert local_settings.load(path)['roles']['proposer']['model'] == 'm'


# --- the installed copy -----------------------------------------------------------

def test_the_installer_ships_the_view_and_its_script():
    assert {'ui/connections_view.py', 'ui/assets/connections.js', 'ui/assets/connections.css'} <= set(
        build_local_installer.FILES)


def test_the_section_brings_its_own_style_and_leaves_the_shared_theme_alone():
    theme = (Path(connections_view.__file__).parent / 'theme.css').read_text()
    assert '.rz-card' not in theme
    for text in (section(), section(owner=False)):
        assert text.startswith(f'<style>{connections_view.STYLE}</style>')


def test_the_view_renders_text_through_escape_only():
    # Every value from the settings, the catalogue or the server goes through html.escape(quote=True):
    # a quote in a name cannot end an attribute.
    text = section(name='Q" data-x="1')
    assert 'Q" data-x="1' not in text and html.escape('Q" data-x="1', quote=True) in text
