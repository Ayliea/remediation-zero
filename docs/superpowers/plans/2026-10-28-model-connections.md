# Model Connections Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the four per-role model forms with a connections list and a guided five-step popup that stores keys in an owner-only file, recommends jobs, and saves nothing that has not answered a test.

**Architecture:** A connection (provider, format, base URL, CA file, key source) is new settings state (v6); each job (role) points at one connection plus a model. Keys live behind a secrets port whose local implementation is `<database>.secrets.json` (0600). Pure modules decide endpoints, catalogue matches, recommendations and connection changes; `scripts/local.py` exposes them as small JSON routes for one bundled, hash-allowed script, and as `connection` commands.

**Tech Stack:** Python 3.12 standard library only (local edition runs with `python3 -S`); SQLite accounts store for audit events; plain HTML + one inline script.

**Spec:** `docs/superpowers/specs/2026-10-28-model-connections-design.md`

## Global Constraints

- Standard library only in every module the local edition imports. No new dependency of any kind.
- Every new module carries the Apache 2.0 header used in the repo (`# Copyright 2026 Daviyon Daniels` + 2 licence lines).
- A key never appears in a page, log line, audit event, settings file, `settings show`, a snapshot, an error message, an exception message, or the repository.
- Log lines are `_log(event, ...)` structured JSON naming the connection id and job (role) and the error class only.
- Persisted times (a connection's `last_test`) carry both `real_ts` and `sim_ts` from `SimClock`; runtime timers (rate limits, measuring answer time) use `time.monotonic()` and are never persisted, except the measured answer seconds as a plain number.
- Code keeps the role names `proposer`, `reviewer`, `guard`, `summarizer`. The UI says Triage, Review, Screening, Summaries (`JOB_NAMES` in Task 3).
- Endpoint rules are unchanged: `tools.model_transport.validate_endpoint` (HTTPS unless loopback; no credentials, query or fragment). No "skip TLS verification" option anywhere.
- Owner-only for every change; a tech gets 403 on every `/connections/*` POST. Every POST keeps the existing Origin / Sec-Fetch-Site checks and the session CSRF token.
- No page other than Settings → Models allows a script. That page's CSP is exactly: `default-src 'none'; script-src 'sha256-<hash>'; connect-src 'self'; img-src data:; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`.
- Same-family review is allowed and labelled, never blocked; family `other` counts as same family (`ModelRoles.independence()`).
- Do not change `tools/models/*` adapters' request bodies, retries or `post_json` behaviour (spec non-goal).
- Commits are signed; never add a `Co-Authored-By` or other Claude trailer. Commit at the end of each task.
- Run the suite with `.venv/bin/pytest -q`; local-edition modules must also import under `python3 -S` (`tests/test_local_edition.py` checks this; keep it green).

## Decisions this plan makes (the spec leaves them to the builder)

- **Connection URL is a base URL.** A connection stores `base_url` (e.g. `https://api.anthropic.com/v1`); each call URL is derived by `call_endpoint`. A v5 endpoint that does not end with its format's standard suffix migrates as `endpoint_style: "exact"` and is used verbatim; such a connection offers no model list ("Type a model name" only), and for `gemini_api` its model cannot be changed by Edit (the model is in the URL; Edit says to use Replace key to set a new address).
- **The script is inline**, read from `ui/assets/connections.js` at import, hashed with SHA-256, embedded in a `<script>` on the Models page only. No `src=`, so no SRI support question.
- **Network calls run outside `serial`.** A test can take minutes (`timeout_seconds` up to 600 per job). `/connections/*` routes load settings under `serial`, release it for model-list and test calls, then re-take `serial`, reload, and save only if the settings are unchanged since the first read (else 409, "Settings changed while testing. Nothing was saved."). One connection request in flight per session (as `/upload`).
- **Rate limit:** one `RateLimiter(per_minute=6)` for `/connections/models`, `/connections/test`, `/connections/save`, `/connections/edit`, `/connections/replace-key`, keyed by session account id. A refusal is 429 with `Retry-After`.
- **Replace key** is hidden for a connection whose every job takes its key from the environment.
- **Only `RZ_MODEL` / `RZ_MODEL_ENDPOINT` override fields** in the local edition today (`ModelRoles.from_settings`); they show as "set on the server" on Triage. The `RZ_<ROLE>_MODEL/ENDPOINT/FORMAT/FAMILY` variables are read only by `from_env` (cloud) and are not shown.
- **Audit events** go through a new public `Accounts.record_change`; detail key `connection` (display name) and `jobs` are added to `ALLOWED_DETAIL_KEYS`.

## Review Focus

1. A key containing characters a provider never uses (spaces, newline, non-ASCII, 2 KB long) → refused with one sentence before any call; never stored, never echoed. (Task 2 and Task 7 tests.)
2. The secrets file is deleted or hand-edited into invalid JSON while connections still say `stored` → the job fails with `StoredKeyMissing` (class name only) and the list shows "Key missing: replace it"; settings still load. (Task 2, Task 4.)
3. Two browser tabs: tab A deletes a connection while tab B's popup is testing an edit of it → B gets 409 and nothing is saved. (Task 7.)
4. A provider's model list returns 5,000 entries, non-string ids, or a 64 KB+ body → capped at 200 names, bad entries dropped, oversized body is `ValueError('Model response exceeds limit')` and the step offers typed name. (Task 1.)
5. A display name that collides case-insensitively ("anthropic" vs "Anthropic"), is blank, or holds markup → refused or escaped; CLI `connection test NAME` resolves names case-insensitively and refuses an ambiguous one. (Task 5, Task 9.)

---

### Task 1: Model-list transport and endpoint helpers

**Files:**
- Modify: `tools/model_transport.py` (add `get_json`; share error mapping with `post_json`)
- Create: `tools/model_endpoints.py`
- Test: `tests/test_model_endpoints.py`

**Interfaces:**
- Produces:
  - `model_transport.get_json(url: str, headers: dict, *, ca_file: str | None = None, timeout: float | None = None) -> object` — same opener (no redirects, no proxies, CA file), same size cap and same exception mapping as `post_json`.
  - `model_endpoints.SUFFIXES = {'openai_chat': '/chat/completions', 'anthropic_messages': '/messages', 'gemini_api': '/models/{model}:generateContent'}`
  - `call_endpoint(format: str, base_url: str, model: str, style: str = 'base') -> str` — `style == 'exact'` returns `base_url`; otherwise base + suffix, with the model URL-quoted (`urllib.parse.quote(model, safe='')`) for Gemini. Result passes `validate_endpoint`.
  - `split_endpoint(format: str, endpoint: str, model: str) -> tuple[str, str]` — `(base_url, 'base')` when `endpoint` ends with the suffix (Gemini: with this model), else `(endpoint, 'exact')`.
  - `MODEL_LIST_LIMIT = 200`, `MODEL_LIST_TIMEOUT = 15`
  - `list_models(format: str, base_url: str, key: str | None, ca_file: str | None = None) -> list[str]` — GET `base_url + '/models'` with the format's auth header (`Authorization: Bearer`, `x-api-key` + `anthropic-version: 2023-06-01`, `x-goog-api-key`); parses `{'data': [{'id'}]}` (OpenAI, Anthropic) or `{'models': [{'name': 'models/x', 'supportedGenerationMethods': [...]}]}` (Gemini: keep only those listing `generateContent`, strip `models/`). Drops non-string or >200-char ids, de-duplicates, sorts, caps at `MODEL_LIST_LIMIT`. Raises `ValueError('Model list could not be read')` on an unexpected shape. A key with `\r`, `\n` or non-printable-ASCII raises `ValueError('Invalid API key')` before any request.

- [ ] **Step 1: Write the failing tests** in `tests/test_model_endpoints.py`, using a stub opener (patch `tools.model_transport._open`), never the network:

```python
def test_call_endpoint_per_format():
    assert call_endpoint('openai_chat', 'https://api.openai.com/v1', 'gpt-x') == 'https://api.openai.com/v1/chat/completions'
    assert call_endpoint('anthropic_messages', 'https://api.anthropic.com/v1', 'c') == 'https://api.anthropic.com/v1/messages'
    assert call_endpoint('gemini_api', 'https://generativelanguage.googleapis.com/v1beta', 'gemini-x') == \
        'https://generativelanguage.googleapis.com/v1beta/models/gemini-x:generateContent'
    assert call_endpoint('openai_chat', 'http://127.0.0.1:8080/v1/chat/completions', 'm', 'exact') == \
        'http://127.0.0.1:8080/v1/chat/completions'

def test_split_endpoint_round_trips_and_keeps_unknown_shapes_exact():
    assert split_endpoint('openai_chat', 'http://localhost:11434/v1/chat/completions', 'q') == ('http://localhost:11434/v1', 'base')
    assert split_endpoint('gemini_api', 'https://g.example.invalid/v1beta/models/gemini-x:generateContent', 'gemini-x') == \
        ('https://g.example.invalid/v1beta', 'base')
    assert split_endpoint('gemini_api', 'https://g.example.invalid/v1beta/models/other:generateContent', 'gemini-x')[1] == 'exact'
    assert split_endpoint('openai_chat', 'https://h.example.invalid/complete', 'm') == ('https://h.example.invalid/complete', 'exact')

def test_list_models_sends_the_format_header_and_parses(stub_open): ...
    # anthropic: header x-api-key + anthropic-version; gemini keeps only generateContent models, strips 'models/'
def test_list_models_caps_drops_bad_ids_and_sorts(stub_open): ...
    # 5000 ids + a None + an int + a 300-char id -> 200 sorted strings
def test_list_models_refuses_a_bad_key_before_any_request(stub_open):
    for bad in ('a\nb', 'a b\r', 'kéy'):
        with pytest.raises(ValueError, match='Invalid API key'):
            list_models('openai_chat', 'https://api.openai.com/v1', bad)
    assert stub_open.calls == []
def test_get_json_maps_errors_like_post_json(stub_open): ...
    # 429 -> CapacityError; 401 -> ValueError('Model endpoint rejected request'); oversized -> ValueError('Model response exceeds limit')
def test_get_json_never_puts_the_key_in_an_exception_message(stub_open): ...
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_model_endpoints.py -q` — expect ImportError / failures.
- [ ] **Step 3: Implement** `get_json` by extracting `post_json`'s try/except body into one private `_exchange(request, seconds, ca_file)` both call; then `tools/model_endpoints.py`.
- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_model_endpoints.py tests/test_model_tls.py tests/test_model_roles.py -q` — PASS.
- [ ] **Step 5: Commit** `git add tools/model_transport.py tools/model_endpoints.py tests/test_model_endpoints.py && git commit -m "Read a provider's model list under the same transport rules as model calls"`

---

### Task 2: Secrets port and the owner-only key file

**Files:**
- Create: `tools/secrets_port.py` (the plug-in point: a `Protocol`)
- Create: `tools/local_secrets.py`
- Test: `tests/test_local_secrets.py`

**Interfaces:**
- Produces:
  - `secrets_port.SecretsPort` Protocol: `put(connection_id: str, key: str) -> None`, `get(connection_id: str) -> str | None`, `delete(connection_id: str) -> None`, `hint(connection_id: str) -> str | None`.
  - `secrets_port.check_key(key: str) -> str` — strips surrounding whitespace; refuses empty, longer than 4096, or any character outside printable ASCII 0x21–0x7E with `ValueError('An API key is one line of letters, digits and symbols')`. Returns the key.
  - `local_secrets.secrets_path(database) -> Path` — `Path(database).resolve().with_suffix('.secrets.json')` (beside `settings_path`).
  - `local_secrets.SecretsFile(path)` implements `SecretsPort`. File JSON: `{"version": 1, "keys": {id: {"key": str, "hint": str}}}`; `hint` is the last four characters, computed in `put`.
  - `local_secrets.SecretsFileUnsafe(Exception)` — message: `f'{path} must be readable only by its owner. Run: chmod 600 {path}'` (names the file, never its contents).
  - `local_secrets.StoredKeyMissing(Exception)` — raised by callers (Task 4) when a connection says `stored` but `get` returns None.
  - `local_secrets.Overlay(base: SecretsPort | None, pending: dict[str, str])` — a read-only `SecretsPort` whose `get`/`hint` answer from `pending` first, then `base`; `put`/`delete` raise `TypeError`. Used to test a draft's key before anything is stored.

Rules, all from the spec's "Key storage": created via `os.open(tmp, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0o600)` in the same directory, `fsync`, `os.replace`; every read opens with `O_NOFOLLOW`, `fstat`s, and raises `SecretsFileUnsafe` if `st_mode & 0o077` or `st_uid != os.getuid()`; no module-level cache; a missing file reads as empty; invalid JSON reads as empty for `get`/`hint` and is refused (ValueError, no contents in the message) for `put`/`delete`, so a broken file is never silently overwritten. Windows (`os.name == 'nt'`): skip the mode/uid check and document in the docstring that the file relies on the profile directory's ACL.

- [ ] **Step 1: Write the failing tests** (plus `test_overlay_answers_pending_first_and_refuses_writes`):

```python
def test_put_get_hint_delete(tmp_path):
    s = SecretsFile(tmp_path / 'ws.secrets.json')
    s.put('conn-1', 'sk-test-ABCD1234')
    assert s.get('conn-1') == 'sk-test-ABCD1234' and s.hint('conn-1') == '1234'
    s.delete('conn-1')
    assert s.get('conn-1') is None and s.hint('conn-1') is None

def test_file_is_created_0600(tmp_path): ...            # stat.S_IMODE == 0o600
def test_loosened_file_is_refused_naming_the_fix(tmp_path):
    # chmod 0o644 -> SecretsFileUnsafe; str(exc) contains 'chmod 600' and the path, not the key
def test_symlinked_file_is_refused(tmp_path): ...        # OSError (ELOOP) or SecretsFileUnsafe; target untouched
def test_broken_json_reads_empty_and_is_not_overwritten(tmp_path): ...
def test_no_temp_file_is_left_behind(tmp_path): ...
def test_check_key_refuses_unusable_keys():
    for bad in ('', '   ', 'a b', 'a\nb', 'kéy', 'x' * 4097):
        with pytest.raises(ValueError):
            check_key(bad)
    assert check_key('  sk-abc  ') == 'sk-abc'
def test_secrets_path_sits_beside_settings(tmp_path):
    assert secrets_path(tmp_path / 'ws') == settings_path(tmp_path / 'ws').with_name('ws.secrets.json')
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_local_secrets.py -q` — FAIL.
- [ ] **Step 3: Implement** both modules.
- [ ] **Step 4: Run** the same — PASS.
- [ ] **Step 5: Commit** `"Keep model keys entered in the browser in an owner-only file"`

---

### Task 3: Provider presets and the model catalogue

**Files:**
- Create: `tools/model_catalogue.json`
- Create: `tools/model_catalogue.py`
- Test: `tests/test_model_catalogue.py`

**Interfaces:**
- Produces:
  - `JOB_NAMES = {'proposer': 'Triage', 'reviewer': 'Review', 'guard': 'Screening', 'summarizer': 'Summaries'}`; `JOB_ORDER = ('proposer', 'reviewer', 'guard', 'summarizer')`.
  - `Preset` frozen dataclass: `id, name, letter, colour, format, base_url, needs_key: bool, key_page: str` (key_page empty for Ollama and Other).
  - `presets() -> tuple[Preset, ...]` in this order, with these values:

| id | name | letter | format | base_url | needs_key | key_page |
|---|---|---|---|---|---|---|
| anthropic | Anthropic | A | anthropic_messages | https://api.anthropic.com/v1 | yes | https://console.anthropic.com/settings/keys |
| openai | OpenAI | O | openai_chat | https://api.openai.com/v1 | yes | https://platform.openai.com/api-keys |
| gemini | Google Gemini | G | gemini_api | https://generativelanguage.googleapis.com/v1beta | yes | https://aistudio.google.com/apikey |
| openrouter | OpenRouter | R | openai_chat | https://openrouter.ai/api/v1 | yes | https://openrouter.ai/keys |
| ollama | Ollama | Ol | openai_chat | http://127.0.0.1:11434/v1 | no | (none) |
| other | Other | + | (chosen) | (typed) | optional | (none) |

    Colours: `#c96442`, `#111111`, `#4f7df3`, `#6d5bd0`, `#52525b`, `#a1a1aa`.
  - `preset(id: str) -> Preset` (KeyError on unknown); `preset_for(format: str, base_url: str) -> Preset` — the preset whose format and base URL match, else `other`.
  - `Entry` frozen dataclass: `provider, pattern, family, tier ('large'|'small'|'local'), strengths: str, cost ('higher'|'lower'|'free')`.
  - `match(provider: str, model: str) -> Entry | None` — first entry whose provider matches and whose `fnmatch.fnmatchcase(model.lower(), pattern)` matches; `provider == 'ollama'` with no entry match returns a generic local entry (family from `suggest_family`, tier `local`, cost `free`, strengths "Runs on your own server").
  - `family_for(provider, model) -> str` — the entry's family, else `model_roles.suggest_family(model)`.

  The JSON file holds `{"version": 1, "providers": [...], "models": [...]}`; the loader validates every field (unknown tier/cost/family → ValueError at import) so a bad edit fails the suite. Initial model entries are the builder's (spec: "Initial catalogue contents"), at least one `large` and one `small` pattern for each of anthropic, openai, gemini; strengths lines are one short sentence and claim nothing beyond tier and speed.

- [ ] **Step 1: Write failing tests**: presets order and the table's values; `preset_for('openai_chat', 'http://127.0.0.1:11434/v1').id == 'ollama'`; `preset_for('openai_chat', 'https://x.example.invalid/v1').id == 'other'`; `match` is first-match-wins and case-insensitive; unmatched cloud model → None; any Ollama model → tier `local`, cost `free`; every catalogue entry's family is in `FAMILIES`; a malformed JSON entry (write a temp file, call the loader on it) raises ValueError.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `"Ship provider presets and a small model catalogue"`

---

### Task 4: Settings version 6, migration, and key lookup

**Files:**
- Modify: `tools/local_settings.py` (v6 schema, v5→v6 upgrade, `validate`, `save`)
- Modify: `tools/model_roles.py` (`RoleConfig.connection`, `ModelRoles.secrets`, `from_settings`, `adapter`, `key_source`)
- Modify: `scripts/local.py` (`load_roles`; `apply_settings_form` / `settings_form` / `settings_set` for section `model`)
- Modify: every existing test that builds a v5 settings dict and passes it to `validate`/`save` (build v6 instead; do not weaken an assertion)
- Test: `tests/test_settings_v6.py`

**Interfaces:**
- Consumes: Task 1 `call_endpoint`, `split_endpoint`; Task 2 `SecretsFile`, `secrets_path`, `StoredKeyMissing`; Task 3 `preset_for`, `JOB_NAMES`.
- Produces:
  - Settings v6: `DEFAULTS['version'] == 6`, new top-level `connections: {}`. Connection value (exact field set):
    `{'name': str (1-60 chars, no control chars), 'provider': preset id, 'format': FORMATS, 'base_url': str, 'endpoint_style': 'base'|'exact', 'ca_file': str, 'key_source': 'stored'|'environment'|'none', 'last_test': None | {'ok': bool, 'error': str (exception class name or ''), 'seconds': float, 'jobs': [role,...], 'real_ts': float, 'sim_ts': float}}`.
    Connection id: `CONNECTION_ID_RE = re.compile(r'conn-[0-9a-f]{12}')`; `new_connection_id() -> str` uses `secrets.token_hex(6)`.
    Role value: `None | {'connection': id, 'model', 'family', 'timeout_seconds'}`; the id must exist in `connections`. Names unique case-insensitively. `call_endpoint(...)` of each role must pass `validate_endpoint`; `ca_file` rules as `RoleConfig` today.
  - `_upgrade_v5(value)`: each configured role becomes its own connection: id from `new_connection_id()`, name `f'{preset.name} ({JOB_NAMES[role]})'` (`preset_for(format, base_url)`), `split_endpoint`, `key_source` `'none'` for preset `ollama`, else `'environment'`, `last_test: None`. `load` upgrades v5 (and v1–v4 through v5) in memory; the next save writes v6. No job's format, call endpoint, model, family, CA file or timeout changes (test asserts `ModelRoles.from_settings` before == after for every role).
  - `RoleConfig` gains `connection: str = ''` (last field; ignored by `as_settings`, not in `provenance`).
  - `ModelRoles` gains `secrets: SecretsPort | None = field(default=None, repr=False, compare=False)`. `from_settings(settings, environ, secrets=None)` resolves each role through its connection with `call_endpoint`; the `RZ_MODEL`/`RZ_MODEL_ENDPOINT` override is unchanged. `adapter(role)` key order: environment names (`_key_names`) first; else if the connection's `key_source == 'stored'`: `secrets.get(connection)` and `StoredKeyMissing` if None; else no key.
  - `key_source(settings, role, environ) -> str` in `model_roles`: `'environment'` if `key_present(role, environ)`, else the connection's `key_source`.
  - `load_roles(database, environ)` passes `SecretsFile(secrets_path(database))`.
  - `apply_settings_form(values, 'model', fields)` accepts exactly `{'same_family_policy'}` (the new page) or `MODEL_FIELDS` (the CLI). With `MODEL_FIELDS`, each role with endpoint or model set reuses the connection with the same format, `split_endpoint` result and CA file, else creates one named as in `_upgrade_v5` (key source `none` for Ollama, else `environment`); a cleared role becomes None; its connection stays. `settings_form(values, 'model')` keeps returning `MODEL_FIELDS`, resolved through connections, so `settings set model proposer.model=X` still works.
  - `settings_shown` output never includes anything from the secrets file (it reads only settings).

- [ ] **Step 1: Write failing tests** in `tests/test_settings_v6.py`:

```python
def test_v5_file_migrates_with_no_change_to_any_job(tmp_path): ...
    # write a v5 file with proposer (ollama), reviewer (anthropic https://api.anthropic.com/v1/messages),
    # guard (exact custom URL); compare ModelRoles.from_settings(...) role by role before (v5 path) and after
def test_migrated_names_and_key_sources(tmp_path): ...  # 'Ollama (Triage)' none; 'Anthropic (Review)' environment
def test_save_writes_v6_and_validate_refuses_v5(tmp_path): ...
def test_role_must_point_at_an_existing_connection(): ...
def test_connection_names_are_unique_ignoring_case(): ...
def test_connection_fields_are_exact(): ...  # an extra 'key' or 'api_key' field is refused
def test_environment_key_wins_over_a_stored_key(tmp_path): ...
    # stored 'sk-stored-1111', env RZ_REVIEWER_API_KEY='sk-env-2222' -> adapter api_key == 'sk-env-2222'
def test_stored_key_is_used_when_no_environment_key(tmp_path): ...
def test_missing_stored_key_raises_stored_key_missing(tmp_path): ...
def test_settings_set_model_reuses_or_creates_a_connection(tmp_path): ...
def test_settings_show_never_reads_the_secrets_file(tmp_path): ...  # key text absent from json.dumps(settings_shown(...))
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_settings_v6.py -q` — FAIL.
- [ ] **Step 3: Implement**, then run the whole suite and convert each failing test that builds v5 settings in code to v6 (files written as v5 on disk stay v5: they now prove the migration).
- [ ] **Step 4: Run** `.venv/bin/pytest -q` — all PASS; `python3 -S -c "import tools.local_settings, tools.model_roles, tools.local_secrets"` succeeds.
- [ ] **Step 5: Commit** `"Move model settings to connections (settings version 6), with keys from the environment or the key file"`

---

### Task 5: Connection operations (pure, no HTTP)

**Files:**
- Create: `tools/connections.py`
- Test: `tests/test_connections.py`

**Interfaces:**
- Consumes: Tasks 1–4.
- Produces (all take and return plain settings dicts; none writes files; callers save):
  - `Draft` frozen dataclass: `provider: str, name: str, format: str, base_url: str, ca_file: str, key: str | None, jobs: dict[str, JobChoice]`; `JobChoice(model: str, family: str, timeout_seconds: int = 60)`.
  - `validate_draft(settings, draft, *, replacing: str | None = None) -> Draft` — name: strip, 1–60 chars, no control chars, unique ignoring case (except the connection being replaced); `check_key` when the preset needs one (or a key was given for Other); `validate_endpoint(call_endpoint(...))` for each job; CA file via `local_settings.check_ca_file`. Raises `ConnectionRefused(sentence)`.
  - `test_jobs(roles: ModelRoles, jobs: list[str], *, now=time.monotonic) -> TestResult` — `roles` is `ModelRoles.from_settings(with_connection(...), environ, secrets=Overlay(stored, {conn_id: draft.key}))`, so the draft's key is used without being stored; runs `tools.model_check._run(role, roles_after.adapter(role))` per job in `JOB_ORDER`, stops at the first failure; `TestResult(ok: bool, failed_job: str | None, error: str, seconds: float)`; `error` is `type(exc).__name__` or `_run`'s short name, never `str(exc)`.
  - `with_connection(settings, conn_id, draft) -> dict` — the settings as they would be after adding (or editing) the connection and assigning its jobs; `key_source` `'stored'` when `draft.key` is set, `'none'` for Ollama/no key.
  - `record_test(settings, conn_id, result, jobs, stamp) -> dict` — sets `last_test` with `stamp.real_ts`, `stamp.sim_ts` (a `SimClock` stamp).
  - `without_connection(settings, conn_id) -> dict` — removes it and every role pointing at it.
  - `deletion_consequences(settings, conn_id) -> str` — e.g. `'Anthropic does Review and Summaries. After deleting, nobody reviews, so new triage waits for a person.'`; per-job clauses: proposer "nobody triages, so no cycle runs"; reviewer "nobody reviews, so new triage waits for a person"; guard "nobody screens scanner text, so it is withheld from the models"; summarizer "nobody writes the cycle summary". A connection with no jobs: `'<Name> does no jobs. Deleting it changes nothing else.'`
  - `rows(settings, environ, secrets, *, now_real_ts: float) -> list[dict]` — `now_real_ts` is the caller's `time.time()`, used only to word "Tested <n> min ago" and never persisted; per connection: `id, name, provider, letter, colour, jobs: [{role, job, model, key: 'stored …1234' | 'set on the server' | 'no key needed' | 'key missing'}], key_hint, last_test_text ('Tested <n> min ago' | 'Failed: <Error>' | 'Not tested'), can_replace_key: bool`. Never the key.
  - `coverage(settings, environ) -> list[dict]` — per job in `JOB_ORDER`: `{role, job, connection name | None, model | None, family_note: 'different family' | 'same family' | None (Review only), overridden: bool (Triage when RZ_MODEL/RZ_MODEL_ENDPOINT set)}`.
  - `find_by_name(settings, name) -> str` (conn id) — case-insensitive; `ConnectionRefused` if none or ambiguous.

- [ ] **Step 1: Write failing tests**: name rules (blank, 61 chars, `"<b>"` accepted as text but `rows` returns it raw for the view to escape, duplicate "anthropic" vs "Anthropic" refused); `test_jobs` stops at first failure and reports class name only (adapter raising `ValueError('sk-secret-9999 rejected')` → `error == 'ValueError'`, and `'sk-secret-9999'` absent from `repr(result)`); nothing changes when a test fails (caller contract — assert `with_connection` is pure: input dict unchanged); `deletion_consequences` sentences above verbatim; `rows` per-job key source with env set for one job only (`"Review: set on the server · Summaries: stored …7Qx2"` data); `can_replace_key` False when all jobs env-sourced; `last_test_text` from `now_real_ts - last_test['real_ts']`; `find_by_name` ambiguity.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `"Add, edit, test and delete model connections as pure settings changes"`

---

### Task 6: Job recommendations

**Files:**
- Create: `tools/connection_advice.py`
- Test: `tests/test_connection_advice.py`

**Interfaces:**
- Consumes: Task 3 `match`, `family_for`, `JOB_NAMES`, `JOB_ORDER`; Task 5 `coverage`.
- Produces: `recommend(settings, *, provider: str, model: str, family: str, editing: str | None = None) -> list[Card]`, one per job in `JOB_ORDER`; `Card` frozen dataclass: `role, job, description, badge ('recommended'|'covered'|'not_suggested'), on: bool, reason: str, cost: str | None, same_family: bool, policy_note: str | None`. `editing` = the connection being edited: its own jobs count as uncovered-by-others for rules 1 and 3.

Rules, applied in this order (spec "Recommendations", verbatim intent):
1. Uncovered job → `recommended`, on. Triage's reason when uncovered: "Without triage no cycle runs."
2. Review: compare with the triage family *after this popup* (the chosen family when Triage is on by rule 1, else the current triage model's family; triage unset → independent). Differs and neither is `other` → `recommended` (when uncovered), reason names both families. Same family or `other` → `not_suggested`, off, `same_family=True`, reason: `'Same family as your triage model, so the record would read "reviewed by the same model family".'`; `policy_note`: `"With 'wait', triage waits for a person before anything is assigned."` or `"With 'proceed', it is assigned without waiting."` from `same_family_policy`.
3. Covered job (by another connection) → `covered`, off; reason names what switching on replaces, plus the knock-on when switching Triage on would make Review same family: `'OpenAI already does this. Switching on replaces it, and then Review would be the same family, which the record would say.'`
4. Tier: Triage/Review on a `small`/`local` tier keep their rule-1 badge with reason suffix "A stronger model would do this better." Screening/Summaries on a `large` tier when the job is covered by a `local`/`small`/lower-cost model → `not_suggested` with reason naming the cheaper one; uncovered → `recommended` with "A smaller model would be cheaper here, but this one works."
5. `cost` sentence from the entry: higher → "Costs more per finding.", lower → "Costs less per finding.", free → "Free, runs on your own server." Cost never changes `badge` or `on` (test: same inputs with cost flipped → same badges).
6. Unknown model (`match` is None) → rules 1–3 by family only; reason ends "We don't know this model's strengths."; `cost` None.

Job descriptions (fixed copy): Triage "Proposes severity, deadline and fix, citing evidence."; Review "Double-checks every triage proposal before anything happens."; Screening "Checks scanner text for tricks before any model reads it."; Summaries "Writes the plain-English report of each cycle."

- [ ] **Step 1: Write failing tests**: the jobs-step mockup scenario (OpenAI triage, Ollama screening, adding a large Anthropic model) → Review recommended/on, Summaries recommended/on, Triage covered/off with the knock-on sentence, Screening not_suggested/off; first connection ever (all gaps, one family) → Triage/Screening/Summaries on, Review not_suggested/off with `same_family` and the policy note for `wait` and for `proceed`; `other` family treated as same; covered job never starts on (property over every combination of covered sets); cost flip leaves badges; unknown model sentence; `editing` treats the edited connection's jobs as its own (no "replaces" sentence for them).
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `"Recommend jobs for a new model from coverage, family and tier"`

---

### Task 7: Audit events and the `/connections/*` routes

**Files:**
- Modify: `tools/accounts.py` (public `record_change`)
- Modify: `tools/account_store.py` (`ALLOWED_DETAIL_KEYS` += `"connection"`, `"jobs"`)
- Modify: `ui/account_views.py` (`_EVENT_NAMES` += the four events)
- Modify: `scripts/local.py` (routes, rate limiter, in-flight guard, outside-`serial` network calls, revision check)
- Modify: `tools/access.py` only if a new action name is needed (reuse the Settings write action; do not widen any role)
- Test: `tests/test_connection_routes.py`

**Interfaces:**
- Consumes: Tasks 2, 4, 5, 6.
- Produces:
  - `Accounts.record_change(actor_id: str, event: str, *, detail: dict, via: str, source: str | None) -> None` — stamps with `self.clock.now()`, writes through `store.insert_event`; `event` must be one of `CONNECTION_EVENTS = ('connection_added', 'connection_edited', 'connection_key_replaced', 'connection_removed')` (ValueError otherwise). Detail: `{'connection': display name, 'jobs': [role, ...]}`. Page wording: "Model connection added / edited / key replaced / removed".
  - JSON routes (POST only; `Content-Type: application/json`; body ≤ `local_auth.FORM_LIMIT`; body field `token` = session CSRF, checked with `secrets.compare_digest`; reply `application/json`, `Cache-Control: no-store`, never containing a key):

| Path | Body | Re-confirm | Rate-limited | Result |
|---|---|---|---|---|
| `/connections/confirm` | `token, password` or `token, code` | — | sign-in limiter (existing) | `{ok}`; calls `accounts.confirm` |
| `/connections/models` | `token, provider, base_url, ca_file, key` or `token, connection` | no | yes | `{models: [...], suggested: str or null}` or `{error: <sentence>}` |
| `/connections/recommend` | `token, provider, model, family?, editing?` | no | no | `{cards: [...], coverage: [...]}` |
| `/connections/save` | `token, draft` | yes | yes | tests switched-on jobs, then saves + stores key + audit `connection_added` |
| `/connections/edit` | `token, connection, jobs` | yes | yes | re-tests changed jobs; key not asked; audit `connection_edited` |
| `/connections/replace-key` | `token, connection, key, base_url?, ca_file?` | yes | yes | tests every job of the connection with the new key, then replaces; audit `connection_key_replaced` |
| `/connections/test` | `token, connection` | no | yes | records `last_test` only |
| `/connections/delete` | `token, connection` | yes | no | removes connection, roles, stored key; audit `connection_removed` |

  - An unconfirmed session on a re-confirm route gets `401 {"confirm": true}` and nothing is done (the popup asks in place, Task 8).
  - Network work (`list_models`, `test_jobs`) happens with `serial` released: load settings under `serial` and keep a deep copy; release; call; re-take `serial`; `local_settings.load` again; if it differs from the copy → `409 {"error": "Settings changed while testing. Nothing was saved."}`; else save settings, then `SecretsFile.put` (save) — on `put` failure, restore the earlier settings file and answer 503. A delete removes the key after the settings save.
  - One `/connections/*` request in flight per session (set keyed by `session.csrf`, as `/upload`) → 409 with `Retry-After`.
  - Tech → 403 on every route above except none (all are owner-only, including `/connections/test` and `/connections/models`).
  - Failure replies name the job and error class (`{"error": "Review failed: ModelTimedOut", "hint": PROBLEM_HINTS.get(...)}`); log `_log('connection_test_failed', connection=id, role=..., error=Class)`.

- [ ] **Step 1: Write failing tests** with the existing in-process server fixtures in `tests/test_local_server.py` / `tests/test_local_sign_in_server.py` (reuse their helpers for a signed-in owner and tech session) never the network: `scripts/local.py` calls `connections.test_jobs` and `model_endpoints.list_models` as module attributes, so tests `monkeypatch.setattr` those two:
  - save with a passing fake → connection, roles and stored key exist; audit row `connection_added` with detail name and jobs.
  - save with one failing job → 200 `{ok: false, failed_job}`; settings file bytes and secrets file unchanged.
  - unconfirmed save → 401 `{"confirm": true}`, nothing written; after `/connections/confirm` with the password, the same body saves.
  - tech → 403 on all eight routes; missing/wrong token → 403; wrong Origin → 403; non-JSON → 400.
  - the 409 revision race (Review Focus 3): patch `test_jobs` to modify the settings file mid-test.
  - rate limit: the 7th `/connections/test` in a minute → 429 with `Retry-After`.
  - **Key sweep** (the spec's first test that matters): with key `sk-sweep-QX7Z9` run add, edit, replace-key, test, delete, a failing test and a refused body; assert the key is absent from every response body and header, every captured log record (`caplog`), every `account_events` row, the settings file, `settings show`, and `store.snapshot()`; and present only in the secrets file between add and delete.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_connection_routes.py -q` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_connection_routes.py tests/test_local_server.py tests/test_local_sign_in_server.py tests/test_local_accounts_cli.py -q` — PASS.
- [ ] **Step 5: Commit** `"Serve model connection changes as owner-only JSON routes, tested before anything is saved"`

---

### Task 8: The Models page, the popup and its script

**Files:**
- Create: `ui/connections_view.py`
- Create: `ui/assets/connections.js`
- Modify: `ui/settings_view.py` (section `model` renders `connections_view.models_section(...)`; tab label "Models"; drop the per-role forms; the same-family policy form stays, below the coverage strip, posting section `model` with only `same_family_policy`)
- Modify: `scripts/local.py` (`_send_html(..., script_hash=None)`; the Models GET sends the script CSP; the page gets rows, coverage, presets, `confirmed` flag)
- Modify: `ui/theme.css` or the inline style block the settings page uses (card look)
- Test: `tests/test_connections_view.py`

**Interfaces:**
- Consumes: Task 3 `presets`, Task 5 `rows`, `coverage`, `deletion_consequences`; Task 7 routes.
- Produces:
  - `SCRIPT: str` (file contents) and `SCRIPT_HASH: str` (`'sha256-' + base64(sha256(SCRIPT))`) computed at import in `ui/connections_view.py`.
  - `models_section(rows, coverage, presets, policy, token, *, owner: bool, confirmed: bool, deletions: dict[str, str]) -> str` — escapes every value with `html.escape(..., quote=True)`; embeds data as `data-*` attributes or one `<script type="application/json" id="rz-connections">` block (JSON with `<`, `>`, `&` escaped as `<` etc.; a JSON data block is not executed and needs no hash). The executable `<script>` contains exactly `SCRIPT`. No inline event handlers anywhere.
  - For a tech (`owner=False`): list and coverage only; no add/edit/replace/test/delete controls and no executable script.

Popup behaviour the script implements (spec "The add popup" and "Edit, replace, test, delete"; reference look: white rounded card, simple inline-SVG icon, bold centred title, one muted line, one light and one dark button; lettered tiles):
1. Opening (+ Add, Edit, Replace key, Delete) when `confirmed` is false shows the confirm card first (password or code, one box filled) posting to `/connections/confirm`.
2. Step 1 tiles filtered by the search box (name match, case-insensitive); "Where do I find this?" is `<a target="_blank" rel="noopener noreferrer">`. Other asks format and base URL.
3. Step 2 key: `<input type="password" autocomplete="off" spellcheck="false">`; Ollama shows the address field instead. Advanced: base URL override and CA file.
4. Step 3 calls `/connections/models` once on entry; shows catalogue line and "Suggested"; "Type a model name" always available; on error shows the sentence and the typed-name field.
5. Step 4 calls `/connections/recommend`; renders the coverage strip and one card per job with icon, name, description, badge, reason, cost, policy note, and a switch (`role="switch" aria-checked`); recommended start on.
6. Step 5 Test posts to `/connections/save` (or `edit` / `replace-key`); a `401 {"confirm": true}` shows the confirm card in place and then retries the same request with the same in-memory values; success card "<Provider> is connected!", answer seconds, what it now does, buttons "Add another" and "Done" (Done reloads the page).
7. Back keeps every typed value; Cancel and Escape close and clear the key from memory (assign `''` and drop references).
8. Keyboard: the dialog is a `<dialog>` opened with `showModal()`, focus moves to the card's first control, Tab stays inside, every control is a real button/input.

- [ ] **Step 1: Write failing tests**:

```python
def test_models_page_csp_allows_exactly_the_script_hash(owner_client):
    r = owner_client.get('/?view=settings&section=model')
    csp = r.headers['Content-Security-Policy']
    assert f"script-src '{SCRIPT_HASH}'" in csp and "connect-src 'self'" in csp
    assert hashlib.sha256(SCRIPT.encode()).digest() == base64.b64decode(SCRIPT_HASH.split('-', 1)[1])
    assert SCRIPT in r.text

def test_no_other_page_allows_a_script(owner_client):
    for path in ('/', '/?view=actions', '/?view=settings&section=scanner', '/?view=accounts', '/signin', '/confirm?next=/'):
        assert 'script-src' not in owner_client.get(path).headers.get('Content-Security-Policy', '')

def test_no_inline_event_handlers_or_eval():
    assert not re.search(r'\son[a-z]+\s*=', models_section(...))
    assert 'eval(' not in SCRIPT and 'new Function' not in SCRIPT and 'innerHTML' not in SCRIPT

def test_tech_sees_list_and_coverage_without_controls_or_script(tech_client): ...
def test_names_and_models_are_escaped(): ...      # a connection named '<img src=x>' renders as text
def test_list_shows_hint_never_key(): ...          # 'ends in …1234', never 'sk-…'
def test_coverage_shows_nobody_and_family_note(): ...
def test_delete_dialog_text_is_the_consequence_sentence(): ...
```

  `innerHTML` is banned in the script so model names and reasons from the server are always inserted as text (`textContent`), never parsed.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.**
- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_connections_view.py tests/test_local_server.py -q` — PASS. Then the real check: start the local edition per CLAUDE.md (`python3 -S -m scripts.local --database <scratch ws> serve`), sign in, and click through add (Ollama on loopback if it is running, else a refused key showing the error path), Back, Escape, keyboard-only Tab order, Edit, Delete; record what was checked in the task report, including anything not checked.
- [ ] **Step 5: Commit** `"Show model connections as a list with a guided popup to add one"`

---

### Task 9: `connection` commands, docs and CLAUDE.md

**Files:**
- Modify: `scripts/local.py` (`_parser`: `connection list|add|replace-key|test|remove`; `main` dispatch)
- Modify: `CLAUDE.md` (Commands list)
- Modify: `docs/development/local-edition.md` (models section: connections, the key file, at-rest protection, env vars still win; the table of `RZ_*_API_KEY` stays)
- Modify: `ui/settings_view.py` storage section copy: "API keys are read from the environment" → "API keys come from the environment or from the owner-only key file beside the settings file; back it up with the same care."
- Test: `tests/test_connection_cli.py`

**Interfaces:**
- Consumes: Tasks 2–7 (`Draft`, `validate_draft`, `test_jobs`, `with_connection`, `record_test`, `without_connection`, `deletion_consequences`, `rows`, `find_by_name`, `Accounts.record_change`, `local_accounts.resolve_as`).
- Produces:
  - `connection list` — one line per connection: `name  provider  key(hint | set on the server | no key needed)  jobs(Job: model, ...)`; works without `--as`.
  - `connection add PROVIDER [--name N] [--endpoint BASE_URL] [--ca-file PATH] [--format F (Other only)] --jobs triage,review,screening,summaries --model M [--family F] [--timeout S] --as EMAIL` — key read with `getpass.getpass('API key (not shown): ')` when the preset needs one; there is no key flag. Tests, then saves; prints `'<Name> is connected. It now does Review and Summaries.'` or `'<Job> failed: <Error>. Nothing was saved.'` (exit 1).
  - `connection replace-key NAME --as EMAIL`, `connection test NAME` (no `--as`; records `last_test`), `connection remove NAME --as EMAIL` (prints `deletion_consequences` first and asks `Type the name to delete:`; `--yes` skips the prompt).
  - `--as` must resolve to an active owner (as `exception accept`); audit events use `via='command_line'`.

- [ ] **Step 1: Write failing tests**: add with a patched `getpass` and a fake tester → saved and audited; `--key` is not an accepted flag (argparse exits 2); the key is absent from stdout/stderr and from `connection list`; tech `--as` refused; `remove` without `--yes` and a wrong typed name changes nothing; `test` on an ambiguous or unknown name prints one sentence and exits 1.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement**, then update CLAUDE.md Commands with:

```bash
python3 -S -m scripts.local connection list                                 # name, provider, key hint or "set on the server", jobs
python3 -S -m scripts.local connection add PROVIDER --jobs triage,review --model M --as EMAIL  # asks for the key at a hidden prompt; tests before saving
python3 -S -m scripts.local connection replace-key NAME --as EMAIL
python3 -S -m scripts.local connection test NAME
python3 -S -m scripts.local connection remove NAME --as EMAIL
```

  and the `--help` subcommand list line (`... | settings | connection`).
- [ ] **Step 4: Run** `.venv/bin/pytest -q` — full suite PASS.
- [ ] **Step 5: Commit** `"Add connection commands and document where model keys live"`

---

## Not in this plan (spec non-goals, kept out)

Downloading local models; real provider logos; the cloud edition's key store implementation; the wider Settings refresh and moving Accounts under Settings; any change to how a configured model is called.
