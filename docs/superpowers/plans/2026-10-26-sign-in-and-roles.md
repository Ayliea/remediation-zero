# Sign-in and Roles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Accounts with mandatory MFA, owner and tech roles, invites by link, HTTPS served by the local edition itself, and an SSH command for every action, so the local edition can run as an appliance reached from other machines.

**Architecture:** New core modules in `tools/` hold the logic (passwords, TOTP, QR, account store, account service, permissions, TLS certificates) and know nothing about HTTP. `ui/account_views.py` renders the new pages as pure functions. `scripts/local.py`'s handler classifies each request (direct loopback, proxied, direct network), resolves its session and asks `tools/access.py` before doing anything. `scripts/local_accounts.py` holds the `account` and `settings` commands. Accounts live in `accounts.sqlite3`, which no agent stage can open.

**Tech Stack:** Python 3.12 standard library only (`hashlib.scrypt`, `hmac`, `secrets`, `ssl`, `sqlite3`, `http.server`), the `openssl` command for self-signed certificates, and Nayuki's QR Code generator (MIT), vendored.

**Spec:** `docs/superpowers/specs/2026-10-26-sign-in-and-roles-design.md`

## Global Constraints

- Local edition is standard-library only and runs with `python3 -S`; the only bundled third-party code is the vendored QR generator (owner approved).
- Every module carries the Apache 2.0 header; the vendored file keeps its own MIT header and gets its licence text beside it.
- Passwords 12–128 characters after NFKC normalisation, no character-class rules, refused if on the bundled breached list; scrypt hashes.
- TOTP: RFC 6238, HMAC-SHA1, 6 digits, 30 s, ±1 step, each step accepted once per account.
- 10 recovery codes, shown once, stored hashed, each spent on use.
- Session cookie `rz_session`: HttpOnly, SameSite=Strict, Path=/, Secure except on a direct loopback request with a loopback Host. Token 256 bits, stored hashed. Idle 30 minutes, absolute 12 hours.
- Re-confirm (password, or a fresh TOTP code) is valid 5 minutes.
- Lockout: 5 failures in 15 minutes lock the account 15 minutes. Per client address: 10 sign-in attempts a minute, then 429 with `Retry-After`.
- Invite and reset tokens: 256 bits, stored as SHA-256, single use, 7 days, revocable.
- Self-signed certificate: EC P-256, 825 days, SAN = every configured name and IP, files 0600 in the workspace.
- TLS 1.2 minimum. A non-loopback listen address always means HTTPS.
- Default listen `127.0.0.1`, port 8081: nothing changes for an existing install until set.
- Identical response and timing for an unknown email (a dummy scrypt runs).
- `account_events` and logs never carry passwords, codes, tokens, TOTP secrets or session ids.
- Every persisted account record and event carries `real_ts` and `sim_ts` (`SimClock`). Session and lockout expiry are runtime security timers and use `time.time()` **(ruling: they are not lifecycle records; CLAUDE.md allows process time for runtime concerns; they are persisted only so a restart and the CLI see them)**.
- The cloud edition is not wired to any of this; `engine/` changes are optional keyword arguments whose default writes exactly what it writes today (cloud golden fixtures unchanged).
- `--by` is removed from the local CLI's `approve` and `exception accept`; using it prints exactly: `--by was replaced by --as EMAIL, which must name an account.` The cloud's `scripts/exception.py` is not changed.
- Commit after each task; signed commits; no Claude attribution lines (the commit-msg hook rejects them).

## Review Focus

1. A TLS client that connects and never finishes the handshake must not stop the server answering anyone else → Task 9 test `test_a_stalled_handshake_does_not_block_other_clients`.
2. A proxied request carrying `Host: 127.0.0.1:8081` (curl through the tailnet) must not be treated as a local visit → Task 7 test `test_a_loopback_host_through_a_configured_proxy_is_not_local`.
3. Two concurrent invite acceptances or two uses of one recovery code must not both succeed → Task 4 test `test_a_token_or_code_is_spent_exactly_once_under_concurrency`.
4. A removed or demoted account's open browser tab must lose its rights on its next request, including when the change came from the CLI while the server runs → Task 7 test `test_a_cli_removal_ends_a_live_session_on_the_next_request`.
5. An owner who edits their own role must not leave the workspace with no owner → Task 4 test `test_the_last_owner_cannot_demote_themself`.

---

### Task 1: Passwords, TOTP and recovery codes

**Files:**
- Create: `tools/passwords.py`, `tools/totp.py`, `tools/vendor/__init__.py`, `tools/vendor/breached_passwords.txt`, `tools/vendor/BREACHED_PASSWORDS_SOURCE.md`
- Test: `tests/test_passwords_totp.py`

**Interfaces:**
- Produces:
  - `passwords.check_new(password: str) -> str` returns the NFKC-normalised password or raises `PasswordRefused(reason)` with reason in `{'too_short', 'too_long', 'breached'}`.
  - `passwords.hash_password(password: str) -> str`, format `scrypt$32768$8$1$<salt b64>$<hash b64>` (16-byte salt, 32-byte key, `maxmem=64*1024*1024`).
  - `passwords.verify(password: str, stored: str | None) -> bool`; with `stored=None` it runs one scrypt against a fixed dummy hash and returns False (timing equaliser).
  - `totp.new_secret() -> str` (20 random bytes, base32, no padding).
  - `totp.code_at(secret: str, step: int, digits=6) -> str`; `totp.step_for(ts: float) -> int`.
  - `totp.match(secret: str, code: str, now: float, last_step: int | None) -> int | None` returns the matched step if `code` matches step−1, step or step+1 and that step > `last_step`, else None.
  - `totp.otpauth_uri(secret: str, email: str, issuer='Remediation Zero') -> str`.
  - `passwords.new_recovery_codes() -> list[str]` (10 codes, `xxxxx-xxxxx`, lowercase base32), `passwords.recovery_hash(code: str) -> str` (SHA-256 hex of the code with `-` and spaces removed, lowercased).

- [ ] **Step 1: Write the failing tests**

```python
RFC_SECRET = base64.b32encode(b'12345678901234567890').decode()

@pytest.mark.parametrize('ts, eight', [(59, '94287082'), (1111111109, '07081804'),
    (1111111111, '14050471'), (1234567890, '89005924'), (2000000000, '69279037')])
def test_rfc6238_sha1_vectors(ts, eight):
    assert totp.code_at(RFC_SECRET, totp.step_for(ts), digits=8) == eight

def test_a_code_from_the_next_or_previous_step_matches_once():
    step = totp.step_for(1_000_000)
    code = totp.code_at(RFC_SECRET, step + 1)
    assert totp.match(RFC_SECRET, code, 1_000_000, None) == step + 1
    assert totp.match(RFC_SECRET, code, 1_000_000, step + 1) is None   # replay
    assert totp.match(RFC_SECRET, totp.code_at(RFC_SECRET, step + 2), 1_000_000, None) is None

@pytest.mark.parametrize('pw, reason', [('a' * 11, 'too_short'), ('a' * 129, 'too_long')])
def test_length_rules(pw, reason): ...  # PasswordRefused.reason == reason

def test_twelve_plain_lowercase_letters_are_fine():
    assert passwords.check_new('horsebattery') == 'horsebattery'   # not on the list, no class rules

def test_a_listed_password_is_refused():  # first ≥12-char entry of the bundled list
    ...

def test_hash_round_trip_and_format():
    stored = passwords.hash_password('correct horse battery')
    assert stored.startswith('scrypt$32768$8$1$') and passwords.verify('correct horse battery', stored)
    assert not passwords.verify('correct horse batterz', stored)

def test_unknown_account_still_runs_scrypt(monkeypatch): ...  # hashlib.scrypt called once for stored=None

def test_recovery_codes_are_ten_distinct_and_hash_ignores_format():
    codes = passwords.new_recovery_codes()
    assert len(set(codes)) == 10 and all(re.fullmatch(r'[a-z2-7]{5}-[a-z2-7]{5}', c) for c in codes)
    assert passwords.recovery_hash(codes[0].upper().replace('-', ' ')) == passwords.recovery_hash(codes[0])
```

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_passwords_totp.py -v`. Expected: FAIL, modules missing.

- [ ] **Step 3: Implement.** TOTP uses `hmac.new(key, struct.pack('>Q', step), 'sha1')`, dynamic truncation per RFC 4226; comment the SHA-1 deviation as the spec words it. The breached list holds only entries of 12–128 characters (shorter ones are already refused), one per line, NFKC-lowercased, deduplicated, from a licence-compatible public list. Name the source, its licence and the filter in `BREACHED_PASSWORDS_SOURCE.md`. Comparison is case-insensitive. Load lazily into a frozenset. Keep it under 2 MB.

- [ ] **Step 4: Run** the same command. Expected: PASS.

- [ ] **Step 5: Commit** `git commit -m "Add password hashing, TOTP and recovery codes for local sign-in"`

### Task 2: Vendored QR generator and SVG rendering

**Files:**
- Create: `tools/vendor/qrcodegen.py` (Nayuki's Python implementation, unmodified apart from a header line naming the upstream commit), `tools/vendor/QRCODEGEN_LICENSE.txt`, `tools/qr_svg.py`, `THIRD_PARTY_NOTICES.md`
- Test: `tests/test_qr_svg.py`

**Interfaces:**
- Produces: `qr_svg.qr_svg(text: str) -> str` returns an `<svg>` element: one `<path>` of dark modules and a quiet zone of 4 modules, ECC level M, `viewBox` sized to the matrix, no script and no external references.

- [ ] **Step 1: Write the failing tests**

```python
def test_an_otpauth_uri_renders_as_one_inline_svg_path():
    svg = qr_svg.qr_svg(totp.otpauth_uri(totp.new_secret(), 'owner@client.example'))
    assert svg.startswith('<svg') and svg.count('<path') == 1
    assert 'script' not in svg.lower() and 'href' not in svg.lower()

def test_the_matrix_matches_the_vendored_generator():
    q = qrcodegen.QrCode.encode_text('otpauth://totp/x?secret=ABC', qrcodegen.QrCode.Ecc.MEDIUM)
    assert f'viewBox="0 0 {q.get_size() + 8} {q.get_size() + 8}"' in qr_svg.qr_svg('otpauth://totp/x?secret=ABC')

def test_the_vendored_file_is_the_recorded_upstream_file():
    assert hashlib.sha256(Path('tools/vendor/qrcodegen.py').read_bytes()).hexdigest() == RECORDED_SHA256
```

`RECORDED_SHA256` is the hash of the vendored file as committed. Name the upstream commit in `THIRD_PARTY_NOTICES.md`.

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_qr_svg.py -v`. Expected: FAIL.

- [ ] **Step 3: Vendor and implement.** Download `python/qrcodegen.py` and `LICENSE` at a tagged release from `github.com/nayuki/QR-Code-generator` into an empty scratch directory. Read it in full: it must import only the standard library and must not touch the network or files. Then copy it in. `THIRD_PARTY_NOTICES.md` names the project, version, URL, MIT licence and the vendored path. **The README is public-facing: do not edit it.** Report "README third-party line pending owner confirmation" in the task report instead.

- [ ] **Step 4: Run** the same command. Expected: PASS.

- [ ] **Step 5: Commit** `git commit -m "Vendor Nayuki's MIT QR generator and render MFA setup codes as inline SVG"`

### Task 3: Account store

**Files:**
- Create: `tools/account_store.py`
- Modify: `tools/local_layout.py` (add `ACCOUNTS_FILE = "accounts"`; `Workspace.accounts_path()`; `init()` creates it 0600; it is in neither `AGENT_FILES` nor `SHARED`, so `docs_for` cannot reach it)
- Test: `tests/test_account_store.py`

**Interfaces:**
- Produces `AccountStore(path)` over plain `sqlite3` (WAL off, `busy_timeout=10000`, `BEGIN IMMEDIATE` for every write). Tables:
  - `accounts(id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, role TEXT CHECK(role IN ('owner','tech')), status TEXT CHECK(status IN ('invited','active','removed')), password_hash TEXT, totp_secret TEXT, last_totp_step INTEGER, failed_count INTEGER DEFAULT 0, first_failed_at REAL, locked_until REAL, real_ts REAL, sim_ts REAL, updated_real_ts REAL, updated_sim_ts REAL)`
  - `recovery_codes(account_id, code_hash, spent INTEGER DEFAULT 0, PRIMARY KEY(account_id, code_hash))`
  - `invites(token_hash TEXT PRIMARY KEY, kind TEXT CHECK(kind IN ('join','reset_password','reset_mfa','recover')), email TEXT, role TEXT, account_id TEXT, created_by TEXT, totp_secret TEXT, expires_at REAL, used INTEGER DEFAULT 0, revoked INTEGER DEFAULT 0, real_ts REAL, sim_ts REAL)`
  - `sessions(token_hash TEXT PRIMARY KEY, account_id TEXT, csrf TEXT, created_at REAL, last_seen REAL, confirmed_until REAL)`
  - `account_events(id INTEGER PRIMARY KEY, event TEXT, actor_id TEXT, subject_id TEXT, via TEXT, source TEXT, detail TEXT, real_ts REAL, sim_ts REAL)`
- Methods: `transaction()` is a context manager yielding a cursor inside `BEGIN IMMEDIATE`. The thin queries the service needs are `account_by_email`, `account_by_id`, `active_owner_count`, `count_accounts`, `insert_event` (JSON `detail` from a dict whose keys are checked against an allowlist), `events(limit=200)`, `spend_invite(token_hash, now) -> row | None` and `spend_recovery_code(account_id, code_hash) -> bool`. The two `spend_*` methods are single `UPDATE … WHERE used=0 / spent=0` statements checked by `rowcount`.

- [ ] **Step 1: Write the failing tests:** `test_accounts_file_is_private_and_unreachable_by_every_stage`, which asserts mode 0600, and that for each stage in `STAGE_WRITES`, `ws.docs_for(stage)` raises `KeyError` for each of the four collection names; `test_email_is_unique_case_insensitively`, where emails are stored lowercased; `test_event_detail_refuses_secret_keys`, where keys `password`, `code`, `token`, `secret` and `totp_secret` raise `ValueError`; `test_spend_invite_once`.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_account_store.py tests/test_local_layout.py -v`. Expected: the new tests FAIL, the existing ones pass.
- [ ] **Step 3: Implement.** Use `_private_file` before connecting, as for the other files.
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Keep local accounts in their own file that no agent stage can open"`

### Task 4: Account service and permissions

**Files:**
- Create: `tools/access.py`, `tools/accounts.py`
- Test: `tests/test_accounts.py`

**Interfaces:**
- Consumes: Tasks 1 and 3.
- Produces:
  - `access.ACTIONS = {'view', 'settings', 'upload', 'approve', 'accept_risk', 'manage_accounts', 'view_audit'}`. `access.allowed(role: str | None, action: str) -> bool` implements the spec's table: owner all, tech everything except `accept_risk`, `manage_accounts` and `view_audit`, None nothing. An unknown action raises `KeyError` (default deny).
  - `access.may_invite(inviter_role, invitee_role, owner_exists: bool) -> bool`: an owner may invite either role; a tech may invite only an owner, and only while `owner_exists` is False.
  - `Accounts(store: AccountStore, clock: SimClock, now=time.time)` with:
    - `setup_first(email, role, password, secret, code) -> list[str]` (recovery codes). Refuses `AccountRefused('accounts_exist')` if any account exists.
    - `invite(by_id, email, role) -> str` (raw token).
    - `reset_link(by_id, account_id, kind) -> str`, kind `reset_password` or `reset_mfa`, owner only, not for oneself.
    - `recover_owner(email, promote=False) -> str`, as the spec's `recover-owner` paragraph says, with `by_id=None` and via `command_line`.
    - `invite_view(token) -> InviteView | None`, where `InviteView(kind, email, role, totp_secret)` and a `join`, `reset_mfa` or `recover` invite gets a stored `totp_secret` on first view.
    - `accept_invite(token, password, code, *, current_password=None, current_code=None) -> tuple[str, list[str] | None]`, returning the account id and new recovery codes when MFA was (re)enrolled. `reset_password` needs a new password and the current TOTP code; `reset_mfa` needs the current password and a code from the new secret; `join` and `recover` need a new password and a code from the new secret.
    - `revoke_invite(by_id, token_hash)`, `set_role(by_id, account_id, role)`, `remove(by_id, account_id)`.
    - `owner_exists() -> bool`, which counts active owners only.
  - Every mutation writes one `account_events` row (event names: `setup`, `invite_created`, `invite_accepted`, `invite_revoked`, `reset_link_created`, `password_reset`, `mfa_reset`, `role_changed`, `removed`, `recover_owner`) and logs it with `_log`. Ending sessions: `remove`, `set_role`, `password_reset`, `mfa_reset` and `recover_owner` delete every session of the subject.
  - `AccountRefused(code)`, with codes `accounts_exist`, `not_allowed`, `last_owner`, `no_such_account`, `invalid_link`, `bad_code`, `password` (wrapping `PasswordRefused.reason`), `email_taken`.

- [ ] **Step 1: Write the failing tests.** One test per rule, with these names:
  - `test_permission_table_matches_the_spec` (parametrised over every role and action pair);
  - `test_unknown_action_is_denied`;
  - `test_first_account_only_once`;
  - `test_tech_may_invite_only_an_owner_and_only_before_one_exists`;
  - `test_pending_invite_is_not_an_owner`;
  - `test_the_last_owner_cannot_be_removed_or_demoted`;
  - `test_the_last_owner_cannot_demote_themself`;
  - `test_techs_cannot_reset_or_remove_anyone`;
  - `test_owner_cannot_reset_themself_by_link`;
  - `test_invite_expires_after_7_days`;
  - `test_revoked_invite_is_refused`;
  - `test_a_token_or_code_is_spent_exactly_once_under_concurrency` (two threads, each with its own `AccountStore` on one file; exactly one success);
  - `test_reset_password_needs_the_current_code`;
  - `test_reset_mfa_needs_the_current_password`;
  - `test_recover_owner_refuses_an_unknown_email_and_promotes_a_tech_only_with_promote`;
  - `test_resets_and_removal_end_every_session`;
  - `test_every_mutation_writes_one_event_without_secrets`.

  Use `SimClock` with a fixed sim time and inject `now` for the 7-day check.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_accounts.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Do each check-and-write inside one `store.transaction()`, so the last-owner rule cannot race.
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Add local accounts: roles, invites, resets and the last-owner rule"`

### Task 5: Sign-in, sessions, lockout and re-confirm

**Files:**
- Modify: `tools/accounts.py`
- Test: `tests/test_sign_in.py`

**Interfaces:**
- Produces:
  - `Accounts.sign_in(email, password, code, source) -> str | None` returns the raw session token, or None for any failure. There is one failure path: dummy scrypt for an unknown email, no difference for a locked account, and a `sign_in_failed` event whose `detail.email_sha256` is the hash of the typed email when unknown.
  - `Accounts.session(token) -> Session | None`, with `Session(account_id, email, role, csrf, confirmed: bool)`. It checks idle 30 min and absolute 12 h, and that the account is still `active`. It updates `last_seen`.
  - `Accounts.sign_out(token)`.
  - `Accounts.confirm(token, password=None, code=None) -> bool` sets `confirmed_until = now + 300`.
  - Constants: `IDLE_SECONDS = 1800`, `ABSOLUTE_SECONDS = 43200`, `CONFIRM_SECONDS = 300`, `LOCK_AFTER = 5`, `LOCK_WINDOW = LOCK_SECONDS = 900`.
  - `Accounts.actor_for(session) -> dict` returns `{'via': 'dashboard', 'account_id': …, 'verified': True}`. **Ruling:** today's dashboard has no approve or accept form (the console replacement, project 4, adds them), so this helper is built and tested here and used there. Approvals and acceptances made now come through the CLI with `verified: False`.
  - A lockout writes a `locked` event (subject = the account), so owners see it on the Accounts page.
  - `RateLimiter(per_minute=10, now=time.monotonic)` with `.hit(source) -> int | None` (None when allowed, else the Retry-After seconds). It's in memory, bounded to 10 000 sources by evicting the oldest.

- [ ] **Step 1: Write the failing tests**, with these names:
  - `test_sign_in_needs_all_three`;
  - `test_a_recovery_code_replaces_the_totp_code_once`;
  - `test_five_failures_lock_for_fifteen_minutes`, which includes a correct password while locked failing identically;
  - `test_unknown_email_takes_the_same_path`, which asserts scrypt is called once and the return value is identical;
  - `test_idle_and_absolute_expiry`;
  - `test_sign_in_issues_a_new_token_each_time`;
  - `test_confirm_lasts_five_minutes`;
  - `test_rate_limiter_returns_retry_after_and_evicts`;
  - `test_session_ends_when_the_account_is_removed_or_role_changes`;
  - `test_lockout_writes_a_locked_event`;
  - `test_actor_for_a_session_is_verified_dashboard`.

  Inject `now`.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_sign_in.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Session token: `secrets.token_urlsafe(32)`, stored as SHA-256 hex. CSRF: `secrets.token_urlsafe(32)` per session.
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Add sign-in with lockout, sessions and re-confirmation"`

### Task 6: Settings v5 and certificates

**Files:**
- Create: `tools/server_tls.py`
- Modify: `tools/local_settings.py`, `ui/settings_view.py`, `scripts/local.py` (application form fields)
- Test: `tests/test_server_tls.py`, `tests/test_local_settings.py`

**Interfaces:**
- Produces:
  - Settings `version: 5` with new top-level keys `listen_address` (default `'127.0.0.1'`, an IP literal including `0.0.0.0` and `::`), `server_names` (default `[]`, at most 20 host names or IPs, each validated with the same host rule as `public_origin`), and `certificate` (default `{'mode': 'self-signed', 'cert_file': '', 'key_file': ''}`; `mode` in `{'self-signed', 'own'}`; with `own`, both paths are absolute). `_upgrade_v4` adds the defaults.
  - `local_settings.exposed(settings) -> bool` is True when `listen_address` is not loopback.
  - `local_settings.check_certificate(cert_file, key_file)` is save-time only: it loads the pair into an `ssl.SSLContext(PROTOCOL_TLS_SERVER)` or raises `ValueError`. `local_settings.check_bindable(address, port)` binds and closes, raising `ValueError`.
  - `server_tls.ensure_self_signed(root: Path, names: list[str]) -> tuple[Path, Path]` creates or renews `server-cert.pem` and `server-key.pem` (0600) via `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 -subj /CN=<first name> -addext subjectAltName=…`. It renews when fewer than 30 days remain or the SAN set differs from `names`, and raises `NoOpenssl` when `shutil.which('openssl')` is None.
  - `server_tls.fingerprint(cert_path) -> str` is SHA-256 of the DER, as colon-separated uppercase hex.
  - `server_tls.server_context(cert, key) -> ssl.SSLContext` uses a TLS 1.2 minimum.
  - Settings page, application section: the three fields, the fingerprint when one exists, and the sentence `Listen address, names and certificate take effect when Remediation Zero restarts.` A save with a non-loopback address checks bindable and, for `own`, the certificate. Page refusals say `… Nothing was saved.` as the other forms do.

- [ ] **Step 1: Write the failing tests:**
  - `test_v4_settings_upgrade_to_v5_with_loopback_defaults`;
  - `test_listen_address_must_be_an_ip_literal`;
  - `test_own_certificate_needs_two_absolute_paths`;
  - `test_check_certificate_refuses_a_mismatched_key`;
  - `test_self_signed_names_every_server_name_and_ip`, which reads the SANs back with `ssl._ssl._test_decode_cert` and is skipped without openssl;
  - `test_self_signed_is_reused_and_renewed_when_names_change`;
  - `test_fingerprint_format`;
  - `test_no_openssl_raises_NoOpenssl`;
  - `test_settings_page_says_restart_required`.

  Update the existing v4 fixtures to v5 in the same way the v3→v4 change did.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_server_tls.py tests/test_local_settings.py -v`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement.** Pass the `openssl` arguments as a list, never through a shell. Names go into the SAN as `DNS:` or `IP:` after validation, so no free text reaches `-addext`.
- [ ] **Step 4: Run** the full suite, `.venv/bin/pytest -q`. Expected: PASS. Fix fixture fallout by sampling the failures, as CLAUDE.md asks.
- [ ] **Step 5: Commit** `git commit -m "Add listen address, server names and certificate settings (v5)"`

### Task 7: Signed-in requests in the dashboard server

**Files:**
- Modify: `scripts/local.py` (`handler`, `serve` wiring), `ui/dashboard_view.py` (signed-in name and sign-out button in the header; "No owner has joined yet, so risks cannot be accepted." when `owner_exists()` is False)
- Create: `ui/account_views.py` (sign-in, setup, invite, confirm and first-account-only pages; pure functions)
- Test: `tests/test_local_server.py`, `tests/test_local_sign_in_server.py` (new)

**Interfaces:**
- Consumes: Tasks 4–6.
- Produces:
  - `handler(..., accounts: Accounts, settings_exposed: bool, server_names: tuple[str, ...], scheme: str)`.
  - Request classification `_kind() -> 'local' | 'proxied' | 'direct'`:
    - `local`: a loopback peer, a loopback Host, no `--public-url` and not exposed.
    - `proxied`: a loopback peer and Host equal to the public host.
    - `direct`: Host is one of `server_names[:port]` over the TLS listener.
    - Anything else: 403, as today.
  - Client address: for `proxied`, the last `X-Forwarded-For` entry if it parses as an IP, else the peer; otherwise the peer.
  - Routes:
    - `GET/POST /signin`;
    - `POST /signout`;
    - `GET/POST /setup` (local only, no accounts);
    - `GET/POST /invite/<token>`;
    - `GET/POST /confirm?next=<path>`, where `next` must be a relative path from a closed set;
    - every existing route requires a session and `access.allowed`.

    Without a session, a GET redirects to `/signin` (or to `/setup` when local with no accounts). When there are no accounts and the request is not local, every page shows only the first-account page with the `account setup` command.
  - Expected POST Origin = the scheme and Host the request came in on (`http://127.0.0.1:PORT` for local, the public origin for proxied, `https://name[:port]` for direct). The per-form token becomes `session.csrf`; `/signin`, `/setup` and `/invite` use a short-lived pre-session token in a SameSite=Strict cookie `rz_pre`.
  - Settings saves and uploads need `confirmed`; otherwise 303 to `/confirm`.
  - The read-only proxy rule and `NO_SIGN_IN` go: proxied requests with a session get everything their role allows. Update the existing proxy tests to the new rule. This removal is in the approved design.
  - Cookie: `Set-Cookie: rz_session=…; HttpOnly; SameSite=Strict; Path=/` plus `; Secure` unless the kind is `local`.
  - 429 with `Retry-After` from `RateLimiter` on `POST /signin`, `/setup`, `/invite/*` and `/confirm`.

- [ ] **Step 1: Write the failing tests.** Use real sockets, as `tests/test_local_server.py` does, with these names:
  - `test_every_page_needs_a_session` (parametrise over the views, Settings and upload);
  - `test_setup_only_local_and_only_without_accounts`;
  - `test_a_loopback_host_through_a_configured_proxy_is_not_local`;
  - `test_no_accounts_through_the_proxy_shows_only_the_setup_command`;
  - `test_sign_in_sets_a_strict_httponly_cookie_and_secure_when_not_local`;
  - `test_a_tech_cannot_reach_owner_actions` (403 on the Accounts page and invite POST);
  - `test_settings_save_requires_reconfirm`;
  - `test_post_origin_must_match_the_way_in`;
  - `test_csrf_token_is_per_session`;
  - `test_forwarded_for_is_used_only_through_the_proxy`;
  - `test_sign_in_rate_limit_returns_429_with_retry_after`;
  - `test_unknown_email_and_wrong_password_return_identical_responses` (status, headers apart from Date, body);
  - `test_a_cli_removal_ends_a_live_session_on_the_next_request`;
  - `test_signed_in_proxy_gets_settings_back`.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_local_sign_in_server.py tests/test_local_server.py -v`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement.** Add no route that isn't listed; unknown paths stay 404 with or without a session. `log_message` stays silent, so invite tokens in paths never reach a log. Comment the cookie deviation, and the invite token in the path (single use, 7 days, `Referrer-Policy: same-origin`, not logged).
- [ ] **Step 4: Run** `.venv/bin/pytest -q`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Require sign-in for every dashboard page and form"`

### Task 8: Accounts page for owners

**Files:**
- Modify: `ui/account_views.py`, `scripts/local.py`
- Test: `tests/test_local_sign_in_server.py`

**Interfaces:**
- Consumes: Task 4's `Accounts` methods.
- Produces:
  - `GET /?view=accounts` (owner) lists accounts (email, role, status), pending invites (email, role, expiry) and the last 200 `account_events` with time, event, actor email, subject email and via.
  - POST forms, all re-confirmed:
    - `/accounts/invite` shows the link once on the response page;
    - `/accounts/revoke`;
    - `/accounts/role`;
    - `/accounts/remove`;
    - `/accounts/reset` (kind), which shows the link once.
  - Every refusal maps an `AccountRefused` code to one fixed sentence.
  - Records made before sign-in show as "recorded before sign-in" wherever an approver or accepter is shown: a record with no `actor` field.

- [ ] **Step 1: Write the failing tests**, with these names:
  - `test_owner_sees_accounts_invites_and_events`;
  - `test_invite_link_is_shown_once_and_works`;
  - `test_tech_gets_403_on_the_accounts_page_and_every_accounts_post`;
  - `test_last_owner_refusal_is_explained`;
  - `test_records_without_actor_say_recorded_before_sign_in`.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_local_sign_in_server.py -v`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Let owners manage accounts and read the audit trail in the dashboard"`

### Task 9: HTTPS listener and launcher

**Files:**
- Modify: `scripts/local.py` (`DashboardServer`, `serve`), `scripts/local_launcher.py`
- Test: `tests/test_local_https.py` (new), `tests/test_local_launcher.py`

**Interfaces:**
- Consumes: Task 6's `server_tls` functions and settings.
- Produces:
  - `DashboardServer(address, handler, tls_context=None)`. With a context, `get_request` returns the raw socket, and the handshake runs in the request thread under `IDLE_TIMEOUT`: wrap with `do_handshake_on_connect=False`, then `settimeout` and `do_handshake()`. A failed handshake closes quietly.
  - `serve` binds `settings['listen_address']` and `settings['port']`. When exposed, it ensures the certificate (self-signed or own) and serves TLS. Otherwise it serves plain HTTP on loopback, as today. `NoOpenssl` exits with `No openssl command was found, so a certificate cannot be made. Set your own certificate (settings set application certificate.mode=own …) or use a proxy.`
  - Banner lines: the existing first line for the URL (`https://<first server name or address>:<port>/` when exposed), then `Certificate fingerprint (SHA-256): …` when TLS. With no accounts, it also prints `No accounts yet. Create the first one on this server: python3 -S -m scripts.local --database DIR account setup`.
  - Launcher: when exposed, it never opens a browser, and prints the same lines. `is_ready_line` still matches the first line.

- [ ] **Step 1: Write the failing tests**, with these names:
  - `test_exposed_settings_serve_https_with_tls12_minimum` (skip without openssl; a TLS 1.1 client is refused);
  - `test_a_stalled_handshake_does_not_block_other_clients` (a socket that connects and sends nothing; a second client still gets a response within 5 s);
  - `test_plain_http_is_refused_on_the_tls_listener`;
  - `test_banner_prints_the_fingerprint_and_the_setup_command`;
  - `test_launcher_does_not_open_a_browser_when_exposed`;
  - `test_loopback_default_is_unchanged`.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_local_https.py tests/test_local_launcher.py -v`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `.venv/bin/pytest -q`. Expected: PASS.
- [ ] **Step 5: Commit** `git commit -m "Serve the dashboard over HTTPS on a network address, with a printed fingerprint"`

### Task 10: Account and settings commands, `--as` and recorded actors

**Files:**
- Create: `scripts/local_accounts.py`
- Modify:
  - `scripts/local.py` (parsers; `approve` and `exception accept` take `--as EMAIL`; `--by` is refused with the exact Global Constraints message, via a hidden `--by` argument that exits 2 with it);
  - `engine/approve.py` and `engine/sweep.py` (keyword `actor: dict | None = None`, written as `actor` only when given);
  - `tools/exception_store.py` (pass `actor` through);
  - `ui/dashboard_view.py` (the shown approve command uses `--as you@example.com`);
  - `docs/development/local-edition.md`, `CLAUDE.md` (commands list);
  - `scripts/build_local_installer.py` (`FILES` gains every new module, `tools/vendor/*` and the notices).
- Test: `tests/test_local_accounts_cli.py` (new), `tests/test_local_commands.py`, `tests/test_local_installer.py`

**Interfaces:**
- Consumes: Tasks 4–6.
- Produces:
  - Commands:
    - `account setup` (interactive via `getpass`; prints the key, the otpauth link and the recovery codes);
    - `account invite --email E --role owner|tech --as EMAIL` (prints the link built from the first server name, else `http://127.0.0.1:PORT`);
    - `account list`;
    - `account remove EMAIL --as EMAIL`;
    - `account set-role EMAIL ROLE --as EMAIL`;
    - `account reset-password EMAIL --as EMAIL` and `account reset-mfa EMAIL --as EMAIL` (print the link);
    - `account events [--limit N]`;
    - `account recover-owner --email E [--promote]`;
    - `settings show` (JSON, no secrets exist in settings);
    - `settings set SECTION FIELD=VALUE…`, which applies the same validation as the page, including `check_certificate` and `check_bindable`, and prints `Saved. Restart Remediation Zero for listen address, names or certificate changes to take effect.` when one of those changed.
  - `--as` must name an active account. `exception accept` needs an owner; a tech gets exit 1 with `Only an owner can accept a risk; EMAIL is a tech.` The record gets `actor = {'via': 'command_line', 'account_id': id, 'verified': False}`, and `accepted_by` / `approved_by` become the account email.

- [ ] **Step 1: Write the failing tests**, with these names:
  - `test_setup_creates_the_first_account_and_prints_recovery_codes` (feed `getpass` and `input`);
  - `test_setup_refuses_when_an_account_exists`;
  - `test_by_is_refused_with_the_replacement_message`;
  - `test_as_must_name_an_active_account`;
  - `test_a_tech_cannot_accept_a_risk_from_the_command_line`;
  - `test_cli_actor_is_recorded_unverified`;
  - `test_engine_records_are_unchanged_without_an_actor` (the cloud golden fixture still passes);
  - `test_settings_set_validates_like_the_page`;
  - `test_settings_set_says_restart_required`;
  - `test_recover_owner_prints_a_link_and_records_the_event`;
  - `test_installer_bundle_runs_account_setup` (build to a temp path, run the installer, and import `tools.accounts`, `tools.vendor.qrcodegen` and `tools.server_tls` with `-S`).
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_local_accounts_cli.py tests/test_local_commands.py tests/test_local_installer.py -v`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement.** Update `local-edition.md` with a "Sign-in and remote access" section: setup, invites, roles, recovery, HTTPS (self-signed with fingerprint check, own certificate, proxy), the CLI `--as` rule and what "not verified" means, and the code-boundary note for `accounts.sqlite3`.
- [ ] **Step 4: Run** `.venv/bin/pytest -q && python3 -S -m scripts.verify_local_install`. Expected: all pass, then `PASS`.
- [ ] **Step 5: Commit** `git commit -m "Add account and settings commands; name the person on approvals and acceptances with --as"`

### Task 11: Live check on the server

Not a code task; the controller runs it after the final review, with the owner.

- [ ] Restart the lab launcher container from the branch with `--public-url https://aylieadevsvr.tailb3baf1.ts.net:8081`. The page shows only the first-account command. Run `account setup` in the container, then sign in from another tailnet machine. Settings now open through the proxy.
- [ ] Invite a tech by link and sign in as them in a private window. The Accounts page gives 403, and `exception accept --as tech@…` is refused.
- [ ] In a throwaway container on Docker's default bridge (never the rz-lab network), set `listen_address=0.0.0.0`, `server_names=[rz.test]` with port 18443, then restart. The banner shows a fingerprint; `curl --cacert` with the generated certificate succeeds; `openssl s_client -tls1_1` is refused.
- [ ] Report to the owner. Merging and pushing are theirs to approve.
