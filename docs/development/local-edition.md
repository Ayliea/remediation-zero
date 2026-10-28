# Local edition

The local edition runs the whole remediation lifecycle on one machine: triage,
review, ownership, chase, risk acceptances, rescans and reports. It uses SQLite
and models you configure. It needs Python 3.12 or newer and nothing from pip,
and it makes no cloud calls. Python 3.12 on Linux is the tested runtime;
Windows and macOS have not been exercised.

Demo data is synthetic. A connected install keeps its owner's scan data on that
machine. It leaves only for destinations the owner sets up: the configured model
endpoints receive finding details for triage, and a ticket tracker, if one is
configured, receives ticket text. Updating enrichment downloads public CVE data
and sends at most CVE identifiers.
Never commit a real report or a workspace. It is still not a scanner: it reads
results from scanners you already run.

## Single-file installer

Download `install-remediation-zero.py` from the supplied development bundle and
run `python3 install-remediation-zero.py` (Windows: `py -3.12
install-remediation-zero.py`).

- The installer shows its plan and asks before it creates files.
- It bundles the application files, downloads nothing, installs no packages,
  asks for no credentials and calls no model.
- It installs into a new `RemediationZero` directory under your home
  directory, starts the dashboard in demo mode and opens the browser.
- It accepts `--directory`, `--no-start` and `--yes`, and never overwrites an
  existing directory. There is no upgrade or migration path. A failed install
  may leave a partial new directory; inspect it before removing it.
- The installer is unsigned. Its embedded SHA-256 checks detect corruption,
  not a malicious replacement of the installer itself.

The installer does not ship the synthetic corpus (`data/`) or the enrichment
cache (`data/cache/`). See "Seed" and "Enrichment cache" below.

Restart with `python3 /path/to/RemediationZero/start-remediation-zero.py`.
Its flags are `--saved` or `--demo`, `--database DIR`, `--no-browser` and
`--port PORT`. Stop it with Ctrl+C.

Build an installer from reviewed source:

```bash
python3 -S -m scripts.build_local_installer /absolute/path/install-remediation-zero.py
python3 -S -m scripts.verify_local_install
```

## Commands

Every command takes `--database DIR`, the workspace folder. The default is
`remediation-zero`. Run them from the repository or installation folder:

```bash
python3 -S -m scripts.local init                     # create the workspace
python3 -S -m scripts.local seed --corpus DIR        # load findings, assets, owners
python3 -S -m scripts.local cycle --cycle N          # triage, chase, sweep, report
python3 -S -m scripts.local rescan --cycle N --scan PATH --dry-run   # what would close
python3 -S -m scripts.local rescan --cycle N --scan PATH             # apply it
python3 -S -m scripts.local exception accept FINDING --ttl DAYS --as OWNER_EMAIL \
    --reason TEXT --cycle N [--approved-by-person]
python3 -S -m scripts.local exception list
python3 -S -m scripts.local approve FINDING --cycle N --as EMAIL
python3 -S -m scripts.local serve [--demo] [--port PORT]
python3 -S -m scripts.local check-models [--role ROLE]
python3 -S -m scripts.local update-enrichment
python3 -S -m scripts.local greenbone tasks
python3 -S -m scripts.local greenbone test
python3 -S -m scripts.local greenbone pull [--cycle N]
python3 -S -m scripts.local greenbone upload FILE [--add-task] [--cycle N]
python3 -S -m scripts.local account setup             # the first account, on this server
python3 -S -m scripts.local account invite --email E --role owner|tech --as EMAIL [--public-url URL]
python3 -S -m scripts.local account list
python3 -S -m scripts.local account set-role EMAIL owner|tech --as EMAIL
python3 -S -m scripts.local account remove EMAIL --as EMAIL
python3 -S -m scripts.local account reset-password EMAIL --as EMAIL [--public-url URL]
python3 -S -m scripts.local account reset-mfa EMAIL --as EMAIL [--public-url URL]
python3 -S -m scripts.local account events [--limit N]
python3 -S -m scripts.local account recover-owner --email E [--promote] [--public-url URL]
python3 -S -m scripts.local settings show
python3 -S -m scripts.local settings set SECTION FIELD=VALUE...
```

Only `cycle` and `check-models` call a model, and a hosted endpoint may charge
for both. `seed`, `rescan`, `exception` and `approve` work with no model
configured. `cycle` with no proposer configured exits with
`no proposer configured: set one in Settings, then run the cycle again`
before it creates or writes anything.

- **seed** loads `findings.json`, `assets.json` and `owners.json` from
  `--corpus`. In a repository checkout the default is `data/`. In an installed
  tree there is no `data/`, so `seed` without `--corpus` exits with
  `no corpus: pass --corpus DIR (findings.json, assets.json, owners.json)`.
  A folder missing any of the three files is refused. Both refusals create
  nothing.
- **cycle** first assigns any approved decision not yet assigned. It then
  triages only pending findings: open findings with no decision yet, and
  findings whose risk acceptance lapsed (each lapse is re-triaged once). Chase,
  the exception sweep and the report follow, in that order.
- **rescan** applies a follow-up scan file to a demo (seeded) workspace and is
  the only thing that marks a demo finding resolved. Read the dry run first: it
  writes nothing. In a workspace that imports from Greenbone it refuses ("This
  install imports from Greenbone; use greenbone pull or greenbone upload.") and
  writes nothing; there, only `greenbone pull`, `greenbone upload` (or the
  dashboard's upload) and the timer's pull resolve findings. Nothing else
  resolves a finding.
- **exception accept** records a risk acceptance that expires after `--ttl`
  days; the sweep in the next `cycle` past expiry reopens it. A KEV CVE needs
  `--approved-by-person`. `--as` must name an active owner account; a tech is
  refused with `Only an owner can accept a risk; EMAIL is a tech.` and nothing
  is written.
- **approve** records a person's approval of an `unreviewed` or
  `held_for_approval` decision. `--as` names an active account, owner or
  tech. See "Review" below.
- `--by` is gone from both: using it exits 2 with
  `--by was replaced by --as EMAIL, which must name an account.`
- **account** and **settings**: see "Sign-in and remote access" below.
- **serve** shows the dashboard and Settings on `http://127.0.0.1:8081` (the
  saved port; `--port` overrides it). With
  `--demo` it shows illustrative fixtures instead of saved records. Its first
  line is `Local synthetic preview: <url>` with `--demo` and
  `Local dashboard: <url>` for saved records. By default it binds
  only to loopback, over plain HTTP; a network listen address serves HTTPS
  instead (see "HTTPS on a network address" below). If the address or port
  cannot be used it exits with one sentence, such as
  `This machine cannot listen on 127.0.0.1:8081: the port is already in use.`
  Every page and form needs a signed-in account (password
  and authenticator code); with no account yet, a visit on the server itself
  (`http://127.0.0.1:PORT`, no `--public-url`) opens the first-account setup
  page, and any other visit shows only the setup command. Saving Settings or
  uploading a report asks for the password or a fresh code again first. A
  form or report must arrive within 15 seconds plus one second per 256 KiB
  (about 2 Mbit/s for a large report); a slower upload is cut off, so use
  `greenbone upload FILE` on the server for a large report over a slow link.
  - `--public-url https://NAME[:PORT]` (also accepted by the launcher) lets an
    HTTPS proxy in front, such as Tailscale Serve, nginx or Caddy, forward the
    dashboard to other machines. The server still listens only on 127.0.0.1;
    the option adds that one name to the Host names it answers. A signed-in
    session gets the full dashboard through it, Settings included, as its role
    allows; without a session every page asks for sign-in. With the option
    set, setup is never offered in the browser, even on 127.0.0.1, because a
    proxy also connects from there. The
    URL must be `https://` with a host name and an optional port and nothing
    after it; anything else is refused before the server starts. With the
    option set, `serve` prints a second line,
    `Also at <url> through your HTTPS proxy.`, saying every page there asks
    for sign-in. For Tailscale:

    ```bash
    sudo tailscale serve --bg --https 8081 http://127.0.0.1:8081
    python3 -S start-remediation-zero.py --saved --public-url https://HOST.TAILNET.ts.net:8081
    ```

    A proxy is still the simplest way to give the dashboard a certificate
    browsers already trust.

- **update-enrichment** downloads CISA KEV, FIRST EPSS and NVD data into the
  workspace cache. It is the one command that reaches the internet. The
  optional NVD key comes only from `NVD_API_KEY`.
- **greenbone** reads from your Greenbone server and never changes anything
  there. Credentials come only from `RZ_GREENBONE_USERNAME` and
  `RZ_GREENBONE_PASSWORD`; they are never saved or printed. If either is
  missing the command exits 2, names the variables and connects to nothing.
  Failures print the error class only. Task names come from the server, so they
  are stripped of control characters and cut to 80 characters.
  - `tasks` prints `task_id  name` for each task the account can see.
  - `test` prints the same three lines as the Settings page: connected,
    signed in, tasks listed.
  - `pull` imports the next finished report (the newest one the first time),
    at most one, for each chosen task and
    prints one line per task: the result, then findings added, resolved,
    skipped, refused and deferred, and in words any results not imported
    because another result on that host could not be read and any entries in
    Greenbone's report list that could not be read. A task whose last import's
    cycle has not completed prints "waiting for the previous cycle to finish".
    It exits 0 when every task imported, had nothing new, had already imported
    in this cycle, or is waiting for that cycle, and 1 otherwise. `--cycle` defaults to the next cycle number.
    With no task chosen it connects to nothing.
  - `upload FILE` imports an exported report by the same checks. The report's
    own task decides: if that task is not chosen the command stops with
    "Task <id> is not chosen for this install. Re-run with --add-task to add
    it." and writes nothing. With `--add-task` the task is added to the
    settings only after the report parses and the import succeeds. A refused
    import prints its reason and leaves the settings unchanged. Files over
    64 MiB are refused without being read.

A `--database` that names a single database file from an earlier version is
refused with "... is not a Remediation Zero workspace directory ...;
nothing was changed." It is not converted. Choose a new or empty folder.

## HTTPS on a network address

To reach the dashboard directly from other machines (a VM or a headless
server), set the listen address in Settings, Application, from a browser on
the server itself, and restart. `0.0.0.0` (or `::`) listens on every address;
a specific IP listens on that one. Any address that is not loopback always
means HTTPS, TLS 1.2 or newer, and never plain HTTP; a plain `http://` request
to that port is closed without an answer. In the same section:

- **Server names**: the host names and IPs people type to reach the server.
  The server answers only to these (and to `127.0.0.1` / `localhost` on its
  port); any other Host is refused with 403. Left empty, it uses this
  machine's host name, plus the listen address when that is a specific IP,
  or, for `0.0.0.0` or `::`, the machine's own addresses as its host name
  resolves (never loopback ones, and never an IPv6 address with a scope ID),
  so typing the server's IP works. The same list is in the certificate and on
  the `Answers to:` line `serve` prints.
  If neither gives a name, `serve` exits with
  `No server name is set, so a certificate cannot be made. Set the names people use to reach this server: settings set application server_names=NAME`.
- **Certificate**: `self-signed` (the default) or `own`.
  - Self-signed: at start, `serve` runs `openssl` to make an EC P-256 key and a
    certificate valid 825 days, naming every server name, as
    `server-cert.pem` and `server-key.pem` (both 0600) inside the workspace
    folder. It is reused on later starts, and made again when the names change
    or fewer than 30 days remain. Without `openssl` (usually Windows), `serve`
    exits with `No openssl command was found, so a certificate cannot be made. Set your own certificate (settings set application certificate.mode=own …) or use a proxy.`
  - Own: absolute paths to a PEM certificate (or chain, server certificate
    first) and its key. The pair is checked when saved and again at start; a
    file that cannot be loaded stops `serve` with a sentence naming the file,
    never its contents.

Started this way, `serve` prints:

```text
Local dashboard: https://NAME:PORT/
Answers to: NAME, 192.0.2.10
Certificate fingerprint (SHA-256): AB:CD:…
No accounts yet. Create the first one on this server: python3 -S -m scripts.local --database DIR account setup
```

`Answers to:` lists every name and address the server answers to; any other
is refused with 403. The last line appears only while there are no accounts; the first account
is created on the server itself, never through the network listener. A
loopback install started with `--public-url` prints the same line, since the
browser does not offer setup there either. A self-signed key or certificate
that will not load (a corrupt file, or one replaced without the other) is made
again at start; if that does not help, `serve` stops with a sentence naming
both files. A
browser warns about a self-signed certificate: compare the fingerprint it
shows with the printed one (also shown in Settings) before going on, so you
know the warning is for this server and not for something in between. The
launcher prints the same lines and never opens a browser for a network
address. Each connection runs in its own thread and has 15 seconds in all,
from being accepted to the end of its request headers, the TLS handshake
included, however slowly the bytes arrive; a client that connects and sends
nothing, or trickles a byte at a time, is cut off then and does not hold up
anyone else. At most 64 connections are served at once, on every listener
(loopback too). Of those, 16 are kept for loopback (the server itself and a
proxy such as Tailscale Serve), so other machines together hold at most 48,
and any one other address at most 16 (an IPv6 address counts under its
/64, since one host can rotate through those); loopback has no per-address cap,
since a proxy brings everyone in through 127.0.0.1. A connection over a cap
is closed as soon as it is accepted and logged as `connection_refused` with
the reason only, never the address. Each connection carries one request. A failed
handshake is logged as `tls_handshake_failed` with its error class only.

## Sign-in and remote access

Every dashboard page and form needs a signed-in account: an email, a
password (12 to 128 characters, not on the bundled list of breached
passwords) and a six-digit code from an authenticator app. Ten recovery codes
are shown once, at setup; each signs in once in place of a code.

- **First account.** Only while no account exists, and only on the server
  itself: `account setup` asks for the email, whether you are the business
  owner (`owner`) or an IT provider setting it up for a client (`tech`), and
  the password twice (never echoed). It prints the authenticator key and an
  `otpauth://` link, asks for a code, then prints the recovery codes. The
  setup page does the same in a browser on `http://127.0.0.1:PORT`, but only
  while the server listens on loopback with no `--public-url`. With any
  account present, `account setup` refuses with
  `An account already exists, so the first account cannot be created again.`
- **Invites.** An owner invites people (`account invite --email E --role
  owner|tech --as EMAIL`, or the Accounts page). Before any owner has joined,
  the installing tech may invite the owner, and nothing else. The link is
  shown once; it works once, expires after 7 days and can be revoked. The
  person opening it sets a password and an authenticator. Each time the page
  is opened it shows a new authenticator key, and the one on the page that is
  submitted is the one set up; no key is stored for a link, so something that
  fetched the link first (a mail scanner, a chat preview) never holds the
  account's second factor. A page opened before the server restarted no
  longer saves; it says "This page has expired. Open the link again." A
  removed person can be invited again: their
  account comes back with the same id, so older records still name them, and
  the audit trail says "invited again after being removed".
- **Roles.** An owner does everything, and is the only role that can accept a
  risk, manage accounts or read the audit trail. A tech works the findings,
  uploads reports, approves held decisions and changes Settings. The last
  active owner cannot be removed or made a tech.
- **Resets and recovery.** An owner can make a one-time link for someone else
  to set a new password (`account reset-password EMAIL --as EMAIL`) or a new
  authenticator (`account reset-mfa EMAIL --as EMAIL`), and can remove an
  account. A tech cannot reset anyone. When no owner can sign in,
  `account recover-owner --email E` on the server clears that owner's
  password and authenticator, ends their sessions and prints a link to set new
  ones; for a tech it does so only with `--promote`, which makes them owner.
  It never creates an account. There is no self-service password change or
  new-authenticator form yet: a signed-in person cannot change their own
  password or authenticator, and an owner cannot make a reset link for
  themself. An owner who has lost their phone signs in with a recovery code
  (each works once), then either asks another owner for an authenticator
  reset link (`account reset-mfa EMAIL --as OTHER-OWNER`, or the Accounts
  page), or, as the sole owner, runs `account recover-owner --email E` on the
  server and opens the printed link to set a new password and authenticator,
  which also gives ten new recovery codes. Do that before the recovery codes
  run out. To change a password, the same two ways apply: another owner's
  password reset link, or `recover-owner` on the server for the sole owner.
  Every one of these is recorded in the audit
  trail (`account events [--limit N]`, 1 to 1000, default 50, or the Accounts
  page), which never holds passwords, codes, tokens or secrets. Each event
  shows when, what, by whom, for which account, how (`dashboard` or
  `command_line`), from which address (the client address the sign-in rate
  limit uses; `—` when there is none, as for a command) and, for a role
  change or an owner recovery that promoted a tech, the old and new role.
- **Links** printed by the commands start with `https://<first server
  name>:<port>` when the saved listen address is a network one, and
  `http://127.0.0.1:<port>` otherwise. Behind a proxy, whose address is not
  saved, add `--public-url https://NAME[:PORT]` (checked as `serve
  --public-url` checks it) to `invite`, `reset-password`, `reset-mfa` or
  `recover-owner`, and the link starts with that address. Links go to the
  terminal only, never to a log.
- **HTTPS.** A network listen address always serves HTTPS (see "HTTPS on a
  network address"): a self-signed certificate whose SHA-256 fingerprint
  `serve` prints and Settings shows, so people can check the browser warning
  is for this server; or your own certificate and key; or keep listening on
  loopback and put an HTTPS proxy in front with `--public-url`. Use one mode
  or the other: a proxy in front of a network listen address (which speaks
  only TLS) must connect to it over HTTPS, for Tailscale Serve
  `https+insecure://127.0.0.1:PORT`; a plain `http://` backend gets only
  `tls_handshake_failed`.
- **HSTS.** With your own certificate, every response carries
  `Strict-Transport-Security: max-age=31536000` (no `includeSubDomains`, no
  preload). With the self-signed certificate it is not sent, a deliberate
  deviation from the web baseline: a browser that has seen HSTS for a name
  refuses the certificate warning's click-through, so the next renewal or
  name change would lock everyone out. The printed fingerprint is the check
  there instead.
- **Settings over SSH.** `settings show` prints the settings file as JSON
  (it holds no secrets; API keys and Greenbone credentials live only in the
  environment). `settings set SECTION FIELD=VALUE...` changes the
  `application`, `model` or `scanner` section through the Settings page's own
  validation, including the certificate pair check and the bind check for a
  network listen address. Nested fields are dotted (`certificate.mode=own`,
  `certificate.cert_file=/path`, `proposer.endpoint=URL`), lists are
  comma-separated (`server_names=rz.example.test,192.0.2.10`, `task_ids=...`)
  and a checkbox takes `true` or `false`. A change of listen address, names
  or certificate prints
  `Saved. Restart Remediation Zero for listen address, names or certificate changes to take effect.`
  If a change leaves the dashboard unreachable, `settings set` on the server
  is the way back.
- **`--as` on the command line.** Commands that change records take
  `--as EMAIL`, which must name an active account, and act with that
  account's role (a tech cannot remove anyone; only an owner can accept a
  risk). There is no password prompt, re-confirm or lockout there, because
  shell access to the server already reaches every file in the workspace.
  So the record says what is known: an approval or acceptance made this way
  carries `actor = {"via": "command_line", "account_id": ..., "verified":
  false}`, and account events say `via: command_line`. "Not verified" means
  the command named that account; nobody signed in as it. The dashboard
  records `{"via": "dashboard", ..., "verified": true}`. Records made before
  sign-in have no `actor`, and the dashboard says "recorded before sign-in".
- **Where accounts live.** `accounts.sqlite3` in the workspace (0600; the
  folder is 0700) holds accounts, hashed passwords, hashed recovery codes,
  hashed link and session tokens, and the audit trail. TOTP secrets are stored
  as they are: the standard library has no encryption, and whoever can read
  the file can already read every record. The file is outside every agent
  stage's store by construction: workspace creation only makes it, empty and
  0600, when it is absent, without opening it; only the dashboard server and
  the `account` and `--as` commands open it, never through an agent's
  docstore, so no stage can read or write it. A sign-in problem never stops
  the remediation lifecycle: `seed`, `cycle`, `rescan`, `greenbone` and
  `exception list` work even when the accounts file cannot be read. When it
  cannot be read or written, `serve`, the `account` commands and `--as` stop
  with `The accounts file could not be read or written. Nothing was changed.`
  before anything listens or is written.

## Model roles

There are four roles, shown in Settings as four jobs: Triage (proposer), Review
(reviewer), Screening (guard) and Summaries (summarizer). A **connection** is one
provider account or endpoint (a format, a base URL, an optional CA file and a
key) that can do any of the jobs; Settings -> Models lists the connections and
a popup adds, edits, tests, re-keys or deletes one. A connection is tested, job
by job, before it is saved; nothing is saved if a job fails. Only an owner can
change connections, and each change is recorded in the account audit trail.

| Role | Does | API key variable |
|---|---|---|
| proposer | Triage: severity, SLA, remediation, with cited evidence | `RZ_PROPOSER_API_KEY`, else `RZ_MODEL_API_KEY` |
| reviewer | Ratifies or rejects each proposal | `RZ_REVIEWER_API_KEY` |
| summarizer | Narrates the report's figures | `RZ_SUMMARIZER_API_KEY` |
| guard | Screens untrusted text before any model sees it | `RZ_GUARD_API_KEY` |

### Where API keys live

A key comes from the environment or from the key file:

- **Environment.** The variables in the table above. If a job's variable is set,
  it is used and wins over a stored key. A connection added without a key uses
  these ("set on the server" in the list, only for a job whose variable is
  set; otherwise "key missing", and Replace key stores one). A key typed for a
  job whose variable is set, or for Triage while `RZ_MODEL_ENDPOINT` sends it
  elsewhere, would never be tested or used, so the save is refused with a
  sentence naming the variable: unset it first, or connect without a key.
- **Key file.** A key typed in the Settings popup (or at the `connection`
  command's hidden prompt) is stored in `<database>.secrets.json`, beside the
  settings file. It is created readable only by its owner (0600), written
  atomically, and refused on read if it is group- or world-accessible, a
  symbolic link, or owned by someone else; the refusal names the
  `chmod 600` fix. A key is sent only to the address it was entered for:
  changing a connection's address or certificate asks for the key again.
- **At rest.** The protection is the file mode plus full-disk encryption of
  the host. There is no encryption with a key kept next to the file, because
  that would add nothing. Back the key file up with the same care as the
  database, and keep it out of anything shared.
- **Never** in the settings file, `settings show`, a record, a log line, the
  audit trail, an error message or a page. The list shows at most the last four
  characters of a stored key, and nothing for a short key.

### Connection commands

`python3 -S -m scripts.local connection` does on the server what Settings ->
Models does, through the same checks:

```bash
python3 -S -m scripts.local connection list
python3 -S -m scripts.local connection add openai --jobs review,summaries --model MODEL --as OWNER_EMAIL
python3 -S -m scripts.local connection replace-key NAME --as OWNER_EMAIL
python3 -S -m scripts.local connection test NAME
python3 -S -m scripts.local connection remove NAME --as OWNER_EMAIL
```

- `list` and `test` need no account. `add`, `replace-key` and `remove` need
  `--as EMAIL`, an active owner; the audit event says `via: command_line`.
- `add PROVIDER` takes `--name`, `--endpoint BASE_URL`, `--ca-file PATH`,
  `--format` (provider `other` only), `--jobs` (comma-separated: `triage`,
  `review`, `screening`, `summaries`), `--model`, `--family` and `--timeout`.
  It tests every chosen job and saves only if all pass.
- A key is never a command-line argument: it would reach shell history and the
  process list. The command asks at a hidden prompt, or reads the variable
  named by `--key-env VARIABLE` (`add` and `replace-key` both take it). An empty answer stores no key and the
  environment variables above are used. An argument the command does not
  know, including a mistyped `--key`, is refused with a fixed sentence that
  does not repeat what was typed.
- `remove` prints what deleting would stop, then asks for the connection's name
  to be typed; `--yes` skips the question.
- The command runs in its own process and cannot take the dashboard's settings
  lock. It refuses to save if the settings changed while it was testing, but a
  Settings save landing in the same instant could be overwritten; run it when
  nobody is changing Settings.

### Overrides, limits and checks

`RZ_MODEL_ENDPOINT` and
`RZ_MODEL` override the saved proposer connection (an overridden endpoint does
not inherit the saved CA file). HTTP is allowed only on loopback; a hosted
endpoint must use HTTPS (see "A model on another machine"). Redirects and inherited proxies are
disabled. Requests are capped at 32 KiB in, 64 KiB back and 2048 output tokens.
Each role has a timeout, 60 seconds unless set in Settings (5 to 600): a local
model on a CPU-only server, or one loading for its first request, can need
several minutes (a 3B model here needed 63 seconds to review cold). `check-models` sends the bundled synthetic
example to each configured role. No real provider was called during validation.

With no summarizer, the report stores the metrics and a marker saying no
summarizer is configured, in place of prose.

### A model on another machine

A model on another server is reached over HTTPS; plain `http://` works only on
loopback. If that server's certificate is self-signed or issued by your own CA,
set the role's **CA certificate file**: the absolute path, on the Remediation
Zero server, of that certificate or of the CA that signed it. That file is then
the only thing trusted for the endpoint (not the system's list), and the
certificate must still name the host in the endpoint URL. There is no setting
that skips verification: every request carries finding details and possibly an
API key. The file is checked when Settings are saved; a file that is missing or
holds no certificate is refused and nothing is saved.

Example: Ollama on another machine, with Caddy in front issuing a certificate
from its own local CA (`tls internal`).

```caddyfile
models.example.internal:11443 {
    tls internal
    reverse_proxy 127.0.0.1:11434 {
        header_up Host 127.0.0.1:11434
    }
}
```

Copy Caddy's root certificate (`<caddy data dir>/pki/authorities/local/root.crt`)
to the Remediation Zero server, then set the endpoint to
`https://models.example.internal:11443/v1/chat/completions` and the CA
certificate file to the copy's path. Make sure the Remediation Zero server
resolves the name (DNS or `/etc/hosts`).

`check-models` names a certificate problem and what to do about it:

| Line | Meaning |
|---|---|
| `failed (CertificateNotTrusted: ...)` | No CA file, or the wrong one |
| `failed (CertificateNameMismatch: ...)` | The certificate is for another name than the URL's host |
| `failed (CertificateExpired: ...)` | Expired or not yet valid |
| `failed (CertificateFileUnreadable: ...)` | The CA file is gone or holds no certificate |
| `failed (TLSRefused: ...)` | The server ended the handshake, often because it serves no certificate for that name |
| `failed (ModelTimedOut: ...)` | No answer within the role's timeout; raise it |

During a cycle a certificate problem or a refused handshake counts as an outage:
the finding is recorded unavailable and retried next cycle, never read as a
reviewer's verdict, and it is not retried in place, because waiting cannot fix
a certificate. A timeout is retried with backoff, like any other load.

## Review

Every decision records how independent its review was:

- **Cross-family**: the reviewer's family differs from the proposer's. A
  ratified decision is assigned and its SLA clock starts.
- **Same family**: proposer and reviewer are the same family (or either is
  `other`). The record and dashboard say "Reviewed by the same model family".
  The same-family setting in Settings decides what happens next. With `wait`
  (the default) a ratified proposal is held for a person
  (`held_for_approval`). With `proceed` it is ratified, and still labelled
  same-family.
- **Unreviewed**: no reviewer is configured. The decision is `unreviewed` and
  goes to the human queue.

A held or unreviewed decision is not assigned until a person approves it:

```bash
python3 -S -m scripts.local approve RZ-0002 --cycle 2 --as you@example.com
```

The approval is its own record. The decision keeps its outcome, models and
review label. The next `cycle` assigns it, and the dashboard shows the base
label plus "approved by" the person. A ratified, rejected or unavailable
decision cannot be approved. Neither can a closed finding, or a decision a
newer one has superseded.

An outage is not an answer. If a finding's newest decision is `unavailable`
(the reviewer could not be reached after its retries), or `human_queue`
because triage hit a capacity error (the note starts
`triage failed: CapacityError`), the next `cycle` triages it again, and so does
every later cycle until a model answers. The earlier record and its human
queue entry are kept. During a long outage this costs one failing call per
finding per cycle. A rejection, or a triage failure for any other reason,
stays with a person.

## Untrusted text

Scanner comments and advisory prose are untrusted. Each finding's text goes to
the guard model before triage. With no guard model configured, nothing is
screened, so untrusted text is withheld from the models: each model sees a
withheld notice in its place, and the structured fields. One exception: for a
Greenbone finding with no CVE, a test name that is plain text (after collapsing spaces, only ASCII
letters, digits, spaces and `.,:()/_+-`, at most 120 characters) is shown
unscreened, so a no-CVE finding is not triaged blind. Plain text can still be
worded as an instruction; the decision record carries
`screening.nvt_name_unscreened_strict` and the dashboard says "the test name
was shown because it is plain text". Any other name stays withheld. With a
guard configured, the name is screened with the notes as before.

## Permissions

The local permission boundary is enforced in the code by construction, not by
the operating system: one local user owns every workspace file. Each agent's
collections live in their own SQLite file, and each stage opens a store that
can write only its own collections. The reporting stage cannot write tickets.
Approvals have their own file (`approvals.sqlite3`), so `approve` opens the
findings file read-only. A workspace made before that file existed has its
approvals moved into it, in one transaction, the next time it is opened.
The workspace folder is 0700 and each database file 0600 on POSIX.

## Failed runs

If a finding's run raises, triage stops there, and the next `cycle` retries
it. Chase, the exception sweep and the report still run for that cycle,
because they read only what is already stored. The command then exits 1
with the triage error's class name. The failure is recorded once in
`failed_runs`:

| Field | Value |
|---|---|
| `finding_id` | The finding whose run stopped |
| `cycle` | The cycle number |
| `error_class` | The exception's class name only, never its message |
| `real_ts`, `sim_ts` | When it was recorded |

The dashboard lists these under "Runs that did not finish". The command line
prints only the class name too, because a message can carry an endpoint.

## Ticket delivery

Delivery is dashboard-only by default: tickets, nudges and escalations are
recorded and shown on the dashboard, and nothing leaves the machine. GitHub
issues are opened only when both `GITHUB_TICKET_REPO` and `GITHUB_TOKEN` are set.

## Enrichment cache

A cycle reads the workspace's own cache, `DIR/enrichment/` (CISA KEV, EPSS,
NVD), read only and offline. It is filled only by
`python3 -S -m scripts.local --database DIR update-enrichment`, the one command
that reaches the internet (or, with "Fetch enrichment automatically after an
import" on, by the timer after a Greenbone import).

- **Demo workspaces** (seeded findings, none from Greenbone): when the
  workspace cache is empty, the cycle reads the bundled demo cache
  `data/cache/` instead, as before. The installer does not ship it.
- **Greenbone workspaces** never read `data/cache/`: their enrichment comes
  only from the workspace cache, and is empty until `update-enrichment` runs.

When a source is absent from the cache the cycle reads:

- `cycle` logs `enrichment_absent` and prints a warning naming the cache path
  and the sources that were not checked.
- The triage prompt says the KEV status is unknown, not that the CVE is
  absent from KEV.
- Every risk acceptance requires `--approved-by-person`.

## Interval runner

Set "Run a cycle automatically every N minutes (0 = off)" on the Settings
page, under Application. It is saved as `cycle_interval_minutes` (a whole
number from 0 to 1440) in `<workspace>.settings.json`, the file beside the
workspace folder. With a value above 0, the launcher runs one cycle every
interval and calls your models. The launcher reads it at startup, so restart
it after a change. It also runs in demo mode. A run is skipped, not queued, while the
previous one is still going. A failed run is logged by class name, and the
runner continues. The default is 0, off.

Each run starts with the Greenbone pull, then runs the cycle. The pull reads the
chosen tasks (as `greenbone pull` does). If "Fetch enrichment automatically
after an import" is on and the pull added findings with new CVEs, it then
fetches enrichment for the CVEs in the imported report that the NVD cache does
not hold yet (new findings and earlier failed fetches). A failure in either step is logged by
class name and the cycle still runs. With no task chosen nothing is contacted
and nothing is logged. With tasks chosen but no credentials in the environment,
`greenbone_credentials_missing` is logged once per run.

## Dashboard

The dashboard shows the newest 60 decisions and failed runs, the newest 20
scans and 10 reports, and up to 60 queue items, SLA clocks, tickets and
exceptions. Older records stay in the workspace. Reading a page never calls a
model.

## Settings

Settings stores each role's connection, the same-family policy and the startup
preferences in `<workspace>.settings.json` beside the workspace folder. Saving
never contacts a provider. Saves require a signed-in session confirmed in the
last 5 minutes, a valid Host, a matching Origin and the session's form token;
`settings set` on the server applies the same checks to the values. Writes are atomic and private (0600 on POSIX). There is
no API key field and no database reset control. Sign-in is a password and an
authenticator code for every page (see "Sign-in and remote access"). The
dashboard listens on 127.0.0.1 unless a network listen address is set, which
is always served over HTTPS; or it stays on loopback behind an HTTPS proxy
with `--public-url`.

Stop every process before copying a workspace and its settings. Do not delete
storage to retry a failed request: rerunning a cycle reuses its checkpoints,
and a new cycle starts a new request budget. There is no global spending cap.

## Not yet built

There are no real scanner connectors, no import workflow and no in-place
upgrade. An Ayliea-hosted offering is a future direction; it would need
authentication, tenant isolation, hosted storage, billing and audit controls,
and none of those is implied here.
