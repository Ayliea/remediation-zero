# Sign-in and roles — design

Status: builder check done, owner answered its questions 2026-10-26; awaiting approval of the whole document. Release project 2 of 6 for the
local edition (see `2026-10-25-greenbone-connection-design.md`, "The release
this belongs to").

## Why

The local edition is an appliance **(owner)**: installed on a VM or headless
server inside the client's network and opened from people's own browsers,
like on-prem InsightVM or Darktrace. Today it has no sign-in, so it listens
only on `127.0.0.1`; through an HTTPS proxy (`--public-url`) it is read-only,
because a Settings visit signs in to Greenbone and a save could send those
credentials elsewhere. The owner hit this on 2026-10-26: signed in to
Tailscale and Greenbone, still no Settings. Without accounts there is also no
honest answer to "who accepted this risk".

## Decisions the owner made

- **One flow, roles as a label.** Whoever installs it creates the first
  account on the server and says what they are: the business owner, or an IT
  provider setting it up for a client. Everyone else is invited. An owner with
  no MSP simply signs in; an MSP tech invites the owner.
- **Invites are a copy-the-link** shown to the inviter, sent however they
  like. Sending email is later.
- **Roles:** owner (accountable; the only one who can accept a risk; can also
  do everything a tech does, since an owner with no MSP is the fixer) and tech
  (works the findings; cannot accept risk; cannot manage accounts).
- **Recovery:** recovery codes at MFA setup; **an owner** can reset another
  person's password or MFA and remove accounts; **techs cannot reset anyone,
  including other techs**; last resort is a reset command on the server.
  Every such action is recorded and shown to owners.
- **HTTPS served by Remediation Zero**, on a network address and port:
  a self-signed certificate made at first start, with the option to bring
  your own. Proxy mode stays.
- **Command line:** commands that change records name an account
  (`--as owner@client.example`) and are recorded "via the server's command
  line, as …, not verified by sign-in". A risk acceptance must name an owner.
- **Defaults** (owner agreed): passwords 12–128 characters, no
  character-class rules, checked against a bundled breached-password list,
  hashed with scrypt; TOTP mandatory for everyone, plus recovery codes;
  sessions end after 30 minutes idle or 12 hours; re-confirm before risky
  actions; HttpOnly, Secure, SameSite=Strict cookie; 5 failed sign-ins lock
  the account for 15 minutes, plus a per-address limit, with identical
  answers whether or not the email exists; an audit trail of every account
  event.

## Goals

- An MSP tech installs it on a client server, signs in from a laptop over
  HTTPS, invites the owner with a link, and both work in the full dashboard,
  Settings included, from their own machines.
- Every page and form requires a signed-in account, checked on the server,
  default deny; the role decides what each request may do.
- Risk acceptances and approvals record which account made them, and how
  (signed-in browser, or command line not verified).
- Lockouts are recoverable without losing the workspace.
- Every dashboard action has a command, so the appliance can be run over SSH.

## Non-goals

- Email sending (invites, alerts, password reset by email).
- The multi-client MSP dashboard and "one password per client account" rule
  (paid edition). Single sign-on, LDAP, WebAuthn/passkeys, SMS codes.
- Wiring sign-in into the cloud edition. It is built in the core so the paid
  layer can reuse it later; the cloud keeps its current access.
- Linking accounts to the `owners` reference collection that assets are
  mapped to. Greenbone assets still arrive unowned (known gap, project 3/4).
- Online breached-password checks (HaveIBeenPwned) — optional later.

## Anti-goals

- Any page, form, upload or Settings read reachable without a session.
- A record that names a person who did not act, or that calls a command-line
  action verified.
- An account system that leaks which emails exist.
- Password hashes, TOTP secrets or session tokens readable by the agents:
  the accounts file is opened only by the dashboard server and the account
  commands.
- A plain-HTTP network address that shows a password box.

## Design

### Accounts and roles

- An account: id (random, opaque), email (lowercased, unique), role
  (`owner` | `tech`), password hash, TOTP secret, recovery code hashes,
  status (`invited` | `active` | `removed`), created/updated on both clocks
  (`real_ts`, `sim_ts`; SimClock for sim). Removed accounts stay, marked, so
  records that name them still resolve.
- Permissions in one table in one module; every handler asks it
  **(designer's call)**:

| Action | Owner | Tech |
|---|---|---|
| View every dashboard page | yes | yes |
| Settings (model, scanner, application) | yes | yes |
| Upload a report, pull, approve a held review | yes | yes |
| Accept a risk | yes | no |
| Invite, remove, change role, reset password or MFA of others | yes | no |
| See the account audit trail | yes | no |

  Settings are open to techs because the MSP usually configures them
  **(designer's call)**; changing them re-confirms.
- At least one active owner must exist once an owner has joined: the last
  owner cannot be removed or demoted. Until any owner exists (an MSP tech set
  it up and the owner has not accepted the invite), risk acceptances wait,
  and the dashboard says "No owner has joined yet, so risks cannot be
  accepted."

### First account

- Only when no account exists. Two ways, both on the server itself
  **(owner: created on the server)**:
  - `python3 -S -m scripts.local account setup` (prompts for email, role,
    password; prints the TOTP key and otpauth link; asks for a code; prints
    recovery codes);
  - the setup page, served only when the request is on loopback **and the
    server is not exposed**: listening on loopback with no `--public-url`.
    A proxy such as Tailscale Serve also connects from 127.0.0.1, so the
    peer address alone cannot tell a local visit from a proxied one; with a
    proxy or a network listen address configured, setup is the command only
    **(designer's call)**.
- Never offered on a network address, so nobody on the network can claim it.
- **Existing workspaces** (records and a Greenbone connection, no accounts):
  until the first account exists, every page except setup shows only "Create
  the first account" with the command, and the launcher opens the setup
  page. Records made before sign-in keep their name and get no `actor`;
  the dashboard shows them as "recorded before sign-in" **(designer's
  call: never backfill a claim about who acted)**.

### Invites

- A pending invite is not a joined owner: it counts for neither the
  last-owner rule nor risk acceptance. A workspace with techs only keeps the
  "No owner has joined yet" notice for as long as that is true
  **(designer's call)**.
- An owner (or the first account, whatever its role, while no owner exists —
  so the installing tech can invite the owner) creates an invite: email and
  role. A tech can invite only an owner, and only while no owner exists
  **(designer's call: the MSP's bootstrap case and nothing more)**.
- The inviter sees a one-time link once: `https://<address>/invite/<token>`.
  The token is 256 bits, stored only as a SHA-256 hash, single use, expires
  after 7 days **(designer's call)**, revocable. Opening it: set password,
  set up MFA, see recovery codes, signed in.

### Signing in and MFA

- Email + password, then a 6-digit TOTP code (RFC 6238, 30 s, ±1 step,
  a code accepted once only). A recovery code may replace the TOTP code and
  is then spent.
- **TOTP uses HMAC-SHA1 (deviation from the baseline's "no SHA-1"):** it is
  the algorithm authenticator apps support; several ignore SHA-256 and
  silently produce wrong codes. HMAC-SHA1 in TOTP is not a collision use.
  Recorded in code comments.
- Enrolment shows a QR code, the key (base32) and an `otpauth://` link.
  **QR (owner: bundle a generator):** the standard library has no QR
  encoder, so Nayuki's QR Code generator (MIT) is vendored as one module
  under `tools/vendor/`, with its licence text and attribution kept and
  noted in the README's third-party section. Rendered server-side as inline
  SVG; nothing is installed and no request leaves the server.
- 10 recovery codes, shown once, stored hashed.
- **TOTP secrets are stored unencrypted (deviation):** the standard library
  has no AES. The accounts file is 0600 in the 0700 workspace; someone who
  can read it can already read every record. Recorded in code comments and
  docs.

### Sessions and requests

- Session token: 256 bits random, cookie `rz_session`, HttpOnly, Secure
  (omitted only on `http://127.0.0.1`), SameSite=Strict, Path=/. Stored as a
  hash. Idle 30 minutes, absolute 12 hours. A new token on sign-in (no
  fixation).
- **Cookie, not bearer token (deviation):** the baseline's rule is for APIs;
  a server-rendered page needs a cookie. Kept with the existing Origin and
  Sec-Fetch-Site checks and per-form tokens (now tied to the session).
- Sign-out, password change, MFA reset, role change and removal end that
  account's sessions (removal and resets: all of them).
- Re-confirm (password, or a fresh TOTP code) before: accepting a risk,
  changing a role, inviting, resetting or removing someone, changing
  Settings. Valid 5 minutes **(designer's call)**.
- Lockout: 5 failures in 15 minutes lock that account for 15 minutes; per
  source address, 10 sign-in attempts a minute, then 429 with Retry-After.
- **Source address behind a proxy (designer's call):** a request through the
  configured `--public-url` host comes from the proxy, so its client address
  is the last `X-Forwarded-For` entry, trusted only when the peer is loopback
  and the Host is the configured proxy name; otherwise the peer address. The
  address is used for the rate limit and the audit trail. The Secure-cookie
  exemption applies only to a direct loopback request with a loopback Host,
  never to a proxied one.
  The response and its timing are the same for an unknown email (a dummy
  scrypt runs). A locked account's owner sees it in the audit trail.
- Every page except sign-in, invite and (loopback only) setup requires a
  session; unknown paths are 404 either way.

### HTTPS and listening

- New application settings: listen address and port (default `127.0.0.1`,
  8081 as today, so nothing changes until set); certificate mode
  (`self-signed` | `own`), own certificate and key paths; the names the
  server answers to (host names and IPs people type).
- **Self-signed:** at first start with a network listen address, run
  `openssl` to make an EC P-256 key and certificate (SAN: every configured
  name and IP), in the workspace, 0600. Printed at start and on the Settings
  page: the SHA-256 fingerprint, so people can check the browser warning is
  for the real server. Renewed before expiry (validity 825 days,
  **designer's call**). No `openssl` (Windows): the server says so and asks
  for an own certificate or a proxy.
- **Own certificate:** paths to PEM certificate (chain) and key; checked on
  save.
- TLS 1.2 minimum. A network listen address always means HTTPS; plain HTTP
  only on loopback.
- Host check: loopback names, the configured names and the `--public-url`
  name; anything else 403, as today.
- **Proxy mode:** `--public-url` stays. With sign-in, the read-only rule for
  the proxied address goes: a signed-in session gets the full dashboard,
  Settings included, through the proxy.

### Audit trail

- Collection `account_events`: sign-in success and failure (email as typed,
  hashed when unknown), lockout, sign-out, invite created/accepted/revoked,
  password and MFA resets (who, whom), role changes, removals, recovery code
  use, setup and server-command resets. Both clocks, source address, account
  ids. Never passwords, codes, tokens or secrets.
- Shown to owners on an Accounts page; the same events go to the structured
  log.

### Command line (SSH)

- Account commands: `account setup`, `account invite --email --role`
  (prints the link), `account list`, `account remove`, `account set-role`,
  `account reset-password` and `account reset-mfa` (print a one-time link
  the person opens to set a new one), `account events`, and
  `account recover-owner --email` (the last-resort reset when no owner can
  sign in): for an active owner, clears password and MFA, ends their
  sessions and prints a one-time link to set new ones; for an active tech,
  does the same and makes them owner only with `--promote`; for an email with
  no account, refuses. It never creates an account (setup does, when none
  exist). Recorded as a server-command reset **(designer's call)**.
- Settings commands, so every Settings field can be set over SSH:
  `settings show` and `settings set <section> <field>=<value>…`, validated
  exactly as the page is.
- Listen address and certificate changes take effect on restart; the page
  and the command say "restart required". On save, the certificate and key
  must load together and the address must be bindable. If a change still
  leaves the dashboard unreachable, `settings set` on the server is the way
  back **(designer's call)**.
- Commands that change records take `--as EMAIL` (an active account; an
  owner where the dashboard requires one; no re-confirm or lockout on the
  command line, since shell access already reaches the files) and record
  `{"via": "command_line", "account_id": …, "verified": false}`. Existing
  `--by` on `approve` and `exception accept` is **replaced by `--as` now
  (owner)**: `--by` is removed, and using it fails with "--by was replaced
  by --as EMAIL, which must name an account." No local-edition users exist
  yet to keep compatible.
- **(Owner confirmed)** `--as` naming an active owner is enough to accept a
  risk from the command line: no password prompt or lockout there.
- Browser actions record `{"via": "dashboard", "account_id": …,
  "verified": true}`.

### Where the data goes (schema: needs owner approval)

- New workspace file `accounts.sqlite3` with collections `accounts`,
  `invites`, `sessions`, `account_events`. Opened only by the dashboard
  server and the `account` commands; no agent stage lists it, and the
  general read-all `docs_for` excludes it. **This is a code boundary, like
  the rest of the local edition's per-stage files:** agents and the
  dashboard run as the same OS user, so file permissions cannot separate
  them. The test asserts no stage can open it; the docs say so plainly
  rather than claiming process isolation.
- `exceptions` and `approvals` records gain an `actor` field
  (`via`, `account_id`, `verified`) beside the existing name.
- Settings gain the listen and certificate fields (settings version 5).

## Testing

- Real sockets, as `tests/test_local_server.py` does: no page or form
  without a session; role table enforced server-side (a tech POSTing a risk
  acceptance or an invite gets 403); setup only on loopback and only with no
  accounts; invite single-use, expired, revoked; lockout and 429; identical
  answers for unknown emails; session idle and absolute expiry (SimClock not
  used: these are runtime timeouts, per CLAUDE.md); cookie flags; re-confirm.
- TOTP against RFC 6238's test vectors; replayed code refused.
- HTTPS: self-signed generation (skipped without `openssl`), fingerprint,
  own certificate, plain HTTP refused on a network address.
- Agents cannot open `accounts.sqlite3`.
- `--as` records `verified: false`; a tech named on `exception accept` is
  refused.

## Left to the builder

Page layout and wording within the rules above, module split, the breached
password list's source and size (compatible licence, attributed), the
dummy-hash timing approach, log field names.
