# Local edition: first runnable slice

## Single-file installer

Download install-remediation-zero.py from the supplied development bundle.
With Python 3.12 or newer installed, run `python3 install-remediation-zero.py`
(Windows: `py -3.12 install-remediation-zero.py`). The installer shows its plan
and asks for confirmation before creating files. It bundles all application
files, downloads nothing, installs no packages, requests no credentials and makes
no model calls. It installs into a new RemediationZero directory under your home
directory, starts a local synthetic demo and opens the browser.

Restart with `python3 /path/to/RemediationZero/start-remediation-zero.py`.
Use `--saved` for saved suggestions, `--no-browser` to skip opening the browser,
or `--port 8082` if the default port is occupied. Stop with Ctrl+C in that terminal.
The installer accepts `--directory`, `--no-start` and explicit `--yes` options.
It never overwrites an existing directory. There is no upgrade/migration workflow.
No background service or OS configuration is installed. On failure it may leave
a partial new directory; inspect it before removing it or choosing another path.

The installer is unsigned. Embedded SHA-256 checks detect corruption, not a
malicious replacement of the installer itself. Download only from a trusted
distribution source. There is not yet a published release URL or platform-native
installer. Python installation remains a prerequisite; Windows and macOS have
not been exercised. Installing or configuring a model is still a separate step.

Build from reviewed source:
`python3 -m scripts.build_local_installer /absolute/path/install-remediation-zero.py`.

This post-hackathon edition uses SQLite and a user-configured model endpoint.
Python 3.12 is the tested runtime. No pip installation, Google account, API key,
model download or network access is needed to initialize storage and view the
synthetic dashboard. Run from the repository root:

```bash
python3 -m scripts.local init
python3 -m scripts.local serve --demo
```

Open http://127.0.0.1:8081. Demo mode shows illustrative fixtures, not saved
assessment results. To view saved suggestions, omit `--demo`. The application
binds only to loopback and does not serve arbitrary files. The only HTTP write
path saves validated local preferences; it cannot change infrastructure or run a model.
It has no user authentication and must not be reverse-proxied onto a network.

## Connect a model

Configure a full OpenAI-compatible chat-completions URL and a model already
available at that endpoint. Example for a locally installed model server:

```bash
export RZ_MODEL_ENDPOINT=http://localhost:11434/v1/chat/completions
export RZ_MODEL=your-installed-model-name
python3 -S -m scripts.local check-models
python3 -S -m scripts.local cycle --cycle 1
python3 -S -m scripts.local serve
```

The commands (`--database DIR` names the workspace folder; the default is
`remediation-zero`): `init`, `seed`, `cycle --cycle N`, `rescan --cycle N
--scan PATH [--dry-run]`, `exception accept|list`, `approve FINDING --cycle N
[--by NAME]`, `serve` and `check-models`. A folder from an earlier version that
held a single database file is refused, not converted; choose a new folder.

For a hosted endpoint use HTTPS and, if needed, set RZ_MODEL_API_KEY through
your shell's secret-management mechanism. Credentials are never saved in SQLite.
Compatibility varies; no real provider was
called during validation. Redirects and inherited proxies are disabled. HTTP is
allowed only on loopback. Responses are capped at 64 KiB, output at 2048 tokens,
input at 32 KiB, and each request has a 60-second socket timeout (not an absolute
wall-time deadline for a streaming malicious server).

Only `cycle` and `check-models` invoke a model; hosted endpoints can charge
for them. `check-models` sends the bundled synthetic example. A decision that is
unreviewed or held for a same-family review waits for a person: `approve` records
that person's approval, and the next `cycle` assigns it. It uses four durable
request slots per cycle, backoff, and the existing 600-second claim lease. A
crashed request consumes a slot. Rerunning the same cycle reuses its checkpoint;
changing endpoint/model/prompt in that cycle is rejected. A new cycle deliberately
starts a new budget. There is no global spending cap. Do not delete storage to
retry a failed request. Back up the database while the process is stopped.

## Trust and scope

Every generated suggestion is unreviewed, including well-formed model output.
The model cannot execute tools, change infrastructure, mark findings resolved,
or approve its own recommendation. Existing rejection checkpoints remain durable.
SQLite creation uses a restrictive process umask in the CLI; existing database
permissions and machine access remain the operator's responsibility.

This slice is synthetic-only. There are no real infrastructure connectors,
import workflow, local ingress screening, independent reviewer setup, complete
inventory or scan freshness checks. Do not feed real client data into it yet.
The standard-library HTTP server is a local preview server, not hosted service
infrastructure. The existing Google Cloud runner and evidence console remain.

The repository already uses Apache-2.0. No license changes were made. An
Ayliea-hosted offering is a future product direction, not an implemented service:
it requires authentication, tenant isolation, hosted storage, billing, audit
controls and operational review. None of those are implied by this local edition.

Next milestone: a validated synthetic finding-import contract and current-status
projection, then explicit reviewer configuration before any approved guidance.

## Settings (2026-10-24)

Open **Settings** in the local dashboard. Model connection stores the endpoint
and model in a `.settings.json` file beside the selected database. API keys stay
in `RZ_MODEL_API_KEY`; never paste a key into an endpoint URL. Environment
`RZ_MODEL_ENDPOINT` and `RZ_MODEL` values override saved preferences when running
`cycle` or `check-models`. Saving never contacts a provider. Optional sample checks remain
explicit CLI operations and may cost money; the dashboard has no model test button.

Application preferences set the installed launcher's default demo/saved mode,
browser opening, and port on its next start. `--saved`, `--no-browser`, and
`--port` launcher flags take precedence. Direct `scripts.local serve` continues
to use its own CLI flags. The launcher always binds to loopback.

Data & storage, Safety & limits, and Updates explain current behavior. They do
not implement backups, migrations, automatic updates, independent local review,
or editable request budgets. Stop all processes before copying a database and
its preferences. Preserve request history. There is no supported in-place upgrade;
install a new preview in a separate directory and keep the old copy.

Settings forms validate exact fields, endpoint and port constraints. Saves require
a valid Host, matching Origin, and per-process unguessable form token. Writes are
atomic and private (0600 on POSIX). No API key input or database reset control is
provided. This is local preview access control, not authentication for public use.
