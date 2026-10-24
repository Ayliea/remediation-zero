# Local edition

The local edition runs the whole remediation lifecycle on one machine: triage,
review, ownership, chase, risk acceptances, rescans and reports. It uses SQLite
and models you configure. It needs Python 3.12 or newer and nothing from pip,
and it makes no cloud calls. Python 3.12 on Linux is the tested runtime;
Windows and macOS have not been exercised.

It is still a synthetic preview. Do not feed real client data into it yet.

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
python3 -S -m scripts.local exception accept FINDING --ttl DAYS --by OWNER_ID \
    --reason TEXT --cycle N [--approved-by-person]
python3 -S -m scripts.local exception list
python3 -S -m scripts.local approve FINDING --cycle N [--by NAME]
python3 -S -m scripts.local serve [--demo] [--port PORT]
python3 -S -m scripts.local check-models [--role ROLE]
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
- **rescan** is the only command that marks a finding resolved. Read the dry
  run first: it writes nothing.
- **exception accept** records a risk acceptance that expires after `--ttl`
  days; the sweep in the next `cycle` past expiry reopens it. A KEV CVE needs
  `--approved-by-person`.
- **approve** records a person's approval of an `unreviewed` or
  `held_for_approval` decision. See "Review" below.
- **serve** shows the dashboard and Settings on `http://127.0.0.1:8081`. With
  `--demo` it shows illustrative fixtures instead of saved records. It binds
  only to loopback and has no user authentication, so do not reverse-proxy it
  onto a network.

A `--database` that names a single database file from an earlier version is
refused with "... is not a Remediation Zero workspace directory ...;
nothing was changed." It is not converted. Choose a new or empty folder.

## Model roles

There are four roles. Configure each in Settings with a format
(`openai_chat`, `anthropic_messages` or `gemini_api`), an endpoint, a model and
a family:

| Role | Does | API key variable |
|---|---|---|
| proposer | Triage: severity, SLA, remediation, with cited evidence | `RZ_PROPOSER_API_KEY`, else `RZ_MODEL_API_KEY` |
| reviewer | Ratifies or rejects each proposal | `RZ_REVIEWER_API_KEY` |
| summarizer | Narrates the report's figures | `RZ_SUMMARIZER_API_KEY` |
| guard | Screens untrusted text before any model sees it | `RZ_GUARD_API_KEY` |

API keys are read only from the environment. They are never written to the
settings file, the workspace, a record or a log. `RZ_MODEL_ENDPOINT` and
`RZ_MODEL` override the saved proposer connection. HTTP is allowed only on
loopback; a hosted endpoint must use HTTPS. Redirects and inherited proxies are
disabled. Requests are capped at 32 KiB in, 64 KiB back and 2048 output tokens,
with a 60-second socket timeout. `check-models` sends the bundled synthetic
example to each configured role. No real provider was called during validation.

With no summarizer, the report stores the metrics and a marker saying no
summarizer is configured, in place of prose.

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
python3 -S -m scripts.local approve RZ-0002 --cycle 2 --by "Your name"
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
withheld notice in its place, and the structured fields.

## Permissions

The local permission boundary is enforced in the code by construction, not by
the operating system: one local user owns every workspace file. Each agent's
collections live in their own SQLite file, and each stage opens a store that
can write only its own collections. The reporting stage cannot write tickets.
The workspace folder is 0700 and each database file 0600 on POSIX.

## Failed runs

If a finding's run raises, the cycle stops, and the next `cycle` retries it.
The failure is recorded once in `failed_runs`:

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

The cache is `data/cache/` (CISA KEV, EPSS, NVD). It is read only and offline:
the local edition never fetches it. The installer does not ship it. When a
source is absent:

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

## Dashboard

The dashboard shows the newest 60 decisions and failed runs, the newest 20
scans and 10 reports, and up to 60 queue items, SLA clocks, tickets and
exceptions. Older records stay in the workspace. Reading a page never calls a
model.

## Settings

Settings stores each role's connection, the same-family policy and the startup
preferences in `<workspace>.settings.json` beside the workspace folder. Saving
never contacts a provider. Saves require a valid Host, a matching Origin and a
per-process form token. Writes are atomic and private (0600 on POSIX). There is
no API key field and no database reset control. This is local access control,
not authentication for public use.

Stop every process before copying a workspace and its settings. Do not delete
storage to retry a failed request: rerunning a cycle reuses its checkpoints,
and a new cycle starts a new request budget. There is no global spending cap.

## Not yet built

There are no real scanner connectors, no import workflow and no in-place
upgrade. An Ayliea-hosted offering is a future direction; it would need
authentication, tenant isolation, hosted storage, billing and audit controls,
and none of those is implied here.
