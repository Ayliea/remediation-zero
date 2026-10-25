# Greenbone connection (local edition)

The local edition can read finished scan reports from Greenbone
(gvmd, over GMP) and run them through the remediation lifecycle: triage,
review, ownership, chase, and closure when a later report proves a fix.
It reads only. The only GMP commands it ever sends are `authenticate`,
`get_tasks` and `get_reports`; it never creates, starts, changes or deletes
anything in Greenbone.

Remediation Zero is not a scanner. Greenbone finds the vulnerabilities;
this connection takes its finished reports.

## Setup

Use a new, empty workspace folder (`DIR` below). A workspace that holds the
seeded demo data refuses every Greenbone import, so demo and real findings
never mix.

Start the launcher on that workspace's saved records, not the demo examples:

```bash
python3 -S start-remediation-zero.py --saved --database DIR
```

(or set *Open by default* to *Saved records* in Settings). Pass the same
`--database DIR` to every `scripts.local` command; without it a command uses
a different default workspace.

### Credentials

Set these two environment variables in the shell that runs the launcher or
the `greenbone` commands:

```bash
export RZ_GREENBONE_USERNAME=...   # a Greenbone account that can read the chosen tasks
export RZ_GREENBONE_PASSWORD=...
```

They are read from the environment only. They are never entered in
Settings, and never written to settings, records or logs. A read-only
Greenbone account is enough.

### Connection

In **Settings → Connect Greenbone**, choose one connection:

- **Unix socket** (gvmd on the same machine): set *Socket path (Unix)* to
  gvmd's socket, often `/run/gvmd/gvmd.sock`. The user running Remediation
  Zero needs permission to open it (usually membership of gvmd's group).
- **TLS** (gvmd on another machine): set *Host (TLS)* and *Port (TLS)*
  (default 9390). The server certificate is always verified, and the host
  name must match it. If the certificate is not signed by a CA this machine
  already trusts, set *CA certificate file (TLS, optional)* to the CA that
  signed it.

Opening the Settings page never contacts Greenbone. **Test connection and
list tasks** does, using the saved settings, and gives up after 5 seconds.
From a terminal:

```bash
python3 -S -m scripts.local --database DIR greenbone test    # Connected / Signed in / Tasks listed
python3 -S -m scripts.local --database DIR greenbone tasks   # task_id  name, one per line
```

### Choosing tasks

Only explicitly chosen task IDs are imported. Paste them into *Task IDs,
one per line*. An empty list means nothing is pulled at all.

### Pulling

```bash
python3 -S -m scripts.local --database DIR greenbone pull    # one line per chosen task
```

With *Run a cycle automatically every N minutes* above 0, the launcher pulls
the chosen tasks before each cycle. A failed pull is logged by its error
class and the cycle still runs.

*Fetch enrichment automatically after an import* is off by default. Then
CISA KEV, EPSS and NVD data come only from
`python3 -S -m scripts.local --database DIR update-enrichment`, the one command that
reaches the internet.

### Upload instead of pulling

A report exported from Greenbone as XML can be imported by hand, through the
same checks as a pulled one:

```bash
python3 -S -m scripts.local --database DIR greenbone upload report.xml
python3 -S -m scripts.local --database DIR greenbone upload report.xml --add-task  # also choose its task
```

The dashboard's upload form does the same. It accepts the form a browser
sends; any other client should use `greenbone upload`. Uploads need no
credentials and make no connection.

## What is imported, what is skipped, and why

- **Reports.** Only reports Greenbone marks Done. Stopped, Interrupted and
  other unfinished reports are skipped and shown on the task's card with
  their status.
- **First report of a task.** Only its newest Done report is imported as
  the baseline; older ones are counted, not imported.
- **After that.** A report is imported only if its scan time is newer than
  the last one imported for that task. At most one report per task per
  cycle; a second upload in the same cycle is refused as already imported
  this cycle. At most 5 report downloads per task per pull; the rest wait
  for the next pull.
- **Refused reports.** A report is refused, and closes nothing, when it is
  unsafe (it contains a DOCTYPE or ENTITY), too large, malformed, without a
  scan time, not newer, or when its scan time disagrees with Greenbone's
  listing of it (more than 1 day before the listing time or 14 days after
  it). Scans running longer than 14 days are therefore refused. A refused
  report is recorded and skipped; the next report is still imported.
- **Clock.** A report whose scan time is more than one day ahead of this
  machine's clock is retried later only when Greenbone's listing time for it
  is also more than one day ahead of this machine's clock (Greenbone's clock
  is ahead); otherwise it is refused permanently as malformed. If this machine's clock runs behind, valid reports can be
  refused. Keep the clock synchronised.
- **Results.** Log-level results (severity 0) and results below the
  quality-of-detection floor (default 70) are skipped and counted on the
  card. Results with no CVE are imported and triaged; their KEV, EPSS and
  NVD fields read "not applicable (no CVE)". Accepting the risk on a high
  or critical no-CVE finding needs a person's approval.
- **Hosts.** A host counts as covered only if the report says its scan
  finished. Assets are keyed on Greenbone's host asset ID (IP as a
  recorded fallback) and arrive with no owner.

## How closure works

A finding is Greenbone's host, test (NVT OID) and port. It belongs to the
task that first saw it, and only that task's reports may close or reopen
it; another task's report on the same host changes nothing about it.

When a newer report from the owning task covers the host and no longer
shows the finding, the finding is marked resolved. If a later report shows
it again, it is reopened as regressed.

Greenbone assets arrive without an owner. A finding on an unowned asset is
triaged, then goes to the human queue as needing an owner; no ticket is
opened. Until an owner is recorded, closure shows as the finding marked
resolved: no ticket exists, so there is nothing to close. Once an asset has
an owner, chase opens a ticket for its findings, closes it in the cycle that
follows the resolving pull, and reopens it on a regression.

A host that is absent or did not
finish closes nothing. A report that could not be tied to its hosts closes
nothing either; its card says it "could not be trusted for coverage".

## Manual end-to-end check against a real gvmd

The automated suite runs against a fake gvmd only. Do this by hand against
a real one before relying on the connection, and again after a Greenbone
upgrade. **Never commit a real report**, or anything copied from one, to
this repository.

1. Create a new, empty workspace folder `DIR` outside the repository and
   start the launcher on its saved records:
   `python3 -S start-remediation-zero.py --saved --database DIR`.
2. Set `RZ_GREENBONE_USERNAME` and `RZ_GREENBONE_PASSWORD` for a read-only
   account, save the connection in Settings, and click **Test connection
   and list tasks**. Expect three "yes" lines and the task count.
3. Run `python3 -S -m scripts.local --database DIR greenbone tasks`. Confirm every task the account can see is listed
   (this checks that gvmd accepts `get_tasks` with `filter="rows=-1"` and
   returns all tasks, not one page).
4. Choose one task that has at least two Done reports and save it in
   Settings. Run `python3 -S -m scripts.local --database DIR greenbone pull
   --cycle 1`. Expect `imported` for that task, and only its newest Done
   report imported. Then run `python3 -S -m scripts.local --database DIR
   cycle --cycle 1` (this calls your configured models) to triage it.
5. Open the dashboard's **My infrastructure** view. Check the task's card:
   last imported report, its scan end, what it changed, skipped counts.
   Compare the findings, hosts and ports with the same report in
   Greenbone's web interface.
6. Run `python3 -S -m scripts.local --database DIR greenbone pull --cycle 1`
   again. Expect `already_imported_this_cycle`. With `--cycle 2`, expect
   `nothing_new`.
7. Run a new scan of that task in Greenbone, after fixing or switching off
   one detected service on a scanned host. When the report is Done, run
   `python3 -S -m scripts.local --database DIR greenbone pull --cycle 2`
   and then `python3 -S -m scripts.local --database DIR cycle --cycle 2`.
   Expect that finding marked resolved, with no ticket to close (the asset
   has no owner), and nothing closed on hosts the scan did not finish.
8. Stop a scan of the task partway. Run
   `python3 -S -m scripts.local --database DIR greenbone pull --cycle 3`.
   Expect the Stopped report shown as skipped, never imported.
9. Search `DIR`, its settings file (`DIR.settings.json`, beside it), and the launcher's
   terminal output for the username and password. Expect no match.
10. Confirm the protocol and report assumptions below hold, and record any
    that do not. A mismatch is a bug to fix in `tools/gmp.py` or
    `tools/greenbone_report.py`, with a synthetic fixture.

Assumptions to confirm (inspect real responses locally, for example with
`gvm-cli`, and keep them out of the repository):

- Every response root is `<COMMAND_response status="NNN" status_text="...">`.
- A failed sign-in answers `authenticate_response` with status 400; there is
  no greeting or other handshake.
- gvmd accepts several requests one after another on one connection, with
  no bytes after each response's root element.
- `get_tasks filter="rows=-1"` returns every task; each is
  `<task id="..."><name>...</name></task>`.
- `get_reports filter="task_id=<id> rows=-1" details="0"
  ignore_pagination="1"` lists the task's reports as
  `<report id><report id><task id/><scan_run_status/><timestamp/>...`.
  The listing time is the inner `<timestamp>`, else `<creation_time>`,
  else `<scan_end>`.
- Listing timestamps are ISO 8601 with `Z` or an offset (one without a zone
  is read as UTC).
- `get_reports report_id=<id>` returns one response holding exactly one
  report with that id (not a GSA-style export).
- In a report: the task (`task@id`, `task/name`) and `scan_run_status` are on
  the inner report; `scan_end` is present on a Done report.
- Hosts: `host/ip`, `host/asset@asset_id`, `host/end` (empty while the host
  is unfinished), and `host/detail` name/value pairs `hostname`,
  `best_os_cpe` and `ports`. The `ports` value is assumed to be a
  comma-separated list such as `22/tcp,80/tcp`; real gvmd may instead list
  open ports as `<ports><port>` elements, which are not read.
- Results: `result@id`, `host` text with child `asset@asset_id` (and
  `hostname`), `port` as `N/proto` or `general/proto`, `nvt@oid`,
  `nvt/name`, `nvt/tags` (pipe-separated `key=value`, with `summary=`),
  `nvt/solution`, `nvt/refs/ref[@type="cve"]@id`, `severity`,
  `qod/value`, `description`.
