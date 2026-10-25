# Greenbone connection — design

Date: 2026-10-25 · Project 1 of 6 in the local-edition release. Owner
decisions are marked **(owner)**; calls made by the designer are marked
**(designer's call)** so they can be checked and overturned.

## The release this belongs to

**(owner)** The open-source local edition is released on GitHub and listed
on the Ayliea website as a product once this first hour works:

> An MSP tech installs it on a server inside the client's network, connects
> it to the client's Greenbone, and within the first hour sees triage and
> recommendations on the vulnerabilities that client already has, ranked by
> what to fix first, using KEV, EPSS, CVSS **and the client's own business
> context**.

Decided for the release as a whole:

- **Free is single-client (owner).** One install serves one client. The
  multi-client MSP dashboard (email, password and mandatory MFA in front of
  every client environment; a password usable on only one client account) is
  the paid edition.
- **Hosted on a server, reached from other machines (owner).** The dashboard
  is opened from people's own devices, so sign-in is required. SSH is a
  second way in and needs a full set of commands matching the dashboard.
- **Roles (owner):** the business owner is accountable and is the only person
  who can accept a risk. MSP techs fix.
- **Business context (owner):** a short summary of the business per client;
  per system an importance (mission-critical, high, medium, low), tags such as
  location, and an optional note on why it matters. The AI may suggest tags
  from scanner evidence (for example a CentOS host with cPanel ports open:
  "probably a locally hosted website", tagged *Internal server*); a suggestion
  stays marked as one until a person confirms it. Advice uses the context:
  "This mission-critical printer has a critical, actively exploited
  vulnerability. Verify that today is not a game day before patching it."
- **The cloud evidence console is retired (owner)**; everything lives in the
  dashboard.
- **Not discovery (owner).** Remediation Zero reads what the vulnerability
  management platform already found. It does not scan, discover or probe.

The six projects, in build order **(owner agreed the order)**:

1. **Greenbone connection** — this document.
2. **Sign-in and roles** — accounts with mandatory MFA, owner and tech roles,
   HTTPS, and a command for every dashboard action (for SSH).
3. **Business context and ranking** — summary, importance, tags, notes,
   confirmed suggestions, context-aware ranking and advice.
4. **Dashboard takes over from the console** — deadline clocks and breaches,
   ticket trails, risk acceptances, reports, coverage; then the console is
   retired in both editions.
5. **First-run setup in the browser** — accounts, model, Greenbone, first
   triaged findings.
6. **Release** — public material cleaned of hackathon wording and cloud
   identifiers, SECURITY.md, changelog, version, signed release download,
   README and website product page.

## Intent of this project

Today the only way findings enter the local edition is three hand-written
JSON files in the project's own format (`seed --corpus DIR`). No scanner
parser exists, and the "scanner sources" plug-in point named in CLAUDE.md
has no interface. This project makes a real Greenbone the source of truth for
findings and assets, so the lifecycle runs on a client's actual
vulnerabilities, and it builds the scanner-source plug-in point that later
sources (Nuclei, Trivy, Wazuh, …) will reuse.

## Goals

- Pull finished Greenbone reports automatically **(owner)**, from scan tasks
  someone has explicitly chosen for this install **(owner)**.
- Accept an uploaded Greenbone XML report as a fallback **(owner)**, through
  the same code after parsing.
- Turn each report into assets and findings, and reconcile later reports as
  rescans, so findings are resolved, kept or reopened only on the evidence of
  what a report covered.
- Bring in findings without a CVE and triage them like everything else
  **(owner)**.
- Refresh KEV, EPSS and NVD data for the CVEs actually found, cached to disk.
- Standard library only, as the rest of the local edition.

## Non-goals

- Starting scans, creating targets or tasks, or changing anything in
  Greenbone. The connection is read-only.
- Any discovery, probing or network contact with client devices.
- Owners and accounts (project 2). Assets arrive with no owner; see below.
- Tag suggestions and business context (project 3). This project only keeps
  the evidence those need (OS, hostname, open ports).
- Other scanners. Only the plug-in point is built; Greenbone is the one
  implementation.
- The cloud edition. Nothing here is wired into the cloud workers.

## Anti-goals

- Importing a different client's data. Pulling everything the Greenbone
  account can see, or trusting a report's origin without checking it, is the
  failure this design exists to prevent.
- Closing a finding because a report simply did not mention it. Closure
  needs coverage evidence, exactly as today.
- Treating "no CVE" like "KEV list unavailable". They mean different things
  and must read differently everywhere.

## What exists (verified 2026-10-25, main 73a63eb)

- `engine/rescan.run_rescan(ports, cycle, scan, dry_run)` takes a scan
  `{scan_id, covered_asset_ids, findings}`, reconciles it against
  `findings`, and records it: `resolved`, `persisting`, `unverifiable`,
  `new` and `regressed` (`tools/rescan.py`). On an empty workspace every
  finding is `new`, so the first report needs no separate import path.
  `tools/scan_store.ScanWriter` writes the scan manifest before any
  resolution it justifies, and every write is keyed (idempotent).
- `tools/ingest.to_document` stamps `real_ts`/`sim_ts` on reference records.
- `tools/local_layout.STAGE_WRITES["rescan"] = {"findings", "scans"}`.
  Assets are written only by `seed`.
- A finding today requires `cve_id`: `engine/triage_cycle.py:174`
  (`enrichment.enrich(finding["cve_id"])`), `:180`, `engine/sweep.py:95`,
  `tools/inference.py:162` (`render_finding`).
- `tools/enrichment.EnrichmentCache` reads only `data/cache/` (KEV, EPSS,
  NVD), never the network. `scripts/fetch-enrichment.py` fills it, but only
  for CVEs in the synthetic `data/findings.json`, and is not a local
  command. The installer ships no cache; with none, KEV reads "unknown (KEV
  list not available)" and risk acceptance needs a person (fail closed).
- The triage prompt (`prompts/triage.md`) already weighs KEV, then EPSS,
  then CVSS, then asset criticality, environment and internet exposure, and
  treats `scanner_comment` as untrusted. `render_finding` fences it.
- Untrusted text crosses `engine/triage_cycle.screen_finding` (guard role, or
  withheld when no guard is configured) before any model sees it.
- Local settings are a versioned JSON file beside the workspace
  (`tools/local_settings.py`); the Settings page has sections Model
  connection, Data & storage, Application, Safety & limits, Updates
  (`ui/settings_view.py`). Secrets are environment variables only.
- The local server binds 127.0.0.1 and checks Host and Origin on writes.
  Network access with sign-in is project 2, not this one.

## Design

### The scanner-source plug-in point

A source turns whatever a scanner produces into **normalised scans**:

- `scan_id` — stable and unique per report.
- `source` — `"greenbone"`.
- `task_id` — the scanner's own grouping that the install chose.
- `covered` — the assets the report says it examined, each with its stable
  asset key and the evidence fields below.
- `findings` — normalised findings (fields below).

A normalised scan is converted into the existing rescan input and the asset
records, and from there everything runs through code that already exists.
The source interface is small: list what is available (tasks, for
Greenbone), fetch new reports for the chosen ones, and parse an uploaded
file. The shape of the interface and its module layout are left to the
builder; it must be an edition plug-in point in the sense of
`engine/ports.py` (shared code, no cloud imports, one contract test suite
that any future source must pass).

### Connecting to Greenbone (GMP)

- Two transports **(designer's call)**: the gvmd Unix socket, when
  Remediation Zero runs on the Greenbone host (as on Ayliea's own server,
  where gvmd exposes only `gvmd_socket_vol`), and TLS over TCP for a
  separate server. TLS verifies the certificate; a self-signed gvmd
  certificate is used by pointing at its CA file, never by turning
  verification off.
- Credentials: `RZ_GREENBONE_USERNAME` and `RZ_GREENBONE_PASSWORD`,
  environment only, never written to settings, records or logs, in line with
  the model API keys.
- Read-only GMP use: authenticate, list tasks, list reports for a task, get a
  report. No command that creates, modifies, starts or deletes anything.
- Bounded like the model transport: connect and read timeouts, a maximum
  response size (reports can be large; the limit is the builder's to set
  from real report sizes, and exceeding it is a clear error, never a
  truncated import).

### Choosing tasks **(owner: only explicitly chosen tasks)**

- Settings holds the list of chosen task IDs (not secret, so it lives in the
  settings file). IDs can also be typed in by hand, so an air-gapped install
  that only uploads can still choose tasks **(designer's call)**. Empty means **pull nothing**, and the dashboard and the
  command say so plainly. Fail closed.
- A command lists the tasks the Greenbone account can see, with their names
  and IDs, so someone can choose. The Settings page gains a **Scanner**
  section with a tick-box per task and the connection fields (transport,
  socket path or host and port, CA file), alongside a "test connection"
  action that reports what it could and could not do.
- **Every report is checked against the chosen tasks**, using the task ID
  inside the report itself, before anything is written. A report from an
  unchosen task is refused, whether it was pulled or uploaded.

### Pulling

- Runs on the existing cycle timer (`cycle_interval_minutes`) and as a
  command. Each run fetches finished reports for chosen tasks that have not
  been imported, oldest first, so reconciliation sees them in scan order.
- "Already imported" is the report's scan record: `scan_id` is the Greenbone
  report ID, and recording a scan is already keyed, so a repeated pull adds
  nothing. Nothing about a report is re-imported once recorded.
- A pull that fails (Greenbone down, bad credentials, timeout) writes
  nothing, is logged with the error class only, and is shown on the
  dashboard as "last pull failed" with the time, never as "no new findings".

### Upload fallback **(owner)**

- A command and a Settings/dashboard action that take one Greenbone XML
  report file. After parsing, it goes through exactly the same checks and
  conversion as a pulled report, including the task check and the
  one-report-per-task-per-cycle rule.
- An upload from a task that has not been chosen is refused, with the
  option to add that task and import, which needs an explicit confirmation
  naming the task **(designer's call)**. The fallback works without any
  GMP connection.

### Reading the XML safely **(designer's call)**

- Reports are input from outside. A document containing a `<!DOCTYPE` (and
  so any entity declaration) is refused before parsing; parsing uses the
  standard library and never resolves external resources. Size is bounded
  before parsing.
- Report text fields (descriptions, detection details, banners) are
  untrusted and travel as untrusted text (below). Structured fields (IDs,
  ports, severities, QoD) are parsed and validated as typed values; a value
  that does not parse is a rejected result with a logged reason, never a
  guess.

### Assets

- Keyed on Greenbone's host asset ID from its asset database, which survives
  IP changes, rather than on the IP **(designer's call)**. A host with no
  asset ID falls back to a key derived from source and IP, and that fallback
  is recorded on the asset so it is visible.
- Evidence kept: IP, hostname (when Greenbone reports one), detected OS,
  open ports seen, first and last seen (scan and both clocks). Project 3
  reasons over this; this project only stores it.
- `criticality`, `environment` and `internet_facing` are left unset (unknown)
  until project 3. The triage prompt must read unset as "not known", not as
  low or development.
- **No owner.** Assets arrive unowned. Triage still runs; assignment for an
  unowned asset already goes to the human queue as needs-human ("no owner on
  the asset"), which is the honest state until project 2 adds people.

### Findings

- Keyed on host asset key, Greenbone test (NVT OID) and port
  **(designer's call)**, so the same issue matches across reports.
- Fields: source, NVT OID and name, port and protocol, Greenbone severity
  (CVSS score as Greenbone reports it), QoD, CVE IDs (zero or more),
  detection details, solution text, first seen scan.
- **Results with no CVE come in (owner).** For these:
  - enrichment does not run; the record and the prompt say KEV, EPSS and NVD
    are **not applicable (no CVE)**, distinct from **unknown (KEV list not
    available)**;
  - the model works from Greenbone's severity and the test's own
    description, plus the asset;
  - risk acceptance **(owner)**: nothing proves a no-CVE finding is not
    exploited, so accepting the risk on a high or critical one needs a
    person's approval, exactly as a KEV finding does. Medium and low follow
    the normal rules. The refusal message says why ("no CVE, so exploitation
    status cannot be checked").
- Results with several CVEs: one finding, all CVEs listed; enrichment
  covers each, and the strongest signal (any in KEV, highest EPSS) is what
  the prompt sees first. **(designer's call.)**
- Log-level results (severity 0) are skipped. **(designer's call.)**
- QoD floor **(designer's call)**: results below Greenbone's own default of
  70% are skipped, configurable in the Scanner section; every finding shows
  its QoD to the triage model so weaker detections are treated with caution.
- Untrusted text: detection details and the test description become the
  finding's untrusted text and cross `screen_finding` with the scanner
  comment. Nothing from the report reaches a model unscreened.
- **With no guard configured (owner):** that text is withheld, as today, and
  findings are still triaged on the trusted fields (test name, severity, QoD,
  CVE IDs and their enrichment, the asset). The decision says plainly
  "scanner text withheld, triaged on limited evidence", on the record and in
  the dashboard. This bites hardest on no-CVE findings, which have no
  enrichment to lean on. Project 5's first-run setup strongly recommends
  configuring a guard; it does not require one.
- `cve_id` stops being required everywhere listed under "What exists". The
  record and the prompt must still say plainly which CVE(s) a finding is
  about, or that it has none.

### Reconciliation

- Each report becomes the existing rescan input: `scan_id` = report ID,
  `covered_asset_ids` = the hosts the report lists as scanned, `findings` =
  the normalised findings. The first report produces `new` findings; later
  reports resolve, keep, reopen or add, using the existing rules.
- A host that appears in a report with no results counts as covered (clean).
  A host absent from the report is not covered and nothing on it is closed.
- **A finding belongs to the task that first saw it (designer's call).** It
  records that task ID, and only reports from that task may resolve, keep or
  reopen it. A report from another task that shows the same finding (same
  host, test and port) changes nothing about it: no duplicate, no closure.
  Coverage today is a set of hosts only (`tools/rescan.reconcile`), so this
  is a change to reconciliation: the scan's previous findings are filtered
  to its own task's before reconciling. Synthetic seed/demo scans have no
  task and keep today's behaviour. Greenbone does not reliably list which
  tests actually ran, so per-test coverage is deliberately not attempted.
  Two tasks with different scan configs on one host is normal; the builder
  pins this with a test.
- **One report per task per cycle (designer's call).** Rescan writes are
  keyed on (finding, action, cycle), hard constraint 1, and that derivation
  does not change. Importing several reports in one cycle would suppress a
  second resolve of the same finding (resolved, regressed, resolved again)
  and leave it wrongly open. So:
  - when a task is first chosen, only its **newest** finished report is
    imported, as the baseline; older ones are not back-filled;
  - after that, each pull imports at most one new report per task, oldest
    first, and the rest wait for the next cycle. Greenbone scans are
    typically daily or weekly, so the queue drains.
- **Only finished scans close anything (designer's call).** Only reports
  Greenbone marks Done are imported; Stopped and Interrupted reports are
  skipped and shown as skipped with their status. Within a Done report, a
  host counts as covered only if Greenbone finished scanning it; dead or
  unfinished hosts are not covered, so nothing on them is closed.
- Asset upserts are written before findings, under a new stage whose write
  boundary is `{"assets", "findings", "scans"}` plus whatever pull state the
  builder needs. This widens what an ingestion stage may write; seed and
  rescan keep their current boundaries.

### Enrichment refresh **(designer's call)**

- A command `update-enrichment` fetches CISA KEV, EPSS and NVD records for the
  CVEs present in the workspace's findings and writes them to the on-disk
  cache. Runtime triage still reads only the cache (hard constraint 7).
- It is the one command that reaches the internet, and it says so. It is
  resumable, rate-limited for NVD, and reports what it fetched and what
  failed. An optional `NVD_API_KEY` environment variable speeds it up.
- The pull run may call it for new CVEs **only if** the operator turned that
  on in Settings; off by default, so an air-gapped install never tries to
  reach out.

## Where the data goes (schema)

**(owner)** Approved in principle; the plan lists the exact fields and the
owner signs them off before building starts.

- `assets`: new fields for source, asset key origin, IP, OS, open ports,
  first/last seen; existing `criticality`/`environment`/`internet_facing`
  may be absent.
- `findings`: `cve_id` becomes optional; new fields for source, NVT OID and
  name, CVE list, QoD, protocol, solution text, task ID.
- `scans`: new fields for source and task ID.
- `findings` also records the task that first saw it.
- Pull state (last pull time and result per task, imported and skipped
  reports) and the enrichment-refresh status live in a **new collection in a
  new workspace file**, written only by the import stage **(designer's
  call)**.
- Existing findings keyed by `cve_id` keep working, since the field only
  becomes optional; no migration is needed.
- **Demo and real data never mix (designer's call).** Connecting Greenbone to
  a workspace holding seeded synthetic data is refused, and so is seeding
  into a workspace holding Greenbone data. One workspace is one client.

## Observability

Every behaviour above must be checkable by someone who did not write it:

- Dashboard: chosen tasks, last pull time and result per task, reports
  imported, what each report changed (new, resolved, reopened, kept,
  unverifiable), and how many results were skipped and why (log level, below
  QoD floor, rejected as malformed).
- Logs: one structured line per report and per finding written, carrying the
  finding and cycle IDs (CLAUDE.md conventions), error classes only on
  failure.

## Testing

- Fixtures are **synthetic Greenbone XML**, hand-built to the GMP report
  schema: `.invalid` hostnames, documentation IP ranges, real CVE IDs. No
  real report enters the repository (hard constraint 5). Testing against
  Ayliea's own Greenbone happens locally and is never committed.
- Must be pinned by tests: task allowlist on pull and upload (and the
  confirmed add-and-import); DOCTYPE refusal; QoD floor; log skip; no-CVE
  findings end to end through triage with "not applicable" wording, and with
  "limited evidence" when no guard is set; no-CVE high/critical acceptance
  needs a person; multi-CVE findings; newest-only baseline; one report per
  task per cycle, including resolved, regressed, resolved across three
  reports; Stopped/Interrupted reports skipped; dead hosts not covered;
  per-task ownership of findings across two tasks on one host; demo/real
  mixing refused both ways; repeated pull writes nothing; failed pull writes
  nothing and shows as failed; credentials never appear in settings, records
  or logs.
- The GMP transport is tested against a local fake speaking GMP over a Unix
  socket and over TLS, in the offline suite. A real Greenbone is not mocked
  into passing anything that matters: an end-to-end check against a real
  gvmd is a documented manual step, like `verify-controls.sh` is for cloud.

## Left to the builder

- Module layout and the exact source interface.
- Exact GMP request sequence and paging.
- Report size limit and timeouts, from real report sizes.
- Field names, within the schema list above.
- How the Scanner section is laid out.
