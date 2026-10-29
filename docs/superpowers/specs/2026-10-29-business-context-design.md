# Business context and ranking — design

Date: 2026-10-29 · Project 3 of 6 in the local-edition release. Owner
decisions are marked **(owner)**; calls made by the designer are marked
**(designer's call)** so they can be checked and overturned.

## Intent

Findings that are exploitable and sit on the assets a business cannot do
without should be fixed first **(owner)**. Exploitability already arrives
automatically (CISA KEV, known ransomware use, EPSS). What the business cares
about does not: only the owner knows it, and today there is nowhere to say it.

Triage already uses business context. `tools/inference.py` hands the model
`environment`, `criticality` and `internet_facing` for each asset, and
`prompts/triage.md` tells it an internet-facing production asset raises
severity. Synthetic assets carry these facts. Hosts imported from Greenbone do
not: they arrive "not known", and the importer keeps any value a person sets
(`engine/scanner_import.py`, `_ASSET_REFRESHED`) but nothing lets a person set
one. This project gives the owner a place to say what matters, and makes the
ranking and deadlines follow it.

Modeled on Expel's Organization Settings → Context page: named labels, a count
of what each covers, and context that can be typed in or uploaded **(owner,
by reference)**.

## Who it serves

The person using the platform: an MSP tech running it for a client, or the
business owner. They keep this information in many ways: in their head, in a
spreadsheet, or in an asset management platform. Getting it in must be
flexible **(owner)**.

## Goals

1. A **Context** page under Settings holding labels and the hosts each covers
   **(owner, approved from the mockup)**.
2. Three ways in, all filling the same labels **(owner, approved)**:
   - **Answer a few questions** — for "it's in my head": plain questions over
     the hosts the scanner found, answered with tick boxes.
   - **Upload a spreadsheet** — map its columns once, preview what changes,
     then save.
   - **Rules that suggest** — see below.
3. Labels raise or lower severity, which moves the fix-by deadline and how
   soon chasing escalates to the owner **(owner)**.
4. When a label changes, the open findings on that host are re-ranked on the
   next cycle and their deadlines adjusted. No rescan is involved; rescans stay
   manual **(owner)**.
5. The fix recommendation names the business reason ("this is your file
   server, which holds client records") alongside the remediation steps
   **(owner: "recommend the remediation of those vulnerable assets"; wording is
   the designer's call)**.
6. Only the owner sets, changes or removes labels, approves suggestions, and
   uploads context. A tech sees them **(owner)**. Every change is in the audit
   trail.

## Non-goals (later projects)

- Email or webhook alerts for high-ranked findings **(owner: "eventually")**.
- Connecting an RMM or asset platform. A CSV export from it covers the need
  first **(owner, approved)**.
- Charts comparing findings by criticality: project 4, when the dashboard
  replaces the console **(owner)**. This project makes sure the data exists.
- Host identity across IP changes (DHCP): its own design, already deferred.

## Anti-goals

- **Asset discovery.** Labels attach to hosts a scanner already reported. A
  spreadsheet row never creates an asset.
- **Silent defaults.** A host nobody has described is "business context not
  known", shown and passed to triage as such, never quietly treated as
  unimportant.
- **Rules that apply themselves.** Automation suggests; a person decides
  **(owner)**.
- **Untraceable deadline moves.** Every moved deadline says what moved it, who,
  and when.

## Labels

Four built-in labels, each mapped onto a fact triage already reads
**(designer's call; the four were in the approved mockup)**:

| Label | Meaning shown to the owner | Triage fact |
|---|---|---|
| Crown jewels | The business stops if this goes down | `criticality: high` |
| Internet-facing | Reachable from outside | `internet_facing: true` |
| Production | Real work runs here | `environment: production` |
| Sensitive data | Patient, client or payment records | `sensitive_data: true` (new fact) |

The owner can also mark a host **Development** or **Not internet-facing**, so a
lowering is a deliberate statement, not the absence of a label
**(designer's call)**. Each fact has three states: yes, no, not known.

**Custom labels** (for example "Billing", "Front desk") are names for grouping
and display. Each custom label also carries one of the built-in effects or
none: "treat as Crown jewels", "treat as Sensitive data", or "for grouping
only" **(designer's call)**. A custom label's name is free text and reaches the
reasoning context, so it crosses the guardrail boundary like other untrusted
text (hard constraint 8). Names are also limited to 40 characters of letters,
digits, spaces and `- _ .` **(designer's call)**.

## Getting context in

### Answer a few questions

A short guided flow over hosts whose context is not known, one question per
screen, each answered by ticking hosts from the scanner's list **(designer's
call on the exact questions)**:

1. Which of these would stop the business if they went down?
2. Which can be reached from the internet?
3. Which hold patient, client or payment records?
4. Which are for testing or development only?

Hosts not ticked stay "not known", not "no". Skipping a question is allowed.

### Upload a spreadsheet

- **CSV only.** Excel and asset tools export CSV; parsing `.xlsx` would need a
  dependency the standard-library edition does not take **(designer's call)**.
- The owner maps columns once: which column is the host name or IP, and which
  columns say each label (yes/no/blank). The mapping is remembered for the
  next upload.
- A preview lists every change before anything is saved: hosts that gain or
  lose a label, and rows that matched no host.
- **Unmatched rows** create nothing. They are kept as pending suggestions and
  surface when a later scan reports a matching host, for approval like any
  other suggestion **(designer's call, from the "rules suggest" decision)**.
- Upload size and row limits mirror the Greenbone upload's existing limits.

### Rules that suggest

The owner can write a rule such as "everything in 192.0.2.0/24 is Production"
or "host names ending `.files.example` are Crown jewels" **(owner: automations
are wise)**. A rule never applies itself. When a scan reports hosts a rule
covers, the Context page shows the suggestion with **each affected host**, and
the owner approves or denies each one **(owner)**. A denied host stays denied
for that rule until the owner changes it. Rule matchers: IP range (CIDR) and
host-name suffix **(designer's call)**.

## How ranking changes

- Triage reads the label facts in place of today's empty asset fields, plus the
  new `sensitive_data` fact and any custom label names (guarded). The prompt
  gets a versioned update (`prompts/triage.md` next version) describing
  sensitive data and stating that "not known" must be reported as missing
  context, not assumed low.
- Severity drives the SLA days triage proposes, and the reviewer still checks
  every proposal (hard constraint 3).
- **Fixed floor** **(owner)**: a finding on a Crown-jewels host whose CVE is in
  CISA KEV is never ranked below High, whatever the model or reviewer says. The
  model and reviewer still decide everything above the floor. The floor is a
  deterministic check applied after adjudication, so it is testable without a
  model, and the record says when it was applied ("raised to High: Crown
  jewels and actively exploited"). With the floor, the SLA is no longer than
  14 days, or the KEV due date if that is sooner **(designer's call on the
  14 days)**. A finding whose KEV status is unknown (list not available) is not
  floored and the record says why.
- Escalation timing needs no new mechanism: chase already escalates against the
  SLA clock, so a shorter deadline escalates sooner.
- **Re-ranking.** On the next cycle after a host's labels change, each open
  finding on that host is triaged and reviewed again. The idempotency key is
  the usual finding / action / cycle triple, so a resumed cycle re-ranks once.
  Findings on hosts whose labels did not change are not re-run, which keeps
  model cost proportional to what changed **(designer's call)**.
- **Moving the deadline.** The SLA clock keeps its original start. The new due
  time is original start + new SLA days, never earlier than the re-rank cycle
  plus one day, so a raised finding is not born overdue **(designer's call)**.
  Deadlines can move in both directions; a lengthening is the owner's call and
  is recorded the same way **(designer's call, confirmed in playback)**.
- Each move is recorded with old due, new due, the label change that caused it,
  who made that change, and both `real_ts` and `sim_ts` (hard constraint 2).
  The finding page and the tracker comment say it in plain words: "Deadline
  moved from Nov 20 to Nov 6 because the owner labeled files.example Crown
  jewels on Oct 29."
- A finding under an active risk acceptance keeps its acceptance; re-ranking
  updates its severity for when the acceptance expires **(designer's call)**.

## Pages

- **Settings → Context** (new, owner edits, tech views): label tiles with
  counts, the three ways in, pending suggestions, and the host list with each
  host's labels and where they came from (questions, spreadsheet, rule, by
  whom, when). Hosts with no context are listed first with a count.
- **Dashboard:** a nudge while any host's context is not known ("6 hosts have
  no business context — label them"), linking to the Context page.
- **Finding view:** the host's labels, the business reason in the
  recommendation, and any deadline moves.

## Constraints

- Local edition stays standard-library only; runs under `python3 -S`.
- **Storage schema change approved (owner, 2026-10-29)**: host facts and
  labels, custom label definitions, rules, suggestions with approve/deny state,
  the saved column mapping, and deadline-move records. Host facts live on the
  asset document (the importer already preserves person-set fields); the rest
  are new collections owned by no agent and written only by the owner's
  actions, like the reference collections. They go through the storage port
  and are built and tested on SQLite; no Firestore-specific work is in this
  project **(designer's call)**.
- The feature is core, not cloud-only. It goes through the storage port so the
  cloud edition can use it later.
- New owner-only action in `tools/access.py` (for example `manage_context`),
  with tests on the permission boundary.
- Every write is audited; untrusted text (custom label names, CSV cells shown
  back on pages) is escaped on pages and guarded before any model sees it.
- No real data in tests: synthetic hosts under `.invalid` / `example`
  domains and documentation IP ranges.

## Edge cases (all designer's calls, from the builder check)

**Combining sources.** Each fact (criticality, internet-facing, environment,
sensitive data) holds one value with its provenance: source (questions,
spreadsheet, rule, direct edit), account, and time. The most recent owner
decision wins, whatever its source. A fact set directly on the host wins over
a custom label's effect; a custom label's effect fills only a fact that is
"not known". Environment is one value: production, development or not known,
so Production and Development cannot both hold. Scanner imports never set
these facts.

**Re-rank trigger.** A host is marked "context changed" only when an
effective fact changes; re-saving the same value is not a change. Several
changes before a cycle make one re-rank. A rule approval counts like any other
change. Re-ranking covers open, chased findings. Findings that are held, in
the human queue or rejected pick up the new context the next time they are
triaged. A re-rank that leaves the due time unchanged writes no deadline-move
record. Lowering a severity keeps the finding chased under its new deadline;
nothing closes except by rescan, and no lowering skips the reviewer.

**Matching rows and rules to hosts.** Host names match case-insensitively on
the full name; a short name matches only when exactly one host has it. An IP
matches when exactly one host has it. A row that matches several hosts, or
several rows that disagree about one host, are shown in the preview as
problems and not applied. Pending suggestions from unmatched rows expire after
90 days and are capped at 5,000; a hand-set fact on a host supersedes any
pending suggestion for that fact. Editing a rule clears its pending
suggestions; approvals already made stay, because they are facts now.

**Who.** Owner only, as decided. In an MSP install the tech who set it up is
normally the first account, which is an owner. The account recorded on every
change and deadline move is the signed-in account's identity.

**Custom label names and the guardrail.** A name is checked when it is saved;
one the guardrail blocks is refused at entry with a plain message, not saved
and silently dropped later.

**Tracker comment.** One comment per finding per re-rank that moved its
deadline. It is a lifecycle event, so it supersedes an older undelivered
reminder, under the same at-least-once delivery as other comments.

## Left to the builder

- Page layout within the existing Settings style.
- The exact question wording beyond the four above.
- How the column mapping is stored and shown.
- Which existing upload limits to reuse.
