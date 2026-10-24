# Portable engine and model roles — design

Date: 2026-10-24 · Covers projects 1 (edition split) and 2 (pluggable models)
of the post-hackathon roadmap. Projects 3–5 (accountable/fixer roles and ticket
delivery, scanner sources and connector, MSP accounts) are out of scope here.

## Intent

Remediation Zero is one product in two editions. The open-source local
edition is for technical users who want no cloud and run their own models.
The paid cloud edition is for companies that want to start quickly with
nothing to host, with models chosen and paid for by Ayliea. **Both editions
run the full remediation lifecycle**: triage, independent review, ownership,
chasing, exceptions, rescans and reporting. (Owner decision, 2026-10-24.)

Today only the cloud edition does. The local edition is a one-finding demo:
`scripts/local.py suggest-demo` sends a bundled synthetic finding
(`DEMO-WEB-01`) to one model and stores an "unreviewed" suggestion. The real
engine, `scripts/cycle.py`, is wired directly to Firestore, Vertex and Model
Armor.

This design makes the engine run on swappable parts, so the same code drives
both editions. The owner's concern: changes must not have to be made twice.
The answer is a single engine with narrow plug-in points, and one contract
test suite that every implementation of a plug-in point must pass.

## What exists (verified 2026-10-24, commit a0ca27c)

- **Already cloud-free, standard library only:** `tools/adjudication`
  (propose/review loop; `triage` and `review` are injected callables),
  `chase`, `exceptions`, `ownership`, `clock`, `idempotency`, `rescan`,
  `metrics`, `enrichment`, `ingest`, `model_armor` (stdlib HTTP),
  `github_tickets`, `cycles`, `recall`, `recovery_audit`, `inference_journal`,
  `model_endpoint`, `local_settings`, `sqlite_store`.
- **Bound to Firestore or Vertex:** `decisions` (`DecisionWriter`),
  `assignments`, `tickets` (`TicketWriter`), `exception_store`, `scan_store`,
  `reports` (also calls Gemini for the summary), `finding_lookup`, `delivery`
  (`GitHubDelivery` reads Firestore), `fleet_memory` (Memory Bank),
  `telemetry` (Cloud Trace), `store` (`FirestoreIdempotencyStore`),
  `review_models` (Vertex `genai.Client`).
- `SQLiteStore` already implements the same idempotency journal interface as
  `FirestoreIdempotencyStore` (`get`, `put`, `reserve_once`, `acquire`,
  `complete`, `abandon`), plus one `decisions` table.
- `ModelEndpoint` already speaks OpenAI-compatible chat completions with
  strict transport rules: HTTPS unless loopback, no redirects, no inherited
  proxies, no URL credentials, input ≤32 KiB, response ≤64 KiB, 60 s socket
  timeout, `max_tokens` 2048.
- The deployed ADK orchestrator on Agent Engine (`agents/`) builds ADK
  `Agent`s from `REASONING_MODEL` / `REVIEWER_MODEL`. `scripts/cycle.py`, run
  by `tick.sh`, calls `tools/review_models` directly and does not use ADK for
  model calls.
- **The cloud lifecycle is several processes, not one.** `scripts/cycle.py`
  runs read, enrich, screen, adjudicate, record and assign, then the cycle
  record and Memory Bank. Chase and the exception sweep are separate Cloud
  Run workers (`worker/app.py`: `run_chase`, `run_sweep`), each under its own
  service account; only chase holds the GitHub token. They number cycles by
  day (`cycle_for_day`), not by the triage cycle number. The report is
  `scripts/report.py`. Rescans are `scripts/rescan.py`.
- `scripts/graph_cycle.py` (run by `graph.sh`) is an ADK Workflow version of
  the triage cycle. It re-implements screen, triage, review, record, assign
  and queue as graph handlers, so it is already a second copy of that logic.
  It is the only cycle path that emits Cloud Trace spans.
- Several cloud writes are atomic batches across collections: decision plus
  `human_queue`, and ticket escalation plus `sla_clocks`. `human_queue`,
  `sla_clocks` and the idempotency journal are written by more than one
  agent.
- `SimClock`'s scenario offset lives in process memory and is never
  persisted.

## Goals

1. One engine. The lifecycle logic for a cycle lives in one place and is
   called by both editions with different plug-ins.
2. Six plug-in points (ports), each a small explicit interface:
   **storage, models, guardrail, ticket delivery, memory, telemetry.**
   Scheduling stays outside the engine; each edition triggers cycles its
   own way.
3. A local implementation of every port that uses only the standard library.
   The local edition installs and runs with `python3 -S`, as it does today.
4. Model access by **role**, with each role configured on its own: proposer,
   reviewer, summarizer, and an optional guard. Three request formats:
   OpenAI-compatible chat completions, Anthropic Messages, Gemini.
5. The cloud edition keeps working exactly as it does now, with its existing
   models, while gaining the same model roles. Vertex becomes one provider.
6. Drift between editions is caught by tests, not by vigilance.

## Non-goals

- Real scanner ingestion (project 4). Until then the local edition's full
  lifecycle runs on the synthetic corpus and the existing seed and rescan
  scripts, pointed at SQLite.
- Email or PSA ticket delivery, and accountable/fixer roles (project 3).
- MSP accounts, multi-tenancy, billing (project 5).
- Any change to the deployed ADK orchestrator or Agent Engine resource.
- Exposing the local server beyond loopback. Hosting it publicly stays
  unsupported.
- Vector search for memory.

## Anti-goals (would be a failure even if it technically works)

- A local decision that looks independently reviewed when it was not.
- Two engines, or two copies of lifecycle logic, that can drift.
- The core or local edition needing `pip install`.
- Untrusted text reaching a model unscreened because no guard was configured.
- Anything that deletes or recreates the Agent Engine resource or its session.
- A cloud regression in the behaviors `verify-controls.sh` proves.

## Constraints

Everything in CLAUDE.md applies. These are the ones this design leans on:

- Idempotency keys on every authoritative state change. SimClock for every
  persisted business time, with both `real_ts` and `sim_ts`.
- The reviewer is a different model family from the proposer, or the record
  says it is not. A capacity error is never a rejection.
- Each agent's credential is scoped to its own collections. The reporting
  agent cannot write tickets.
- Untrusted text crosses a guardrail boundary first, failing closed.
- Shared code imports no cloud-only package. New dependencies need approval.
- Storage schema changes need approval. **Approving this design approves**
  the SQLite schema it implies and the new decision fields listed under
  "Model roles".
- Every cloud dollar is out of pocket. Nothing here adds an always-on
  resource.

## Decided

### The engine

- The core holds **one stage function per agent process that exists
  today**: the triage cycle (what `scripts/cycle.py` does), chase, the
  exception sweep, the report, and the rescan. Each takes only the ports
  that stage is allowed to use, and imports no backend. Each keeps its
  current cycle numbering: the triage cycle number for triage and rescan,
  `cycle_for_day` for chase and sweep. That keeps every existing idempotency
  key unchanged. *(My call.)*
- **The cloud keeps its process split and identities.** `scripts/cycle.py`,
  `worker/app.py` (`run_chase`, `run_sweep`), `scripts/report.py` and
  `scripts/rescan.py` become thin wiring that build their cloud ports and
  call their stage. Service accounts, the chase-only GitHub token, schedules,
  command-line behavior, log events and their fields all stay unchanged.
- `scripts/graph_cycle.py` is in scope. Its handlers are rebased onto the
  triage stage's steps so the per-finding logic exists once. It keeps its
  Cloud Trace spans; `cycle.py` keeps emitting none. The telemetry port
  makes that a wiring choice, so neither path's behavior changes.
  *(My call: removing the second copy is the anti-drift goal, and
  `graph_cycle.py` is a local script, not the deployed Agent Engine
  resource.)*
- The local edition calls the same stages from `scripts/local.py`, which
  gets these new commands:
  - `seed`: load the synthetic corpus.
  - `cycle`: run triage, chase, sweep and report in order, in one process.
    Each stage gets only its own ports.
  - `rescan`: with `--dry-run`, as in the cloud.
  - `exception accept` / `exception list`: the local counterpart of
    `exception.sh`.

  `suggest-demo` is retired once a local cycle works.
- **Time, locally:** real use runs in real time. No simulated-time offset is
  persisted, so this adds no clock state and constraint 6 is untouched.
  Escalation over weeks and exception expiry are shown by the lifecycle test,
  which runs in one process and advances `SimClock` in memory exactly as the
  cloud demo does. *(My call.)*
- Structured log lines keep carrying finding ID and cycle ID in both editions.

### Storage port

- One interface per collection, shaped after what the current writers
  actually do: decisions, assignments, tickets, exceptions, scans, reports,
  cycles, human queue, SLA clocks, the idempotency journal, and the
  read-only references (findings, assets, owners).
- Firestore implementations wrap today's code without changing document
  shapes, apart from the decision fields named below.
- SQLite implementations live in the core and use only the standard library.
- **Permission boundary, local:**
  - Each agent's **owned** collections (the CLAUDE.md agent table) live in
    that agent's own SQLite file. Only that agent opens the file read-write;
    others open it read-only (`mode=ro` URI).
  - The collections several agents write today (`human_queue`,
    `sla_clocks`, the idempotency journal) live in one **shared** file. Every
    agent opens it read-write, which matches the cloud, where those
    collections are written by several service accounts.
  - Cross-collection atomic writes keep their atomicity locally through
    `ATTACH` of the owned and shared files in one transaction. All local
    databases use SQLite's rollback journal (the default `DELETE` mode, not
    WAL), because only the rollback journal makes multi-file commits atomic.
  - The reporting agent is handed no read-write ticket connection, and its
    store type has no ticket write methods.
  - The docs must say plainly that this is a boundary in the code, enforced
    by construction, and **not** an OS-level boundary like the cloud's IAM:
    one local OS user owns all the files. *(My call.)*
- The dashboard's local snapshot returns the same keys as the cloud snapshot
  (`counts`, `decisions`, `human_queue`, `scans`, `tickets`, `sla`,
  `exceptions`, `cycles`, `reports`, `resolved_total`, `sim_now`), so the
  dashboard shows real totals locally rather than "Unknown".

### Model roles

- Roles: **proposer** (triage), **reviewer**, **summarizer** (the reporting
  summary in `tools/reports.py`), and **guard** (optional, see Guardrail).
  Each role has its own provider format, endpoint, model name and API key
  environment variable.
- Formats and where they live:
  - OpenAI-compatible chat completions: core, stdlib. Covers Ollama,
    llama.cpp, vLLM, LM Studio and hosted providers that speak this format.
  - Anthropic Messages: core, stdlib.
  - Gemini with an API key: core, stdlib.
  - Gemini and Gemma through Vertex, using Google auth: **cloud only**,
    because it needs `google-genai` / `google-auth`. It wraps today's
    `review_models` client.
- Every core adapter inherits `ModelEndpoint`'s transport rules unchanged.
- An adapter returns text and maps overload responses (408, 429, 5xx,
  connection failure, timeout) to `CapacityError`. Prompt loading, fencing,
  `parse_proposal_payload` and `parse_review_text` stay shared, so every
  provider is held to the same output contract. Prompts stay the versioned
  files in `prompts/`; the local edition uses the same `triage.md` and
  `reviewer.md` as the cloud.
- **Reviewer independence:**
  - Each configured role has a model **family** label (e.g. `gemini`,
    `gemma`, `llama`, `claude`, `gpt`, `qwen`, `mistral`).
  - Every decision record gains `review_independence`: `cross_family`,
    `same_family`, or `unreviewed`. It also gains `models`, recording the
    format, model name and family for each role used. Endpoints and keys are
    never recorded.
  - The dashboard shows `same_family` as "reviewed by the same model family"
    and `unreviewed` as "not reviewed".
- **No reviewer configured:** triage still runs. The decision is recorded as
  `unreviewed`, never as ratified, and it goes to the human queue with
  reason "needs a person's review: no reviewer configured". Only a ratified
  decision proceeds to ownership and chasing, which is today's gate,
  unchanged.
- **Same-family reviews are a user setting.** (Owner decision, 2026-10-24.)
  When proposer and reviewer share a family and the reviewer ratifies, the
  local setting "Same-family reviews" decides what happens next:
  - **Wait for a person** (default): the decision goes to the human queue with
    reason "same-family review: needs a person's approval", and does not
    proceed to ownership or chasing until a person approves it.
  - **Proceed automatically:** the decision proceeds like a cross-family
    ratification, labeled "reviewed by the same model family" everywhere it
    appears.

  The policy in force is recorded on each decision (`same_family_policy`) and
  included in the inference journal's context fingerprint, so a decision's
  record always says which rule produced it. The setting never applies to
  `unreviewed` decisions: with no reviewer at all, a person always decides.
  Settings explains the trade-off in one sentence: a model reviewing its own
  family's reasoning shares its blind spots. Cloud deployments are
  cross-family and never consult the setting. *(Default is my call: a fresh
  install should not auto-proceed on a review the user never chose to
  trust.)*
- `unreviewed` is a **new `AdjudicationOutcome` value**, not `human_queue`.
  Counting "no reviewer configured" as `human_queue` would read as two
  rejections in the metrics. `tools/metrics.py` counts it separately and
  never as a rejection or as unavailable. The cloud never produces it, so
  cloud metrics are unchanged. *(My call.)*
- The inference journal's context fingerprint covers format, endpoint, model
  and family for every role. Changing any of them mid-cycle needs human
  review, as it does today.
- API keys are read from per-role environment variables
  (`RZ_PROPOSER_API_KEY`, `RZ_REVIEWER_API_KEY`, `RZ_SUMMARIZER_API_KEY`,
  `RZ_GUARD_API_KEY`) and are never written to settings files.
  `RZ_MODEL_API_KEY` stays as a fallback for the proposer, for
  compatibility.
- The Settings "Model connection" section grows one block per role:
  format, endpoint, model and family, plus key-present status. Saving still
  makes no model call. The existing explicit sample-check command is
  extended to check each configured role.
- Cloud: the role configuration comes from deployment environment variables.
  Today's values (proposer `gemini-3.5-flash`, reviewer
  `gemma-4-26b-a4b-it-maas`, both Vertex `global`) become the cloud defaults,
  so behavior is unchanged.

### Guardrail port

- Interface: screen text, returning the existing verdict shape (screened,
  blocked, reasons, confidence), with the existing fail-closed rule: if
  screening did not run, the untrusted text is withheld and triage proceeds
  on trusted metadata and enrichment alone.
- Cloud: Model Armor, as today.
- Local, with a guard model configured: the guard role screens the text, with
  a versioned prompt in `prompts/` that requires a fixed parseable answer.
  Anything unparseable means not screened, so the text is withheld.
- Local, with no guard configured: the text is withheld. That is the same
  fail-closed path as an unreachable Model Armor, and the decision record
  shows the comment was not screened.

### Ticket delivery, memory, telemetry ports

- Ticket delivery: `GitHubDelivery`, reading through the storage port instead
  of a Firestore client, works in both editions when a token is configured.
  The local default is dashboard-only: tickets and their state live in the
  local store and show on the dashboard, with no external delivery. The
  at-least-once and coalescing rules carry over unchanged.
- Memory: cloud uses Memory Bank. Local uses a SQLite table with the same
  `remember_cycle` / `recall` behavior: recall returns the most recent
  memories that match the query's terms. No embeddings.
- Telemetry: Cloud Trace where a cloud path emits spans today
  (`graph_cycle.py`), none where it does not (`cycle.py`). Local spans are a
  no-op; structured logs carry the same events.
- Reporting with no summarizer configured: the report is still written, with
  the computed metrics and no model summary, and is marked "no summary: no
  summarizer configured". *(My call.)*

### Scheduling and failed runs

- Cloud: Cloud Scheduler and Pub/Sub with its dead-letter queue, unchanged.
- Local: cycles run on explicit command. The launcher may also run them on an
  interval set in Settings, off by default. A failed local cycle is
  recorded in a failed-runs table with finding and cycle IDs and shown on
  the dashboard, so findings are never silently dropped.

### Drift protection

- **Contract tests.** One test suite per port, parametrized over every
  implementation of it. SQLite always runs in the offline suite. Firestore
  runs against the Firestore emulator when it is available, following
  `docs/development/emulator-validation.md`, and is skipped with an explicit
  reason otherwise, never silently. A change to lifecycle behavior is made
  once in the runner and checked against both editions by these tests.
- **One lifecycle test.** A full multi-cycle scenario on the synthetic corpus
  runs through the core runner on SQLite with stub model adapters: triage,
  review, ownership, chase escalation, an exception expiring, a rescan
  closing a finding. The same scenario's assertions are reused against the
  cloud wiring through the emulator.
- **Model adapters** get recorded-response tests per format, offline,
  including overload mapping and malformed-output rejection.
- The cloud's deployed proof stays `verify-controls.sh`, run before any
  cloud deploy of this work.

## My calls (marked so the owner can check them)

- The core does not require ADK. The deployed ADK orchestrator stays as
  cloud-only orchestration and is not touched by this project.
- Per-agent SQLite files plus read-only connections as the local permission
  boundary, documented honestly as code-level rather than OS-level.
- No reviewer configured means unreviewed and the human queue, never an
  automatic pass.
- No guard configured means untrusted text is withheld, never passed through.
- Model family is a label on each role, declared in Settings with a suggested
  value from the model name, rather than detected automatically. Detection
  from model names is unreliable, and a wrong guess would make
  `review_independence` lie.
- The local permission boundary, the guard prompt and the failed-runs table
  are new behavior and are documented in `docs/development/local-edition.md`.

## Left to the builder

- File and package layout for ports and implementations, provided existing
  Firestore modules keep their behavior and their tests keep passing without
  edits to assertions. Moving modules between core and cloud needs the
  owner's approval under CLAUDE.md; this layout is the one place it is
  pre-approved.
- The exact method signatures of each storage interface, derived from the
  current writers' real call sites.
- Exact SQLite table definitions.
- How the local interval scheduler runs inside the launcher.
- The order of work, provided the cloud wiring passes the existing suite and
  `verify-controls.sh` before the local wiring is called done.

## Open, deferred to project 5

Where the private cloud layer lives (a private repository or package versus
this public repository). Nothing in projects 1–2 is paid-only: the cloud
wiring built here is the same code that is already public in this
repository, so the decision can wait until billing and MSP accounts are
designed.
