# Remediation Zero

An autonomous agent fleet that owns the vulnerability remediation lifecycle for a one-person security team.

Built for the All Things Agentic Hackathon, Fortified Enterprise Fleet track.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

---

## The friction

Finding vulnerabilities is a solved problem. Scanners do it well. What breaks a one-person security program is the six weeks after the scan: chasing owners who never opened the ticket, re-opening work that silently stalled in week three, tracking risk acceptances that expired without anyone noticing, and rebuilding the same context from scratch every Monday morning.

That work is not intellectually hard. It is relentless, stateful, and spread across weeks, which is exactly the shape of work an agent fleet should carry and a human should not.

Remediation Zero is built for the analyst who *is* the security department. No SOC, no triage tier, no program manager. One person, one backlog, and a calendar that does not care.

## What it does

A finding lands. From there no human is involved until a decision genuinely needs one.

1. **Triage and Enrichment** proposes a severity, an SLA, and a remediation path, citing CISA KEV, NVD, and EPSS.
2. **Adversarial Reviewer** receives the proposal and the raw finding and must either ratify it or reject it with a stated reason. Nothing becomes state without passing this gate.
3. **Ownership and Routing** maps the affected asset to an accountable human.
4. **Remediation Chase** opens the ticket and pursues it across weeks, nudging, escalating, and adapting to what has historically worked with that specific owner.
5. **Exception and Expiry** records risk acceptances with a TTL and re-opens the finding automatically when one lapses.
6. **Reporting** produces the weekly metrics the analyst would otherwise assemble by hand.

## Architecture

![Architecture](docs/architecture.png)

*One finding's path through the fleet. Source: [`docs/architecture.svg`](docs/architecture.svg).
Every record written anywhere on this path carries both `real_ts` and `sim_ts`; the deadlines
in Chase run on the second while the first stays wall clock.*

The design decisions worth defending:

**Cross-family adversarial review before commit.** A single reasoning agent that is confidently wrong produces a wrong SLA on a real vulnerability. Every triage decision is challenged before it becomes state by a reviewer agent running on Gemma rather than Gemini. Using a different model family is the point: a model auditing its own reasoning shares its own blind spots. Disagreements are logged, rejections are capped at one retry, and anything still contested routes to a human queue.

**Idempotency keys on every side-effecting tool.** A long-running agent that resumes after a crash must not open the same ticket twice or send a fourth nudge as its first. Every mutation carries a deterministic key derived from finding ID, action type, and cycle number.

**Injectable clock.** All time reads pass through a `SimClock` service. Every document carries both `real_ts`, which is wall clock and never falsified, and `sim_ts`, which is simulation. This makes a six-week remediation cycle demonstrable in three minutes without fabricating evidence of elapsed time.

**Least privilege per agent, and an honest account of its limit.** Each sub-agent runs under its own service account. There is no shared credential.

Firestore cannot enforce collection-level access control for server-side clients, and the design says so rather than implying otherwise. `roles/datastore.user` resolves to `datastore.entities.create/update/delete`, which are database-scoped, and Security Rules — which *are* collection-aware — are bypassed entirely by server SDKs authenticating as a service account.

So the boundary was put where IAM can actually enforce it. Reports live in their own Firestore database. The reporting identity holds `roles/datastore.viewer` on the operational database and `roles/datastore.user` conditioned to the reports database, which leaves it structurally unable to write a ticket. `scripts/verify-controls.sh` proves this by running a Cloud Run job whose service account *is* the reporting identity and attempting the write:

```
expect DENIED   | got DENIED (PermissionDenied)   | write a ticket
expect DENIED   | got DENIED (PermissionDenied)   | write to the human queue
expect ALLOWED  | got ALLOWED                     | read a finding
expect ALLOWED  | got ALLOWED                     | write a report
```

The last two matter as much as the first two. An identity that can write nothing proves only that it is broken; the control is that the boundary falls in a specific place.

The remaining five agents hold distinct identities with collection separation enforced in application code. That is a weaker guarantee than IAM enforcement and is named as such here rather than blurred into the same sentence.

**Two-layer injection defense, measured rather than assumed.** Untrusted text — scanner comment fields, ticket replies, vendor advisories — passes Model Armor before reaching any reasoning context. Against the planted payload it returns `MATCH_FOUND` on the prompt-injection filter at `MEDIUM_AND_ABOVE`; against a benign scanner comment it returns `NO_MATCH_FOUND`. The boundary fails closed on an unreachable screener, a filter that did not execute, and an unparseable response, because passing unscreened text into a reasoning context on a bad minute is exactly the failure it exists to prevent.

The reviewer is the second layer, and measuring it corrected an overclaim. With Model Armor disabled the reviewer rejected the planted finding every time, but named the injection in only one run out of five: it was finding a sufficient reason to reject on severity grounds and stopping. The injection never succeeded, but "the reviewer independently catches it" was not true as written. The reviewer now assesses the untrusted text first, before the proposal at all, and reports the result on every finding whether or not it is the reason for rejecting. Detection went from one in five to six in six.

**The fleet runs itself, and says so when it cannot.** Cloud Scheduler publishes one tick a day to a single topic, which fans out to two push subscriptions and two workers — one running as `rz-chase`, one as `rz-exception`. The fan-out is not decoration: a single worker running both agents would need one credential holding both agents' access, which is the shared credential the architecture does not have.

The scheduled work is deliberately the chase and the exception sweep rather than triage. Those are the relentless, stateful weeks this project argues a human should not carry, and neither calls a reasoning model, so a daily tick costs essentially nothing.

Cloud Scheduler cannot template a date into its payload and keeps no counter, so the tick carries no cycle number and the worker derives one from the day. That gives the idempotency key the two properties it needs: stable within a day, so a Pub/Sub redelivery is absorbed; distinct across days, so tomorrow is new work. A literal cycle in the payload would have been the same integer every day, and the guard would then have correctly skipped every tick after the first — the schedule would have quietly stopped doing anything on day two while still reporting success.

**Failure containment.** A worker never returns success for a message it did not process. Malformed ticks answer 400 and failed ones answer 500; both leave the message unacknowledged, so Pub/Sub redelivers and the dead-letter policy catches it after five attempts. Nothing drains that queue on a schedule, because the point is that a person finds it. `scripts/verify-events.sh` proves this the way `verify-controls.sh` proves the rest — by publishing a message the worker genuinely cannot process and reading it back out of the queue:

```
published a message the worker cannot process
{"cycle": "poison-20260827165607"}
[PASS] The dead-letter queue caught it
       2 of 2 expected copies, first after ~99s, in remediation-tick-dead-hold.
       One per subscription: each dead-letters independently.
```

Two copies rather than one because the tick fans out to two subscriptions and each exhausts its delivery attempts separately. A dead-letter queue nobody has watched catch anything is a configuration line, not a control, and its two common failure modes are both silent: without publisher access for the Pub/Sub service agent the subscription simply retries forever, and an empty queue looks the same whether nothing failed or nothing could ever arrive. Tool calls retry with backoff, and the triage and review pair has a loop cap and circuit breaker. Failures degrade to a human queue rather than silently dropping findings.

## Tech stack

| Layer | Service |
|---|---|
| Reasoning model | `gemini-3.5-flash` via Vertex / Agent Platform, served from the `global` endpoint |
| Reviewer model | `gemma-4-26b-a4b-it-maas`, deliberately a different model family, pay-per-token, no dedicated endpoint |
| Agent framework | Google Agent Development Kit (ADK) 2.8.0 |
| Runtime | Agent Runtime, long-running orchestrator session |
| Working state | Firestore, Agent Platform Sessions |
| Long-term memory | Agent Platform Memory Bank |
| Governance | Agent Identity, Agent Registry, Model Armor |
| Telemetry | Cloud Trace, Cloud Logging (OpenTelemetry) |
| Events | Pub/Sub with dead-letter queue, Cloud Scheduler |
| Interface | Cloud Run |
| Infrastructure as code | Terraform, in `infra/`, for the event plumbing |

## Running deployment

| | |
|---|---|
| Console | https://remediation-zero-console-978104855285.us-central1.run.app |
| Agent Engine | `projects/remediation-zero/locations/us-central1/reasoningEngines/3119663582942330880` |
| Orchestrator session | `5107592082113953792`, created 2026-08-27T01:04:38Z UTC |

The console is read-only and scales to zero. It runs under a service account holding `roles/datastore.viewer` and nothing else, and its container ships no agent framework, no model clients and no write path: the interface a stranger can reach is structurally unable to change the record it displays.

## Data sources

All vulnerability findings in this repository are **synthetic**. No production, employer, or third-party data is used anywhere in this project.

Enrichment queries real public sources: the CISA Known Exploited Vulnerabilities catalog, NVD, and EPSS. Responses are cached locally so that demonstrations do not depend on third-party availability.

The synthetic corpus in `data/` is dedicated to the public domain under CC0 1.0. See `data/README.md`.

---

## Spin-up instructions

### Prerequisites

- A Google Cloud project with billing enabled, and a budget alert set before deploying anything
- `gcloud` CLI, authenticated for both the CLI and application default credentials:
  ```bash
  gcloud auth login
  gcloud auth application-default login
  ```
  These are separate credentials. The CLI uses the first; the Vertex SDK and ADK use the second.
- Python 3.10 or later (ADK requirement). Built and tested on 3.12.3.

### 1. Clone and configure

```bash
git clone https://github.com/Ayliea/remediation-zero.git
cd remediation-zero
cp .env.example .env
```

Set the following in `.env`:

```
GOOGLE_CLOUD_PROJECT=your-project-id

# Model serving location and Agent Engine location are different, and must
# stay different. gemini-3.5-flash and the Gemma MaaS model are served from
# `global` and return 404 from a named region. Agent Engine deploys into a
# named region. Addressing the engine with the model's location produces
# "The ReasoningEngine does not exist", which reads like the engine was lost.
GOOGLE_CLOUD_LOCATION=global
AGENT_ENGINE_LOCATION=us-central1
GOOGLE_GENAI_USE_VERTEXAI=true

REASONING_MODEL=gemini-3.5-flash
REVIEWER_MODEL=gemma-4-26b-a4b-it-maas

SIM_CLOCK_MODE=real          # "sim" for the accelerated demo
MODEL_ARMOR_ENABLED=true
```

### 2. Enable APIs and provision infrastructure

```bash
./scripts/enable-apis.sh          # idempotent, safe to re-run
./scripts/grant-iam.sh            # read this before running it; it modifies project IAM
```

`enable-apis.sh` turns on Agent Platform, Cloud Run, Firestore, Pub/Sub, Scheduler, Trace, Logging, Model Armor and the build services. `grant-iam.sh` creates the per-agent least-privilege bindings described above, and grants the operator permission to run the control probe.

Set a billing budget alert before running either.

### 3. Seed the synthetic corpus

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt -c constraints-3.12.txt

.venv/bin/python -m scripts.seed        # regenerates data/, produces no diff
.venv/bin/python scripts/ingest.py      # loads it into Firestore
```

The corpus is committed and deterministic: `SEED = 20260827`, so regenerating produces no diff and a change to the data is visible in review rather than buried in churn. 400 findings across 60 assets and 12 owners. Everything is synthetic except the CVE identifiers, which are drawn from the cached CISA KEV catalogue so that enrichment returns genuine data. Addresses use the RFC 5737 documentation ranges and hostnames the reserved `.invalid` TLD, both asserted by tests, because the repository is public and "contains nothing real" has to hold on every regeneration.

One finding carries a planted prompt-injection payload in its comment field. The field marking it is stripped at ingest and never reaches Firestore: an agent that can see a label saying "this one is planted" is reading a label, not detecting an attack.

### 4. Run locally

```bash
.venv/bin/adk run agents/orchestrator     # local inner loop, against Vertex
.venv/bin/uvicorn ui.app:app --port 8080  # console at http://localhost:8080
```

### 5. Deploy

```bash
./scripts/deploy-agent.sh --create   # FIRST ENGINE ONLY. Record the printed
                                     # id in .env as AGENT_ENGINE_ID.
./scripts/deploy-agent.sh            # every deploy after that: updates in place
./scripts/deploy-ui.sh               # console to Cloud Run
./scripts/deploy-worker.sh           # the two scheduled workers
terraform -chdir=infra init
terraform -chdir=infra plan          # read this before applying
terraform -chdir=infra apply         # topics, subscriptions, DLQ, scheduler
.venv/bin/python scripts/session-init.py   # creates the long-running session
```

Two things worth knowing before running these.

`adk deploy agent_engine` creates a **new** Agent Engine instance when `--agent_engine_id` is omitted, and does not error. It also prints `Deploy failed` while exiting 0. `deploy-agent.sh` guards both: the id is mandatory, a non-existent id is treated as a typo rather than a request to create, output is inspected instead of the exit code, and the resource is re-read afterwards to confirm the in-place claim. Nothing in it deletes.

`session-init.py` refuses to run if a session already exists, printing that session's id and age instead. The elapsed time on that session is the demo's strongest proof point and cannot be regenerated, so the script will not create a second one alongside it.

**Agent Registry does not register the agent automatically.** Deployment prints a link to a separate Gemini Enterprise registration flow. This is noted here rather than claimed otherwise.

### 6. Run a cycle

```bash
# Triage and adjudicate. --cycle is required: it is half the idempotency key,
# so there is no default that could quietly overwrite another cycle's record.
./scripts/tick.sh --cycle 1 --limit 3

# Run the same cycle again. Nothing is written a second time, and the
# decisions from the first run are preserved rather than recomputed.
./scripts/tick.sh --cycle 1 --limit 3

# One finding through the ADK Workflow delegation graph, which prints its own
# topology before walking it. This is the run that produces a Cloud Trace.
./scripts/graph.sh --cycle 1 --finding RZ-0101

# Accelerated: replay the weeks after the scan. Simulated time only —
# advance() raises in real mode, so this needs SIM_CLOCK_MODE=sim.
#
# Step the advance at roughly the nudge interval, which is the SLA window
# divided by MAX_NUDGES + 1. One large jump lands every clock past its deadline
# at once, so chase escalates everything and never shows the nudging in
# between. On a 7-day SLA that interval is 1.75 days:
for d in 2 4 6 8 10; do
  SIM_CLOCK_MODE=sim ./scripts/chase.sh --cycle $((2+d)) --advance-days $d
done
SIM_CLOCK_MODE=sim ./scripts/exception.sh --cycle 2 --sweep
./scripts/report.sh --cycle 2
```

Every one of these is safe to repeat. `--cycle` and the finding id form the
idempotency key, so a second run of the same cycle skips rather than duplicates.

[`docs/DEMO.md`](docs/DEMO.md) is the same path as a runbook, with every step
timed against the live deployment and a table of what to do when one of them
misbehaves on camera.

### 7. Let it run itself

```bash
# What the scheduler publishes. Identical to waiting for 09:00 UTC.
gcloud pubsub topics publish remediation-tick --message='{"advance_days":0}'

# Prove the dead-letter queue by sending it something it must catch.
./scripts/verify-events.sh
```

Terraform manages the event plumbing and nothing else. The Agent Engine, its
session, the Firestore databases, the service accounts and the Cloud Run
services are read as data rather than declared as resources, so
`terraform destroy` cannot reach them. That boundary is a safety property: the
session carries days of real elapsed wall-clock time and cannot be regenerated
before the deadline, and importing it to make the configuration look complete
would trade that guarantee for tidiness. `infra/existing.tf` says so in place.

### 8. Verify the controls

```bash
./scripts/verify-controls.sh                          # all four, 3-4 minutes
./scripts/verify-controls.sh --only armor,reviewer,resume   # the fast three, under 20s
```

The probe check executes a Cloud Run job as the reporting identity, which is
what makes it real and also what makes it slow. Timed individually it is 218
seconds; the other three together are 19.5. `--only` exists so a demonstration
is not forced to choose between running the controls live and running them at
all. A partial run prints the checks it did not exercise before printing any
result, because a control suite that quietly skips its slowest check is how
that check stops being run.

Every check performs the action the control is meant to stop and reports what actually happened. There are three outcomes, not two: a check that could not run is reported as inconclusive and exits non-zero, because collapsing "could not run" into "passed" is how a control gets believed on the strength of a test that never exercised it.

```
[PASS] Model Armor blocks the planted injection
[PASS] Reviewer catches it with Model Armor disabled
[PASS] Reporting identity is denied a ticket write
[PASS] A resumed cycle writes nothing a second time
```

### 9. Reset the demo state

Rehearsing advances simulated time, and every advance ages the SLA clocks.
After enough rehearsals almost every clock reads `breached`, so chase escalates
nearly everything and stops showing the lifecycle it exists to demonstrate.

```bash
./scripts/reset-derived.sh              # dry run: prints what would go
./scripts/reset-derived.sh --confirm    # clears sla_clocks and tickets
```

Both collections are derived: chase rebuilds them from the decisions that
produced them, so clearing them costs nothing that cannot be recomputed. The
allowlist is closed and everything else is refused by default, including any
collection added to the schema later. `decisions` and `human_queue` are the
adjudication record, `idempotency` is what the resume control checks itself
against, and the Agent Engine and its session are not reachable from the script
at all — the tests assert its source does not name them.

Winding simulated time backwards would have been the other way to do this, and
it is the wrong one. `real_ts` is wall clock and this script never writes one.

### 10. Tear down

```bash
# Cloud Run scales to zero, so idle cost is already nil. To remove everything:
terraform -chdir=infra destroy       # events only, by construction
gcloud run services delete rz-worker-chase --region=us-central1
gcloud run services delete rz-worker-exception --region=us-central1
gcloud run services delete remediation-zero-console --region=us-central1
gcloud run jobs delete reporting-write-probe --region=us-central1
gcloud firestore databases delete --database=reports
```

Deliberately absent: any command that deletes the Agent Engine or its session. That resource is updated in place for the life of the build and `deploy-agent.sh` refuses to recreate it. Delete it by hand only after the submission is judged.

### Cost notes

Minimum instances are zero and maximum instances are capped, so idle cost is negligible. If Gemma is served from a dedicated endpoint in your region rather than per-token, that endpoint is the only always-on component: deploy it when needed and destroy it immediately after. Set a billing budget alert before running anything.

---

## Findings and learnings

**The reviewer disagrees often, and on substance.** Across the decisions recorded so far it rejected roughly six in ten proposals. The two recurring objections are remediation text that names no version — "apply the vendor security patch" rather than "upgrade to 2.4.39" — and proposed SLAs that exceed the CISA KEV due date for the same CVE. The second is the one that justifies the cross-family design: it requires holding a regulatory deadline and a proposed deadline in mind at once and noticing they conflict.

**A high disagreement rate is a health metric, not a defect.** A reviewer that ratifies everything is indistinguishable from having no reviewer, so the rate is reported as a headline figure rather than buried.

**One rejection class turned out to be an evidence gap, not a reasoning failure.** Early cycles rejected almost everything for vague remediation. Re-running the same findings after the NVD cache finished populating changed the outcome from 1 ratified of 3 to 2 of 3, and the surviving rejection was the KEV due-date conflict. Had the triage prompt been "fixed" while the cache was half full, the fix would have compensated for a transient condition and looked like it worked.

**Idempotency was load-bearing in a way the design note did not anticipate.** The obvious argument is that a resumed agent must not open two tickets. The stronger one showed up in testing: the models are not deterministic, so the same cycle run twice produces *different decisions* for the same finding. One finding was ratified on the first run and rejected twice on the second. Without the guard the second run would not merely have duplicated work, it would have silently overwritten a decision a human may already have acted on, with a contradictory one.

**Correctness guards and cost guards are not the same guard.** The idempotency guard originally wrapped the write, which made the state correct but only fired after triage and review had already run and been billed. Re-running a cycle burned about forty model calls to change nothing. Checking the completed-call record before the model calls took a re-run from 89.9 seconds to 1.5, and that distinction only became visible by running the thing twice and watching the clock.

**The clock cannot simulate the thing it exists to prove.** `sim_ts` can move a six-week SLA into a three-minute demonstration, but the value of a long-lived session is precisely that it was not simulated. `real_ts` is read from wall clock on every write in both modes and there is deliberately no API that sets it; `advance()` raises in real mode. The two figures sit next to each other on every record so the gap is legible rather than narrated.

## Roadmap

Out of scope for the hackathon build, kept here so the boundary is explicit:

- Real scanner integrations rather than a synthetic corpus
- Ticketing system connectors
- Human approval workflow for escalations above a severity threshold
- Multi-tenant isolation

## Submission provenance

Built for the All Things Agentic Hackathon, Fortified Enterprise Fleet category.

- Devpost: `daviyon-daniels `
- GitHub: `daviyondaniels` (personal account)
- Google Cloud project: `remediation-zero`, under a separate business Google account

The deployment shown in the demo video runs in that Google Cloud project. The GitHub account and the Google Cloud account belong to the same author. Commits are signed with an SSH key registered to the GitHub account; every commit in the history verifies.

## Disclosure

This project was built entirely within the hackathon submission period. Implementation was assisted by AI coding tools, which the contest rules expressly permit. No pre-existing code was incorporated.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

The architecture diagram and documentation in this repository may be reused with attribution.
