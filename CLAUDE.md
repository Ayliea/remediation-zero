# CLAUDE.md

Constraints for this repository. Read this before writing code in any session.

## What this is

Remediation Zero, by Ayliea: an autonomous multi-agent system that owns the
vulnerability *remediation* lifecycle for small organizations with little or no
security staff. Triage with cited evidence, independent review of every
proposal, mapping each problem to the people accountable for it, chasing the
fix over weeks, risk acceptances that expire, and closure only when a rescan
proves it.

**It sits on top of discovery; it is not a vulnerability scanner.** Do not
build scanning engines, device agents, or asset discovery. Findings come from
existing tools (Greenbone/OpenVAS, Nuclei, Trivy, osquery, Wazuh, Defender,
cloud-provider scanners). For customers who have nothing, the product may
bundle and configure an open-source scanner as its first source; it never
writes its own. Becoming another generic vulnerability management platform is
the failure mode this product exists to avoid.

Every behavior the system claims should be observable and verifiable by
someone who did not write it, including what was *not* checked. Favor the
boring, verifiable choice over the clever one.

## Editions

One codebase, two editions. A fix to shared behavior is made once, in the core.

| | Open-source core / local edition | Cloud edition (paid) |
|---|---|---|
| Who | Technical users who want no cloud and run their own models | Companies that want fast onboarding with nothing to host |
| Models | User-configured: local models or their own API keys | Chosen, hosted and paid for by Ayliea; invisible to the customer |
| Storage | SQLite | Firestore today |
| Extras | — | Hosting, managed models, MSP accounts spanning many clients, billing, on-network connector |

- The core holds the agents, the lifecycle, the dashboards, and four plug-in
  points: **storage, models, scanner sources, ticket delivery**. The cloud
  edition is a private layer on top of the core and never a fork of it.
- Shared code must not import cloud-only packages. `ui/dashboard_view.py` is
  the pattern: pure rendering, with each edition supplying its own data.
- The core is licensed Apache 2.0.
- The edition split itself is still being designed
  (`docs/superpowers/specs/`). Until it lands, do not move code between core
  and cloud without asking.

### Who the product serves

- Each asset has an **accountable** person (usually the business owner) and
  one or more **fixers** (often an outside IT provider / MSP, sometimes the
  owner). Chasing goes to fixers; escalation goes to the accountable person.
- Only an accountable person can accept a risk. A fixer cannot accept risk on
  the owner's behalf.
- MSPs are both a sales channel (one MSP runs the cloud edition for many
  clients) and the fixers that work is delivered to.

## Hard constraints

These are not preferences. Violating any of them breaks the product's claims.

1. **Every authoritative state-changing tool takes an idempotency key.** Derived deterministically from finding ID, action type, and cycle number. A resumed agent must never apply a ticket, nudge, or escalation transition twice. Tracker notifications are an at-least-once projection of that state: issue creation and comments with persisted, unguessable delivery markers have recovery lookups, but the GitHub API offers no atomic comment idempotency key and the narrow concurrent-post race must not be described as exactly-once.
2. **Every persisted business-time read goes through `SimClock`.** Never call `datetime.now()`, `time.time()`, or a database server timestamp to stamp a lifecycle record or make a lifecycle decision. Runtime-only concerns such as cache expiry and network timeouts may use process time and are never persisted. Every persisted lifecycle record carries both `real_ts` and `sim_ts`. `real_ts` is wall clock and is never falsified or backdated under any circumstances.
3. **The reviewer runs on a different model family from the proposer.** This is a deliberate architectural decision, not an implementation detail. Where a deployment cannot honor it (a local user pointing both roles at the same family), the record and the UI must say "reviewed by the same model family" rather than imply independence. A reviewer capacity error (such as a 429 `The request queue is full`) is retried with backoff and is never read as a rejection: treating capacity pressure as "reviewer rejected" would corrupt the adjudication record.
4. **Each agent's credential is scoped to its own collections.** No shared credential. The reporting agent must be structurally incapable of writing tickets. In the cloud edition this is one service account per agent with IAM on its own Firestore collections.
5. **No real data in the repository.** Tests, fixtures, seeds and demos use synthetic data only: no real hostnames, IPs, people, or customer data. Real CVE identifiers are fine and expected. Customer data handled by a deployment is never copied into the repo or used in development.
6. **Secrets never enter the repo.** `.env`, service account JSON, and API keys are gitignored. Local-edition API keys are read from the environment and never written to settings files.
7. **Enrichment responses are cached to disk.** CISA KEV, NVD, and EPSS are queried once and cached. Nothing should depend on a third-party API being reachable at that moment.
8. **Untrusted text passes a guardrail boundary before reaching any reasoning context.** Scanner comment fields and advisory prose (e.g. NVD) are untrusted; findings metadata generated by the seed script is trusted, free text carried inside it is not. In the cloud edition the boundary is Model Armor. Any edition or new ingress surface (ticket replies, new scanner sources) must cross an equivalent boundary first.
9. **The long-running cloud agent resource is never deleted or recreated.** Its session has accumulated real elapsed time that cannot be regenerated, and it is the strongest evidence that the lifecycle works over weeks. It has a stable, explicit resource name and is always updated in place:
    - Engine: `projects/remediation-zero/locations/us-central1/reasoningEngines/3119663582942330880`
    - Session: `5107592082113953792`, created `2026-08-27T01:04:38Z` UTC (`real_ts 1787792678.119875`)
    - `adk deploy agent_engine` **creates a new instance when `--agent_engine_id` is omitted, and does not error.** It also prints `Deploy failed` while exiting 0. `deploy-agent.sh` guards both; do not bypass it.
    - Any script that could delete or recreate it must refuse and report the existing resource instead.

## Current cloud deployment

What runs today on Google Cloud. Model providers are being made pluggable
(proposer and reviewer roles; OpenAI-compatible, Anthropic Messages, and
Gemini formats). Vertex will be one provider among several, not a
requirement.

| Concern | Choice |
|---|---|
| Reasoning model | `gemini-3.5-flash` via Vertex / Agent Platform, served from `global` |
| Reviewer model | `gemma-4-26b-a4b-it-maas`, pay-per-token, served from `global` |
| Agent framework | ADK 2.8.0, pinned with `constraints-3.12.txt` |
| Runtime | Agent Runtime, long-running orchestrator session |
| Working state | Firestore |
| Cross-session memory | Agent Platform Memory Bank |
| Events | Pub/Sub with dead-letter queue, driven by Cloud Scheduler |
| Guardrails | Model Armor on all implemented untrusted ingress |
| Secrets | Secret Manager, granted per agent on the secret itself |
| Telemetry | Cloud Trace, Cloud Logging |
| Interface | Cloud Run: owner dashboard at `/`, evidence console at `/console` (`/dashboard` redirects to `/`) |
| Infrastructure | Terraform in `infra/` |
| Language | Python 3.12.3 locally; ADK requires >=3.10 |

Operational facts that are easy to get wrong:

- **ADK is 2.x.** 2.0 broke the 1.x agent API, event model, and session schema; do not write 1.x patterns from memory. Check the installed package before using any ADK API.
  - `Workflow` is real and top-level, backed by `google.adk.workflow` (`Node`, `Edge`, `START`, `DEFAULT_ROUTE`, `JoinNode`, `RetryConfig`).
  - **There is no top-level `Task` API.** Task models live at `google.adk.agents.llm.task`. Delegation is expressed through `AgentTool` plus `SequentialAgent` / `ParallelAgent` / `LoopAgent` / `ManagedAgent`.
  - `Agent` has `rerun_on_resume` and `retry_config`; both matter for resume safety and bounded retries.
  - Session and memory services are **async throughout** (`create_session`, `list_sessions`, `add_memory`).
  - The agent loader resolves `root_agent` from `agents/<name>/agent.py`.
- **Model location and engine location are different and must stay separate.** `gemini-3.5-flash` and the Gemma MaaS model are served from `global` and return 404 / `only available via global endpoint` from a named region. Agent Engine deploys into a named region. So `GOOGLE_CLOUD_LOCATION=global` for reasoning, `AGENT_ENGINE_LOCATION=us-central1` for the engine.
- Addressing the **engine** with the model's location returns `The ReasoningEngine does not exist`, which reads like the engine was lost. It was not. Check the location before believing that message.
- Gemma is Model-as-a-Service: **no dedicated endpoint and nothing always-on.**

## The agents

One responsibility each. No agent reaches outside its own collections.

| Agent | Owns | Writes to |
|---|---|---|
| Orchestrator | Cycle control, delegation | `cycles` |
| Triage | Severity, SLA, remediation path, with cited evidence | `decisions` (proposed) |
| Reviewer | Ratify or reject triage proposals with a stated reason | `decisions` (adjudicated) |
| Ownership | Asset to accountable human mapping | `assignments` |
| Chase | Tickets, nudges, escalation over weeks | `tickets` |
| Exception | Risk acceptances with TTL, automatic re-open at expiry | `exceptions` |
| Reporting | Metrics and summaries | `reports` |

No agent owns `human_queue`. Any agent may append to it; nothing reads from it except the console UI. It is the terminal state for anything the fleet could not resolve safely.

Read-only reference collections, written by the seed and rescan scripts and never by an agent: `findings`, `assets`, `owners`, `scans`. Derived state: `sla_clocks`.

`scans` holds each scan's coverage manifest, and `findings.status` is the only thing that marks a finding resolved. Both are written by `scripts/rescan.py`, never by an agent. Chase reads the finding and closes its own ticket; nothing outside chase writes `tickets`.

## Commands

Keep these current. If you add a script, add it here.

All Python runs through the local virtualenv. The system interpreter is
PEP 668 externally-managed, so `pip install` outside `.venv` fails. The local
edition is the exception: it is standard-library only and runs with `-S`.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -c constraints-3.12.txt

.venv/bin/pytest                              # full offline suite; network is blocked
.venv/bin/pytest tests/test_idempotency.py    # the two suites that matter most
.venv/bin/pytest tests/test_clock.py

# local edition (no pip packages, no cloud account)
python3 -S start-remediation-zero.py                                       # launcher; opens http://127.0.0.1:8081
python3 -S start-remediation-zero.py --saved --public-url https://NAME:PORT  # also reachable through an HTTPS proxy (Tailscale Serve); every page needs sign-in
python3 -S -m scripts.local --help                                         # init | seed | cycle | rescan | exception | approve | serve | check-models | update-enrichment | greenbone
python3 -S -m scripts.local update-enrichment                              # fetch CISA KEV, EPSS and NVD into the workspace cache; reaches the internet
python3 -S -m scripts.local greenbone tasks                                # list the account's Greenbone tasks: task_id  name
python3 -S -m scripts.local greenbone test                                 # connect / sign in / list tasks, one line each
python3 -S -m scripts.local greenbone pull [--cycle N]                     # import the next finished report of each chosen task (the newest one the first time)
python3 -S -m scripts.local greenbone upload FILE [--add-task] [--cycle N] # import one exported report; --add-task chooses its task
python3 -S -m scripts.build_local_installer /abs/path/install-remediation-zero.py
python3 -S -m scripts.verify_local_install

# dashboard (/) + console (/console) dev server; synthetic data, no cloud reads on /
RZ_DASHBOARD_DEMO=1 .venv/bin/uvicorn ui.app:app --host 127.0.0.1 --port 8095 --reload --reload-dir ui --reload-dir tools

# cloud edition
./scripts/enable-apis.sh                      # idempotent, safe to repeat
.venv/bin/adk run agents/orchestrator         # local inner loop, against Vertex
./scripts/deploy-agent.sh                     # update in place, safe to repeat
./scripts/deploy-agent.sh --create            # FIRST ENGINE ONLY. never again.
.venv/bin/python scripts/session-init.py      # refuses if a session exists
./scripts/deploy-ui.sh                        # console to Cloud Run
./scripts/deploy-worker.sh                    # the two scheduled workers
./scripts/verify-events.sh                    # prove the dead-letter queue
./scripts/register-agent.sh --apply           # publish to Agent Registry, then prove discovery
./scripts/tick.sh                             # run one cycle
.venv/bin/python scripts/gen_rescan.py        # regenerate the follow-up scan; fixed seed
./scripts/rescan.sh --cycle N --dry-run       # what a rescan would close. ALWAYS read this first
./scripts/rescan.sh --cycle N                 # apply it. the only path that resolves a finding
./scripts/verify-controls.sh                  # prove the six security claims against deployed services
./scripts/verify-controls.sh --only armor,reviewer,resume,coverage  # the fast four, 33s
./scripts/reset-derived.sh                    # dry run: what a reset would clear
./scripts/reset-derived.sh --confirm          # clears sla_clocks + tickets + scans, and undoes
                                              # what a rescan wrote to findings. seeded findings
                                              # are never deleted
terraform -chdir=infra plan                   # ALWAYS read this first
terraform -chdir=infra apply                  # events + the console warmer; nothing else
```

## Cost and infrastructure

Every cloud dollar is paid by Ayliea out of pocket. Terraform and deploy
scripts must respect that; this is a hard requirement, not good practice.

- Minimum instances 0 everywhere. Maximum instances explicitly capped.
- No always-on endpoints. Prefer pay-per-token model serving; never create a dedicated model endpoint without asking.
- Provision minimal CPU and RAM. Scale up only if something actually fails.
- No dedicated vector database or always-on cluster.

## Conventions

- Prompts live in `prompts/` as versioned files. Never inline agent instructions as string literals.
- Tools live in `tools/`, one module per capability, each with an explicit input schema.
- Every module carries an Apache 2.0 header.
- Structured logging only. Every log line carries the finding ID and cycle ID where one exists, so a single finding's journey is traceable end to end.
- Write the test alongside the tool for anything with an idempotency key or a permission boundary. Those behaviors are the product's core claims.
- Don't copy code from other projects unless its license is compatible with Apache 2.0 and it is attributed.

## Failure handling

- Triage and reviewer disagreement: one retry, then route to the human queue. Never loop.
- Every agent loop has an iteration cap, and all of them are bounded `range()` loops rather than conditions that might not become true: `MAX_REVIEW_ATTEMPTS = 2` in `adjudicate`, `max_capacity_retries = 3` around the reviewer, `RetryConfig(max_attempts=4)` on the graph nodes.
- **There is no circuit breaker.** Nothing trips open after N consecutive failures, so a reviewer outage is absorbed per finding rather than once for the run: every finding pays its own retries and backoff before being recorded `unavailable`. The bounded caps mean this terminates and cannot spin, but on a long batch it is slower and more expensive than a breaker would be. Named here as a limit rather than left to be discovered.
- Failed messages go to the dead-letter queue. Findings are never silently dropped.
- Model calls retry with exponential backoff and jitter, capped at four attempts (`_with_backoff` in `tools/review_models.py`, `RetryConfig` on the graph nodes). **Tracker delivery is a coalescing, at-least-once projection**: a failure is persisted and never fails or freezes the state machine; the next cycle retries it, while a newer lifecycle event supersedes an older undelivered reminder. Issue creation and comments with persisted delivery markers are looked up before recovery delivery, but concurrent GitHub comment posts can still race because the API provides no atomic idempotency key.
- A read the UI cannot complete is shown as unknown (HTTP 503), never as an empty success, and is logged with the error class only.

## Ask before

Stop and ask rather than deciding unilaterally:

- Adding any dependency not already in `requirements.txt`, or any dependency at all to the standard-library-only local edition
- Adding any cloud service not listed under Current cloud deployment
- Changing the storage schema (Firestore or SQLite)
- Moving code between the open-source core and the cloud layer, or letting shared code import a cloud-only package
- Anything that would delete or recreate a cloud resource
- Deploying anything
- Any change that removes an observable behavior

## Git

- Commits are signed. Do not change git identity or signing configuration.
- Commit at the end of each working unit, not in one large batch.
- Never commit `.env`, credentials, or Terraform state.

## What not to do

- Do not build scanning engines, device agents, or asset discovery. Integrate with what already finds vulnerabilities.
- Do not add features that are not in an approved design. Scope creep is the primary failure mode.
- Do not mock a cloud service to make a test pass. The offline suite proves logic; `verify-controls.sh` proves deployed behavior. If it does not work deployed, it does not work.
- Do not backdate, simulate, or otherwise manufacture `real_ts` values. The elapsed-time evidence is only worth something because it is real.
