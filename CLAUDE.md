# CLAUDE.md

Constraints for this repository. Read this before writing code in any session.

## What this is

Remediation Zero: an autonomous multi-agent system that owns the vulnerability remediation lifecycle for a one-person security team. Built for the All Things Agentic Hackathon, Fortified Enterprise Fleet track. Submission deadline is 2026-08-31 17:00 PDT.

The system is built to a standard of architectural discipline: decoupled components, explicit state management, scoped tool permissions, and failure tolerance. Every behavior it claims should be observable and verifiable by someone who did not write it. Favor the boring, verifiable choice over the clever one.

## Hard constraints

These are not preferences. Violating any of them breaks the submission.

1. **ADK 2.x only.** ADK 2.0 introduced breaking changes to the agent API, event model, and session schema. Do not write 1.x patterns from memory. Check the installed version and the docs before using any ADK API.
   - Installed and pinned: **2.8.0**. Verified against the installed package, not from memory.
   - `Workflow` is real and top-level, backed by `google.adk.workflow` (`Node`, `Edge`, `START`, `DEFAULT_ROUTE`, `JoinNode`, `RetryConfig`).
   - **There is no top-level `Task` API.** Task models live at `google.adk.agents.llm.task`. Delegation in 2.x is expressed through `AgentTool` plus `SequentialAgent` / `ParallelAgent` / `LoopAgent` / `ManagedAgent`.
   - `Agent` gained `rerun_on_resume` and `retry_config`; both are relevant to resume safety and the circuit breaker.
   - Session and memory services are **async throughout** (`create_session`, `list_sessions`, `add_memory`).
   - The agent loader resolves `root_agent` from `agents/<name>/agent.py`.
2. **No pre-existing code.** Everything in this repo must be written during the submission period. Do not import, adapt, or reconstruct code from any other project.
3. **Reasoning runs on Gemini via Vertex / Agent Platform.** Not the Gemini Developer API. The deployment must produce Google Cloud traces.
   - **Model location and engine location are different and must stay separate.** `gemini-3.5-flash` is served from `global` and returns 404 from a named region. Agent Engine deploys into a named region. So `GOOGLE_CLOUD_LOCATION=global` for reasoning, `AGENT_ENGINE_LOCATION=us-central1` for the engine.
   - Addressing the **engine** with the model's location returns `The ReasoningEngine does not exist`, which reads like the engine was lost. It was not. Check the location before believing that message.
4. **The reviewer agent runs on a different model family (Gemma).** This is a deliberate architectural decision, not an implementation detail. Do not "simplify" it by moving the reviewer onto Gemini.
   - Serving question resolved 2026-08-27: **`gemma-4-26b-a4b-it-maas`, pay-per-token, via the `global` endpoint.** Model-as-a-Service, so **no dedicated endpoint and nothing always-on**. The Gemini fallback in the plan is not needed and should not be taken.
   - `us-central1` returns `only available via global endpoint`. Same split as the reasoning model.
   - **Gemma MaaS returns 429 `The request queue is full` under load.** It succeeded on retry. The reviewer must therefore have retry with exponential backoff, and a 429 must never be read as a rejection: silently treating capacity pressure as "reviewer rejected" would corrupt the adjudication record.
5. **Every side-effecting tool takes an idempotency key.** Derived deterministically from finding ID, action type, and cycle number. A resumed agent must never duplicate a ticket, a nudge, or an escalation. No exceptions, including for tools that seem harmless.
6. **Every time read goes through `SimClock`.** Never call `datetime.now()`, `time.time()`, or a database server timestamp directly. Every persisted record carries both `real_ts` and `sim_ts`. `real_ts` is wall clock and is never falsified or backdated under any circumstances.
7. **Each sub-agent has its own service account with IAM scoped to its own Firestore collections.** No shared credential. The reporting agent must be structurally incapable of writing tickets.
8. **No real data, ever.** No production systems, no employer data, no client data, no real hostnames, IPs, or people. Synthetic corpus only. Real CVE identifiers are fine and expected.
9. **Secrets never enter the repo.** `.env`, service account JSON, and API keys are gitignored from the first commit.
10. **The deployed agent resource is never deleted or recreated.** The live identifiers, recorded here so they cannot be lost:
    - Engine: `projects/remediation-zero/locations/us-central1/reasoningEngines/3119663582942330880`
    - Session: `5107592082113953792`, created `2026-08-27T01:04:38Z` UTC (`real_ts 1787792678.119875`)
    - `adk deploy agent_engine` **creates a new instance when `--agent_engine_id` is omitted, and does not error.** It also prints `Deploy failed` while exiting 0. `deploy-agent.sh` guards both; do not bypass it.
 It has a stable, explicit resource name and is always updated in place. A long-running session with days of real elapsed time is tied to it, and that elapsed time is the single strongest proof point in the demo. If it is lost it cannot be regenerated before the deadline. Any script that could delete or recreate it must refuse and report the existing resource instead.
11. **Enrichment responses are cached to disk.** CISA KEV, NVD, and EPSS are queried once and cached. The live demo must never depend on a third-party API being reachable at that moment.
12. **Untrusted text passes Model Armor before reaching any reasoning context.** Untrusted means anything that originated outside the system: scanner comment fields, ticket replies, vendor advisory text. Findings metadata generated by the seed script is trusted; free text carried inside it is not.

## Stack

| Concern | Choice |
|---|---|
| Reasoning model | `gemini-3.5-flash` via Vertex / Agent Platform, served from `global` |
| Reviewer model | `gemma-4-26b-a4b-it-maas`, pay-per-token, served from `global` |
| Agent framework | ADK 2.8.0, pinned with `constraints-3.12.txt` |
| Runtime | Agent Runtime, long-running orchestrator session |
| Working state | Firestore |
| Cross-session memory | Agent Platform Memory Bank |
| Events | Pub/Sub with dead-letter queue, driven by Cloud Scheduler |
| Guardrails | Model Armor on all untrusted ingress |
| Secrets | Secret Manager, granted per agent on the secret itself |
| Telemetry | Cloud Trace, Cloud Logging |
| Interface | Cloud Run |
| Infrastructure | Terraform in `infra/` |
| Language | Python 3.12.3 locally; ADK requires >=3.10 |

## The agents

One responsibility each. No agent reaches outside its own collections.

| Agent | Owns | Writes to |
|---|---|---|
| Orchestrator | Cycle control, delegation | `cycles` |
| Triage | Severity, SLA, remediation path, with cited evidence | `decisions` (proposed) |
| Reviewer (Gemma) | Ratify or reject triage proposals with a stated reason | `decisions` (adjudicated) |
| Ownership | Asset to accountable human mapping | `assignments` |
| Chase | Tickets, nudges, escalation over weeks | `tickets` |
| Exception | Risk acceptances with TTL, automatic re-open at expiry | `exceptions` |
| Reporting | Metrics and summaries | `reports` |

No agent owns `human_queue`. Any agent may append to it; nothing reads from it except the console UI. It is the terminal state for anything the fleet could not resolve safely.

Read-only reference collections, written by the seed script and never by an agent: `findings`, `assets`, `owners`. Derived state: `sla_clocks`.

## Commands

Keep these current. If you add a script, add it here.

All Python runs through the local virtualenv. The system interpreter is
PEP 668 externally-managed, so `pip install` outside `.venv` fails.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -c constraints-3.12.txt

.venv/bin/pytest                              # full test suite
.venv/bin/pytest tests/test_idempotency.py    # the two suites that matter most
.venv/bin/pytest tests/test_clock.py

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
./scripts/verify-controls.sh                  # prove the five security claims
./scripts/verify-controls.sh --only armor,reviewer,resume  # the fast three, ~17s
./scripts/reset-derived.sh                    # dry run: what a reset would clear
./scripts/reset-derived.sh --confirm          # clears sla_clocks + tickets ONLY
terraform -chdir=infra plan                   # ALWAYS read this first
terraform -chdir=infra apply                  # events only; manages nothing else
```

## Cost and infrastructure

**There are no credits.** The Google Cloud credit form closed before this
project applied, so every dollar spent is out of pocket. Terraform and deploy
scripts must respect that, and the cost guidance below is a hard requirement
rather than good practice.

- Minimum instances 0 everywhere. Maximum instances explicitly capped.
- No always-on endpoints. Gemma is pay-per-token MaaS, so no dedicated endpoint is needed and none should ever be created.
- Provision minimal CPU and RAM. Scale up only if something actually fails.
- No dedicated vector database or always-on cluster.

## Conventions

- Prompts live in `prompts/` as versioned files. Never inline agent instructions as string literals.
- Tools live in `tools/`, one module per capability, each with an explicit input schema.
- Every module carries an Apache 2.0 header.
- Structured logging only. Every log line carries the finding ID and cycle ID so a single finding's journey is traceable end to end.
- Write the test alongside the tool for anything with an idempotency key or a permission boundary. Those two behaviors are demonstrated on camera and cannot be discovered broken on Day 4.

## Failure handling

- Triage and reviewer disagreement: one retry, then route to the human queue. Never loop.
- Every agent loop has an iteration cap and a circuit breaker.
- Failed messages go to the dead-letter queue. Findings are never silently dropped.
- Tool calls retry with exponential backoff and a maximum attempt count.

## Ask before

Stop and ask rather than deciding unilaterally:

- Adding any dependency not already in `requirements.txt`
- Adding any Google Cloud service not listed in the stack table
- Changing the Firestore schema after 2026-08-28
- Anything that would delete or recreate a cloud resource
- Any change that removes an observable behavior

## Git

- Commits are signed. Do not change git identity or signing configuration.
- Commit at the end of each working unit, not in one large batch. The commit history is evidence that the work happened inside the submission period.
- Never commit `.env`, credentials, or Terraform state.

## What not to do

- Do not add features not in the plan. Scope creep is the primary failure mode of a five-day build.
- Do not mock a Google Cloud service to make a test pass. If it does not work deployed, it does not work.
- Do not backdate, simulate, or otherwise manufacture `real_ts` values. The elapsed-time proof is only worth something because it is real.
- Do not refactor working code for elegance after 2026-08-29 18:00. Feature freeze is in effect from that point; everything after is documentation, verification, and hardening.
