<!--
Copyright 2026 Daviyon Daniels

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Demo runbook

Every command here was executed end to end against the live deployment on
2026-08-27, and every duration is measured rather than estimated. The dry run
that produced these numbers also found five defects; they are fixed in
`4f0e4f7` and the timings below are from after that.

Durations are wall clock on a warm console and a warm Python import cache.
The first run of anything in a fresh shell adds roughly two seconds of import.

## Pre-flight, five minutes before recording

```bash
# 1. The console scales to zero, and a cold start is 18.2 seconds of white
#    screen. Warm it. This is the single most important line in this file.
curl -s -o /dev/null -w '%{time_total}s\n' \
  https://remediation-zero-console-978104855285.us-central1.run.app/
#    Run it twice. The second should be under 1.5s. If it is not, wait and
#    repeat rather than starting the recording.

# 2. Start the slow control check now, in another terminal. It takes 218
#    seconds, so starting it here means the result is on screen when you
#    reach it rather than being waited for on camera.
./scripts/verify-controls.sh --only probe

# 3. Confirm the suite is green and the drivers parse.
.venv/bin/pytest -q

# 4. Pick a cycle number nothing has used. Cycles 1-65 are consumed.
#    Re-using one makes the fleet skip everything, which is correct behaviour
#    and a terrible opening shot.
export C=70
```

Nothing in the demo needs `--create`, `session-init.py`, or any Terraform.
Those run once and have already run.

## The path, in order

Total command runtime is 1m57s. Narration is what fills the rest.

### 1. The ledger — 20s of talking, no commands

Open the console. Two things are on screen before anything is said: **real
elapsed** in wall clock, and **scenario time**, side by side. The first number
can only be earned by waiting; the second is where the simulation reached.

The line worth saying out loud is that every record on the page carries both,
and where they differ the page prints `simulation ahead by 8d` on the record
rather than smoothing it away.

### 2. A cycle — 49s

```bash
./scripts/tick.sh --cycle $C --limit 3
```

Three findings triaged, adjudicated, and assigned. Expect roughly two ratified
and one routed to a person after two rejections. The rejection reasons are the
point — they cite CVSS scores and CISA KEV due dates, not style.

The reviewer runs on Gemma while triage runs on Gemini. Say this here, while a
rejection is on screen: a model auditing its own reasoning shares its own blind
spots.

### 3. The same cycle again — 6s

```bash
./scripts/tick.sh --cycle $C --limit 3
```

`skipped_already_adjudicated` three times, and `preserved_outcomes` showing the
first run's decisions intact. 49 seconds becomes 1.2.

The strong claim is not that this avoids duplicate tickets. It is that the
models are not deterministic, so a second run produces *different* decisions
for the same finding — without the guard, a re-run silently overwrites a
decision a human may already have acted on with a contradictory one.

### 4. The delegation graph — 21s

```bash
./scripts/graph.sh --cycle $C --finding RZ-0101
```

The ADK Workflow prints its own topology, then walks it. The routed edge out of
`review` is the adversarial gate: `ratified` to `record`, `human_queue` to a
person, `unavailable` to neither.

Which edge it takes varies between runs, because the models are not
deterministic. That is not a flaw to hide — it is the same non-determinism that
makes the idempotency guard load-bearing, and it is worth naming here rather
than re-running until the graph produces the shot you wanted. The best
rejection seen in rehearsal came out of this step: *"The SLA of 14 days exceeds
the CISA KEV due date of 2022-05-04."*

### 5. Cloud Trace — 30s, in the browser

The graph run above emits a trace. Open Cloud Trace and show the nesting:

```
remediation.finding
  invocation
    invoke_workflow remediation_cycle
      invoke_node screen → triage → review → record → assign
```

Traces take a minute or two to index. If it is not there, this is indexing lag,
not a failure — move on and come back. Do not debug it on camera.

### 6. Six weeks in eight seconds — 10s

```bash
SIM_CLOCK_MODE=sim ./scripts/chase.sh --cycle $C --advance-days 8
SIM_CLOCK_MODE=sim ./scripts/exception.sh --cycle $C --sweep
```

**Use 8 days, not 42.** This is the correction the dry run earned. A 42-day
advance jumps past every intermediate state at once: each clock lands far
beyond its deadline, so chase escalates nearly all of them and the screen fills
with `human_queue`. At 8 days the same command shows the whole range —
`wait`, `open_ticket`, `escalate`, `human_queue`, and a reasoned
`skipped_not_chaseable` — which is the lifecycle the agent exists to
demonstrate. Repeat the command with a larger advance to walk it forward.

Chase runs over every SLA clock, so what it prints depends on accumulated
state rather than on this cycle alone. Check the mix before recording:

```bash
.venv/bin/python -c "
from google.cloud import firestore
from collections import Counter
print(Counter(d.to_dict().get('status')
      for d in firestore.Client().collection('sla_clocks').stream()))"
```

If almost everything reads `breached`, rehearsal has aged the corpus past the
interesting part and this step will not show the range no matter what advance
is used.

`SIM_CLOCK_MODE=sim` is required and worth showing. Without it `advance()`
raises rather than fabricating elapsed time — the clock refuses to lie about
the one number the demo is staking its credibility on.

### 7. Reporting — 15s

```bash
./scripts/report.sh --cycle $C
```

The reporting agent has no model client that can compute and no access to
write anything but reports. It describes figures it was handed. The console
prints those figures beside the prose so the narrative can be checked against
them.

### 8. The controls — 18s

```bash
./scripts/verify-controls.sh --only armor,reviewer,resume
```

Then switch to the terminal where `--only probe` has been running since
pre-flight and show its result: a Cloud Run job whose service account **is**
the reporting identity, attempting to write a ticket and being denied.

Say the part that is easy to skip: two of those four checks expect ALLOWED. An
identity that can write nothing proves only that it is broken. The control is
that the boundary falls in a specific place.

### 9. The honest limit — 15s, no commands

Firestore IAM is database-scoped, not collection-scoped, and Security Rules are
bypassed by server SDKs. So the boundary was put where IAM can actually enforce
it, and the other five agents are named as application-level separation rather
than blurred into the same sentence.

Ending on a named limit is stronger than ending on a claim.

## If something breaks on camera

| Symptom | What it is | Do this |
|---|---|---|
| Console blank or slow | Cold start, 18s | Keep talking. It arrives. |
| Cloud Trace empty | Indexing lag, one to two minutes | Move on, return later |
| `429 RESOURCE_EXHAUSTED` | Gemma MaaS capacity | It retries with backoff. Let it. A failed finding routes to the human queue rather than dropping. |
| `advance() is not available in real mode` | Missing `SIM_CLOCK_MODE=sim` | This is the guard working. Say so, prefix, re-run. |
| Everything says `skipped` | `$C` already used | Pick a higher number |

The 429 is worth keeping if it happens. It is a real capacity failure being
absorbed by a real retry path, which is harder to stage than to encounter.

## Measured timings

| Step | Measured |
|---|---|
| Console, cold | 18.2s |
| Console, warm | 0.6–1.3s |
| `tick.sh --limit 3` | 49.4s |
| `tick.sh` re-run, same cycle | 5.5s (1.2s of work) |
| `graph.sh`, one finding | 20.4s |
| `chase.sh --advance-days 42` | 7.7s |
| `exception.sh --sweep` | 1.8s |
| `report.sh` | 14.9s |
| `verify-controls.sh --only armor,reviewer,resume` | 17.2s |
| `verify-controls.sh --only probe` | 218s |
| `verify-controls.sh`, all four | 3m23s–3m58s |
| `pytest`, 173 tests | 18.7s |
