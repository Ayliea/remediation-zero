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

# 3. The dead-letter check takes about two minutes. Start it here too.
./scripts/verify-events.sh

# 4. Confirm the console is serving its newest revision. A pinned service
#    accepts deploys and serves none of them: it stays up, answering with old
#    code, so every check of it passes. This happened, and it went unnoticed
#    for six hours.
gcloud run services describe remediation-zero-console --region=us-central1 \
  --format='value(status.traffic[0].revisionName,status.latestReadyRevisionName)'
#    The two must match. If they do not:
#    gcloud run services update-traffic remediation-zero-console \
#      --region=us-central1 --to-latest

# 5. Export the tracker so chase files real issues on camera.
export GITHUB_TICKET_REPO="Ayliea/remediation-zero-tickets"
export GITHUB_TOKEN="$(gh auth token)"

# 6. Confirm the suite is green and the drivers parse.
.venv/bin/pytest -q

# 7. Reset the derived state so the chase arc is legible. Every rehearsal ages
#    sla_clocks; run enough of them and the +8d step escalates everything at
#    once and the nudging never appears on screen. Dry run first -- it prints
#    exactly what it would clear and what it will not touch.
./scripts/reset-derived.sh
./scripts/reset-derived.sh --confirm
#    This clears sla_clocks and tickets ONLY. Decisions, assignments, the
#    human queue and the idempotency ledger all survive, so the resume control
#    still has something to check itself against. Issues already filed on the
#    tracker are not deleted -- GitHub is not ours to reset -- so close them by
#    hand first if the recording pans across the issue list.

# 8. Pick a cycle number nothing has used. Derive it rather than hardcoding
#    one: every rehearsal consumes more, so a literal in this file is correct
#    only until the next time anyone reads it. It was wrong by the second
#    rehearsal -- this file said 70 after 70 had already been spent.
#    Re-using a cycle makes the fleet skip everything, which is correct
#    behaviour and a terrible opening shot.
export C=$(.venv/bin/python -c "
from google.cloud import firestore
c = firestore.Client()
# Every collection that records the cycle it was written in. tickets and
# sla_clocks are deliberately absent: they carry no cycle field, so including
# them reads as thorough and contributes nothing. human_queue is the one that
# matters most -- the chase steps land there and nowhere else, so a picker
# that skips it hands back a cycle the last rehearsal's chase already spent.
used = set()
for coll in ('cycles', 'decisions', 'assignments', 'human_queue', 'reports'):
    used |= {d.to_dict().get('cycle') for d in c.collection(coll).stream()}
used = {v for v in used if isinstance(v, int) and v < 9000}
print(max(used, default=0) + 20)")
echo "cycle $C, and $((C+2))-$((C+10)) for the chase steps"
```

The chase section below advances to `$((C+2))` through `$((C+10))`, so the
picker leaves a gap of 20 rather than taking the next integer — enough to clear
the whole chase range, not just the tick.

Nothing in the demo needs `--create`, `session-init.py`, or any Terraform.
Those run once and have already run.

## The path, in order

Total command runtime is about 2m35s, plus the dead-letter check running in another terminal. Narration is what fills the rest.

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

### 6. The weeks after the scan, stepped — 40s

```bash
for d in 2 4 6 8 10; do
  SIM_CLOCK_MODE=sim ./scripts/chase.sh --cycle $((C+d)) --advance-days $d
done
SIM_CLOCK_MODE=sim ./scripts/exception.sh --cycle $C --sweep
```

Measured on a **freshly reset** corpus of six clocks with a 7-day SLA:

```
+2d    open_ticket: 6
+4d    nudge: 3, wait: 3
+6d    nudge: 6
+8d    escalate: 3, wait: 3
+10d   human_queue: 3, nudge: 3
```

**These counts are a property of the corpus, not of the code, and rehearsal
changes the corpus.** The same five commands run on 2026-08-28 against a corpus
carrying nine clocks left over from earlier rehearsals produced the same arc
with a much muddier mix:

```
+2d    open_ticket: 2, wait: 7
+4d    nudge: 2,      wait: 7
+6d    nudge: 2,      wait: 7
+8d    escalate: 7,   wait: 2
+10d   human_queue: 7, nudge: 2
```

The lifecycle is intact in both — ticket, nudge, nudge, escalate, person — but
in the second the interesting transitions are buried under a `wait` column
seven deep, and seven clocks escalate in one step because they were already
aged. **Reset before recording** rather than hoping the corpus is young; the
step is in pre-flight above for that reason.

**Size the advance to the nudge interval, not to the calendar.** This is the
correction the dry run earned, and it was earned twice. The runbook first said
42 days, on the reasoning that the story is "six weeks in eight seconds": every
clock lands past its deadline at once, chase escalates all of them, and the
screen fills with `human_queue`. Reducing it to 8 was still wrong for the same
reason in miniature — the SLA on these findings is 7 days, so an 8-day jump is
still one step from `open_ticket` to `escalate` with the nudging never shown.

The interval that matters is the SLA window divided by `MAX_NUDGES + 1`, which
is 1.75 days here. Stepping at roughly that size is what makes the lifecycle
legible: the ticket opens, the owner is nudged while there is still time,
escalation happens once when the deadline passes, and only then does it reach
a person. That is the behaviour the agent exists to demonstrate, and a single
large advance hides all of it.

Check the window before choosing the step:

```bash
.venv/bin/python -c "
from google.cloud import firestore
for d in firestore.Client().collection('sla_clocks').stream():
    n = d.to_dict().get('sla_days')
    print(d.id, 'sla', n, 'days · nudge interval', round(n/4, 2) if n else None)"
```

`SIM_CLOCK_MODE=sim` is required and worth showing. Without it `advance()`
raises rather than fabricating elapsed time — the clock refuses to lie about
the one number the demo is staking its credibility on.

If the mix reads mostly `breached` before you start, rehearsal has aged the
corpus past the interesting part. `./scripts/reset-derived.sh` clears
`sla_clocks` and `tickets` and nothing else; run a fresh cycle on untouched
findings afterwards to rebuild them.

**Then show where it landed.** With the tracker exported, each opened ticket is
a real GitHub issue carrying the ratified severity, the deadline, the specific
fix, the evidence cited and the reviewer's own reason for accepting it — and
each nudge and escalation arrives as a comment on it.

```bash
open https://github.com/Ayliea/remediation-zero-tickets/issues
```

The console links to them too: a finding id in the ticket table is an anchor to
its issue. That is the shortest path from "the fleet decided something" to "a
person can act on it", and it is worth clicking on camera rather than
describing.

### 7. It remembers cycles it never ran — 20s

In the same playground session, after the assessment:

```
What has this fleet been doing in past cycles?
```

```
Cycle-300: 3 decisions were adjudicated, resulting in 2 ratifications.
Cycle-301: 2 findings were ratified, and 1 was routed to the human queue.
```

Those cycles ran on a daily schedule, in worker processes that exited hours
ago. **This agent never saw them.** It is reading Agent Platform Memory Bank,
where every completed cycle files one recollection carrying both clocks —
because a memory read weeks later is useless if it cannot say which time it
means, and dangerous if the reader assumes the wrong one.

This is the track's "context across weeks of asynchronous operations", and it
is the hardest thing in the demo to fake.

If it answers that recollection is unavailable, say so and move on: that is the
tool refusing to report an empty history it did not actually look for. An
unreachable memory and a fleet that has done nothing are different claims, and
only one of them is ever true.

### 8. Reporting — 15s

```bash
./scripts/report.sh --cycle $C
```

**Run this last, after every other state change.** A report is a snapshot of
the figures it was handed, so one generated before the chase steps describes a
fleet that no longer exists. The console prints the report prose directly above
the live counters, which means a stale report contradicts the numbers beside it
inside a single screenshot — that is how the dry run noticed, with a report
saying "14 total tickets" sitting above a counter reading 6.

The reporting agent has no model client that can compute and no access to
write anything but reports. It describes figures it was handed. The console
prints those figures beside the prose so the narrative can be checked against
them.

### 9. The controls — 25s

```bash
./scripts/verify-controls.sh --only armor,reviewer,resume,secret
```

Then switch to the terminal where `--only probe` has been running since
pre-flight and show its result. Two of the five checks are Cloud Run jobs, each
running **as** the identity being tested rather than borrowing it:

```
expect DENIED   | got DENIED (PermissionDenied)   | write a ticket        (as rz-reporting)
expect ALLOWED  | got ALLOWED                     | write a report        (as rz-reporting)
expect DENIED   | got DENIED (PermissionError)    | read the tracker token (as rz-exception)
expect ALLOWED  | got ALLOWED                     | read a finding        (as rz-exception)
```

Say the part that is easy to skip: half of these checks expect ALLOWED. An
identity that can do nothing proves only that it is broken. The control is that
the boundary falls in a specific place.

Say the second part too, because it is the stronger claim: **running as the
identity rather than impersonating it is the whole point.** The first attempt at
the token check used `--impersonate-service-account` from a laptop and both
identities returned `PERMISSION_DENIED` on `iam.serviceAccounts.getAccessToken`
— a refusal to impersonate, which says nothing about the secret. It read as
proof of the control. It was proof that the operator cannot impersonate anyone.

### 10. It runs itself — 30s

```bash
# Pick a tick cycle the ledger has never seen. Same trap as $C above, and this
# file fell into it: it hardcoded 9001, then the rehearsal that wrote this file
# spent 9001, so following it verbatim answered tick_already_ran on the FIRST
# publish and the fresh-work shot never happened.
#
# The tick guard keys on an opaque hash of the cycle, so grepping the ledger
# for the number finds nothing. Derive the key and ask.
export T=$(.venv/bin/python -c "
from google.cloud import firestore
from tools.idempotency import derive_record
c = firestore.Client()
for n in range(9001, 9200):
    if all(not c.collection('idempotency').document(
            derive_record(finding_id=f'tick-{n}', action=a, cycle=n).key).get().exists
           for a in ('chase', 'exception')):
        print(n); break")

# Fresh work. An explicit cycle overrides the one derived from the day.
gcloud pubsub topics publish remediation-tick --message="{\"cycle\":$T}"

# Then the guard: publish the same thing again.
gcloud pubsub topics publish remediation-tick --message="{\"cycle\":$T}"
```

**Name a cycle explicitly rather than publishing the scheduler's own payload.**
The empty payload is what Cloud Scheduler sends, and it is the honest thing to
show — but the cycle it derives is the *day*, so if the schedule has already
fired at 09:00 UTC, or you rehearsed earlier, both workers answer
`tick_already_ran` and nothing visible happens. That is the guard working
correctly and it is a terrible opening shot. Rehearsal hit exactly this.

Then show the logs. One publish, two workers, each under its own identity:

```
tick_started  → tick_finished  cycle=30692  rz-worker-chase      {'wait': 6}
tick_started  → tick_finished  cycle=30692  rz-worker-exception  {'none': 1}
```

The second publish gets `tick_already_ran` from both. The cycle is
derived from the day rather than carried in the payload, because Cloud
Scheduler cannot template a date and keeps no counter — a literal cycle would
have been the same integer every day, and the idempotency guard would then have
correctly skipped every tick after the first. The schedule would have reported
success while doing nothing.

**The dead-letter queue is the part worth showing, and it takes two minutes.**
Start it before this section, not during:

```bash
./scripts/verify-events.sh     # about 2 minutes
```

It publishes a message the worker genuinely cannot process, waits for the five
delivery attempts to be exhausted, and reads it back out of the queue. Measured
at `2 of 2 expected copies, first after ~99s` — two because the tick fans out
to two subscriptions and each dead-letters independently.

### 11. Another department can find it — 20s

```bash
./scripts/register-agent.sh --apply
```

```
Discoverable by search, not merely published.
  query   : vulnerability remediation
  skills  : assess_finding,recall_fleet_history,lookup_finding
```

The fleet is published to Agent Registry as an A2A agent card, versioned by the
commit the engine was built from. The script does not stop at publishing: it
searches the catalogue the way a team who did not build this would, and fails
if it cannot find itself. Published and discoverable are different claims.

It also fails if it finds an entry carrying the *wrong* version, which is not a
hypothetical. The 2026-08-28 pre-flight found this step passing in 2.3 seconds
against a catalogue entry eleven commits stale: the PATCH that publishes the
card was missing `updateMask`, so it returned a healthy long-running operation
and changed nothing, and the search loop matched on display name alone and
declared victory. Two faults that concealed each other — a write that silently
did nothing, and a check that could not fail. Both are fixed; the search now
pins to the published version, and a stale hit is reported as stale rather than
as success.

The card's version is HEAD, and the line above it claims HEAD is what the
engine serves. That holds only while nothing has been committed since the last
deploy. Nothing records the engine's build commit, so the script compares the
engine's `updateTime` against the HEAD commit time and prints a note when they
have drifted, rather than publishing the claim unchecked. **Expect that note if
you have committed anything since deploying** — it is accurate, and a
docs-or-scripts-only commit does not require a redeploy. Redeploy first only if
the difference touches something the engine actually serves.

### 12. The honest limit — 15s, no commands

Firestore IAM is database-scoped, not collection-scoped, and Security Rules are
bypassed by server SDKs. So the boundary was put where IAM can actually enforce
it, and the other five agents are named as application-level separation rather
than blurred into the same sentence.

Ending on a named limit is stronger than ending on a claim.

## If something breaks on camera

| Symptom | What it is | Do this |
|---|---|---|
| Console blank or slow | Cold start, 18s | Keep talking. It arrives. |
| Tick says `tick_already_ran` | Today's cycle already ran; the cycle is derived from the day | Publish with an explicit `"cycle"` |
| Cloud Trace empty | Indexing lag, one to two minutes | Move on, return later |
| `429 RESOURCE_EXHAUSTED` | Gemma MaaS capacity | It retries with backoff. Let it. A failed finding routes to the human queue rather than dropping. |
| `advance() is not available in real mode` | Missing `SIM_CLOCK_MODE=sim` | This is the guard working. Say so, prefix, re-run. |
| Everything says `skipped` | `$C` already used | Pick a higher number |
| Console looks like old code | Traffic pinned to an earlier revision | `gcloud run services update-traffic … --to-latest`. The deploy scripts now refuse rather than let this pass. |
| No GitHub issues appear | `GITHUB_TICKET_REPO` or `GITHUB_TOKEN` unset | The log says `delivery_disabled` and names which. The fleet decides identically without it. |
| Registry search finds nothing | The catalogue lags the create operation | The script already waits and retries; give it a minute |

The 429 is worth keeping if it happens. It is a real capacity failure being
absorbed by a real retry path, which is harder to stage than to encounter.

## Measured timings

| Step | Measured |
|---|---|
| Console, cold | 18.2s |
| Console, warm | 0.6–1.3s |
| `tick.sh --limit 3` | 49.4s · 42.7s on 2026-08-28 |
| `tick.sh` re-run, same cycle | 5.5s (1.2s of work) |
| `graph.sh`, one finding | 20.4s · 24.1s on 2026-08-28 |
| `chase.sh --advance-days N` | 6.8–7.7s each |
| `exception.sh --sweep` | 1.8s |
| `report.sh` | 14.9s · 15.9s on 2026-08-28 |
| `verify-controls.sh --only armor,reviewer,resume` | 17.2s |
| `verify-controls.sh --only armor,reviewer,resume,secret` | 2m23s |
| `verify-controls.sh --only probe` | 218s |
| `verify-controls.sh --only secret` | ~2m |
| `verify-controls.sh`, all five | 5–6 min |
| `register-agent.sh --apply`, including the version-pinned search | ~13s |
| `pytest`, 298 tests | 27.4s on 2026-08-28 |
| `gcloud pubsub topics publish` → both workers | ~4s |
| `verify-events.sh` (dead-letter round trip) | ~115s · first copy at ~100s on 2026-08-28 |
| `reset-derived.sh --confirm`, 29 docs | under 5s |
