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

## Pre-flight, six minutes before recording

```bash
# 1. Refresh both credentials before anything else touches the cloud. There
#    are two of them, they expire independently, and neither failure
#    announces itself. Application Default Credentials are what the Python
#    tools and verify-controls authenticate with; the gcloud user credential
#    is what every `gcloud` command in this file uses. Refreshing one does
#    nothing for the other. On 2026-08-28 ADC was dead while gcloud was
#    healthy, and an hour later, with ADC refreshed, gcloud was the dead one.
gcloud auth application-default print-access-token >/dev/null \
  || gcloud auth application-default login --no-launch-browser
gcloud auth print-access-token >/dev/null \
  || gcloud auth login --no-launch-browser
#    Check the tokens, not the listing, and not the file. `gcloud auth list`
#    printed this account as ACTIVE while its token could not refresh at all,
#    and a stale application_default_credentials.json is present, readable
#    and exactly the right shape -- `ls` cannot tell it from a live one
#    either. Only asking for a token distinguishes them.
#
#    The ADC failure is the expensive one to miss, because it is silent and
#    it looks like a real defect: Model Armor fails closed when it cannot
#    reach the screener, so every finding is blocked -- the benign ones too
#    -- and verify-controls reports FAIL on a control that is working exactly
#    as designed. The gcloud failure is louder, but it lands in the middle of
#    step 5 with the camera running.
#
#    --no-launch-browser is not optional here. This machine is headless --
#    reached over SSH with DISPLAY unset -- and both commands default to
#    launching a browser. google-chrome is installed, so gcloud has something
#    to exec and opens it on a server nobody is watching. The flow then never
#    completes, credentials.db is never written, and the stale credential
#    stays in place still failing, with no error to read. The only signal is
#    the mtime on ~/.config/gcloud/credentials.db not moving. This cost three
#    attempts on 2026-08-28 that each looked like they had worked.
#
#    --no-launch-browser prints a URL: open it on the laptop, paste the code
#    back. --no-browser is a different flag and the wrong one -- it expects a
#    second gcloud install on the machine that has the browser.
#
#    Do not add --update-adc to the second command as a shortcut. It would
#    overwrite the ADC the first command just established.
#
#    Reauth needs an interactive terminal, so no script and no agent can do
#    this for you -- run it yourself, now, not at 17:00 on the 31st.

# 2. The console scales to zero, and a cold start is 18.2 seconds of white
#    screen. Warm it. Nothing else here matters if the first frame is white.
curl -s -o /dev/null -w '%{time_total}s\n' \
  https://remediation-zero-console-978104855285.us-central1.run.app/
#    Run it twice. The second should be under 1.5s. If it is not, wait and
#    repeat rather than starting the recording.

# 3. Start both Cloud Run job checks now, in another terminal, and start
#    them before anything else in this list. Together they take 5m23s and are
#    the long pole in pre-flight; everything below runs while they do.
#    Starting them here is the whole reason step 10 is short.
#
#    `secret` belongs here and not in step 10. It is a Cloud Run job exactly
#    like `probe`, which is easy to miss because only `probe` is named in the
#    --only help text. Left in step 10 alongside the fast three it put that
#    step at 258 measured seconds against a 25-second budget: four minutes of
#    dead air with the camera running.
./scripts/verify-controls.sh --only probe,secret

# 4. The dead-letter check takes about two minutes. Start it here too.
./scripts/verify-events.sh

# 5. Confirm the console is serving its newest revision. A pinned service
#    accepts deploys and serves none of them: it stays up, answering with old
#    code, so every check of it passes. This happened, and it went unnoticed
#    for six hours.
gcloud run services describe remediation-zero-console --region=us-central1 \
  --format='value(status.traffic[0].revisionName,status.latestReadyRevisionName)'
#    The two must match. If they do not:
#    gcloud run services update-traffic remediation-zero-console \
#      --region=us-central1 --to-latest

# 6. Export the tracker so chase files real issues on camera.
export GITHUB_TICKET_REPO="Ayliea/remediation-zero-tickets"
export GITHUB_TOKEN="$(gh auth token)"

# 7. Confirm the suite is green and the drivers parse.
.venv/bin/pytest -q

# 8. Reset the derived state so the chase arc is legible. Every rehearsal ages
#    sla_clocks; run enough of them and the +8d step escalates everything at
#    once and the nudging never appears on screen. Dry run first -- it prints
#    exactly what it would clear and what it will not touch.
./scripts/reset-derived.sh
./scripts/reset-derived.sh --confirm
#    This clears sla_clocks, tickets and scans, and undoes what a rescan
#    wrote to findings: the 12 it created are removed, and the ones it
#    resolved lose those fields and go back to open. Seeded findings are
#    never deleted. Without that last part a single rescan makes the demo
#    unrehearsable -- the clocks reset but 106 findings stay resolved, so
#    section 7 closes their tickets on sight and section 6 has no arc left
#    to show. Decisions, assignments, the human queue and the idempotency
#    ledger all survive, so the resume control still has something to check
#    itself against. Issues already filed on the
#    tracker are not deleted -- GitHub is not ours to reset -- so close them by
#    hand first if the recording pans across the issue list. Closing them is
#    cosmetic: find_issue lists with state=all, so a closed issue still owns
#    its finding. The demo uses --start 41 to work on findings no rehearsal has
#    touched AND that rescan-01 resolves, which is what keeps the tracker shot
#    honest and lets section 7 actually close something.

# 9. Pick a cycle number nothing has used. Derive it rather than hardcoding
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
for coll in ('cycles', 'decisions', 'assignments', 'human_queue'):
    used |= {d.to_dict().get('cycle') for d in c.collection(coll).stream()}
# reports are written to their own Firestore database, so the default client
# cannot see them. Listing 'reports' above returned two stale documents from
# the default database and silently missed every current report.
used |= {d.to_dict().get('cycle')
         for d in firestore.Client(database='reports').collection('reports').stream()}
used = {v for v in used if isinstance(v, int) and v < 9000}
print(max(used, default=0) + 20)")
echo "cycle $C, $((C+2))-$((C+10)) for the chase steps, $((C+11))-$((C+12)) for the rescan"

# 10. GATE: the cycle has to actually ratify something. Run it now, in
#     pre-flight, and read the outcomes before trusting it.
#
#     The models are not deterministic. RZ-0041 through RZ-0043 have produced
#     three different splits across three cycles on the same evidence, and on
#     2026-08-31 a cycle came back {"human_queue": 3} with nothing ratified.
#     A finding routed to the human queue is deliberately not assigned -- see
#     the comment at scripts/cycle.py -- so it starts no SLA clock, opens no
#     ticket, and leaves the chase arc at 1:55 and the closing beat at 2:20
#     with nothing to act on. Nothing is broken when that happens. There is
#     simply no ticket, and you find out on camera.
./scripts/tick.sh --cycle $C --start 41 --limit 3

#     Read the last line. Proceed only if it contains "ratified":
#       {"outcomes": {"ratified": 2, "human_queue": 1}}   -> good
#       {"outcomes": {"human_queue": 3}}                  -> derive a new $C
#                                                            and roll again
#     Two empty rolls in a row: raise --limit to 5 or 6. More findings
#     triaged, better odds one survives review. The narration barely changes.
#
#     Confirm the chain actually formed rather than trusting the summary:
.venv/bin/python -c "
from google.cloud import firestore
import os
c = firestore.Client(); C = int(os.environ['C'])
asg = [d.to_dict() for d in c.collection('assignments').stream()
       if d.to_dict().get('cycle') == C]
sla = [d.to_dict() for d in c.collection('sla_clocks').stream()]
print(f'assignments {len(asg)} | sla_clocks {len(sla)}')
print('READY' if asg and sla else 'NOT READY -- no ticket will open, pick a new cycle')"

#     Note this consumes $C for the opening beat: re-running it later prints
#     skipped_already_adjudicated, which is the idempotency beat at 0:50 and
#     not the fresh decision you want at 0:00. Derive a second cycle for the
#     cold open and keep the gated one for everything downstream.
#
#     Known good at the time of writing: C=1096 ratified RZ-0042 (high, 14d),
#     which rescan-01 resolves because ast-046 is inside its coverage
#     manifest -- so the closing beat has a ticket to close. Verify rather
#     than reuse it; by the time you read this its chase cycles may be spent.
```

The chase section advances to `$((C+2))` through `$((C+10))` and the rescan
takes `$((C+11))` and `$((C+12))`, so the
picker leaves a gap of 20 rather than taking the next integer — enough to clear
the whole run, not just the tick.

Nothing in the demo needs `--create`, `session-init.py`, or any Terraform.
Those run once and have already run.

## The path, in order

Total command runtime is roughly 3–4 minutes, plus the dead-letter check running in another terminal. Model latency is the variable: the same cycle measured 42.7s and 67.2s on the same day. Narration is what fills the rest.

### 1. The ledger — 20s of talking, no commands

Open the console. Two things are on screen before anything is said: **real
elapsed** in wall clock, and **scenario time**, side by side. The first number
can only be earned by waiting; the second is where the simulation reached.

The line worth saying out loud is that every record on the page carries both,
and where they differ the page prints `simulation ahead by 8d` on the record
rather than smoothing it away.

Directly below them is a second pair, in the same layout for the same reason:
**remediated** and **unverifiable**. Point at the second one. It is the larger
number, it is amber rather than red because it is an absence of evidence and
not a breach, and those findings are still being chased. Do not explain it
yet — section 7 is where it earns its meaning, and saying it twice spends the
surprise. One sentence is enough: the fleet is more careful about what it
claims to have fixed than about how much it fixed.

### 2. A cycle — 49s

```bash
./scripts/tick.sh --cycle $C --start 41 --limit 3
```

`--start 41` picks RZ-0041 through RZ-0043. **These three are chosen because
`rescan-01` resolves all of them**, which is what makes section 7 work: a
finding the rescan does not resolve never closes its ticket, and the closing
beat has nothing to show. The dry run on 2026-08-29 used `--start 10` and
section 7 printed `wait: 2` where it promised `close_ticket` -- RZ-0010 and
RZ-0101 are both still reported in rescan-01, so they persist, correctly and
undemonstratively. Verified with 41: two of the three ratify, both open
tickets, and both close at cycle $((C+12)) with their tracker issues.

Other starts whose three findings are all resolved and untouched by earlier
rehearsals: 51, 52, 53, 85, 184, 274, 278, 388, 389, 390. Whether a given
finding ratifies is the reviewer's call and can differ between runs, so if
none of the three opens a ticket, take the next start on that list rather
than re-running the same one.

The default start is 1, and
RZ-0001 and RZ-0003 already carry issues on the tracker from earlier
rehearsals. That matters because `find_issue` lists with `state=all`: a closed
issue still counts as the issue for that finding, so chase would comment on a
closed ticket rather than open a new one, and the "watch it file a real ticket"
shot would silently not happen. Closing the rehearsal issues tidies the list
but does not free the finding — only picking an untouched one does.

Three findings triaged, adjudicated, and assigned. Expect roughly two ratified
and one routed to a person after two rejections. The rejection reasons are the
point — they cite CVSS scores and CISA KEV due dates, not style.

The reviewer runs on Gemma while triage runs on Gemini. Say this here, while a
rejection is on screen: a model auditing its own reasoning shares its own blind
spots.

### 3. The same cycle again — 6s

```bash
./scripts/tick.sh --cycle $C --start 41 --limit 3
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

After the reset, on the three clocks a single cycle creates:

```
+2d    open_ticket: 3
+4d    nudge: 1, wait: 2
+6d    nudge: 3
+8d    escalate: 1, wait: 2
+10d   human_queue: 1, nudge: 2
```

Smaller counts than the six-clock run above, and a much clearer arc. This is
what to expect on camera, because it is what the pre-flight sequence in this
file actually produces.

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
`sla_clocks`, `tickets` and `scans`, and undoes what a rescan wrote to
`findings` — see step 8 for the full scope. It deletes no seeded finding. Run
a fresh cycle on untouched findings afterwards to rebuild them.

**Then show where it landed.** With the tracker exported, each opened ticket is
a real GitHub issue carrying the ratified severity, the deadline, the specific
fix, the evidence cited and the reviewer's own reason for accepting it — and
each nudge and escalation arrives as a comment on it.

```bash
open https://github.com/Ayliea/remediation-zero-tickets/issues
```

A finding that comes back keeps its issue rather than gaining a duplicate, and
if that issue had been closed it is **reopened** before the nudge lands —
`"reopened": true` in the log. A comment on a closed issue is out of every
triage view and most notification settings, so it is delivered in the sense
that the API returned 201 and in no other sense. Expect to see this on RZ-0101
if the graph step ratifies it, since earlier rehearsals closed its issue.

The console links to them too: a finding id in the ticket table is an anchor to
its issue. That is the shortest path from "the fleet decided something" to "a
person can act on it", and it is worth clicking on camera rather than
describing.

### 7. The loop closes — target 45 seconds

Run this **after** the chase steps above, never before. A finding the rescan
resolves stops being chased immediately, so resolving first means the nudges
and the escalation never happen and section 6 has nothing to show. The order
here is the order the story runs in: press for weeks, then find out what
actually got fixed.

```bash
# Dry run first, on camera. It writes nothing and prints the same summary the
# real run does, so the closures are read before they happen.
./scripts/rescan.sh --cycle $((C+11)) --dry-run
```

The line to stop on is not `resolved`. It is `unverifiable`:

    "resolved": 106       absent from the scan, and the asset was scanned
    "persisting": 192     still reported
    "unverifiable": 102   absent, but the asset was never scanned
    "new": 12             first seen by this scan; enters triage
    "regressed": 0        reported again after being closed

That 102 is the whole point, and it is worth saying out loud. Absence is the
only evidence of remediation a scanner ever gives you, and two very different
things produce an identical absence: a host that was examined and is clean, and
a host that was never examined at all. Closing on absence alone cannot tell
them apart, and it fails in the direction nobody notices — a live vulnerability
leaves the queue behind a record saying it was handled. So every scan carries
the assets it actually covered, and 102 findings here are deliberately left
open, still chased, still counted against their SLA, because nothing looked at
their hosts.

```bash
# Apply it.
./scripts/rescan.sh --cycle $((C+11))

# Then chase again. The resolved findings close their tickets and their
# tracker issues; everything else carries on.
SIM_CLOCK_MODE=sim ./scripts/chase.sh --cycle $((C+12))
```

If the tracker is configured, the closing comment names the scan and says why
absence counted as evidence, then the issue closes. The comment is posted
before the close on purpose: a closed issue is out of every triage view, so the
reverse order puts the explanation where nobody will read it.

Re-running the rescan on the same cycle is safe and worth showing if there is
time — it reports `newly_resolved: 0`, because the guard suppresses the repeat
and the count reflects what changed rather than what was asked for.

**Timing target: 45 seconds.** The dry run is 2.1s and the apply is a
one-time write of 106 resolutions plus 12 ingests, which is not what a re-run
costs. Rehearse it once from a reset state and put the real number in the
heading and the table below, the way every other number in this file was
obtained. Do not estimate it.

### 8. It remembers cycles it never ran — 20s

In the same playground session, after the assessment:

```
What has this fleet been doing in past cycles?
```

```
Cycle-300: 3 decisions were adjudicated, resulting in 2 ratifications.
Cycle-301: 2 findings were ratified, and 1 was routed to the human queue.
```

Those cycles ran days ago, in processes that exited long since. **This agent
never saw them.** It is reading Agent Platform Memory Bank, where every
adjudication cycle files one recollection carrying both clocks —
because a memory read weeks later is useless if it cannot say which time it
means, and dangerous if the reader assumes the wrong one.

This is the track's "context across weeks of asynchronous operations", and it
is the hardest thing in the demo to fake.

If it answers that recollection is unavailable, say so and move on: that is the
tool refusing to report an empty history it did not actually look for. An
unreachable memory and a fleet that has done nothing are different claims, and
only one of them is ever true.

### 9. Reporting — 15s

```bash
./scripts/report.sh --cycle $C
```

**Run this last, after every other state change.** A report is a snapshot of
the figures it was handed, so one generated before the chase steps describes a
fleet that no longer exists. The console prints the report prose directly below
the live counters, which means a stale report contradicts the numbers beside it
inside a single screenshot — that is how the dry run noticed, with a report
saying "14 total tickets" sitting under a counter reading 6.

The reporting agent has no model client that can compute and no access to
write anything but reports. It describes figures it was handed. The console
prints those figures beside the prose so the narrative can be checked against
them.

### 10. The controls — 33.4s

```bash
./scripts/verify-controls.sh --only armor,reviewer,resume,coverage
```

`coverage` is the one that pairs with section 7. It runs the real reconciler
against the real findings twice with the same empty scan, changing only what
the scan claims to have examined: nothing covered closes 0, the real manifest
closes 204. Say that the second half is the point — a reconciler that refused
everything would pass the first line and be a broken function, not a control.

Then switch to the terminal where `--only probe,secret` has been running since
pre-flight and show its result. Those two of the six checks are Cloud Run
jobs, each running **as** the identity being tested rather than borrowing it:

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

### 11. It runs itself — 30s

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
tick_started  → tick_finished  cycle=9003  rz-worker-chase      {'wait': 6}
tick_started  → tick_finished  cycle=9003  rz-worker-exception  {'none': 1}
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

### 12. Another department can find it — 20s

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

### 13. The honest limit — 15s, no commands

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
| No GitHub issues appear | `GITHUB_TICKET_REPO` or `GITHUB_TOKEN` unset | The log says `delivery_disabled` and names both variables — not which of the two is missing, so check both. The fleet decides identically without it. |
| Registry search finds nothing | The catalogue lags the create operation | The script already waits and retries; give it a minute |

The 429 is worth keeping if it happens. It is a real capacity failure being
absorbed by a real retry path, which is harder to stage than to encounter.

## Measured timings

| Step | Measured |
|---|---|
| Console, cold | 18.2s |
| Console, warm | 0.6–1.3s |
| `tick.sh --limit 3` | 42.7s–67.2s. Gemma latency varies; budget the high end |
| `tick.sh` re-run, same cycle | 5.5s (1.2s of work) |
| `graph.sh`, one finding | 20.4s–59.8s. Same variance, wider |
| `chase.sh --advance-days N` | 6.8–7.7s each |
| `exception.sh --sweep` | 1.8s |
| `report.sh` | 13.8s–15.9s |
| `verify-controls.sh --only armor,reviewer,resume,coverage` | 33.4s on 2026-08-28. Was 17.2s for the three while the reviewer check was re-reading a cached decision instead of calling the models |
| `verify-controls.sh --only probe,secret` (pre-flight) | 3.5-5.5 min. 5m23s on 2026-08-28, 3m29s on 2026-08-29. Two Cloud Run job executions; this is where the whole control-suite spread lives |
| `verify-controls.sh --only probe` | 218s |
| `verify-controls.sh --only secret` | ~2m |
| `verify-controls.sh --only coverage` | 2.1s on 2026-08-28 |
| `verify-controls.sh`, all six | **5-7.5 min.** Two six-check runs on 2026-08-29: 7m30s at `2ad2506` and 4m57s at `a34f1c6`, same machine, all passing both times. A five-check run the day before took 5m40s. `coverage` costs 2.1s, so almost the whole spread is the two Cloud Run job checks. Budget 7.5 minutes and expect less |
| `register-agent.sh --apply`, including the version-pinned search | 13–19s |
| `pytest`, 623 tests | 45.0s on 2026-08-30 |
| `gcloud pubsub topics publish` → both workers | ~4s |
| `verify-events.sh` (dead-letter round trip) | ~115s · first copy at ~100s on 2026-08-28 |
| `rescan.sh --dry-run` | 2.1s on 2026-08-28, three runs |
| `rescan.sh --cycle N`, first apply | 24s on 2026-08-29, from a reset state. 106 resolutions + 12 ingests |
| `reset-derived.sh` dry run | 2.3s on 2026-08-28 |
| `reset-derived.sh --confirm`, 29 docs | under 5s. Predates the rescan; it now also undoes 118 findings and the manifest, so re-measure |
