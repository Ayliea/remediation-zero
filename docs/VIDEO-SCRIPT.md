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

# Demo video script — 3:45 target

Devpost allows ~4 minutes. **The build plan targets 3:45 and that is the
number to hold to** — rehearse twice and time it. If it runs over, the rule set
on Day 0 is: **cut the exception-expiry beat, never the Google Cloud proof.**

Recording constraints, also from the plan: unedited screen capture with voice
over, expect three takes, and upload to YouTube **public, not unlisted**.

Two things must be said out loud or the bonus is not credited. **Gemma**, by
name, as the reviewer model — a bonus the judges do not notice is a bonus you
did not get. And which clock is which, every time simulated time is on screen.

**Every number below was re-measured on 2026-08-31 at `cf23468` and is
reproducible with the command in the right-hand column.** Re-run them the
morning of the recording and change the script if they moved. A figure quoted
from this file that no longer matches the console is worse than no figure.

The three reviewer figures are ratios rather than counts on purpose. Every
rehearsal adds decisions and `reset-derived` preserves them deliberately, so
counts only ever climb while these proportions have held across the whole
build -- 86 decisions and 133 verdicts today against 79 and 121 three days
ago, with all three ratios unmoved.

| Claim in the script | Where it comes from |
|---|---|
| 55% of rejections cite unsupported severity | `decisions` collection, verdict reasons |
| 53% of findings ratified, 65% of proposals rejected | console stat strip |
| unattended run, cycle 30693 | Cloud Logging, `rz-worker-*`, 2026-08-28T09:01 |
| `tick_already_ran` ×2 | same, cycles 9003 and 9004 |
| 106 resolved · 102 unverifiable | produced by section 7 on camera, not before it. `reset-derived --confirm` clears the scan so the beat has something to do, which means the console shows no rescan card until you run it. Confirmed by `rescan.sh --dry-run` (writes nothing) on 2026-08-31 |
| six controls | `./scripts/verify-controls.sh` |

Pre-flight is in `DEMO.md`. Run it. In particular the credential step and the
two Cloud Run job checks, which take 5m23s and must be started first.

---

## Window plan — set this up before you press record

Everything is driven from **two terminals and four browser tabs**. Open all of
them, in this order, and leave them open. Switching is the only navigation the
recording does; nothing is opened from scratch on camera, because a page
loading live is dead air and a mistyped URL is a retake.

**Terminal A — the one on camera.** Full screen, large font. Widen it past
200 columns or the DENIED/ALLOWED rows wrap and the pairs split across lines.

```bash
cd ~/dev/remediation-zero
export GITHUB_TICKET_REPO="Ayliea/remediation-zero-tickets"
export GITHUB_TOKEN="$(gh auth token)"
export C=<the fresh cycle from pre-flight step 9>
```

**Terminal B — off camera.** Start the slow control run here during pre-flight
so its result is already on screen when you reach 2:45:

```bash
./scripts/verify-controls.sh --only probe,secret
```

**Tab 1 — the console.** https://remediation-zero-console-978104855285.us-central1.run.app/
Scroll position matters: the human queue leads the page, the two clocks sit
above it, the rescan card is mid-page, the session footer is at the bottom.
Warm it twice before recording; cold start is 18 seconds of white screen.

**Tab 2 — Cloud Logging**, pre-filtered to the two workers:
https://console.cloud.google.com/logs/query;query=resource.labels.service_name%3D~%22rz-worker-.%2A%22?project=remediation-zero
Set the time range to cover 09:01 UTC on the day of the unattended run before
you record. Finding the range on camera is twenty wasted seconds.

**Tab 3 — the tracker.** https://github.com/Ayliea/remediation-zero-tickets/issues
Filter to `is:issue` so both open and closed are visible; the closure beat
needs a closed issue and the default filter hides it.

**Tab 4 — the Agent Engine.**
https://console.cloud.google.com/vertex-ai/agents/agent-engines/locations/us-central1/agent-engines/3119663582942330880/playground?project=remediation-zero
The resource ID in the URL is the proof; make sure it is readable on screen.

---

## The spine

Three claims, in this order, because this is the order that survives a judge
who stops watching at ninety seconds:

1. A second model, from a different family, catches the first one being wrong.
2. The fleet runs itself, and today it correctly decided to do nothing.
3. The agents cannot exceed their authority, and the proof performs the
   forbidden action rather than describing it.

Everything else is support. If a section runs long, cut from the support, not
from the spine.

---

## 0:00–0:25 — Cold open. No title card.

**On screen:** a terminal, mid-run, the Gemma rejection already printing.

> A language model just proposed that this vulnerability is Critical, with a
> seven-day deadline.
>
> A second model — different family, Gemma rather than Gemini — read the same
> evidence and rejected it. Its reason:
>
> *"The severity is escalated to critical without evidence supporting such a
> jump from the CVSS base of 7.8, and the remediation is vague."*
>
> That is not a filter. That is a reviewer.

**Do this:** Terminal A. Start recording, then run
`./scripts/tick.sh --cycle $C --start 41 --limit 3` and begin talking as the
first `adjudicated` line with a rejection appears. Do not pre-run it and
scroll back — the point is that it is happening.

**Direction:** no logo, no name, no "hi, I'm". The rejection text is the first
thing on screen and the first thing said. Let the quote sit for a beat.

---

## 0:25–0:50 — The problem, fast.

**On screen:** the console, human queue visible.

> Finding vulnerabilities is solved. Every scanner does it. What breaks a
> one-person security team is the six weeks *after* the scan — chasing owners,
> re-opening work that stalled, tracking risk acceptances that quietly expired,
> and rebuilding all of that context every Monday.
>
> Remediation Zero owns that tail. Seven responsibilities, each with its own
> service account, running on Google Cloud.

**Do this:** switch to Tab 1. You land on the human queue because it leads the
page. Do not scroll yet.

**Direction:** twenty-five seconds. Do not elaborate. The problem is not the
interesting part and every second here is taken from the parts that are.

---

## 0:50–1:30 — Claim one, with its denominator.

**On screen:** the console stat strip, then the decisions table.

> Every triage proposal is challenged before it becomes state, by a reviewer
> on a different model family. Using a different family is the point: a model
> auditing its own reasoning shares its own blind spots.
>
> It disagrees with 65% of proposals. That is not a defect I failed to tune
> out, it is the headline metric, because a reviewer that ratifies everything
> is indistinguishable from having no reviewer at all.
>
> And the disagreement is systematic. **55% of all rejections say the same
> thing**: triage proposed a severity its own cited CVSS evidence does not
> support. One model family found a consistent bias in another, and wrote down
> why, every single time.
>
> Rejected once, it is re-proposed with the feedback. Rejected twice, it goes
> to a person.

**Do this:** stay in Tab 1. Scroll up to the stat strip for the two rates, then
down to the decisions table and stop on a rejected row so the reviewer's own
reason is legible. Read it off the screen rather than from this file.

**Direction:** this is the strongest 40 seconds available. Do not rush it.
Say "55%" slowly.

---

## 1:30–1:55 — Claim two. Autonomy, stated honestly.

**On screen:** Cloud Logging, filtered to `rz-worker-chase` and
`rz-worker-exception`. Show the 09:01 `chase_finished` / `sweep_finished`
entries for cycle 30693 — the actions field is empty, which is the point.
Then publish the tick again live so `tick_already_ran` appears on camera.

> At 9:01 UTC, with nobody watching, Cloud Scheduler published a tick through
> Pub/Sub to two workers. Nothing was due, so the correct autonomous answer was
> *not yet*. The workers ship no model client, so this unattended path cannot
> spend model tokens.
>
> I publish the same tick again: **`tick_already_ran`**. Pub/Sub is at-least-
> once, but the second delivery cannot advance the authoritative lifecycle a
> second time.

**Do this:** switch to Tab 2 for the 09:01 entries, then back to Terminal A and
publish the tick twice, using a cycle nothing has claimed:

```bash
gcloud pubsub topics publish remediation-tick --message="{\"cycle\":$T}"
gcloud pubsub topics publish remediation-tick --message="{\"cycle\":$T}"
```

Then return to Tab 2 and refresh. `tick_already_ran` appears twice, one per
worker. Derive `$T` in pre-flight, not here.

**Direction:** point at the literal `tick_already_ran` line. Publishing it
live is stronger than a captured log, not weaker: it is reproducible on
camera, and it
costs nothing to show because it already happened.

---

## 1:55–2:20 — The six weeks, in simulated time, labelled as such.

**On screen:** `./scripts/chase.sh --advance-days ...`, then the GitHub issue
with its nudge and escalation comments.

> To show the full arc I advance simulated time. Every lifecycle record carries
> `real_ts`, wall clock, never falsified, and `sim_ts`, scenario time. The
> console prints both side by side, so you can see which clock every claim
> rests on.
>
> Advancing the scenario clock, the same agents open a ticket, nudge the
> owner, and escalate. These are real GitHub issues carrying the ratified
> severity, deadline, remediation, and the reviewer's own reason.

**Do this:** Terminal A, the stepped loop rather than one jump — one large jump
escalates everything at once and the nudging never appears:

```bash
for d in 2 4 6 8 10; do
  SIM_CLOCK_MODE=sim ./scripts/chase.sh --cycle $((C+d)) --advance-days $d
done
```

Then Tab 3, refresh, and open the newest issue to show the nudge comments.

**Direction:** say "simulated" out loud before showing it. The two-clock design
only counts for something if you draw attention to the distinction yourself.

---

## 2:20–2:45 — Closure must earn its name.

**On screen:** the latest rescan card, then tracker issue 24 closing.

> Here is the outcome that matters: the rescan confirms **106 remediations**,
> while refusing to call **102 findings** fixed. Absence counts only when the
> scanner's coverage manifest says it actually examined that asset. Missing
> telemetry cannot manufacture success. Issue 24 closes with the scan ID and
> that coverage reason preserved in the record.

**Do this:** Terminal A — dry run on camera first, then apply, then chase again
so the ticket and its issue close:

```bash
./scripts/rescan.sh --cycle $((C+11)) --dry-run
./scripts/rescan.sh --cycle $((C+11))
SIM_CLOCK_MODE=sim ./scripts/chase.sh --cycle $((C+12))
```

Then Tab 1, refresh — the rescan card replaces the "No rescan has run yet"
empty state, which is why pre-flight clears it. Then Tab 3, refresh, and show
the issue now closed with its closing comment.

**Direction:** hold 106 and 102 on the same screen. The refusal number is the
credibility proof; never show 106 alone.

---

## 2:45–3:15 — Claim three. The boundary, performed.

**On screen:** the DENIED / ALLOWED table from `verify-controls`.

**Do this:** Terminal A for the fast four, which run in about 33 seconds:

```bash
./scripts/verify-controls.sh --only armor,reviewer,resume,coverage
```

Then switch to **Terminal B**, where `--only probe,secret` has been running
since pre-flight, and show its DENIED/ALLOWED rows. Those two are Cloud Run
jobs and take about five minutes; starting them here is four minutes of dead
air with the camera running.

> Each agent has its own service account. The reporting agent is structurally
> incapable of writing a ticket — and I do not assert that, I prove it by
> doing it. A Cloud Run job whose identity *is* the reporting agent attempts
> the write and reports the denial.
>
> Half of the checks expect ALLOWED; the boundary has to fall in a specific
> place, not merely break every write.
>
> Scanner comments and NVD prose pass Model Armor before any reasoning context.
> In a separately authorized control run, the reviewer still catches the
> planted injection with Armor bypassed. Two layers, tested independently.

---

## 3:15–3:45 — Deployment proof and close.

**On screen:** the Agent Engine resource, then the console footer.

**Do this:** Tab 4 — let the resource ID `3119663582942330880` sit in the URL
bar long enough to read. Then Tab 1, scroll to the bottom, and hold on the
footer where the session's elapsed time is printed. That number is the one
thing in the demo that cannot be manufactured.

> This is deployed. One Agent Engine instance, updated in place, never
> recreated. A session created on August 27th remains addressable. Firestore,
> Pub/Sub with a dead-letter queue proven by poisoning it, Cloud Run, Cloud
> Trace, Secret Manager, Terraform.
>
> What it does not do yet, and I would rather say it than have you find it:
> no cross-asset finding normalization — real scanner output repeats one CVE
> across hundreds of hosts. And the rescan validates the internal consistency
> of its coverage manifest, but cannot independently prove the scanner's
> coverage claim. Both limits are named in the README.
>
> Remediation Zero. It does the six weeks after the scan, and it shows its
> work.

**Direction:** the limitations line is thirteen seconds and it is worth every
one. A judge who has been shown the seams trusts the rest of the demo more,
and every reviewer of this project found those two gaps within an hour.

---

## Cutting order, if long

The plan's rule first: **cut the exception-expiry beat before anything else,
and never the Google Cloud proof.** After that:

1. The Model Armor sentences in 2:45 (keep the DENIED/ALLOWED table)
2. The stack list in 3:15 — the architecture diagram carries it
3. The re-proposal detail in 0:50 (keep the 55%)

Never cut: the cold open, the 55% figure, the paired 106/102 outcome,
`tick_already_ran`, the two-clock distinction, the word **Gemma**, the Google
Cloud deployment proof, or the limitations.

## Do not say

- "Fully autonomous." The reasoning path is operator-triggered and the
  scheduled path deliberately calls no model.
- "Seven agents" without qualification. Three are ADK agents; the rest are
  identities plus deterministic drivers. The README says so.
- Any figure not re-checked against the console that morning.
