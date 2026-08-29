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

**Every number below was measured on 2026-08-28 and is reproducible with the
command in the right-hand column.** Re-run them the morning of the recording
and change the script if they moved. A figure quoted from this file that no
longer matches the console is worse than no figure.

| Claim in the script | Where it comes from |
|---|---|
| 53% of rejections cite unsupported severity | `decisions` collection, verdict reasons |
| 42 of 79 ratified | console stat strip |
| unattended run, cycle 30693 | Cloud Logging, `rz-worker-*`, 2026-08-28T09:01 |
| `tick_already_ran` ×2 | same, cycles 9003 and 9004 |
| six controls | `./scripts/verify-controls.sh` |

Pre-flight is in `DEMO.md`. Run it. In particular the credential step and the
two Cloud Run job checks, which take 5m23s and must be started first.

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

**Direction:** twenty-five seconds. Do not elaborate. The problem is not the
interesting part and every second here is taken from the parts that are.

---

## 0:50–1:35 — Claim one, with its denominator.

**On screen:** the console stat strip, then the decisions table.

> Every triage proposal is challenged before it becomes state, by a reviewer
> on a different model family. Using a different family is the point: a model
> auditing its own reasoning shares its own blind spots.
>
> It disagrees with 47% of proposals. That is not a defect I failed to tune
> out, it is the headline metric, because a reviewer that ratifies everything
> is indistinguishable from having no reviewer at all.
>
> And the disagreement is systematic. Across 79 decisions, **53% of all
> rejections say the same thing**: triage proposed a severity its own cited
> CVSS evidence does not support. One model family found a consistent bias in
> another, and wrote down why, 79 times.
>
> Rejected once, it is re-proposed with the feedback. Five findings were
> ratified on that second attempt. Rejected twice, it goes to a person.

**Direction:** this is the strongest 45 seconds available. Do not rush it.
Say "53%" slowly.

---

## 1:35–2:20 — Claim two. Autonomy, stated honestly.

**On screen:** Cloud Logging, filtered to `rz-worker-chase` and
`rz-worker-exception`. Show the 09:01 `chase_finished` / `sweep_finished`
entries for cycle 30693 — the actions field is empty, which is the point.
Then publish the tick again live so `tick_already_ran` appears on camera.

> At 9:01 UTC, with nobody watching, Cloud Scheduler published a tick. Pub/Sub
> fanned it to two workers, each running as its own service account. They
> walked the fleet and did nothing — no ticket, no nudge, no escalation —
> because in real elapsed time nothing was due yet.
>
> I want to be precise about that, because it is the honest version. The
> autonomous loop's correct answer that morning was *not yet*. That is
> judgment, not inaction, and a system that manufactures activity to look busy
> is worse than one that waits.
>
> And these two workers ship no model client at all. The container has no
> Vertex SDK in it, so the unattended path structurally cannot reach a model
> or spend money while nobody is watching. That is a decision, not an
> omission.
>
> Now let me provoke the thing production has not yet handed me. I publish the
> same tick a second time — **`tick_already_ran`**. Pub/Sub delivers at least
> once, so a redelivered tick is a real possibility rather than a
> hypothetical, and the second copy does nothing. No duplicate ticket, no
> duplicate nudge.

**Direction:** point at the literal `tick_already_ran` line. Publishing it
live is stronger than a captured log, not weaker: it is reproducible on
camera, and it
costs nothing to show because it already happened.

---

## 2:20–2:55 — The six weeks, in simulated time, labelled as such.

**On screen:** `./scripts/chase.sh --advance-days ...`, then the GitHub issue
with its nudge and escalation comments.

> To show the full arc I advance simulated time. Every record carries two
> stamps: `real_ts`, wall clock, never falsified — there is no API in this
> system that can write it — and `sim_ts`, scenario time. The console prints
> both, colour-coded, side by side, so you can always see which one a claim
> rests on.
>
> Advancing the scenario clock, the same agents open a ticket, nudge the
> owner, nudge again, and escalate. These are real GitHub issues in a real
> tracker, carrying the ratified severity, the deadline, the specific
> remediation, and the reviewer's own reason for accepting it.

**Direction:** say "simulated" out loud before showing it. The two-clock design
only counts for something if you draw attention to the distinction yourself.

---

## 2:55–3:30 — Claim three. The boundary, performed.

**On screen:** the DENIED / ALLOWED table from `verify-controls`.

> Each agent has its own service account. The reporting agent is structurally
> incapable of writing a ticket — and I do not assert that, I prove it by
> doing it. A Cloud Run job whose identity *is* the reporting agent attempts
> the write and reports the denial.
>
> Half of these checks expect ALLOWED. An identity that can do nothing proves
> only that it is broken. The control is that the boundary falls in a specific
> place.
>
> There is also a guardrail on untrusted input. Scanner comments are attacker-
> controlled text, so they pass Model Armor before reaching any reasoning
> context — and with that boundary deliberately switched off, the reviewer
> still catches the injection on its own. Two layers, each tested without the
> other.

---

## 3:30–4:00 — Deployment proof and close.

**On screen:** the Agent Engine resource, then the console footer.

> This is deployed. One Agent Engine instance, updated in place, never
> recreated. A session created on August 27th that is still there. Firestore,
> Pub/Sub with a dead-letter queue proven by poisoning it, Cloud Run, Cloud
> Trace, Secret Manager, Terraform.
>
> What it does not do yet, and I would rather say it than have you find it:
> no deduplication — real scanner output repeats one CVE across hundreds of
> hosts and this corpus does not. And the rescan trusts the coverage manifest
> it is handed; it checks that a scan cannot report a host it claims not to
> have examined, but it cannot check that the claim was true. Those are the
> next two things, and they are named in the README.
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

1. The Model Armor sentences in 2:55 (keep the DENIED/ALLOWED table)
2. The stack list in 3:30 — the architecture diagram carries it
3. The re-proposal detail in 0:50 (keep the 53%)

Never cut: the cold open, the 53% figure, `tick_already_ran`, the two-clock
distinction, the word **Gemma**, the Google Cloud deployment proof, or the
limitations.

## Do not say

- "Fully autonomous." The reasoning path is operator-triggered and the
  scheduled path deliberately calls no model.
- "Seven agents" without qualification. Three are ADK agents; the rest are
  identities plus deterministic drivers. The README says so.
- Any figure not re-checked against the console that morning.
