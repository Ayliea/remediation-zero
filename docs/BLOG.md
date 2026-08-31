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

# Blog post — draft

Bonus (+0.2). **Publish on dev.to or Medium** — the venues named in the build
plan — and it **must carry explicit language that it was written for this
hackathon**. That disclosure is a condition of the bonus, not a courtesy; the
closing section below contains it and should not be trimmed.

Written to stand on its own as a technical post rather than as a project
announcement, because a post that is only an announcement is worth nothing to a
reader who has never heard of the project.

Figures were measured on 2026-08-28. Re-check them before publishing.

---

## I asked one model to review another, and it found a bias I would not have

I spent five days building an autonomous system that owns the vulnerability
remediation lifecycle — the six weeks *after* a scan, which is where one-person
security programs actually die. Finding vulnerabilities is solved. Chasing the
owner who never opened the ticket is not.

The part worth writing about is not the pipeline. It is a number I did not
expect and initially misread as a bug.

### 65% disagreement

Every triage decision in this system is challenged before it becomes state.
A reasoning agent on Gemini 3.5 Flash proposes a severity, an SLA, and a
remediation path, with cited evidence. A reviewer then either ratifies it or
rejects it with a stated reason.

The reviewer runs on **Gemma** — deliberately a different model family. The
argument for that is easy to state and hard to verify: a model auditing its own
reasoning shares its own blind spots. I believed it when I designed it. I did
not have evidence for it.

The reviewer rejects 65% of the proposals it sees, and just over half of all
findings survive to be ratified. My first reaction was that something was
broken. A 65% disagreement rate looks like a defect rate.

It is not. A reviewer that ratifies everything is indistinguishable from having
no reviewer at all, so the rate is a health metric — and the direction that
should worry you is the one approaching zero.

### The rejections are not random

I categorised every rejection reason expecting a spread. Instead:

| What the reviewer objected to | Share |
|---|---|
| Severity escalated beyond what the CVSS evidence supports | **55%** |
| Remediation text naming no specific version | 23% |
| Proposed SLA conflicting with the CISA KEV due date | 22% |

More than half of all rejections say the same thing. Verbatim, from the record:

> *"The severity is escalated to critical without evidence supporting such a
> jump from the CVSS base of 7.8, and the remediation is vague."*

> *"The severity is rated as critical despite the scanner's CVSS being 5.4 and
> the NVD description indicating a high (7.8) severity, creating a mismatch
> between evidence and proposal."*

The triage model has a consistent bias toward inflating severity past its own
cited evidence. The split confirms it: rejected proposals skew critical (24
critical to 13 high), ratified ones do not (21 to 21).

This is the part I want to be careful about, because it is easy to overclaim.
I cannot prove a same-family reviewer would have missed it — that experiment is
one I did not run. What I can say is narrower and still worth something: the
cross-family reviewer *did* catch it, it caught it systematically rather than
occasionally, and it wrote down its reasoning 79 times in a form I could count.
I did not find this bias by reading outputs. The architecture found it and
filed it.

### Restraint is also a result

The system runs itself on a schedule. Cloud Scheduler publishes a tick, Pub/Sub
fans it to two workers, each executing as its own service account.

At 09:01 UTC on August 28th, unattended, both workers woke on cycle 30693,
walked the fleet, and did nothing. No ticket, no nudge, no escalation — in real
elapsed time nothing was due yet, because the SLA windows are 7 to 30 days and
the fleet was under two days old.

I could dress that up. I would rather report it accurately: **the autonomous
loop's correct answer that morning was "not yet."** That is judgment, and a
system that manufactures activity to look busy is worse than one that waits.

The duplicate-delivery guard I did have to go and provoke, because production
had not obliged. Publishing the same tick a second time gets this:

```
tick_already_ran   cycle=9004
tick_already_ran   cycle=9003
```

Pub/Sub delivers at least once, so a redelivered tick is a real possibility
rather than a hypothetical. The second copy is recognised and does nothing. Every authoritative state-changing
tool takes a key derived from the finding, the action, and the cycle, so a
resumed agent cannot open a second ticket or send a second nudge.

The obvious argument for that design is "don't duplicate work." The stronger
one only appeared under test: **models are not deterministic.** Running the same
cycle twice produces *different decisions* for the same finding — one finding
was ratified on the first run and rejected twice on the second. Without the
guard, the second run would not merely have duplicated work. It would have
silently overwritten a decision a human may already have acted on, with a
contradictory one.

### Proving a boundary by crossing it

Each agent has its own service account, scoped to its own Firestore
collections. The reporting agent is structurally incapable of writing a ticket.

Asserting that in a README is free. So the check performs the forbidden action:
a Cloud Run job whose identity *is* the reporting agent attempts the write and
reports what happened.

```
expect DENIED   got DENIED (PermissionDenied)   write a ticket        (as rz-reporting)
expect ALLOWED  got ALLOWED                     write a report        (as rz-reporting)
expect DENIED   got DENIED (PermissionError)    read the tracker token (as rz-exception)
expect ALLOWED  got ALLOWED                     read a finding        (as rz-exception)
```

Half of those expect ALLOWED on purpose. An identity that can do nothing proves
only that it is broken; the control is that the boundary falls in a *specific*
place.

The first version of that check was wrong in an instructive way. It used
`--impersonate-service-account` from my laptop, and both identities returned
`PERMISSION_DENIED`. It looked like proof. It was proof that *I* cannot
impersonate anyone — which says nothing whatsoever about the secret. Running
**as** the identity rather than borrowing it is the whole difference.

### The one that had been passing for 37 hours

Late in the build I had the control suite audited. One check — the one
verifying that the reviewer catches a prompt injection with the input guardrail
switched off — had not called a model since the previous day.

It ran a cycle against a fixed probe number. The cycle skips any finding whose
idempotency record already exists. So after its first successful run it
returned immediately, and the check re-read the decision that first run had
written, found the expected text, and reported PASS. In 0.3 seconds. For 37.8
hours.

The evidence was in my own timings table the entire time: three checks
measured 17.2 seconds, while one triage-and-review round costs 15 to 22 seconds
on its own. The number was too good and I read it as good news.

It now clears its prior record and accepts a verdict only if it was written
during that invocation. It takes 31 seconds, because it does the work.

The lesson is not "write better tests." It is that **cheap-and-green is the most
comfortable way for a verification suite to fail**, and the suite you trust most
is the one that most deserves an adversarial read.

### What it does not do

Two gaps that every reviewer found within an hour, so I would rather name them:

There is **no cross-asset finding normalization**: real scanner output repeats one CVE across
hundreds of hosts, and the synthetic corpus here has 400 findings with 400
distinct CVEs, so the problem never arises. That is the next thing.

And the closure loop is newer than the rest of the system, which shows. A
rescan closes what it confirms fixed and refuses to close what it could not
examine — but the scan file's coverage manifest is taken on trust, and a
regression reopening a finding resets that ticket's episode counters rather
than preserving the whole trail. Both are known and neither is exercised by
the committed corpus, which is exactly the kind of thing worth saying out loud
about a feature that is four days old.

### The stack

ADK 2.8 on Vertex AI. Gemini 3.5 Flash for reasoning, Gemma for review,
Firestore for state, Agent Engine Memory Bank across sessions, Pub/Sub with a
dead-letter queue proven by poisoning it, Model Armor on untrusted ingress,
Cloud Run, Cloud Trace, Secret Manager, Terraform. Per-agent service accounts
throughout. 623 tests.

### Written for the All Things Agentic Hackathon

I built Remediation Zero for the **All Things Agentic Hackathon**, in the
Fortified Enterprise Fleet track, over five days in August 2026. Everything in
the repository was written during the submission period. The corpus is entirely
synthetic — reserved ranges only, `.invalid` hostnames and `192.0.2.0/24`
addresses — with real CVE identifiers.

Code, architecture diagram, and a runbook with every step timed:
**github.com/Ayliea/remediation-zero**

#AllThingsAgenticHackathon

---

## Publishing notes

- Cut "Proving a boundary by crossing it" first if a venue wants it shorter;
  the reviewer-bias section and the 37-hour section are the reasons to read it.
- The 37-hour section is the most linkable thing here. Consider it as a
  standalone post if the venue prefers short pieces.
- Re-check every figure against the live console before publishing.
