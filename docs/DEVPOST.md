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

# Devpost — About the project

Paste the sections below into the matching Devpost fields. Every figure was
re-measured against live Firestore on 2026-08-31. Ratios rather than counts,
because rehearsals only ever add decisions.

---

## Inspiration

Finding vulnerabilities is a solved problem. Every scanner does it, and most
of them do it well.

What breaks a one-person security team is the **six weeks after the scan**.
Someone has to decide which of four hundred findings actually matters, work
out who owns the host, open the ticket, notice three weeks later that nothing
happened, nudge, escalate, track the risk acceptance that quietly expired last
Tuesday, and rebuild all of that context every Monday morning because none of
it lives anywhere but in their head.

That tail is unglamorous, it is where remediation actually fails, and it is
the part no tool owns. I wanted to find out whether a fleet of agents could
own it — and, more importantly, whether it could be made to own it
*trustworthily*, which turned out to be a much harder question than making it
work at all.

The design goal I set on day zero was not "autonomous." It was: **every
behaviour this system claims should be verifiable by someone who did not
write it.**

## What it does

Remediation Zero is seven responsibilities, each with its own service account
and its own Firestore collections, running on Google Cloud.

A triage agent on **Gemini** proposes a severity, an SLA and a remediation,
citing CISA KEV, EPSS and NVD evidence. A reviewer agent on **Gemma** — a
different model family, deliberately — reads the same evidence and either
ratifies the proposal or rejects it with a stated reason. Rejected once, the
finding is re-proposed with the feedback attached. Rejected twice, it goes to
a person rather than looping.

Ratified decisions become tickets. The chase agent nudges owners, escalates on
schedule, and files real issues on a real tracker. An exception agent grants
risk acceptances with a TTL and automatically reopens them at expiry. A rescan
reconciles what the estate looks like now against what it looked like before.

The interesting behaviour is not what it closes. It is what it **refuses** to
close.

## How I built it

**Reasoning** runs on Gemini 3.5 Flash through Vertex AI, with the reviewer on
`gemma-4-26b-a4b-it-maas` — pay-per-token Model-as-a-Service, so nothing is
always-on. **Orchestration** is ADK 2.8.0, deployed to Agent Engine as a
single instance that is updated in place and never recreated. **State** is
Firestore. **Events** are Pub/Sub with a dead-letter queue, driven by Cloud
Scheduler into two Cloud Run workers. **Guardrails** are Model Armor on every
untrusted ingress. **Infrastructure** is Terraform. **Interface** is a
read-only FastAPI console on Cloud Run whose service account holds
`roles/datastore.viewer` and nothing else.

Four architectural decisions did most of the work:

**One identity per responsibility.** Seven service accounts, not one. The
reporting agent's write access is granted under an IAM condition scoped to a
separate Firestore database, so it is *structurally* incapable of writing a
ticket rather than merely uninstructed. The three deterministic agents —
ownership, chase, exception — hold no Vertex access at all, verified absent
rather than assumed.

**Two clocks on every record.** Every persisted document carries `real_ts` and
`sim_ts`. Wall clock is never simulated, offset or backdated, in any mode, by
any code path; there is deliberately no API that writes it. Scenario time
moves only when `advance()` is called, which is what lets a six-week
remediation lifecycle be shown in three minutes without anyone claiming six
weeks really passed. The console prints both, colour-coded, so a viewer can
see which clock any claim rests on.

**Deterministic idempotency keys.** Every side-effecting tool takes a key
derived from finding ID, action and cycle. A resumed agent recomputes the same
key and its second attempt is recognised as the first one repeating. Pub/Sub
delivers at least once, so this is a design requirement rather than a nicety.

**Bounded everything.** No loop can fail to terminate:
`MAX_REVIEW_ATTEMPTS = 2` around adjudication, `MAX_MODEL_ATTEMPTS = 4` with
exponential backoff and jitter, `MAX_NUDGES = 3`. Nudge pressure stays
proportional to the deadline rather than fixed, so the interval is the SLA
window divided by one more than the nudge budget:

$$\text{nudge interval} = \frac{\text{SLA window}}{\text{MAX\_NUDGES} + 1}
= \frac{7\ \text{days}}{4} = 1.75\ \text{days}$$

The corpus is 400 synthetic findings across 60 assets and 12 owners, on
RFC 5737 documentation addresses and `.invalid` hostnames — guaranteed
unroutable, not merely fictional. Real CVE identifiers, real KEV and EPSS
enrichment, cached to disk so a live demo never depends on a third-party API
being reachable at that moment.

## What I learned

**A model reviewing its own reasoning shares its own blind spots.** This was
the hypothesis behind the cross-family reviewer, and the data settled it. The
reviewer rejects **65% of proposals**, and **55% of those rejections say the
same thing**: triage proposed a severity its own cited CVSS evidence does not
support. One model family found a consistent, systematic bias in another and
wrote down why, every single time. I did not tune that rate down, because a
reviewer that ratifies everything is indistinguishable from having no reviewer
at all. The direction that should worry you is the one approaching zero.

**Absence is not evidence.** A scanner reporting nothing on a host means one
of two very different things: it looked and the host is clean, or it never
looked. Closing on absence alone cannot tell them apart, and it fails in the
direction nobody notices — a live vulnerability leaves the queue behind a
record saying it was handled. So every scan carries the manifest of assets it
actually examined, and closure is gated on it. The most recent rescan
confirmed **106 remediations** and refused to call **102 findings** fixed,
because nothing had examined those hosts. That 102 is the number I am
proudest of.

**Two denominators, both reported.** A rejected proposal is re-proposed once,
so one finding can produce two verdicts, and the disagreement rate and the
ratification rate are not complements of each other:

$$\text{disagreement} = \frac{\text{rejections}}{\text{verdicts}} = 65\%
\qquad
\text{ratification} = \frac{\text{ratified findings}}{\text{findings}} = 53\%$$

Reporting only one of these would flatter the system. Both are on the console.

**A test double that cannot represent a failure cannot catch it.** The
in-memory Firestore stub applied `set()` and `set(merge=True)` identically. A
ticket-reopen path therefore replaced the whole document — destroying the
nudge count, the escalation state, the entire history and the tracker issue
number — and the suite stayed green throughout, because the stub could not
express the distinction the bug turned on.

**Verification and configuration are different questions.** I proved the test
suite ran without cloud credentials and concluded it ran without
configuration. It did not: a gitignored `.env` was quietly supplying a
setting, and my "clean" virtualenv was sitting in the directory that contained
it. CI was the first environment honest enough to expose a gap that predated
it by the entire build.

**Publish ratios, not counts.** Every rehearsal adds decisions, and the reset
script deliberately preserves them because the resume control checks itself
against them. So counts ratchet upward and can never come back down. A count
in a published artefact is true only until the next run; the proportions have
held to the percentage point across the whole build.

## Challenges I ran into

**Two locations that must never be the same.** The models are served from
`global` and return 404 from a named region. Agent Engine deploys into a named
region and does not exist in `global`. Addressing the engine with the model's
location returns *"The ReasoningEngine does not exist"* — which reads exactly
like the engine has been lost, at the moment you are least equipped to think
clearly about it.

**A capacity error is not a verdict.** Gemma MaaS returns HTTP 429 *"The
request queue is full"* under load. Read naively, a 429 becomes "the reviewer
rejected this," which would silently corrupt the adjudication record with
fabricated disagreement. Capacity pressure is now recognised before anything
interprets it, retried with exponential backoff and jitter, and recorded as
`unavailable` if it persists — never as a rejection.

**The proof that proved the wrong thing.** My first attempt at demonstrating
the secret boundary used `--impersonate-service-account` from a laptop. Both
identities returned `PERMISSION_DENIED`, which looked like a clean result. It
was not: it proved the *operator* cannot impersonate anyone, and said nothing
whatsoever about whether the exception agent can read the token. The check now
runs as a Cloud Run job whose identity **is** the agent under test. Half the
assertions expect ALLOWED, because a boundary has to fall in a specific place
rather than merely break every write.

**Measuring the reviewer corrected an overclaim.** I claimed the reviewer
independently catches the planted prompt injection. With Model Armor disabled
it did reject the finding every time — but it named the injection in only one
run out of five. It was finding a sufficient reason to reject on severity
grounds and stopping. The injection never succeeded, but the claim as written
was false. The reviewer now assesses the untrusted text *before* the proposal
at all, and detection went from one in five to six in six.

**Failures that report success.** Three of these cost real hours. `adk deploy`
prints `Deploy failed` and still exits 0. A Cloud Run service pinned to an old
revision accepts every deploy and serves none of them, so it stays up
answering with stale code and every check of it passes — that one went
unnoticed for six hours. And a deploy that drops an environment variable
leaves a worker unable to file a ticket while looking perfectly healthy. Each
now has a guard that refuses rather than reporting success.

**A latent bug that a new feature made reachable.** The ticket-reopen defect
above had existed since the chase agent landed and was completely unreachable:
a ticket could never go from resolved back to open, so the branch only ever
fired on a document that did not exist yet. Adding rescan reconciliation
opened that path. Reviewing the diff would have cleared the file entirely — it
gained twenty lines, none of them the offending one. What mattered was not
what the change touched but what it made **reachable**.

**Valid shell, invalid JSON.** Publishing a tick with an unset variable sends
`{"cycle":}`. The publish succeeds, `gcloud` returns a message ID, the
terminal looks fine — and thirty seconds later two workers reject it in a log
nobody is watching. The envelope validator caught it, the push returned 400
rather than acknowledging work it had not done, delivery retried, and the
dead-letter queue caught what could not be processed. Four controls behaving
correctly in sequence, over an operator error.

## What it does not do

Named here rather than left to be discovered. There is no cross-asset finding
normalisation — real scanner output repeats one CVE across hundreds of hosts
and this corpus does not. And the rescan validates the internal consistency of
a coverage manifest but cannot independently prove the scanner's coverage
claim was true. Both limits are in the README.

There is also no circuit breaker. A reviewer outage is absorbed per finding
rather than once per run, so every finding pays its own retries before being
recorded unavailable. The bounded caps mean it terminates and cannot spin, but
on a long batch it is slower than a breaker would be. It is documented as a
limit rather than described as a design.

## Built with

`google-cloud` · `vertex-ai` · `agent-development-kit` · `gemini` · `gemma` ·
`agent-engine` · `python` · `firestore` · `pub-sub` · `cloud-run` ·
`cloud-scheduler` · `cloud-build` · `model-armor` · `secret-manager` ·
`cloud-trace` · `cloud-logging` · `iam` · `terraform` · `fastapi` ·
`uvicorn` · `docker` · `pytest` · `github-actions` · `opentelemetry` ·
`agent-registry`

## Try it out

- **Live evidence console** — https://remediation-zero-console-978104855285.us-central1.run.app
- **Source** — https://github.com/Ayliea/remediation-zero
- **The strongest tracker exemplar** — https://github.com/Ayliea/remediation-zero-tickets/issues/24
  (the title shows the scanner's *medium*; the body shows the **high** the fleet
  ratified after review, with its reasoning — that gap is the whole point)
- **Demo runbook** — https://github.com/Ayliea/remediation-zero/blob/main/docs/DEMO.md
- **Architecture** — https://github.com/Ayliea/remediation-zero/blob/main/docs/architecture.png
- **Who can touch what** — https://github.com/Ayliea/remediation-zero/blob/main/docs/identities.png
