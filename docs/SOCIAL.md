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

# Social posts — draft

**The bonus-bearing post is the LinkedIn one, and it must carry
`#AllThingsAgenticHackathon`.** That is the committed +0.2 from the build plan.
The hashtag is how the bonus gets found and credited, so it is not optional and
it does not get dropped for reading better without it. Post that one first.

Instagram is additional reach, not the bonus. Do it after LinkedIn is up.

Figures measured 2026-08-28; re-check against the live console before posting.
One rule everywhere: **do not post a number that is not currently true.** The
whole pitch is that claims are checkable, and a social post is the easiest place
to lose that by rounding for effect.

---

## 1. LinkedIn — the bonus post. Publish this first.

> I built a system where one AI has to convince another AI before anything
> happens.
>
> Remediation Zero owns the part of vulnerability management that actually
> breaks one-person security teams: not finding the vulnerability, but the six
> weeks after — chasing the owner who never opened the ticket, re-opening work
> that stalled, catching risk acceptances that quietly expired.
>
> The design decision I want to talk about is the reviewer.
>
> A reasoning agent on Gemini proposes a severity, a deadline, and a
> remediation path, with cited evidence. Nothing becomes state until a second
> agent ratifies it — and that agent runs on **Gemma**, deliberately a
> different model family. The argument is easy to state and hard to verify: a
> model auditing its own reasoning shares its own blind spots.
>
> I believed that when I designed it. I had no evidence for it.
>
> Then I counted. Across 79 decisions the reviewer rejected 47% of proposals,
> and **53% of those rejections say the same thing**: the first model inflated
> severity past the CVSS evidence it had itself cited. Verbatim from the
> record — *"The severity is escalated to critical without evidence supporting
> such a jump from the CVSS base of 7.8."*
>
> A 47% disagreement rate looks like a defect rate. It isn't. A reviewer that
> ratifies everything is indistinguishable from having no reviewer at all, so
> the number that should worry you is the one approaching zero.
>
> I did not find that bias by reading outputs. The architecture found it, and
> filed 79 reasons.
>
> Built solo in five days on Google Cloud — ADK 2.8, Vertex AI, Firestore,
> Pub/Sub, Cloud Run, Model Armor, per-agent service accounts, 319 tests.
>
> Write-up and code in the comments.
>
> #AllThingsAgenticHackathon #GoogleCloud #AI #AIAgents #Gemini #Gemma
> #CyberSecurity #VulnerabilityManagement #MultiAgent #AIEngineering

**Notes:** put the repo and blog links in the first comment, not the post body.
Keep `#AllThingsAgenticHackathon` as the first hashtag. If LinkedIn truncates
the post at "See more", the cut should fall after the 53% paragraph — that is
the line worth reading.

---

## 2. Instagram — carousel, 4 slides

**Visual:** dark terminal on the project's own palette, large monospace, one
idea per slide. No stock imagery, no faces, no logo slide. Slide 1 carries the
hook; the rest are proof.

### Slide 1 — the hook
> One AI proposed **CRITICAL**.
>
> A second AI, from a different family, said no —
> and explained why.

### Slide 2 — the verbatim rejection
> *"The severity is escalated to critical without
> evidence supporting such a jump from the
> CVSS base of 7.8, and the remediation is vague."*
>
> — the reviewer agent, on the record

### Slide 3 — the number
> **53%**
> of all rejections say the same thing:
> the first model inflated severity past
> its own cited evidence.
>
> 79 decisions. Every reason logged.

### Slide 4 — what it is
> **Remediation Zero**
> An agent fleet that owns the six weeks
> *after* the vulnerability scan.
>
> Built in 5 days · Google Cloud · ADK 2.8
> Gemini proposes · Gemma reviews · neither can act alone

### Caption

> I built a system where one AI has to convince another AI before anything
> happens.
>
> The reviewer runs on a different model family on purpose — a model auditing
> its own reasoning shares its own blind spots. I believed that when I designed
> it. I didn't have evidence for it.
>
> Then I counted. Across 79 decisions it rejected 47% of proposals, and 53% of
> those rejections say the same thing: the first model kept inflating severity
> past the CVSS evidence it had itself cited.
>
> A high disagreement rate looks like a defect. It isn't. A reviewer that
> ratifies everything is indistinguishable from having no reviewer at all.
>
> The architecture found that bias. I didn't.
>
> Built for the All Things Agentic Hackathon — Fortified Enterprise Fleet.
> Full write-up and code in bio.
>
> #AllThingsAgenticHackathon #AI #AIagents #GoogleCloud #Gemini #Gemma
> #CyberSecurity #VulnerabilityManagement #MultiAgent #BuildInPublic
> #AIEngineering #InfoSec #DevOps #SoftwareEngineering #Hackathon

**Alt text (all four slides need it):**
1. "Text slide: one AI proposed Critical, a second AI from a different model
   family rejected it and explained why."
2. "Quoted rejection from the reviewer agent, objecting that severity was
   escalated to critical without supporting CVSS evidence."
3. "Large figure: 53 percent of all rejections cite unsupported severity,
   across 79 decisions."
4. "Project card: Remediation Zero, an agent fleet for the six weeks after a
   vulnerability scan, built on Google Cloud with ADK 2.8."

---

## 3. Alternate angle — the bug story

Use this if you want a second post later in the week, or if the metrics angle
feels overused on your feed. Works on either platform; keep the required
hashtag if it is standing in for the LinkedIn bonus post.

### Slides
1. > My test suite passed in 0.3 seconds.
   >
   > That was the bug.
2. > The check was supposed to prove a prompt-injection
   > guardrail still worked.
   >
   > It had not called a model in **37 hours**.
   > It was re-reading a saved answer.
3. > The evidence was in my own timings table.
   >
   > Three checks: 17.2s
   > One model round-trip alone: 15–22s
   >
   > The number was too good. I read it as good news.
4. > Cheap-and-green is the most comfortable way
   > for a verification suite to fail.
   >
   > Fixed: it now clears its own record and only
   > accepts an answer written during that run.
   > **31 seconds. Because it does the work.**

### Caption

> The most uncomfortable bug I found this week was in the code I was proudest
> of.
>
> My security control suite had a check verifying a prompt-injection guardrail.
> It passed every time, in 0.3 seconds. It had not actually called a model in
> 37 hours — it was re-reading a decision saved on disk and finding the text it
> expected.
>
> The evidence was sitting in my own measured timings the whole time. A single
> model round-trip costs 15–22 seconds. Three checks were finishing in 17.2. I
> looked at that and felt good about it.
>
> A verification suite that is fast and green is the most comfortable thing in
> the world to own, which is exactly why it deserves the most adversarial read.
>
> #AllThingsAgenticHackathon #BuildInPublic #SoftwareEngineering #Testing #AI
> #AIagents #GoogleCloud #CyberSecurity #AIEngineering

---

## Do not post

- Anything missing `#AllThingsAgenticHackathon` on the LinkedIn post. That
  hashtag is the bonus.
- "Fully autonomous." The reasoning path is operator-triggered; the scheduled
  path deliberately calls no model.
- "Seven agents." Three are ADK agents; the others are identities plus
  deterministic drivers.
- Any framing implying the system fixes vulnerabilities. It runs the
  remediation lifecycle up to escalation. There is no closure loop yet.
- Screenshots showing real hostnames or IPs — the corpus is synthetic
  (`.invalid`, `192.0.2.0/24`) and should visibly stay that way.
- Veo or Lyria tie-ins. The build plan rules them out: no honest role here, and
  a bolted-on integration reads as point-farming to a judge scoring
  architectural discipline at 30%.
