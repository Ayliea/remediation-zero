# Remediation Zero

An autonomous agent fleet that owns the vulnerability remediation lifecycle for a one-person security team.

Built for the All Things Agentic Hackathon, Fortified Enterprise Fleet track.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

---

## The friction

Finding vulnerabilities is a solved problem. Scanners do it well. What breaks a one-person security program is the six weeks after the scan: chasing owners who never opened the ticket, re-opening work that silently stalled in week three, tracking risk acceptances that expired without anyone noticing, and rebuilding the same context from scratch every Monday morning.

That work is not intellectually hard. It is relentless, stateful, and spread across weeks, which is exactly the shape of work an agent fleet should carry and a human should not.

Remediation Zero is built for the analyst who *is* the security department. No SOC, no triage tier, no program manager. One person, one backlog, and a calendar that does not care.

## What it does

A finding lands. From there no human is involved until a decision genuinely needs one.

1. **Triage and Enrichment** proposes a severity, an SLA, and a remediation path, citing CISA KEV, NVD, and EPSS.
2. **Adversarial Reviewer** receives the proposal and the raw finding and must either ratify it or reject it with a stated reason. Nothing becomes state without passing this gate.
3. **Ownership and Routing** maps the affected asset to an accountable human.
4. **Remediation Chase** opens the ticket and pursues it across weeks, nudging, escalating, and adapting to what has historically worked with that specific owner.
5. **Exception and Expiry** records risk acceptances with a TTL and re-opens the finding automatically when one lapses.
6. **Reporting** produces the weekly metrics the analyst would otherwise assemble by hand.

## Architecture

![Architecture](docs/architecture.png)

The design decisions worth defending:

**Cross-family adversarial review before commit.** A single reasoning agent that is confidently wrong produces a wrong SLA on a real vulnerability. Every triage decision is challenged before it becomes state by a reviewer agent running on Gemma rather than Gemini. Using a different model family is the point: a model auditing its own reasoning shares its own blind spots. Disagreements are logged, rejections are capped at one retry, and anything still contested routes to a human queue.

**Idempotency keys on every side-effecting tool.** A long-running agent that resumes after a crash must not open the same ticket twice or send a fourth nudge as its first. Every mutation carries a deterministic key derived from finding ID, action type, and cycle number.

**Injectable clock.** All time reads pass through a `SimClock` service. Every document carries both `real_ts`, which is wall clock and never falsified, and `sim_ts`, which is simulation. This makes a six-week remediation cycle demonstrable in three minutes without fabricating evidence of elapsed time.

**Least privilege per agent.** Each sub-agent runs under its own Agent Identity with IAM scoped to its own Firestore collections. The reporting agent is structurally unable to write tickets. This is enforced rather than documented.

**Two-layer injection defense.** Untrusted text, meaning scanner comment fields, ticket replies, and vendor advisories, passes Model Armor before reaching any reasoning context. The reviewer agent independently catches instruction-shaped content that gets through. One layer is a hope, not a control.

**Failure containment.** Pub/Sub carries a dead-letter queue, tool calls retry with backoff, and the triage and review pair has a loop cap and circuit breaker. Failures degrade to a human queue rather than silently dropping findings.

## Tech stack

| Layer | Service |
|---|---|
| Reasoning model | Gemini 3.5 Flash via Gemini Enterprise Agent Platform |
| Reviewer model | Gemma, deliberately a different model family |
| Agent framework | Google Agent Development Kit (ADK) 2.0 |
| Runtime | Agent Runtime, long-running orchestrator session |
| Working state | Firestore, Agent Platform Sessions |
| Long-term memory | Agent Platform Memory Bank |
| Governance | Agent Identity, Agent Registry, Model Armor |
| Telemetry | Cloud Trace, Cloud Logging (OpenTelemetry) |
| Events | Pub/Sub with dead-letter queue, Cloud Scheduler |
| Interface | Cloud Run |
| Infrastructure as code | Terraform |

## Data sources

All vulnerability findings in this repository are **synthetic**. No production, employer, or third-party data is used anywhere in this project.

Enrichment queries real public sources: the CISA Known Exploited Vulnerabilities catalog, NVD, and EPSS. Responses are cached locally so that demonstrations do not depend on third-party availability.

The synthetic corpus in `data/` is dedicated to the public domain under CC0 1.0. See `data/README.md`.

---

## Spin-up instructions

### Prerequisites

- A Google Cloud project with billing enabled
- `gcloud` CLI, authenticated
- Python 3.10 or later (ADK 2.0 requirement)
- Terraform 1.6 or later. Manual `gcloud` equivalents are in `docs/manual-setup.md`

### 1. Clone and configure

```bash
git clone https://github.com/<handle>/remediation-zero.git
cd remediation-zero
cp .env.example .env
```

Set the following in `.env`:

```
GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_CLOUD_LOCATION=us-central1
REASONING_MODEL=gemini-3.5-flash
REVIEWER_MODEL=gemma-<version>
SIM_CLOCK_MODE=real          # "sim" for the accelerated demo
```

### 2. Enable APIs and provision infrastructure

```bash
./scripts/enable-apis.sh
terraform -chdir=infra init
terraform -chdir=infra apply
```

This provisions Firestore, the Pub/Sub topics and dead-letter queue, Cloud Scheduler, one service account per sub-agent with scoped IAM, and the Model Armor template.

Expect roughly four minutes. Set a billing budget alert before running it.

### 3. Seed the synthetic corpus

```bash
python -m scripts.seed --findings 400 --assets 60 --owners 12
```

The seed includes one finding carrying a planted prompt-injection payload in its comment field, used to exercise both the Model Armor boundary and the reviewer agent.

### 4. Run locally

```bash
pip install -r requirements.txt
adk run agents/orchestrator
```

The console UI serves at `http://localhost:8080`.

### 5. Deploy

```bash
./scripts/deploy-agent.sh    # orchestrator and sub-agents to Agent Runtime
./scripts/deploy-ui.sh       # console to Cloud Run
```

Agents deployed to Agent Runtime register automatically in Agent Registry. Verify with:

```bash
gcloud alpha agent-registry agents list
```

### 6. Run a cycle

```bash
# Real time
./scripts/tick.sh

# Accelerated: replay a six-week remediation lifecycle
SIM_CLOCK_MODE=sim ./scripts/tick.sh --advance-weeks 6
```

### 7. Verify the controls

```bash
./scripts/verify-controls.sh
```

Confirms that Model Armor blocks the planted payload, that the reviewer agent independently flags it with Model Armor disabled, that the reporting agent's service account is denied a ticket write, and that a resumed cycle produces no duplicate tickets.

### 8. Tear down

```bash
terraform -chdir=infra destroy
```

### Cost notes

Minimum instances are zero and maximum instances are capped, so idle cost is negligible. If Gemma is served from a dedicated endpoint in your region rather than per-token, that endpoint is the only always-on component: deploy it when needed and destroy it immediately after. Set a billing budget alert before running anything.

---

## Findings and learnings

*(To be completed before submission. Cover: what the reviewer agent caught that triage got wrong and how often; where the idempotency design was actually load-bearing; where Memory Bank earned its place and where session state would have been enough; what the injectable clock could not simulate honestly.)*

## Roadmap

Out of scope for the hackathon build, kept here so the boundary is explicit:

- Real scanner integrations rather than a synthetic corpus
- Ticketing system connectors
- Human approval workflow for escalations above a severity threshold
- Multi-tenant isolation

## Submission provenance

Built for the All Things Agentic Hackathon, Fortified Enterprise Fleet category.

- Devpost: `daviyon-daniels `
- GitHub: `daviyondaniels` (personal account)
- Google Cloud project: `remediation-zero`, under a separate business Google account

The deployment shown in the demo video runs in that Google Cloud project. The GitHub account and the Google Cloud account belong to the same author. Commits are signed. For verification, contact `<email>`.

## Disclosure

This project was built entirely within the hackathon submission period. Implementation was assisted by AI coding tools, which the contest rules expressly permit. No pre-existing code was incorporated.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

The architecture diagram and documentation in this repository may be reused with attribution.
