# Paid cloud edition — scope

Date: 2026-10-29 · Scoping only, not an approved design. Nothing here is to be
built or deployed until its own design is written and approved. Owner
decisions are marked **(owner)**; calls made while scoping are marked
**(scoping call)** so they can be checked and overturned.

## Intent

A hosted, paid edition for companies and MSPs that want to start quickly with
nothing to host, with models chosen and paid for by Ayliea. The cloud might be
Google Cloud or AWS **(owner)**. No public hosting is tested until the product
is perfected **(owner)**.

## What already carries over

The portable-engine work (`2026-10-24-portable-engine-and-model-roles-design.md`)
left the seams a hosted edition needs:

- **Storage port.** Every writer speaks `tools/docstore.py`; Firestore and
  SQLite are two adapters behind it. A third (DynamoDB, Postgres) is an
  adapter, not a rewrite.
- **Model roles.** Providers are pluggable; Vertex is one provider. Bedrock
  could be another.
- **Guardrail, ticket delivery and scheduling ports** are defined.

## What it still needs, on either cloud

| # | Piece | Why |
|---|---|---|
| 1 | Edition-split design | `CLAUDE.md` says the split is still being designed, and code cannot move between core and cloud until it is. It decides what is paid-only. |
| 2 | Multi-tenancy | Every record carries a client ID; each client's data is walled off; MSP accounts span many clients; per-agent credential scoping (hard constraint 4) holds per client. Today one deployment is one organization. |
| 3 | Hosted identity | Local sign-in is SQLite accounts with TOTP. The cloud needs a managed identity service (Identity Platform or Cognito) with MFA, the owner and tech roles, and an MSP role. |
| 4 | New dashboard on cloud storage | The cloud still runs the console. Retiring it (local release project 4) and running the new pages on cloud storage are the same work, so this follows project 4. |
| 5 | On-network connector | Greenbone usually sits inside the customer's network, out of reach of the cloud. A small connector pulls results and pushes them outward, with upload as the fallback. It forwards findings from tools the customer already runs and never scans. The largest new piece. |
| 6 | Managed models and cost metering | Ayliea chooses and pays for models; each client's spend is measured and capped. |
| 7 | Billing | Free is single-client; paid is multi-client with MFA (owner, 2026-10-25). Needs a payment provider and plan enforcement. |
| 8 | Operations | Per-client backup, export and deletion; audit trail; alerting; a security review before any outside customer. |

Multi-tenancy is the hardest piece to add late: every query, idempotency key
and credential must carry the client ID. It belongs in the edition-split
design, before the cloud dashboard work **(scoping call)**.

## Google Cloud or AWS

Recommendation: Google Cloud first, AWS later as an adapter set
**(scoping call)**.

- Google Cloud is built and proven: Terraform in `infra/`, the deploy scripts,
  the Firestore adapter, Model Armor, and `verify-controls.sh` proving six
  security claims against deployed services.
- AWS means DynamoDB (or Postgres) storage, Bedrock Guardrails in place of
  Model Armor, SQS and EventBridge in place of Pub/Sub and Cloud Scheduler,
  IAM per agent, new Terraform and a new controls check: close to a second
  deployment to maintain.
- The long-running Agent Engine session stays on Google Cloud regardless
  (hard constraint 9). On AWS the lifecycle would run on the portable engine
  in containers.
- The trigger for AWS is customer demand, for example MSPs buying through AWS
  Marketplace or a customer whose policy requires AWS. Adding AWS is a new
  cloud service and needs the owner's approval.

## Suggested order

1. Finish local release projects 3–6. Project 4 (dashboard replaces console)
   unblocks piece 4.
2. Edition-split design, including tenancy and the identity model.
3. Tenancy and hosted identity, then the dashboard on cloud storage.
4. The connector, then managed models with metering, then billing.
5. A private beta with one friendly MSP, not public. Public hosting only when
   the owner says the product is ready.

## Open

- Which payment provider.
- Whether the connector ships as a container, a single Python file like the
  local installer, or both.
- Per-client cost caps: hard stop or degrade to a cheaper model.
- Data residency, if a customer asks for it.
