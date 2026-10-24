# Reconstructed recovery patch — 2026-10-23

Base: `6204de04193af56732a28d6b77e3ae720fe51a4a`.
Local branch: `dev/rebuild-reviewer-recovery-20261023`.

The previous local checkout and patch were removed by workspace maintenance.
Two Library searches found no recoverable artifact. This is a reconstruction
from the original commit and the conversation's recorded implementation details,
not a byte-identical recovery. Historical test totals (718 unit tests and the
earlier emulator run) do not establish correctness of these reconstructed bytes.
Fresh results are in validation-results.txt.

## Latest integration checkpoint — 2026-10-24

Run `python3 -S start-remediation-zero.py` from the repository or bundled
local-edition folder. On Windows use `py -3.12 -S start-remediation-zero.py`.
The installer and checkout now share a launcher. Settings are integrated in the
local dashboard; the preserved cloud console has not changed. See
`platform-integration.md` and `validation-results.txt` for scope and test evidence.
The owner subsequently approved one unsigned development-branch publication,
excluding CLAUDE.md changes. See platform-integration.md for the publication scope.

## Scope restored

- Both procedural and graph runners persist reviewer outages and escalate once.
  Earlier rejection evidence survives outages and model/validation errors.
- Decision and escalation are created in one Firestore batch. Existing canonical
  decisions win; missing escalation can be repaired create-only. Orphan queues
  and completed ledgers without a decision refuse automatic reconstruction.
- Four durable request slots per stage; two semantic rounds; up to 16 application
  model requests per finding/cycle. The existing SDK request retry multiplier is
  disabled in the runners. Standalone adapters retain their existing default retry.
- Proposals, verdicts and permanent inference failures are checkpointed into the
  existing scalar idempotency result field. Request reservations cannot expire.
  Changed input/model/prompt context refuses pending work. Active stage claims
  defer instead of inventing a human escalation. Corrupt/unavailable state stops.
- Strict verdict and retry-limit validation; 32,768 input bytes including prompts,
  2,048 output tokens, 60-second request timeout. These are not a dollar ceiling.
- Read-only recovery snapshot audit returns repair_candidate/manual_review/no_action.
  It does not fetch a cloud snapshot, infer lost evidence, or apply backfills.
- Offline guards reject credentials, network transports and SDK inference, including
  the staged-import child process. Caught violations still fail the session.
- Separate loopback-only Firestore integration command, synthetic project identity
  and anonymous credentials; no cloud fallback. Concurrency deferrals are counted.

The reconstruction consolidates new behavioral tests in test_recovery_rebuild.py;
it does not reproduce every individual test or narrative paragraph from the lost
patch. Relevant existing tests are retained and adapted to the restored contracts.
Changes to CLAUDE.md and .env.example only document the local integration command.
No active environment configuration, application dependency, schema, submission
artifact, or deployment definition was changed.

## Reviewed behavior and limits

Inference retries are bounded and resumable. A response lost before checkpointing
may differ when retried; its reserved slot is still consumed. Persisted rejection
history survives replay. Only one re-proposal is allowed. Persistence failures do
not authorize additional model calls or an unguarded escalation.

The policy does not cover external-action retries, guarantee exactly-once model
execution, create a global cross-cycle human hold, or add a cross-finding circuit
breaker. A hard process death can retain the existing stage lease for 600 seconds.
The baseline five emulator checks do not establish hard process-kill/lease-expiry
behavior; the follow-up below adds that coverage with a shortened test lease.
Production IAM/index parity, cloud availability and provider billing remain untested.
Snapshot audit requires complete, consistent exports. Restore is write-capable;
use audit_recovery_snapshot for read-only inspection.

## Applying and signing locally

Use a clean isolated checkout from the exact base. Do not overwrite unrelated work.

```bash
git switch -c dev/reviewer-recovery-rebuilt 6204de04193af56732a28d6b77e3ae720fe51a4a
git apply --check /absolute/path/remediation-zero-local-development.patch
git apply /absolute/path/remediation-zero-local-development.patch
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -c constraints-3.12.txt
.venv/bin/pytest -q
git diff --check
git diff
```

After reviewing/staging the intended files in the owner's signing-enabled checkout,
use `git commit -S` and verify the signature. This reconstruction is uncommitted;
signing identity/configuration was not changed. Never send a private key in chat.

No push, merge, deployment, paid model call, live cloud repair or publication is
authorized by this handoff. The original gate remains: official All Things Agentic
results must be published, not merely scheduled, before merge/deployment; ask
before publication. No current result-publication verification was performed in
this reconstruction turn. Origin push is locally disabled.

## Follow-up: interrupted assignment recovery

The procedural runner previously treated a stored decision as proof that the
entire finding had finished. An interruption between decision persistence and
assignment therefore permanently skipped the owner/SLA step on rerun.

It now sends restored ratified decisions through the existing idempotent
assignment writer before counting adjudication as skipped. Restored unavailable
and human-queue decisions still cannot start an assignment or SLA. Reconciliation
has its own structured log event. No schema or assignment persistence change was
needed, and no model call is repeated for the restored decision.

Two new regressions reproduce interruption before assignment for owned and
unowned assets. Both failed before the fix and passed afterward. They verify
assignment/SLA or unassigned escalation creation, unchanged records on a third
run, and exactly one triage/review pair. The affected regression run passed
50 tests (one existing ADK deprecation warning). This is the current validation
for the follow-up; the full 670-test and five-emulator-check results above are
the preceding reconstruction baseline, not a new full run of this follow-up.

Remaining at that point: signed local commit, process-kill/lease-expiry coverage, and
production integration behind the gate. This fix covers interruption before
assignment begins; it does not make the assignment writer's multiple writes
atomic or establish recovery guarantees for a crash midway through those writes.

## Follow-up: killed worker and lease expiry

The emulator harness now kills a real child process after request reservation.
It verifies live-lease deferral, recovery after real elapsed expiry, preservation
of both consumed request slots and prior rejection evidence, and rejection of
stale completion. Only the disposable child uses a ten-second lease; production
still uses 600 seconds. No production implementation or schema changed.

All six emulator checks passed. Targeted offline validation passed 71 tests with
one existing ADK deprecation warning in 1.81 seconds. This is not a new full-suite
run. Exact 600-second timing, mid-assignment crash recovery, signed commit and
production integration remain gaps. No cloud calls or publication occurred.

## Dashboard discovery

ui/app.py already provides a read-only FastAPI evidence console with Firestore
snapshots. Preserve that judge-facing console. A separate operator dashboard can
reuse its data concepts after the user supplies the intended visual reference.
This discovery preceded the dashboard implementation below.

## Small-business owner dashboard

The dashboard is mounted in the read-only console at `/dashboard`, sharing
its snapshot cache, security headers and viewer-only service account. The
console page at `/` is unchanged. Rendering lives in ui/dashboard_view.py,
which the local SQLite edition also uses. Overview, My infrastructure, Action list and
Activity reuse the existing snapshot shape. Recommendations are deduplicated
within the latest 60 decisions and sorted by recorded severity; they are not
represented as a complete open backlog. Unapproved proposals are withheld from
next-step instructions. Evidence and prior reviews remain expandable.

Run locally with synthetic fixtures (no cloud reads):

```bash
RZ_DASHBOARD_DEMO=1 .venv/bin/uvicorn ui.app:app --host 127.0.0.1 --port 8081
# then open http://127.0.0.1:8081/dashboard
```

The application labels the environment synthetic, escapes record text, has no
write endpoints, disables shared caching, and fails closed to an unknown-status
page on snapshot errors. Demo records contain no invented lifecycle timestamps.
No new dependencies, schema changes, cloud changes or deploy scripts were added.

24 dashboard and existing-console tests passed (one existing Starlette warning).
Tests cover navigation, cloud-free demo mode, failed reads, untrusted text,
unapproved recommendations, retained history and absence of write endpoints.
Browser visual validation has not been performed. Authentication, tenant isolation,
full asset inventory, reliable current finding state, overdue calculations,
connector health and scan freshness remain prerequisites for a customer release.
This is a local synthetic preview, not a production-ready business service.

## Portable local edition

The user approved an open-source local edition with a model endpoint connection
and a potential future Ayliea-hosted offering. SQLite now implements the existing
idempotency interface, with transactional reservations, token-owned leases,
durable checkpoints and a create-only suggestion projection. The shared journal
can import without optional cloud/HTTP packages. Dashboard rendering is pure
Python and reused by a loopback-only standard-library server. The separate
FastAPI dashboard and original console remain available.

The model adapter uses an explicitly configured chat-completions endpoint,
blocks redirects, bounds responses and validates proposals. Only the explicit
`cycle` and `check-models` commands invoke a model, plus the launcher's interval
runner when a cycle interval is set in Settings. (`suggest-demo` has been
retired.) Each decision is labelled with how it was reviewed: cross-family,
same-family or unreviewed. `check-models` sends only the bundled synthetic
example. No infrastructure is modified.

The archive now includes a runnable local-edition directory; see its README.
82 targeted tests and four real loopback HTTP view checks passed, including
running with third-party packages disabled. No provider calls were made.
SQLite lease expiry under actual process death, browser visual checks and real
provider compatibility remain unverified for this edition. Cloud emulator
results above do not establish SQLite process-death behavior.

The official Devpost gallery was verified to show winners on 2026-10-23:
https://allthingsagentichackathon.devpost.com/project-gallery
The publication-results condition is satisfied. Prior push/deploy attempts were
blocked by missing signing configuration and cloud authentication. This portable
edition has not been committed, pushed or published; no license changes were made.

## Installer follow-up

The archive includes install-remediation-zero.py: a single offline installer
generated from an explicit allowlist of local-edition sources. It discloses its
plan and prompts before installation, refuses existing targets, validates the
embedded payload and starts a loopback demo with an optional browser launch.
Python 3.12+ remains required. No credentials, dependencies, models or background
services are installed. Source and tests are included in the development patch.
36 targeted tests and a real installed-launcher HTTP check passed. See the local
edition README for limitations, stopping, restarting and removal. There is no
public release URL, signature, update mechanism or verified Windows/macOS build.

## Ayliea theme

The four dashboard views now share Ayliea's navy/blue/cyan tokens, the approved
product logo and by Ayliea endorsement. Overview prioritizes the next action;
evidence and totals are collapsed. The installer and portable archive bundle the
same stylesheet and logo. See theme-review.md for source and visual QA limits.
