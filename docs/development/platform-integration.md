# Portable platform integration — 2026-10-24

## What is integrated

The repository root `start-remediation-zero.py` calls the shared launcher in
`scripts/local_launcher.py`. The installer packages those same files, with an
explicit source allowlist, so a source checkout and an installed preview run
the same dashboard and Settings implementation. An explicit `--database`
selects a different workspace folder.

The lifecycle runs from one shared engine (`engine/`): triage and review,
assignment, chase, the exception sweep, reports, rescans, seeding, a person's
approval and the dashboard snapshot. Each edition supplies its parts through
`engine.ports.Ports`: Firestore, Model Armor and the GitHub tracker in the
cloud; SQLite, a guard model and dashboard-only delivery locally. The cloud
scripts (`scripts/cycle.py`, `graph_cycle.py`, `chase.py`, `exception.py`,
`report.py`, `rescan.py`, `ingest.py`) call the same stage functions the local
commands do. The engine runs on the standard library alone (`python3 -S`).

The local edition runs the full lifecycle from `python3 -S -m scripts.local`
(`init`, `seed`, `cycle`, `rescan`, `exception`, `approve`, `serve`,
`check-models`). It has four model roles: proposer, reviewer, summarizer and
guard. The earlier `suggest-demo` command is gone. See
[local-edition.md](local-edition.md) for behaviour and limits.

`tests/test_lifecycle_local.py` runs one multi-cycle scenario in one process
against a local workspace. It covers seed, cross-family, same-family and
unreviewed decisions, assignment, one escalation across two chase runs,
approval, a lapsed acceptance reopening, a rescan dry run and apply, the
report, a failed run, and both clocks on every lifecycle record. The same
scenario runs against `FirestoreDocStore` on the Firestore emulator when
`FIRESTORE_EMULATOR_HOST` is set. Otherwise it is skipped with that reason.
The emulator half has not been run.

The README includes local startup and installer-build instructions. CI has a
separate standard-library-only portable-install job with a Linux, Windows and
macOS matrix. It builds a fresh installer, installs in a path containing
spaces, checks launcher imports from an unrelated working directory, serves
all pages, saves preferences, rejects a foreign Origin, and checks that
reinstalling cannot overwrite preferences. That job has not run remotely.

## What stays separate

- `ui/app.py` and the original Dockerfile remain the cloud evidence console.
- The cloud dashboard is mounted read-only at `/` in `ui/app.py`, as the local
  edition's is; the evidence console is at `/console`, and `/dashboard`
  permanently redirects to `/`. It has no Settings writes.
- The local SQLite edition is not a cloud backend and does not synchronize its
  workspace or settings with Firestore.
- Real scanner ingestion exists in the local edition: Greenbone/OpenVAS reports
  are pulled from gvmd or uploaded as exported files (see
  [greenbone.md](greenbone.md)). The cloud edition still reads the committed
  synthetic corpus. The approved inventory designs and the complete first-run
  onboarding flow are still future work.
- The local edition has sign-in (owner and tech roles, mandatory MFA) and HTTPS
  for use on a private network or behind a proxy such as Tailscale Serve.
  Exposing it directly to the public internet is unsupported. A hosted edition
  needs tenant isolation, secret storage and operations design first.

## Development branch publication

On 2026-10-24 the owner approved a one-time unsigned development commit through
the GitHub integration, excluding all changes to CLAUDE.md. Publication targets
`dev/portable-platform-20261024`, based on
`6204de04193af56732a28d6b77e3ae720fe51a4a`. This exception does not authorize
merging, deployment, or changes to Git identity/signing configuration.

The original CLAUDE.md is inherited unchanged from the base commit. The local
post-hackathon edition and its scope were separately authorized by the owner;
see the local-edition guide for its supported behavior and limitations.

The checked-in workflow runs on main pushes and pull requests to main, not on
this development branch push. External deployment triggers have not been audited.
No release or pull request is created as part of this publication.

## Validation and remaining gates

What has run, on Linux only: the offline suite (`.venv/bin/pytest`) and
`python3 -S -m scripts.verify_local_install`. No model provider was called and
no cloud operation was performed.

Nothing has been deployed. The cloud code changed (the cloud scripts now call
`engine/`), so the deployed services still run the earlier code. Before the
deployed services reflect this branch, with the owner's sign-off:

1. The worker image needs `engine/`. `Dockerfile.worker` now has
   `COPY engine/ ./engine/`; without it the worker fails at import. The next
   `./scripts/deploy-worker.sh` picks it up.
2. Run `./scripts/deploy-ui.sh` and `./scripts/deploy-worker.sh` between
   cycles, not while one is running.
3. Then run `./scripts/verify-controls.sh` against the deployed services.
4. `./scripts/deploy-agent.sh` is not needed: the Agent Engine resource is
   untouched.

Still pending:

- the Windows and macOS CI matrix (not run anywhere)
- the Firestore emulator half of the lifecycle test
- visual browser QA of the local dashboard
