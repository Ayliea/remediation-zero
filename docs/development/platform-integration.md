# Portable platform integration — 2026-10-24

## What is integrated

The repository root `start-remediation-zero.py` calls the shared launcher in
`scripts/local_launcher.py`. The installer packages those same files, with an
explicit source allowlist, so source checkout and installed preview run the
same dashboard and Settings implementation. The default SQLite database and
preferences live beside the root launcher, independent of the terminal's cwd.
An explicit `--database` selects a different existing workspace location.

The local server renders the four existing dashboard views and all five Settings
sections. Model connection and startup preferences persist; API keys remain in
the process environment. No startup, install, GET, or Settings save invokes a
model. `scripts.local suggest-demo` is the separate explicit inference command.

The README includes local startup and installer-build instructions. CI now has
a separate standard-library-only portable-install matrix for Linux, Windows,
and macOS. The validation command builds a fresh installer, installs in a path
containing spaces, checks launcher imports from an unrelated working directory,
serves all pages, saves preferences, rejects a foreign Origin, and verifies
that reinstalling cannot overwrite preferences. CI has not run remotely yet.

## What stays separate

- `ui/app.py` and the original Dockerfile remain the preserved cloud evidence console.
- `ui/dashboard.py` is a read-only FastAPI adapter; it has no local Settings writes.
- The local SQLite edition is not a new cloud backend and does not synchronize
  its database or settings with Firestore.
- Real scanner ingestion, independent local review, the approved inventory
  table/details designs, and the complete first-run onboarding flow are still
  future work. The integration does not claim those concepts are implemented.
- Hosting this local HTTP server publicly is unsupported. A future hosted edition
  needs explicit authentication, tenant isolation, secret storage, and operations
  design before deployment.

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

See `validation-results.txt` for exact test results. Linux offline installation
and HTTP checks have run; Windows/macOS matrix execution and visual browser QA
remain pending. No model-provider calls or cloud operations were performed.
