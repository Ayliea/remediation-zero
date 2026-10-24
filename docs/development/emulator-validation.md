# Reconstructed emulator checks

The reconstructed script verifies:

1. Eight racing durable reservations have one winner and cannot reset the slot.
2. Eight claim contenders have one winner; stale completion/abandonment cannot
   mutate a replacement claim.
3. An orphan queue conflict rolls back the decision batch and preserves the queue.
4. Concurrent terminal writes preserve prior rejection evidence and produce one
   escalation; a fresh writer restores the same result.
5. A fresh journal replays rejection and cannot reset four exhausted request slots.

Model callables are synthetic. Firestore uses the actual SDK against the emulator.
The unit suite is separate and denies networking. No cloud testing is claimed.

Start a local emulator in another terminal, then execute from the repository:

```bash
gcloud emulators firestore start --host-port=127.0.0.1:8787
FIRESTORE_EMULATOR_HOST=127.0.0.1:8787 .venv/bin/python -m scripts.verify_recovery_emulator
```

Only a literal loopback address with an unprivileged port is accepted. The script
uses anonymous credentials and a unique demo-rz-* project. Keep this environment
variable unset for other commands. Never forward this address to production.

Fresh tooling: Google Cloud CLI 590.0.0, Firestore emulator 1.22.0, Temurin Java 21.
It was reinstalled locally using the earlier explicit installation approval.
The CLI post-install warning concerns Unix socket restrictions; TCP emulator
startup succeeded. In this environment the emulator and runner were launched in
one process tree and terminated at completion. No cloud sign-in was performed.

An initial fresh run passed the first three checks, then failed when contention
left every terminal writer deferred. The harness now allows four bounded recovery
attempts after that race, and still requires a committed result plus one queue
entry. All other errors fail. The successful fresh run had four reservation
deferrals, one claim deferral, zero terminal ABORTED deferrals and zero post-race
recovery attempts. All five checks passed. The extra post-race recovery branch
was not needed in that successful run. Production code was not changed for this
emulator-specific contention observation.

The baseline stdout is stored in validation-results.txt.

The follow-up adds a sixth check: SIGKILL a child after durable request reservation,
assert that its live lease defers another request, wait for real elapsed expiry,
then recover with a fresh journal. Both request slots remain consumed, the prior
rejection replays, and the dead worker's stale claim cannot overwrite recovery.
All six checks passed. The child alone uses a ten-second lease; the production
600-second constant is unchanged. Timestamps come from SimClock without backdating.
This validates expiry behavior, not an actual 600-second wait. Production IAM/index
behavior remains untested. No production readiness or exactly-once claim is made.
