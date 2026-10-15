# Replay-ledger sidecar initialization race

Concurrent SQLite writers can remove a completed `-journal`, `-wal` or `-shm`
sidecar between an existence check and a subsequent metadata lookup. Hosted
source CI exposed this race in the concurrent one-winner reservation test.

ReplayLedger now obtains one non-following metadata snapshot per sidecar. Only
FileNotFoundError is treated as absence, which was already permitted. Symlinks
are rejected from that same snapshot before the existing regular-file, link-count,
ownership and permission checks. Other inspection errors propagate. This does
not make a path snapshot a durable filesystem trust guarantee or change the
ledger's existing trusted-parent assumptions.

A deterministic regression recreates the stale existence observation for each
sidecar and checks that the ledger still refuses a consumed nonce after reopening.
Additional regressions reject dangling sidecar symlinks and permission-denied
inspection. Existing concurrent one-winner tests remain required.

This is source preparation only. No live ledger, controller command, policy,
status, registration, lease or runtime is changed. It does not recover a frozen
lane, certify a prerequisite or admit Middleware PR453's promotion route.

Source assignment: `governance/source-preparation/task-replay-ledger-sidecar-race.json`.
PRODUCTION_GO=NO; LIVE_CAPABILITIES_ENABLED=NO; EXTERNAL_EFFECTS=false.
