# Status publisher: database unavailable

This runbook separates source certification from runtime activation when
`codestra-control-plane-status.service` cannot reach its configured database.
It does not authorize service, database, container, credential, TLS, or
production changes.

Keep `PRODUCTION_GO=NO`, `LIVE_CAPABILITIES_ENABLED=NO`, and
`EXTERNAL_EFFECTS=false` while following this procedure.

## Expected fail-closed behavior

The checked-in publisher enters through `publisher_session()` and
`run_configured_cycle()`. Unexpected database, credential, configuration, or
API failures are converted to
`PublisherUnavailable("AUTHENTICATED_PUBLISHER_CYCLE_REFUSED")`; the executable
then exits nonzero with the stable `PUBLICATION_REFUSED` prefix. Secret DSNs,
keys, API bodies, and raw database errors must not appear in its diagnostic.

A failed publisher cycle is not evidence that a controller runtime or TLS
endpoint is installed. It must never be converted into a successful status,
retried through another database endpoint, or used to broaden publication
scope.

## Read-only diagnosis

Use the configured unit and Docker endpoint exactly as declared. Record:

1. `systemctl show codestra-control-plane-status.service` fields `FragmentPath`,
   `ExecStart`, `User`, `Group`, `EnvironmentFiles`, `Result`,
   `ExecMainStatus`, `ActiveState`, and `SubState`.
2. `systemctl status codestra-control-plane-status.service --no-pager --full`.
3. The configured Docker context and its endpoint. If the approved endpoint is
   `unix:///var/run/docker.sock`, inspect only that socket.
4. Exact metadata and SHA-256 for the installed publisher and checked-in
   candidate. Different hashes mean source and runtime certification are
   separate.
5. Listener presence only for the configured database port. Do not connect to
   or substitute an unapproved listener.

Do not scan other Docker contexts, adopt an unpinned container, inspect private
credential files, change permissions, or start/restart a service during this
diagnosis.

## Decision rules

- Connection refusal at the configured endpoint with no listener is an
  environmental availability failure. It does not prove a source defect.
- A configured target container missing from the exact approved Docker socket
  blocks live certification. Do not repin by name, image, port, or similarity.
- A runtime publisher whose digest differs from the certified source is not
  certified by source tests. Deployment requires its own reviewed batch and
  post-deployment hash/readback evidence.
- Port `5435`, another loopback listener, or another Docker context is not a
  replacement for configured port `5432` without an exact reviewed binding and
  explicit approval.
- A nonzero publisher result must remain nonzero. Do not suppress the failure,
  synthesize healthy status, or retry GitHub publication against partial state.

## Required recovery evidence

Before any activation attempt, the authorized custodian must provide a
nonsecret receipt establishing one of these outcomes:

- the exact pinned database/container identity is restored on the approved
  socket, with its original system identifier, database OID, port, and
  preservation checks; or
- a reviewed replacement target/configuration is proposed with exact immutable
  identity, impact, rollback, and migration evidence.

Separately, deployment of a certified publisher candidate requires exact source
and installed hashes, the unit/configuration diff, service-specific approval,
one bounded start, sanitized output, and rollback to the preserved installed
file. A source commit or passing test does not authorize that deployment.

After those gates pass, verify the configured database transport and publisher
cycle. Controller TLS, credentials, runtime admission, repository writes, and
production activation remain distinct gates.

## Recorded recovery

The 2026-10-26 dev-desktop recovery observation is recorded in
[`verification/2026-10-26-status-publisher-database-recovery.json`](verification/2026-10-26-status-publisher-database-recovery.json).
It establishes that the original port-5432 cluster and its named volume are
again available, the recovery archive passed bounded integrity checks, and one
automatic cycle of each installed legacy status publisher exited successfully.

That receipt deliberately does not certify the checked-in authenticated
publisher as installed. The installed executable has a different digest, the
database transport and roles do not satisfy the authenticated-controller
contract, and the available controller and AUTH3 candidates remain inactive
and unapproved. Those gates must remain blocked until their own current,
reviewed inputs and action-time approvals exist.

The nonsecret current-target inputs needed to prepare that later review are
recorded separately in
[`verification/2026-10-26-recovered-target-tls-auth-inputs.json`](verification/2026-10-26-recovered-target-tls-auth-inputs.json).
That record is evidence only: it contains no private-key digest or contents,
password, verifier, protected DSN, executable command, activation window, or
authorization to change the target.
