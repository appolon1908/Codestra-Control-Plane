# Executable frozen recovery: source contract

This implements the recovery step explicitly requested by the user. It is a
source-only extension of the existing PR21 design, not deployment or operator
admission. PR21's version1 inspection remains inactive and unchanged.

## Version2 action and identity

The sole action is RELEASE_STALE_WORKTREE_TO_FREE. It accepts only a workstation
whose exact server snapshot is FROZEN, BLOCKED and STALE_DIRTY_WORKTREE, has a
previous agent/task, and has no completion/certification timestamps. A successful
transaction clears that exact recovery blocker and lease ownership/timestamps,
sets FREE/NOT_STARTED, and preserves source SHAs, tests/review/evidence, atomic
task records and certification history. It issues neither a new lease nor a
certification. Any ACTIVE assignment_leases row denies; an operator must use the
existing explicit revocation API before this distinct recovery action.

New frozen_recovery storage is operator-controlled. No policy, principal,
permission, grant, credential or active runtime record is seeded. Authenticated
PostgreSQL SCRAM system_user bound exactly to session_user, plus the registered
role OID over TLS, is required. Other authentication methods are not admitted by
this version. This prevents SET SESSION AUTHORIZATION from impersonating a
restricted executor after an elevated login. SET ROLE, elevated identities,
schema owners, DML-capable callers and revoked/recreated identities deny. Operator, reviewer, verifier and executor
are distinct registered identities with separate product capabilities.

An operator-authorized grant pins an incident UUID/revision, complete frozen-row
snapshot, policy, roles/OIDs and repaired subsection checkout. The checkout
contains repository/ID, exact source and parent refs/SHAs, worktree/root/common
Git directory, host and UID; it is not a new atomic candidate checkout. The grant
is immutable through public APIs except for consumption and permanent per-grant
revocation. A separate authenticated operator revoke API cancels one grant
without disabling unrelated grants; cancellation is audited and never reversed.
An independent reviewer countersigns its exact server digest. The separate verifier uses the existing strict GitMaterializer
and read-only GitHub observer, then submits a one-use, bounded-age observation.

## Database and external boundaries

008-frozen-recovery.sql is a forward source migration depending on005 and007.
A server-controlled trigger rotates incident UUID and increments a monotonic
revision on a new freeze or any frozen-row change, and invalidates the incident
on leaving FROZEN. This fences refreeze/ABA even with identical timestamps.
All snapshots and request digests use server-enforced UTC independently of client
timezones. Scoped workstation/lane/section metadata is locked and matched too.
Existing frozen rows receive initial incident records on installation; grants
must be newly obtained afterward. Delete/recreate cannot reuse an incident.

Execution uses the assignment issuer's advisory lock namespace, then row locks
and current authorization revalidation. It checks exact snapshot/policy/identity,
review and proof, denies active modern leases, advances the assignment slot epoch,
consumes the grant/proof, updates exactly one matching workstation, and appends
its before/after audit event in one transaction. Any failure rolls everything
back. Proof/grant expiry is checked again before the state update and after the
audit/events writes. A historical receipt lookup cannot execute recovery or
authorize a claim. Database authorization locks serialize current policy changes;
no instant revocation across an already pending commit is claimed.

The independent checkout observation is outside the database transaction. Its
freshness is bounded by explicit operator policy and rechecked at execution.
Filesystem and remote refs can change after observation; no cross-system atomic
fence is claimed. Production adoption requires independent acceptance of this
residual race, credential/custody/TLS policies and actual identities.

The protected-credential CLI has distinct operator/reviewer/verifier/executor
configuration. It rolls back unless --apply is explicit, never accepts caller
DSNs or raw repair observations, and reveals only generic failures. No credentials,
roles, migration, services or runtime changes are applied by source tests. A lost
commit response is resolved through authenticated historical lookup; recovery
never replays an already consumed grant. Source/interpreter/dependency custody
still requires an externally accepted immutable installation; local file checks
cannot establish that trust after compromised code has already executed.

## Required validation

Disposable PostgreSQL16/TLS/SCRAM fixtures verify real session identity, exact
scope, incident/revision ABA fencing, review/proof separation, expiry/revocation,
role replacement, restricted privileges, active-lease rejection, epoch invalidation,
concurrent one-winner recovery and transaction rollback on audit failure.
Composition tests verify independent materializer use and rollback-default CLI.
The existing full offline suite remains required on the exact published head.

PRODUCTION_GO=NO; LIVE_CAPABILITIES_ENABLED=NO; EXTERNAL_EFFECTS=false.

Authentication reference: [PostgreSQL16 system_user and session identity](https://www.postgresql.org/docs/16/functions-info.html).
