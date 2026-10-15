# Inactive scoped frozen-recovery contract

The legacy stale-recovery command processes STALE rows, but a FROZEN lane has no
supported scoped recovery operation. The ordinary source claim path correctly
rejects a frozen lease. Reclaiming through historical behavior is not recovery.

`lib/codestra_control/frozen_recovery.py` supplies a distinct, inactive inspection
contract for independently reviewed recovery integration. It does not extend
bootstrap, change lifecycle commands or read/write any database, filesystem,
Git ref, service, grant, certificate or status. No CLI or deployment is included.

## Exact request and evidence bindings

The immutable request binds repository/product, workstation/task, previous owner,
canonical declared worktree, branch/parent, matching exact local/remote SHA,
frozen snapshot identity, freeze-incident identity, repair evidence and validity
window. Identifiers are declarations, not proof of filesystem or Git identity.

A trusted in-process verifier must return separately identified attestations for
operator recovery authority, eligible independent review, the genuine frozen
snapshot, repaired worktree/Git observation and durable replay fencing. Each
attestation must cover the complete identical request. No dictionary/JSON success
flag is accepted. Python constructors and fixture objects grant no authority.
The callback owns authentication, accepted identity/issuer, review eligibility,
revocation and genuine observations; these policies are not invented here.

Missing, malformed, mismatched, expired or unavailable evidence denies. Time is
checked again after verification so a slow verifier cannot validate an expired
request. Timestamp ordering and binding comparisons use UTC instants, preserving
distinct daylight-saving folds while accepting equivalent offset representations.
Even a complete fixture inspection returns `authority=false`,
`ready=false`, `released=false`; it is not a transferable receipt or certificate.

## Future executor: independently reviewed prerequisites

No production verifier or persistence executor is implemented. Independent
security/operator decisions must establish a genuine freeze-incident/revision
fence, durable one-use grant consumption, issuer/revocation semantics and trusted
worktree observation. The legacy schema's `updated_at` alone must not be assumed
to prevent an old frozen snapshot from being reused after a later freeze.

An eventual executor must use one transaction to lock and re-read exactly the
requested frozen lane; revalidate current authorization, independent review,
incident and source/worktree evidence; consume the unique recovery grant;
compare-and-set exactly one matching row; and append the immutable audit event.
All steps must roll back together on any failure. It must address changes between
filesystem observation and commit, and reject concurrent or repeated attempts.

The post-release state/ownership/blocker contract requires explicit review.
Recovery cannot certify prerequisites, claim a new task, change source refs,
clear retained certification evidence, publish success statuses or admit a
feature-to-development route. Recovered work must still obtain a valid task
lease, pass the original preflight, run real required checks and receive review.

## Source assignment and validation

`governance/source-preparation/task-scoped-frozen-recovery.json` records the
user-authorized source-only task, not a live assignment or lease. Existing
bootstrap, scoped registration and promotion-route work remain separately owned.

Offline tests bind every request field to every attestation, reject malformed and
missing evidence and verify inactivity for both success and failure. They do not
execute recovery against a live controller. Full runtime acceptance remains gated.

PRODUCTION_GO=NO; LIVE_CAPABILITIES_ENABLED=NO; EXTERNAL_EFFECTS=false.
