# Scoped L1/L2 admission design

## Objective and authority

Implement the approved staged authorization design in Control Plane source.
The user explicitly directed implementation after the design discussion.
L1 authorizes dedicated-worktree source writes. L2 separately authorizes a
fast-forward push of one exact candidate to its registered atomic source branch.
Neither grants PR creation, merge, certification, deployment or provider effects.

This is source preparation: runtime assignment, registration, lease,
certification, installation and operational grants remain absent. Use the
committed parent c1890bdcc478cf40231087b57f95ba64ff0a7049, containing coordinator
migration 009. Preserve other worktrees and the existing immutable baseline
lease/materializer behavior.

## Existing gap

The current materializer requires a clean local HEAD and remote source at the
binding's immutable head SHA. Relabeling that receipt as L1/L2 cannot authorize
editing followed by publication of a new commit. Add stage observations and
operation grants without updating the original binding or relaxing its checks.

## Server authority

Add 010-scoped-operation-admission.sql after 005, 007 and 009, in a new
scoped_admission schema. It creates no roles, grants, assignments or policy rows.
All tables/functions deny PUBLIC access. Runtime principals receive specific
function EXECUTE only, never table DML or schema ownership.

Operator-owned grants bind an existing assignment binding, operation L1 or L2,
an exact nonempty relative-path inventory and explicit validity. Grants default
inactive. Every update increments a monotonic revision; deletion is denied.
Revoke/re-enable cannot resurrect an old intent or proof. Runtime callers
cannot edit grants or choose a principal/owner.

Every API requires a restricted credential-authenticated TLS session with
session_user/OID identity. Privileged roles, SET ROLE impersonation, recreated
roles and membership/DML access to any authority schema deny. Reuse the current
lease, coordinator mapping and issuer authority checks, including issuing
verifier revocation, credential provenance, exact dependencies, lease epoch and
expiry. Preserve operator mapping/policy and frozen-lane denials.

Intent creation snapshots the complete grant, mapping, lease receipt and
dependency inventory. Its expiry is bounded by grant, lease and existing
operator attestation policy. No new accepted TTL default is introduced.

## Intent payloads

L1 has exactly paths (a sorted, unique, nonempty list) and mutation_sha256
(nonzero lowercase SHA-256). The digest binds the exact mutation artifact; the
trusted effect consumer must check that digest and its actual paths before use.

L2 has exactly paths, candidate_sha, candidate_tree_sha, expected_remote_sha
and target_base_sha. SHA values are full nonzero Git SHA-1 object IDs.
expected_remote_sha must be the immutable baseline source SHA and target_base_sha
must be the bound target SHA. Publication is fast-forward-only. Version one
requires the registered atomic source ref already at its accepted baseline;
absent refs deny. New-ref bootstrap needs its separately accepted mechanism.

Paths use canonical slash-separated ASCII Git-relative names; reject empty,
absolute, duplicate, unsorted, dot/dot-dot components, .git components,
backslashes, NULs and directory-only paths. Exact path matching; no globs.
All requested/observed paths must be in the operator grant. Both rename endpoints
and all paths introduced anywhere in the candidate commit range count.

## Database API and return contract

- request(grant_uuid uuid, lease_uuid uuid, epoch bigint, payload jsonb,
  request_id text) -> pending intent JSON; only assigned builder.
- describe(intent_uuid uuid) -> server-owned verifier description; only a
  distinct authenticated principal with current attest and read capabilities.
- attest(intent_uuid uuid, observations jsonb) -> proof JSON; only that independent
  verifier. The builder cannot supply observations or create a proof.
- consume(intent_uuid uuid, proof_uuid uuid) -> one-use operation receipt; only
  the original builder. Revalidate all current snapshots/authority, consume proof
  and intent and append audit in one transaction.
- inspect(intent_uuid uuid) -> current request/outcome for the original builder;
  never a new usable admission or retry authorization.

The description contains intent_id, operation, request_digest, payload, grant,
binding, lease and dependencies. The immutable mapping and lease/grant snapshots
are held on the server. The digest is server-generated over the canonical JSONB
request; callers never attest their own authority.

Observation fields are exactly intent_id, request_digest, operation, lease_id,
epoch, head_sha, tree_sha, changed_paths, directory_device, directory_inode,
dependencies and observed_at. Dependency observations use the existing online
issuer/check/capability verifier and equal the complete protected dependency map.
Directory identity must equal the owned lease. L2 HEAD/tree and changed_paths
must equal its requested candidate. L1 observed changes must remain in its grant.

Proofs pin the complete intent snapshot and verifier name/OID and credential
provenance. No arbitrary JSON field such as approved or PASS confers authority.
Bound observation freshness by existing operator policy. Revalidate verifier
identity, privileges and capabilities at consumption, not merely at attestation.
Use existing materialization advisory-lock order before row locks; consume exactly
once. A duplicate nonce with different payload denies; identical pending request
may resolve to the same pending intent. Consumed/expired intents cannot reissue.

## Independent stage observer

Add admission_materialization.py reusing safe Git/remote/dependency primitives.
Keep protected ancestry, canonical path/UID/host/common-directory/origin identity,
no-filter/no-hook Git invocation, output/time bounds, and repeated local/remote
observations. Never execute repository test commands or attributes as the verifier.

L1 supports baseline-descendant local commits and in-scope staged, dirty, added
or deleted regular files. Reject symlinks, submodules, path escapes, unexpected
file modes and out-of-scope changes, including ignored/untracked files.
L2 requires a clean candidate checkout; HEAD and tree equal the request.
Require baseline ancestry and collect changed paths for every introduced commit
against every parent, without rename collapsing, including merge commits and
changes later reverted. Require the remote source still at the expected baseline
and remote target still at its bound base. Authentication/network errors and 404
do not establish an authorized absent ref. Observe directory identity and remote
refs twice around dependency inspection. Return only exact server-bound fields.

## Protected client and operation boundary

Add scoped_admission.py and bin/codestra-admission.
Builder operations request/consume/inspect use the protected lease-builder.dsn.
Verifier operation verify uses existing independently provisioned verifier
configuration and read-only GitHub App custody. Builders cannot load verifier
credentials or pass raw observations through the CLI.

Default rollback: result usable=false, authority=NONE_DRY_RUN and no admission
receipt. Committed consume may return usable=true only for its exact operation,
paths, mutation/candidate, binding, grant revision, lease ID/epoch and expiry.
Inspect always returns usable=false even when current authority is still valid.
A commit error after consumption reports OUTCOME_UNKNOWN; inspect the same
intent, never auto-request/reverify/reconsume or execute a second effect.

This API grants an online scoped authorization; it is not an OS filesystem
fence or a Git push broker. A trusted effect consumer must bind exact payload,
recheck online authority at the operation boundary and execute at most once.
Database commit, filesystem mutation and GitHub ref update are not atomic.
An uncertain/partial external outcome remains consumed and needs reconciliation.
The source CLI executes no write, push, merge or provider effect itself.

## Verification

Use test-first real disposable PostgreSQL 16 with TLS/SCRAM identities for the
authorization API, including positive L1/L2 decisions, cross-stage isolation,
restricted principal/OID identity, trust+TLS rejection, revoked assignments,
verifier/grant/dependency/epoch changes, payload substitution, freshness, one-use
consumption, rollback and concurrent consumption.

Use real temporary Git repositories for stage observation: in-scope edit,
out-of-scope edit, dirty L2, wrong candidate tree/ancestry, rename/delete paths,
out-of-scope commits later reverted, moved remote/base, absence/errors,
directory replacement, symlinks/submodules and hostile filters.

Test protected CLI dry-run and uncertain commit handling without live credentials.
Run affected tests, then both normal and python3 -S full suites and diff checks.
Disposable fixture services and synthetic observations are validation, never
production admission or certification. Publish an ordinary source draft PR;
deployment and live grants remain a separately accepted phase.
