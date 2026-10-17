# Scoped L1/L2 admission source contract

The coordinator's ACTIVE lease establishes an authenticated task and immutable
starting binding. The new `scoped_admission` API separately authorizes one exact
L1 source mutation or one exact L2 candidate push. Neither a task assignment nor
an L1 receipt grants L2 authority. This implementation is source preparation;
it installs nothing and grants no live Builder access.

`010-scoped-operation-admission.sql` follows migrations 005, 007 and 009. It adds
protected grant, intent, proof and audit records, with PUBLIC access revoked.
It creates no roles, EXECUTE grants, mappings, assignments or active scopes.
Runtime installation, authentication, credential custody, recovery procedures
and operator acceptance remain separate prerequisites.

## Accepted scope and current authority

The operator-owned grant binds one existing coordinator binding to L1 or L2,
an exact nonempty sorted list of file paths and an explicit expiry. Grants start
inactive. Paths use ASCII letters, digits, `_`, `-` and `.` within slash-separated
components; absolute paths, empty/dot/dotdot/`.git` components, globs and backslashes
are rejected. Updating a grant always advances its revision, including revoke
and re-enable. Deleting a grant cannot erase its authorization history.

Each request snapshots its grant revision, coordinator mapping, current lease
and dependency inventory. The original baseline head and target base stay fixed.
Expiry is bounded by the accepted grant, lease and existing attestation policy.
Request, attestation and consumption recheck current role OID, assignment,
mapping, epoch, grant, lease, dependency capabilities and verifier authority.
Frozen or blocked lanes remain blocked. A changed snapshot requires a new
independently verified request; renewal does not revive an old proof.

This source profile requires PostgreSQL 16, verified TLS and SCRAM authentication
whose `system_user` exactly identifies `session_user`. A trust connection, role
switch, administrative membership, schema ownership or authority-table DML
cannot substitute for a restricted authenticated identity. Membership checks
include roles that can be assumed without inheriting their privileges, and
exclude server-file/program access and schema CREATE authority. The verifier has a
separate registered identity and current `attest` and `read` capabilities.
Credential-authentication provenance is checked for both the baseline lease proof
and the operation proof.

Baseline binding and dependency comparisons retain every field. Their known
expiry timestamps are compared as instants, so different session timezones do
not invalidate an unchanged lease. Original lease and proof snapshots remain
untouched; changing another field still denies authorization.

## Exact request payloads

L1 binds the requested file list and the SHA-256 digest of the intended mutation:

```json
{"paths":["src/one.py"],"mutation_sha256":"<64 lowercase nonzero hex digits>"}
```

L2 binds the exact candidate commit and tree, existing source-ref SHA and target
base SHA, plus every changed path introduced by the candidate history:

```json
{
  "paths":["src/one.py"],
  "candidate_sha":"<40 lowercase nonzero hex digits>",
  "candidate_tree_sha":"<40 lowercase nonzero hex digits>",
  "expected_remote_sha":"<registered baseline head>",
  "target_base_sha":"<registered target base>"
}
```

These are request data, not authority records. Extra fields are rejected. L2
supports an existing registered atomic source ref, a fast-forward candidate and
the registered subsection target. A missing source ref denies admission; this
version provides no branch bootstrap exception. PR creation, merging,
certification, deployment and provider effects are outside these operations.

## Independent observations

`StageMaterializer` observes the assigned host, worktree owner, common Git
directory, branch, canonical origin and the lease's device/inode identity. L1
allows regular in-scope working changes and baseline-descendant commits. L2
requires the exact candidate head/tree and a clean checkout. Both inspect actual
file and index contents, including ignored and untracked files; symlinks,
submodules, conflicted entries, repository filters, shallow history and grafts
deny observation. Existing baseline materialization checks are preserved.

The shared Git reader disables transport execution, lazy fetching and commit-graph
use. Both observers reject partial/promisor and alternate object stores and run
a bounded full object-integrity check, including packed objects. This prevents
local object bytes from masquerading as the requested commit/tree merely by using
its filename. Repository skip-list settings cannot omit this integrity check.

Path scope includes all introduced commits against every parent, rename/delete
endpoints and changes subsequently reverted. A matching net diff alone cannot
satisfy scope. Local state and current remote source/target refs are read again
around the independent dependency checks. Missing refs, failed authentication,
network errors or changed receipts deny verification.

Dependencies use the existing read-only GitHub App observer and accepted issuer,
repository, exact SHA, check and capability bindings. Database snapshots cannot
replace these remote observations. Remote observations have a bounded freshness
window; they are not continuous remote monitoring.

## Protected client and one-use consumption

`bin/codestra-admission` exposes `request`, `verify`, `consume` and `inspect`.
Omitting `--apply` rolls back changes and returns `usable=false`,
`authority=NONE_DRY_RUN`, with no proof or receipt. The Python API requires an idle
non-autocommit connection and owns its transaction.

After separately accepted runtime provisioning, the intended sequence is:

```sh
codestra-admission request --grant GRANT_UUID --lease LEASE_UUID --epoch EPOCH --manifest REQUEST_JSON --request-id REQUEST_ID --apply
# Separate verifier process and credential custody:
codestra-admission verify --intent INTENT_UUID --apply
# Original authenticated Builder, using the committed independent proof:
codestra-admission consume --intent INTENT_UUID --proof PROOF_UUID --apply
```

Builder commands use only `/etc/codestra/control-plane/lease-builder.dsn`.
Verification uses the separate protected `lease-verifier.toml`, verifier DSN and
read-only GitHub App key. Environment DSNs, caller observations and agent-name
strings cannot select authority. Protected code custody includes the new client,
materializer and executable.

Consumption atomically records the one-use outcome and audit under current
authority. The client exposes `ONLINE_SCOPED_OPERATION_RECEIPT` and `usable=true`
only after the transaction commits. A consumed intent/proof cannot be reused.
An identical pending request ID may resolve the same pending intent; changing
the payload or replaying a consumed/expired request denies.

A lost consumption commit response returns
`ADMISSION_OUTCOME_UNKNOWN_USE_INSPECT`. The client never retries consumption,
generates a replacement request or repeats the effect. Inspect the same intent:

```sh
codestra-admission inspect --intent INTENT_UUID --apply
```

Inspection reports the stored outcome with `usable=false`; it does not issue
another permission.

## Effect-consumer boundary

This API performs no product filesystem writes or Git pushes. A trusted effect
consumer must bind the exact mutation digest or candidate/tree/ref payload,
recheck current online authority at its execution boundary, enforce the admitted
paths and perform the effect at most once. L1's digest does not itself verify or
apply mutation bytes. The source client is not an operating-system write fence
or a Git credential broker.

A PostgreSQL transaction cannot make a filesystem mutation or GitHub push
atomic. State can change after observation or consumption. Partial or uncertain
external outcomes require reconciliation while the intent stays consumed. Never
turn an inspection or historical receipt into permission to repeat an effect.

This source change supplies no accepted admission for `frontend_repairs`, issue
#47 or another product task. Genuine runtime admission still requires separately
accepted installation, authenticated principals, mapping, dependencies and
operator scope grants. `PRODUCTION_GO=NO`, `LIVE_CAPABILITIES_ENABLED=NO` and
`EXTERNAL_EFFECTS=false` remain in force.

## Source validation

The tests use disposable PostgreSQL 16 with synthetic SCRAM identities and a
temporary TLS certificate, and real temporary Git repositories with controlled
remote observations. SQL authorization is exercised through separate actual
Builder/verifier sessions. Client transport doubles test rollback, credential
selection and commit-response loss; they do not stand in for authorization.
Nothing connects to the installed controller database or publishes statuses.

```sh
TMPDIR=/dev/shm python3 -m unittest discover -s tests -v
TMPDIR=/dev/shm PYTHONPATH=/usr/lib/python3/dist-packages python3 -S -m unittest discover -s tests -v
```

Test modules bootstrap the repository library independently of discovery order.
The second command explicitly exposes the installed psycopg2 dependency while
skipping Python site initialization. Adjust that dependency path for another
distribution. The temporary-memory directory is an optional test-fixture location; it is not
a production durability setting. Validation results are recorded with the source
PR and do not certify deployment or grant runtime permissions.
