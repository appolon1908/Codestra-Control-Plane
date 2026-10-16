# Controller coordinator source contract

The coordinator connects approved task mappings, candidate registration and the
existing assignment-backed lease issuer. It issues atomic-task admission only
as a committed ACTIVE online database lease. Certification and promotion
authorization remain false. This source change does not install migrations,
provision identities or grants, register live tasks, deploy services, push product
branches, or publish successful GitHub checks.

## Authority and registration

`009-controller-coordinator.sql` follows migrations 005 and 007. It adds no roles,
grants or populated authority records. An operator must separately accept and
provision the existing product/workstation registrations, section, principal
role OIDs, task assignment, candidate capability, canonical binding, lease policy,
independent verifier and dependency capabilities. Bindings already depend on
registered products/workstations; the coordinator cannot invent missing ones.

The operator-owned `assignment_leases.coordinator_tasks` row pins the task title
and complete prerequisite inventory to an approved binding. It defaults inactive.
An empty inventory is explicit; missing, duplicated, revoked, expired or extra
dependency rows deny resolution. Legacy scope `CERTIFIED` values satisfy only
the registration metadata check. The independent verifier still checks actual
online issuer/check/capability evidence with `GitMaterializer`.

`resolve_task(task, repository)` authenticates the credential-backed TLS session
and registered role OID, requires exact repository spelling and approved ownership,
and validates policy, hierarchy, product/workstation metadata and lane health.
Candidate fields come from the approved binding and task row, never a supplied
manifest. Existing candidate metadata must match exactly. Frozen/blocked lanes
remain blocked. Resolution locks in the issuer's workstation/worktree order and
rechecks the binding after locking; registration and final admission revalidate
current authority in their own transactions.

The operator may grant only schema usage and EXECUTE on `resolve_task(text,text)`,
`lookup_task(text,text,text)` and `admit_task(text,text,text,uuid)` to the restricted
builder role, plus the existing scoped candidate registration API. No runtime
table DML, broad owner memberships or verifier capability is needed. All new
functions and tables deny PUBLIC access. Runtime installation and grants require
separate acceptance; these are interface requirements, not a deployment recipe.

## Prepare, verify, admit

The source CLI uses only the protected builder DSN at
`/etc/codestra/control-plane/lease-builder.dsn`. It requires verified TLS and
protected code/config custody. It has no environment DSN fallback, agent-name
authentication or verifier credential access. The Python API owns transactions
on an idle, non-autocommit builder connection. Omitting `--apply` rolls back and
returns `usable=false`, `authority=NONE_DRY_RUN`, with no lease receipt.

After separately accepted runtime provisioning, the three stages are:

```sh
codestra-coordinate prepare --task TASK --repository OWNER/REPO --request-id REQUEST --apply
# In the independent verifier process/custody, using the returned binding ID:
codestra-lease verify --binding BINDING_UUID --apply
# Back under the assigned builder identity, using the committed verifier proof:
codestra-coordinate admit --task TASK --repository OWNER/REPO --request-id REQUEST --proof PROOF_UUID --apply
```

Preparation commits idempotent candidate registration and returns
`AWAITING_VERIFICATION`, never admission. The independent verifier describes the
server binding, finishes its read transaction, observes the actual checkout,
canonical remote repository/numeric ID, source and target refs/SHAs, clean Git
state, host/UID/directory identity and accepted dependencies, then commits a
short-lived proof using its separate identity. The source branch must already
exist remotely. No bootstrap exception is introduced.

The proof insert trigger records PostgreSQL 16 credential authentication
provenance. TLS with trust authentication is rejected. Pre-migration proofs with
unknown provenance cannot admit tasks. A UUID alone, uncommitted proof, builder
self-attestation, local PASS, stale verifier grant or replaced dependency receipt
cannot satisfy admission. The server issuer rechecks current authority, consumes
the proof once, advances the epoch and atomically records ownership and audit.

Admission returns `state=ADMITTED`, `usable=true` and the committed issuer receipt.
Receipts contain exact binding/ref/SHA/materialization, principal, epoch and expiry.
They remain time-bounded observations; consumers must check current online lease
state before work or publication. Admission authorizes neither certification nor
promotion and does not satisfy GitHub's required control-plane status by itself.

## Recovery and revocation

Keep the original request ID after a lost response:

```sh
codestra-coordinate recover --task TASK --repository OWNER/REPO --request-id REQUEST --apply
```

Recovery only looks up the existing authenticated request and verifies its exact
current mapping, lease, verifier, database dependency capabilities and previously
observed receipt bindings. It does not query GitHub again. Changes to remote
dependency receipts become visible on the next independent materialization,
subject to the proof and lease lifetime bounds. Recovery never registers,
attests, claims or renews. Repeated admission returns that same valid receipt;
only the server's exact `REQUEST_NOT_FOUND` permits an initial claim attempt.
Consumed, revoked or expired requests remain denials. A commit failure after a
claim reports `ADMISSION_OUTCOME_UNKNOWN_USE_RECOVER`; it never automatically
reattests, releases, generates another request ID or claims again.

Disabling `coordinator_tasks.active` blocks new coordinator admission and recovery.
It is admission policy, not global lease revocation. To invalidate an already
issued lease for existing consumers, use the established operator binding
revocation API. Existing issuer lifecycle and frozen-recovery rules still apply.

## Source validation

The coordinator tests use disposable PostgreSQL 16, synthetic SCRAM identities
and a temporary TLS certificate. They exercise real SQL registration, independent
proofs, rollback, mapping/dependency isolation, revoked verifiers, request recovery,
commit-response loss and concurrent claims/revocation. The existing materializer
suite covers actual temporary Git checkouts and controlled remote observations.
Neither suite connects to the installed control plane or publishes statuses.

```sh
PYTHONPATH=lib python3 -m unittest discover -s tests -v
```
