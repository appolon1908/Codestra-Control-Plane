# Frozen recovery: operational-adoption handoff

This is a source documentation handoff for PR36, not an accepted runtime-adoption
record, an operator admission, a recovery grant, or permission to execute recovery.
It does not supply operational identities or make any protected configuration.
Keep the accepted operational record and its supporting evidence outside Git.

## Source provenance is not runtime acceptance

PR36 added the executable recovery client and version2 SQL API. Its original
source commit is `848888c609708add985b4c55a35380a68c805118`; the recorded merge
commit is `8824a5cac48c0cabcfd72c07c1837648d133e7e5`. Its reported 387-test source
results belong to that source, not a later release or a deployed database.
Source review and test evidence must be refreshed for the selected release.

The source assignment in
[task-frozen-recovery-executor.json](../governance/source-preparation/task-frozen-recovery-executor.json)
identifies implementation ownership only. It does not appoint a runtime operator,
reviewer, verifier or executor. A merge, named GitHub reviewer, same-host account,
fixture identity or filled template cannot establish independent credential custody.
See the [recovery contract](frozen-recovery-executor.md) for the actual behavior.

## Accepted reference register: private operator record

The accountable operator must retain an accepted, versioned adoption record bound
to the intended host, exact database/cluster and released source. Share only its
non-secret record ID, version/digest and acceptance references in the handoff.
No accepted IDs are supplied by this documentation update. Missing or unverified
references remain unresolved; this table must not be imported as authority.

| Required record | Binding and evidence to obtain independently |
| --- | --- |
| Runtime-adoption acceptance | Approved release SHA and artifact/manifest digests, exact host/database/cluster, authorized installation and rollback scope, maintenance window with timezone, accountable acceptance and validity/revocation reference. |
| Installed-code and migration receipt | Verified immutable executable/import/interpreter/dependency custody; reviewed target compatibility and installation receipts for the required schema chain, including 005, 007 and 008. A source SQL file is not a deployed migration. |
| Authentication, TLS and recovery readiness | Accepted credential-custody references, actual SCRAM/session/OID checks, verified CA/server identity, affected-client policy, private backup/tested-restore record and maintained independent recovery access. |
| Four-role identity/capability register | Distinct authenticated operator, reviewer, verifier and executor principals, exact PostgreSQL role OIDs, current product capabilities, validity/revocation and independently controlled credential-custody receipts. |
| Incident authorization | Current server-owned incident UUID/revision, exact frozen workstation snapshot, accepted policy, repaired registered subsection checkout and independently authorized grant/digest. |
| Review and verification evidence | Independent authenticated review of the server digest, verifier observation/proof tied to that grant, current refs and checkout, and unexpired evidence at execution. |
| Execution and reconciliation receipt | Exact executor/request/grant/proof bindings, committed audit/readback or explicit non-commit/uncertain disposition; an uncertain response is reconciled through authenticated lookup, not by replaying recovery. |

Do not populate a missing record by copying a legacy PASS row, generating test
identities, treating Ralph's nomination as accepted custody, or reusing a source
agent's name as an authenticated runtime identity. Adoption of executable code
and authorization of a particular recovery incident are separate decisions.

## Four independently controlled roles and fixed configuration interfaces

The names below are fixed paths read by
[recovery_interface.py](../lib/codestra_control/recovery_interface.py), not evidence
that the files exist or have approved contents. Absence or unsafe custody denies
use. Confirm current target presence and acceptance through the authorized
operator; a historical absence report is not a fresh target inspection.

| Role | Source-defined interface | Required operational reference |
| --- | --- | --- |
| Operator | `/etc/codestra/control-plane/recovery-operator.dsn` | Accepted operator principal/OID, product authorization and independent custody; authorizes or revokes the exact grant. |
| Reviewer | `/etc/codestra/control-plane/recovery-reviewer.dsn` | A different accepted reviewer principal/OID and custody; reviews the exact server-generated grant digest. |
| Verifier | `/etc/codestra/control-plane/recovery-verifier.toml` | A different verifier principal/OID, separate accepted read-only GitHub App/installation and independent credential/signing custody. |
| Executor | `/etc/codestra/control-plane/recovery-executor.dsn` | A different executor principal/OID and custody; executes only the reviewed, verified grant or performs authenticated historical lookup. |

The verifier TOML has exactly `database_dsn_file`, `app_id`, `installation_id` and
`app_key_file`. These field names are not operational values. Its referenced DSN
and key are additional protected dependencies; four top-level files alone do not
constitute complete provisioning or accepted custody. Share neither DSN contents
nor passwords, passfile contents, private keys, tokens or fixture credentials.
The existing protected-file and connection checks remain unchanged.

## Controlled continuation after acceptance

First establish the independently accepted runtime and authentication/custody
records, approved installation/rollback and current product capabilities. The
migration's installation can initialize incident records; do not manufacture an
incident UUID, carry a pre-install grant across that change, or silently adopt a
legacy frozen row as a new authenticated assignment.

For one authorized incident, the operator obtains a grant over the exact current
frozen snapshot and repaired canonical subsection checkout. A separate reviewer
reviews its digest; the separate verifier independently observes the checkout and
refs and submits the bounded proof. Only the separately authorized executor may
apply that current grant/proof. The CLI's explicit apply flag is a technical
commit switch, never approval in itself. Default dry-run results grant no authority.

An ACTIVE modern assignment lease blocks this recovery operation. Use only the
existing separately authorized revocation process when applicable; do not delete,
release or replace an active lease merely to make recovery pass. Recheck grant,
proof, policy, incident revision and identity at the effect boundary.

The only action is `RELEASE_STALE_WORKTREE_TO_FREE`. Successful recovery releases
that exact stale-dirty frozen lane while preserving source and certification
history. It does not implement missing product code, fix a PR conflict, grant a
new task lease, issue certification, create protected refs, publish controller
success, merge a PR or activate production. Those remain separate governed steps.
Preserve `PRODUCTION_GO=NO`, `LIVE_CAPABILITIES_ENABLED=NO`, `EXTERNAL_EFFECTS=false`.

This handoff contains no installer, executable recovery command, schema mutation,
credential value, operational acceptance receipt or automatic rollback/retry.
For publisher-specific adoption, use the separate
[publisher operational-acceptance guide](publisher-operational-acceptance.md).
