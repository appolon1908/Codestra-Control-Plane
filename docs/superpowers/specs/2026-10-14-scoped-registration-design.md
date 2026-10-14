# Scoped registration and authenticated candidate binding

Source preparation only. PRODUCTION_GO=NO, LIVE_CAPABILITIES_ENABLED=NO,
EXTERNAL_EFFECTS=false. No installation, live migration, role/grant provisioning,
registration, lease claim, certification or promotion is authorized by this design.

## Intent and selected trust boundary

Provide reusable product/workstation and atomic candidate registration across
approved products. The operator selected authenticated PostgreSQL session identity
and explicit operator-managed product grants on 2026-10-14. Display labels and
legacy owner strings never authenticate a caller. Never backfill historical
ownership or certificates. Registration records identity and source provenance;
it grants no lease, prerequisite exemption, certification or publishing authority.

Use session_user, never current_user, caller JSON, --owner, SET ROLE or a custom
session setting as authentication. Explicit grants bind a login role to one exact
product and capability (product, workstation, candidate).
Principal records pin role name and PostgreSQL role OID and support explicit
revocation; recreated names receive no old authority. A separately administered per-task assignment binds an exact principal, product,
workstation and task. Candidate registration requires both the capability and task
assignment. Reject superuser session identities and non-login roles. The operator
must provision distinct non-superuser logins; a shared login identifies only that
shared account. Role lifecycle and credentials remain outside this patch.

## Interface and storage

Add a forward migration with a dedicated schema, tables and SECURITY DEFINER
registration functions with a fixed pg_catalog search path and qualified object
references. Revoke PUBLIC function execution; only an explicitly granted runtime
role may invoke the functions. Runtime has no direct DML on protected identity,
grant, assignment, binding or audit tables. An operator installs migration under a
separate schema owner. Existing privileged legacy writers remain outside this new
boundary and cannot serve as authenticated adapters.

Keep existing public tables compatible. New product registration validates an
exact product/repository/test-ref/promotion-chain tuple. Workstation registration
requires an existing matching product and section, and stores a subsection branch,
parent section branch and subsection worktree independently of atomic candidates.
Existing exact rows may be adopted only with operator authorization; conflicting
rows are rejected, never overwritten. Do not retrofit foreign keys onto dirty
legacy rows or reinterpret legacy JSON dependencies as trusted prerequisites.

New candidate bindings use composite keys and foreign keys across product,
workstation and task assignment. Store exact repository, atomic branch, subsection
target, absolute atomic worktree, nonzero 40-character head/base SHA, principal,
manifest digest and request ID. Atomic worktree/branch must differ from the
subsection worktree/branch. A shared subsection/atomic lane table with unique product/branch and global worktree constraints
prevent duplicate declared lane path strings. Filesystem realpath, symlink and
Git identity verification remains a trusted materialization-adapter prerequisite. Cross-product workstation, task, prerequisites
or target bindings are rejected. Branch names are validated, not treated as grants.

Registration uses one transaction and row locks/unique constraints. Identical
retries return the existing immutable record; changed payloads for an existing
request ID or identity conflict fail. Audit records include session identity,
request ID, manifest digest and complete registration binding; retries do not
create duplicate registration events. Dry-run performs validation in a transaction
that always rolls back. No function creates certificates or updates lease/status
fields. An empty prerequisite list permits only metadata registration, never
candidate readiness or authority. Prerequisite readiness belongs to the existing
certification/lease adapter and remains denied until that adapter is authenticated.

CLI uses the selected database connection and parameterized function calls, with
strict JSON input validation and a dry-run option. Never accepts an owner argument.
No automatic trusted loader integration with publisher/checker or legacy devctl
claim is included: those require separate accepted adapter work. Documentation
must say explicitly that the new registration interface does not close legacy
privileged mutation paths or authorize atomic promotion.

## Verification and compatibility

Use an isolated PostgreSQL cluster under a temporary directory, Unix socket only,
with no connection to the installed server. Test fresh migration, existing modern
schema compatibility, repeated migration, rollback, non-superuser authentication,
SET ROLE spoof rejection, missing/revoked/wrong-product grants, task mismatch,
foreign keys, immutable conflicts, dry-run, audit provenance and idempotent retries.
Exercise duplicate registration using independent concurrent connections, including
same identifiers across products. Run existing offline unittest suite. Keep live
schema and mapping observations outside source control.

## Rollback and acceptance

No automatic down migration deletes audit/binding history. Disable function access
first; archive new schema under operator control only after proving no consumers.
Legacy product/workstation metadata is not deleted or restored from fabricated
history. A rollback rehearsal on disposable data must verify existing rows remain.

Operator prerequisites: accepted schema owner and runtime roles, distinct login
principals, exact product capability grants, task assignments, accepted product
mappings and section metadata, authenticated prerequisite/certification adapter,
actual owned lease, current-SHA CI/review/protection and governed promotion.
The source PR targets subsection/cp-01-foundation--02-trusted-decisions. Missing
acceptance gates block promotion through section and environments to main.
