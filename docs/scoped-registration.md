# Scoped registration: source-only operator interface

This patch adds `005-scoped-registration.sql` and `bin/codestra-register`. It is
not installed. No live roles, grants, assignments, registrations, leases or
services were changed. Keep PRODUCTION_GO=NO, LIVE_CAPABILITIES_ENABLED=NO and
EXTERNAL_EFFECTS=false.

## Boundary

PostgreSQL `session_user` identifies the authenticated connection. `current_user`
inside the SECURITY DEFINER function identifies its owner and is deliberately not
used as the caller. `SET ROLE` cannot impersonate another login. No `--owner`
option exists. Superuser, role-administrator and RLS-bypass sessions are rejected. Operator-managed
principal records bind the role name to its PostgreSQL OID, preventing a dropped
and recreated login from inheriting old grants; inactive principals are denied. A shared login identifies only
that shared account; provision distinct restricted principals before use.

An explicit operator-owned grant binds principal, product, capability and exact
repository. The capabilities are `product`, `workstation`, and `candidate`.
Candidate registration additionally requires an exact operator-created task
assignment. No grants or assignments are automatically created by the migration.
The schema, function owner, role membership and PostgreSQL authentication policy
must remain under independent operator control. Production authentication must
authenticate distinct principals; permissive trust authentication is only used in
the socket-only disposable fixtures, not as an accepted production identity policy.

Registration records **declared** refs/SHAs and provenance, not observed Git
truth. It always returns `authority=false` and `ready=false`. Empty prerequisites
cannot grant readiness. Nonempty prerequisites require exact same-product
CERTIFIED scope/commit matches, but historical certificate rows do not become
trusted attestations. An authenticated certificate/lease adapter must still
observe Git and enforce prerequisites, owned leases and review before readiness.

The legacy `codestra-devctl register --root`, claim/evidence/certification commands
and privileged direct SQL writers remain separate historical interfaces. Do not
expose those writers or grant direct public-table DML to the new runtime roles.
This patch does not claim to secure privileged legacy mutation paths or integrate
atomic candidates with the publisher/promotion checker. A shared lane table makes cross-kind uniqueness of declared path strings transactional.
The approved 43-repository
publisher coverage and Keycloak exact-SHA/expiry policy are unchanged.

## Operator provisioning (examples, not executed)

First review/apply the forward migration on a disposable compatibility copy. The
operator must choose an accepted separate schema/function owner with access to
required public tables. Runtime principals must not own that schema, inherit its
owner, have CREATE on it, administer grants/assignments, or have privileged role
membership. The installation administrator is outside the application boundary.

The following are **templates** requiring actual operator-approved identities and
accepted product/section mappings; they do not prescribe real assignments:

```sql
-- Independent administrator, after reviewed migration under the chosen owner:
CREATE ROLE registration_runtime NOLOGIN;
GRANT USAGE ON SCHEMA scoped_registration TO registration_runtime;
GRANT EXECUTE ON FUNCTION scoped_registration.register(text,jsonb,text,text)
  TO registration_runtime;
-- Provision login/authentication separately; never use a shared superuser login.
GRANT registration_runtime TO approved_login;
INSERT INTO scoped_registration.principals(principal,role_oid)
 SELECT rolname,oid FROM pg_roles WHERE rolname='approved_login';
INSERT INTO scoped_registration.grants(principal,product,capability,repository)
 VALUES ('approved_login','Example','product','appolon1908/Example'),
        ('approved_login','Example','workstation','appolon1908/Example'),
        ('approved_login','Example','candidate','appolon1908/Example');
-- Only after authorized product/workstation registration:
INSERT INTO scoped_registration.task_assignments
 (product,workstation_id,task_id,principal)
 VALUES ('Example','Example-ws','Example-task','approved_login');
```

Assignments can be revoked with `active=false` without deleting binding/audit
history. Repeated requests revalidate current grants and assignments.

No workstation/atomic binding is overwritten. A matching legacy row may be
adopted with the corresponding product-scoped capability and, for candidates,
the exact task assignment; a conflicting tuple is rejected. Adoption
retains existing status, lease, gates and dependencies without asserting they are
trusted. Existing task IDs and workstation IDs remain globally unique to match
the legacy schema. New request IDs are scoped by product and authenticated login.

Product manifests contain exactly `product`, `repository`, `test_branch`,
`promotion_chain`. The chain may retain its accepted `test` or `testing` spelling
independently of the registered test ref; both must match existing metadata exactly
when adopting a legacy product. No normalization is performed. Workstations contain exactly `product`, `workstation_id`,
`section`, `subsection`, `branch`, `parent_branch`, `worktree`, `order_index`.
Candidate manifests contain exactly `product`, `workstation_id`, `task_id`,
`title`, `branch`, `target_branch`, `worktree`, `head_sha`, `base_sha`,
`prerequisites`. Each prerequisite has exactly `product`, `scope_type`,
`scope_name`, `sha`. Product/section metadata must already be accepted before a
workstation; task assignment must already exist before a candidate. Atomic lane
names are `atomic/<section>--<subsection>--<task-key>` and target the registered
`subsection/<section>--<subsection>` lane. Worktrees are absolute normalized
metadata paths; existence/symlink/Git identity verification belongs to the trusted
materialization adapter, not this metadata-only interface.

## Commands (operator use only, not run against live state)

Supply a connection through `CODESTRA_REGISTRATION_DSN` using independently
provisioned credentials or PostgreSQL passfile/service configuration. No default
live database is selected. Do not put credentials in command arguments or reports.

```bash
bin/codestra-register product --manifest product.json --request-id product-001
bin/codestra-register workstation --manifest workstation.json --request-id ws-001
bin/codestra-register candidate --manifest candidate.json --request-id candidate-001
# Explicit --apply commits metadata after operator review; omitted means rollback.
```

Dry-run validates and rolls back all changes and audit inserts. Apply writes one
transaction; identical same-request retries produce one audit row. A new request
for unchanged metadata is independently audited. Changed request payload/digest,
conflicting lanes, repository mismatch or revoked grants fail closed. Raw manifest
SHA256 is recorded as caller provenance; it is not a signature or independent
source approval. PostgreSQL diagnostics can include sensitive connection data, so
the CLI emits generic failure codes and never echoes the DSN.

## Tests and rollback

`python3 -m unittest discover -s tests -v` includes real SQL tests using a fresh
PostgreSQL 16 cluster under `/tmp`, socket-only, with fixture identities and no
caller DSN. PostgreSQL 16 binaries and psycopg2 are required; tests report a skip
if the binaries are absent in an ad hoc local run. Both CI workflows explicitly
require PostgreSQL 16 binaries and install the hash-pinned driver from
`requirements-ci.txt` into an isolated directory exposed through `PYTHONPATH`,
including under `python3 -S`. Missing prerequisites fail CI before the suite; all
20 SQL/CLI tests must execute. No installed database is modified. The source has no
schema definition for the installed legacy `scope_certifications` table; tests
construct its relevant contract explicitly. Deployments lacking it cannot validate
nonempty prerequisites and must stop for reviewed schema compatibility work.

Rollback begins by revoking runtime EXECUTE/USAGE and stopping new callers through
the accepted operator process. Preserve audit and binding tables for investigation;
do not automatically DROP CASCADE or delete legacy metadata. Dry-run/failed
transaction rollback is tested, including no orphan atomic task after conflict.
Whole-schema archival/removal is an operator migration after proving no consumers;
this patch deliberately provides no destructive down migration.

Actual installation, login provisioning, product grants, task assignments,
authenticated certification/lease integration, current-SHA checks/review,
repository protection and every promotion step remain operator prerequisites.

The source-preparation branch recorded in governance is not a registered runtime
candidate and is not required to match the runtime atomic branch grammar. Its
registration, lease and certification remain null; never infer a live binding
from a source-preparation branch label.
