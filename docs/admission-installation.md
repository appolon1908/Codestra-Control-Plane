# Admission installation source

This is source preparation under CP-BOOTSTRAP-SOURCE-01 revision 2. No live
installation, credentials, grants, assignments, leases, certification or activation
are authorized. The CLI implements preflight, read-only planning, installation,
independent verification and revoke-first rollback. Operational commands require
separately accepted, preprovisioned protected configuration and authenticated
connections; absent inputs fail closed. Request JSON, approval booleans and owner
strings cannot supply authority. Nothing in this source provisions that setup.

## Candidate and bounded database plan

`SourceCandidate.load` consumes an independently pinned manifest digest. It
captures regular-file bytes, modes, sizes and hashes without following symlinks,
validates import closure, fixed proposed destinations, both component manifests
and the pinned driver. Source proposals retain operational flags as false.
The complete controller package is an inventory, not a migration selection.

The installer selects exactly nine admission sources:

- `schema.sql`, `002-hierarchy-promotion.sql`, `005-scoped-registration.sql`;
- `007-assignment-leases.sql`, `009-atomic-inspection.sql`;
- `009-controller-coordinator.sql`, `010-controller-coordinator-integration.sql`;
- `010-scoped-operation-admission.sql`, `015-admission-installation-state.sql`.

Readiness, family programs, publisher authority, frozen recovery and certifier
schemas are not implicitly applied. Existing unrelated components/version records
are bound and preserved. An expanded selection is rejected.

`build_plan` requires explicit legacy adoption, PostgreSQL 16 and existing public
contracts, including `scope_certifications` columns and a validated, nondeferrable
primary key. Exact observed nullability, defaults and other constraints are review
inputs; no certification rows are fabricated. Catalog fingerprints bind numeric
object/role identities, ownership/ACLs, columns, constraints, functions, indexes,
triggers, views, RLS flags and policies. Coordinator 009/010 are distinguished by
actual function bodies, signatures and settings. Ledger enforcement has its own
fingerprint, bound into immutable attempt history and private receipts.
Before a new attempt, the installer reconstructs the complete plan from fresh
observations under its fences. Hash-consistent false adoption claims cannot skip
missing migrations, even when an external authority admitted that malformed plan.

## Durable engine and authority

The source API provides `build_plan`, `install`, `verify` and `rollback`. Its trusted
online `Authority` must independently accept the exact operation, plan, source,
target cluster/database, authenticated session role/OID, filesystem custody,
configuration digest, current expiry and revocation. Unavailable authority denies
execution. A lease from the uninstalled runtime is not a source-bootstrap input.

### Concrete CLI and independent issuer

The executable uses isolated `/usr/bin/python3 -I`, disables bytecode writes and
checks the complete pinned library inventory before any privileged project
import. Extra importable files, cached bytecode and symlinks are rejected. The
entrypoint and interpreter themselves still require externally accepted custody.
The running client must itself be CPython3.12 at the pinned system interpreter
(the executable image is checked through `/proc/self/exe`), outside a virtual
environment, with exactly the accepted import path order plus the protected
candidate `lib` prefix. A fresh-child probe does not establish parent custody.
Already-loaded driver modules must resolve to pinned wheel package/extension
paths; those origins are checked before and after import, before reading connection
credentials, and again at issuer custody boundaries.
The operational path requires native
root, a protected root-owned candidate (all manifest bytes/modes checked), the
fixed journal, and this separately provisioned root:root `0600` configuration:
`/etc/codestra/control-plane/admission-installer.toml`. It has exactly `schema`
(`codestra.admission-installer-config.v1`) and an `issuer` table. The latter pins
the issuer `identity`, complete user-schema `catalog_sha256`, and `grant_id` UUID.
Identity has `system_identifier`, `database_oid`, `database_name`, `session_user`
and `role_oid`; names/identifiers and positive numeric OIDs must match live reads.
Planning does not contact the issuer; its table may remain empty while preparing
the non-authorizing plan. Other operations require every issuer pin.

Credential references are fixed, never selected by arguments or environment:

- Operator: `/etc/codestra/control-plane/credentials/admission-operator.dsn`.
- Independent verifier: `/etc/codestra/control-plane/credentials/lease-verifier.dsn`.
- Issuer client: `/etc/codestra/control-plane/credentials/admission-issuer.dsn`.

Each private DSN must specify host, port, database, user, password, verify-full TLS
and a protected CA reference beneath `/etc/codestra/control-plane/`; there is no
Unix-socket or multi-host fallback. Connections are checked for actual SCRAM,
TLS, exact session/OID and no SET ROLE. Credential values never enter source or
output. The private configuration bundle is read only from root:root `0600`
`/etc/codestra/control-plane/admission-configuration.json`; it is not a CLI secret
argument. Configuration, credentials, CA and source are checked again at authority
boundaries and before returning. No file or directory is created by planning.

The operational connection requires libpq 16 or newer, rejects inherited `PG*`
settings, requires SCRAM with channel binding, and sets `sslcertmode=disable`
before connecting. Root's default client certificate/key cannot be sent. This
policy follows [libpq's explicit authentication and client-certificate controls](https://www.postgresql.org/docs/16/libpq-connect.html#LIBPQ-PARAMKEYWORDS).
SQL observation and write transactions explicitly put `pg_catalog` first and
`pg_temp` last; role/database search-path defaults cannot redirect catalog reads.

`OnlinePostgresAuthority` is a concrete client for a separately administered
PostgreSQL issuer. Its cluster identifier must differ from the installation
target; another database in the target cluster is insufficient.
Standbys are rejected in the adapter itself because they can serve stale grants
or revocation state with a current database clock. Actual custody
acceptance must additionally establish independent administration, especially
where a host administrator could access both clusters. The client must have no
direct or attainable writer/admin, function/schema/object-owner, database-owner
or database-CREATE capability. Explicit EXECUTE grants on privileged PostgreSQL
file, large-object and maintenance builtins are also rejected across every
overload, including PUBLIC-effective and NOINHERIT-role grants. Those builtin
ACLs are checked independently of the pinned user-schema catalog.
All non-system schemas, helpers, numeric ownership
and ACL identities, triggers, policies, dependencies and extensions are included
in the pinned security catalog; catalog drift denies execution.

The issuer must already provide these independently reviewed API contracts:

```text
admission_bootstrap.describe(uuid grant, text operation, jsonb binding,
                             text phase, uuid nonce) -> jsonb
admission_bootstrap.revoke(uuid grant, jsonb binding, uuid nonce) -> jsonb
```

The installer does not install this issuer schema, implement its grant producer,
seed its records or grant itself access. The authority's operator-managed records
must bind the genuine authenticated client, exact accepted operation and complete
binding, not simply echo caller claims. `describe` executes in a fresh READ ONLY
transaction. Its exact response fields are `schema` (value
`codestra.admission-authority-response.v1`), `grant_id`, `operation`, `binding`,
`phase`, `nonce`, `observed_at`, `not_before`, `expires_at`, `revoked_at`, and
`decision` (value `ALLOWED`). Full binding equality includes `request_sha256`.
Verification additionally includes the separately accepted `verifier_role_oid`;
this operation-specific full object does not change the original request digest.
The issuer must store that independent verifier identity and derive the accepted
verification object from its base installation grant; it must not accept a
caller-selected verifier merely because the base request matches.
Missing, additional, mismatched, stale or future fields deny execution. Validity
is checked against the issuer's current database clock and a bounded observation
duration, then checked again after identity/catalog/custody reads.

`revoke` is narrowly granted, binds the exact grant/binding/nonce and returns only
`grant_id`, `binding`, `nonce`, `state=REVOKED`. It must durably and idempotently
revoke that exact grant. The client commits, then checks revocation in a new
read-only transaction. Lost commit acknowledgement yields an unknown outcome;
reinspect/retry the same attempt, never claim successful revocation prematurely.
Install/verify reject revoked grants. Rollback's `record_revocation`/`return`
phases require the matching durable revocation, still within accepted validity.
Neither this client nor a source approval supplies independently controlled grants.

All four commands consume `--request /absolute/request.json --request-sha256
<sha256>`; the digest pins exact bytes, and duplicate/extra keys are rejected.
The planning request has exactly `schema`
(`codestra.admission-installation-request.v1`), `candidate` (absolute candidate
directory), `manifest_sha256`, `runtime_selection`, `adopted_sources` and
`configuration_sha256`. Planning emits `PLANNED_NOT_AUTHORIZED`, the complete
immutable plan and `plan_sha256`, with authorization flags false. Other requests
add exactly `plan`, `plan_sha256` and stable `attempt_id` UUID. The CLI dispatches
to the engine and never treats a plan, approval field or owner string as authority.

Before creating the ledger, the engine obtains a session advisory lock and a
private filesystem lock. An immutable attempt precedes forward DDL. Pending
migrations and checksums commit transactionally; a lost commit response requires
inspection of the same attempt on a fresh connection, not a new attempt identity.

`INTENT`, `DATABASE_APPLIED`, `FILES_DURABLE`, `CONFIGURATION_DURABLE` and `RECEIPTED`
are separate boundaries. A database commit cannot roll back filesystem publication.
Files and containing directories are synced before completion; exact retries
repeat missing durability barriers without replaying DDL or replacing different
bytes. Interrupted staging files remain for investigation. Receipt completion
requires matching durable database and private filesystem observations.

## Staging and actual runtime destinations

`FileCustody` writes private artifacts only. Its observation is
`DATABASE_APPLIED_ARTIFACTS_STAGED`, with `runtime_installed=false`.

`RuntimeCustody` implements fixed admission code/configuration installation. A host
deployment requires native/effective UID0 and a preprovisioned private journal at
`/var/lib/codestra-control-plane/admission-installation`, shared for host fencing.
All host journal ancestors require protected custody and are identity-bound in
the plan. Relocating the journal through a replaced ancestor invalidates custody
even if its final directory inode is preserved; subsequent boundaries recheck it.
It does not elevate privileges, repair existing permissions or create installation
parents.

Runtime files follow exact manifest destinations beneath
`/opt/codestra-control-plane/releases/<SOURCE_SHA>`, with root-owned `0755`
directories and exact file modes. The two manifest files are explicitly included
as provenance metadata. Null-target templates and the wheel remain source
artifacts. The separately enumerated legacy shim target is
`/opt/codestra-dev/control-plane/bin/github-status-sync`; copying it never runs it.
Existing different targets deny execution before database installation.

The sole private configuration destination is
`/etc/codestra/control-plane/lease-verifier.toml`, root-owned `0600`, containing
exactly `database_dsn_file`, `app_id`, `installation_id` and `app_key_file`.
IDs are positive integers. Credentials must already exist at the fixed
`credentials/lease-verifier.dsn` and `credentials/lease-verifier-app.pem` references
beneath that directory; the installer neither supplies nor changes them.
Private input is a JSON object mapping the absolute configuration destination to
base64-encoded TOML. Both bundle and destination content are hash-bound. Decode,
schema, prerequisite and existing-target checks run before intent/DDL.

The non-authorizing `codestra.admission-runtime-selection.v1` specification requires
machine/interpreter digests, exact import-root fingerprints/order, preinstalled
driver directory, credential/configuration digests, mode/GID and accepted
writer-exclusion/recovery references. Missing selections deny execution. Actual
values/custody require separate operational acceptance; source examples supply none.

Preinstalled prerequisites are CPython 3.12/Linux x86_64, the pinned psycopg2-binary
2.9.10 payload and fixed Git/OpenSSL/library tool pins. Validation compares installed
payloads with the pinned archive's checked RECORD, fingerprints import roots
including bytecode, and checks protected ancestry. Installed RECORD text or a
version string alone establishes no provenance. After custody checks, a fixed
`/usr/bin/python3 -I -B` probe with a minimal environment/timeout verifies actual
interpreter, ordered import roots and driver/extension resolution. It never runs
application entrypoints. Driver, credential and service provisioning are excluded.

Prefixed disposable namespaces cannot alias the host root or change classification.
They never execute the host probe and report
`DATABASE_APPLIED_RUNTIME_FIXTURE_MATERIALIZED`, `runtime_installed=false`.
Only verified actual host destinations can yield
`ADMISSION_RUNTIME_FILES_INSTALLED_UNVERIFIED`. Its scope is admission code and
verifier configuration; publisher/certifier readiness and activation remain separate.

## Independent verification and rollback

`verify` uses a different credential-authenticated PostgreSQL role and read-only
transactions. It rejects direct or attainable writer, owner, server-file/program
and privileged maintenance capabilities, including NOINHERIT memberships. It checks
versions, actual artifacts, directory custody and database/filesystem receipts,
then rechecks identity, restrictions and catalog/attempt state after the final
authority call. It changes no database, assignment or lease state.

The verifier's separately approved read-only capabilities must already cover the
new ledger, for example through accepted schema/table default privileges established
by the operator before installation. Neither this migration nor the installer
creates a verifier role or grants privileges. Changing accepted ACLs afterward
invalidates the observation and requires an explicitly reconciled operational plan.

Rollback derives the immutable accepted attempt binding from the original plan,
then revokes through the trusted issuer and confirms fresh authoritative readback
before opening the target connection or journal. Executing source, interpreter,
import/native-driver/TLS dependencies and issuer configuration/credential custody
remain mandatory. Unused Git/OpenSSL command binaries remain full-installation
prerequisites and are not required merely to revoke through the SQL issuer. Installed release files, verifier credentials and installed TOML
are not recovery-client dependencies. A damaged executing client requires a clean,
independently accepted recovery client; it is never executed under waived checks.

After confirmed revocation, journal-only recording checks the original journal
identity and ancestry, exact authenticated target/attempt and ledger catalog before
recording `REVOKED` and a separate receipt. Damaged installed targets are preserved.
Target/journal failures produce `REVOKED_RECORDING_INCOMPLETE` with a nonzero CLI
exit and confirmed issuer revocation; an unknown recording commit is explicitly
labelled `UNKNOWN`. A lost issuer commit acknowledgement remains an unknown write
outcome, never a claimed successful revocation. Inspect and retry the same attempt.
Rollback retains datasets, grants, audit, checksums and artifacts.
This bounded path exclusively creates absent targets or reuses identical bytes;
it never overwrites an original requiring silent restoration. Replacing differing
configuration or shims requires separately reviewed recovery/cutover work.

The existing Builder CLI independently consumes
`/etc/codestra/control-plane/lease-builder.dsn`. This installer neither creates
that credential nor broadens the verifier configuration to carry it. The receipt's
scope remains admission code and verifier configuration; it establishes no Builder
readiness, product grant, task assignment, exclusive lease or issuer readiness.

Observations are not an atomic fence against privileged external writers. The
operational authority must maintain accepted writer exclusion. Source approval
does not satisfy that condition or authorize any live action.

The source plan/ownership ledger is
`governance/source-preparation/task-admission-installer-bootstrap.json`. Tests use
temporary namespaces and independently created PostgreSQL 16 fixtures, never
installed DSNs, production mounts or provider endpoints. Exact-source testing,
independent final review and actual publication requirements precede a push.

## Restricted CLI publication and private admission inputs

The opt-in `codestra.admission-runtime-selection.v2` selection has exactly the
v1 fields plus `publication_mode="TASK_BOOTSTRAP_CLI_ONLY"` and a
`verifier_credentials` object. It is accepted only with
`task-bootstrap-restricted-v1`. It installs the pinned release and
`/etc/codestra/control-plane/task-bootstrap-verifier.toml`, the configuration
actually consumed by `codestra-task-bootstrap`. It neither reads, validates,
publishes nor records installation history for the global legacy publisher
wrapper. The v1 selection retains its existing publication behavior.

The two `verifier_credentials` keys are `database_dsn_file` and `app_key_file`.
An accepted selection supplies distinct `connection.dsn` and `app.pem` files in
one new private directory beneath `/etc/codestra/control-plane/credentials`.
Both files must already be provisioned and pinned, with mode0600 and a mode0700
immediate parent. Admission installation credential directories cannot be used
as runtime verifier directories. The four-field verifier TOML and its accepted
App identities must agree with those paths. Selection data does not provision
credentials, principals, grants, custody or a service, and does not authorize
publication or startup. A separate unprivileged runtime identity still needs an
accepted secret-loading arrangement; this change does not widen root0600 files.

The restricted installer can explicitly opt into
`codestra.admission-installer-config.v3`, with the v2 `issuer` and
`lock_selection` fields plus `credential_profile="pas233-private-v1"`.
Only its operator and installation-reader paths change, respectively to
`credentials/pas233-admission-install-20261028-v1/connection.dsn` and
`credentials/pas233-admission-verify-20261028-v1/connection.dsn` beneath
`/etc/codestra/control-plane/`. Their immediate parents must be mode0700;
files remain root0600 on every custody recheck. The shared credentials parent,
runtime verifier defaults and issuer path remain unchanged. This configuration
requires an explicit v2/v3 CLI-only runtime selection; historical v1/v2 installer
configurations keep their original paths.

Private installer directory mode, GID and inode identity are checked before
opening credentials, after each connection, and on every custody recheck before
dispatch or authority operations. Replacement or permission drift stops the
attempt and closes its connections; identical credential bytes do not waive
the directory binding.

The new source candidate pins the observed root-owned Git2.43.0 binary by
SHA256 `eb54b535467e0975c1284d4c4d08eea779aeb248a5d34b02e2ee171382e22201`.
The candidate still marks provisioning and target verification false. Existing
installed publisher code, credentials, aliases and timers are not modified.

An independently accepted unprivileged reader can instead be bound by
`codestra.admission-runtime-selection.v3`. It adds exactly `runtime_reader`
with positive integer `uid`, positive integer `gid`, and
`custody_reference_sha256`. The separately provisioned runtime DSN and App key
must be root-owned, mode0640, in a root-owned mode0750 immediate directory;
all three use precisely the selected reader GID. Only that selection permits
installing its verifier TOML as root:reader-GID/mode0640. Both the credentials
and configuration remain unwritable by that group. The parent namespace stays
root-owned and unwritable by non-root identities.

This selection creates no account, group, membership, credential or key and
does not change metadata on an existing credential. Provisioning those exact
new paths and group custody requires its own reviewed effects. Acceptance must
prove the actual non-root runtime UID/GID can read these files, unrelated
identities cannot, and no competing publisher was introduced. A custody hash
alone does not prove those operating-system access results. v2 remains exact
root0600/0700, including the separate installation identities.
