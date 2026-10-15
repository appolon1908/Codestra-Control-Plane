# Assignment-backed leases: source contract

This change implements a proposed Linux-only issuer. It installs nothing. The
registration schema, new schema, restricted roles, credentials, grants, policy,
assignment bindings, dependency capabilities, verifier service and publisher
remain unprovisioned. `PRODUCTION_GO=NO`, `LIVE_CAPABILITIES_ENABLED=NO` and
`EXTERNAL_EFFECTS=false` remain required. Ralph L. Appolon authorized source
implementation; provisioning, migration and activation require a separate phase.
Source assignments and test receipts are not runtime leases or certification.

## Authority and custody

`007-assignment-leases.sql` depends on reviewed `005-scoped-registration.sql`
and the existing product/hierarchy schema. An operator controls every policy,
permission, exact assignment binding and dependency capability. No numeric TTL
policy is accepted by default. Lease duration, renewal duration, total lifetime
and maximum observation age must be explicitly supplied and validated later.
Runtime callers receive narrowly selected function execution only, never table
DML, schema creation, elevated role membership or schema ownership.

Session identity is PostgreSQL `session_user` plus the registered role OID. A
recreated same-name role, `SET ROLE`, arbitrary owner string, legacy `--agent`
and superuser session cannot substitute for the assigned principal. The client
requires a protected explicit DSN and CA with `sslmode=verify-full`; the server
requires TLS. The operator must separately establish authenticated PostgreSQL
credentials and server authentication rules. Disposable tests use synthetic
roles and a temporary TLS endpoint; they do not demonstrate deployed credential
custody or production authentication configuration.

Builder, verifier, read consumer and revoker are distinct capabilities. A builder
cannot attest its own checkout. The independent verifier requires its own
restricted PostgreSQL identity and a dedicated GitHub App whose installation
permissions are all read-only. The concrete client requests only metadata,
contents and checks read permissions for one repository ID at a time. The
publisher's status-writing App and independent scope certifier are separate.
No App IDs, credentials or active capability records are invented here.

The CLI expects protected `/etc/codestra/control-plane/lease-builder.dsn` and
`lease-operator.dsn` files. Verification expects `lease-verifier.toml` with only
`database_dsn_file`, `app_id`, `installation_id`, and `app_key_file` fields. These
are contract paths, not supplied or generated configuration. Root-owned,
immutable source, Python/runtime dependencies and system-tool custody must be
established by an external trusted deployment mechanism before use. An in-process
ownership check cannot secure an already compromised interpreter, import path
or bytecode loader. Readable shared keys are not proof of exclusive custody.

## Materialization and dependencies

Bindings pin product, workstation, atomic task, session principal/OID, numeric
repository ID, repository, source and target refs, full head/base SHAs, canonical
Linux checkout/root/common-Git-directory paths, host identity and checkout UID.
The host identity combines hostname and the protected machine ID. Windows paths,
symlinked paths, group/world-writable directories, detached HEADs, dirty or staged
files, untracked files (including ignored files), submodules and tracked symlinks
are unsupported and denied. The observer requires protected directory ancestry,
checks actual Git branch/HEAD/origin/common-directory and independently reads
GitHub repository ID and both refs twice. Checkout cleanliness compares raw Git
index blobs and files; it never runs repository-configured clean filters.
Observations are bounded by time and output/checkout size limits. Device/inode
replacement prevents renewal of an existing lease.

A verifier fetches the binding from the authenticated server, observes it, and
submits a bounded one-use proof through its separate session. Builders cannot
submit raw observations through the CLI. Proofs pin the complete binding and
operator dependency records. Missing, expired, consumed or mismatched proofs,
revoked verifier authority and changed assignment records deny issuance.

Dependencies require explicit operator capabilities and online GitHub check-run
receipts from an independent accepted issuer; legacy `PASS`/`CERTIFIED` rows and
ordinary CI do not qualify. The source receipt protocol hashes canonical JSON:
`{"schema":"codestra.lease-dependency.v1","promotion":<all PromotionRequest fields>,"scope_type":...,"scope_name":...}`.
The check's `external_id` must equal this digest, with exact full source SHA,
check ID, issuer App ID/name and completed-success state. The prerequisite also
pins product, scope type/name and SHA. No producer has been provisioned or
accepted merely by defining this protocol; an absent compatible receipt denies.

## Lifecycle and consumer checks

`describe` is read-only and restricted to an independent verifier. `attest`
creates a short-lived proof. `claim` consumes it, serializes workstation/path
claims, advances the slot epoch and updates compatibility workstation/task
fields in the same database transaction. Unique indexes additionally prevent
two active workstation or host/device/inode leases. `renew` requires a fresh
proof, the same materialization, owner and epoch, and respects total lifetime.
`release` invalidates ownership and advances the epoch. `lookup` retrieves a
still-current claim after a lost response; it cannot reissue a consumed request.
Audit records retain authenticated actor/OID, action, request and receipt.

`inspect_binding` validates an active lease through a read-only transaction
without impersonating its owner. The concrete publisher calls it on every
acquisition and re-acquisition, binds the receipt to repository ID, product,
refs, SHAs and expected owner, and compares lease ID/epoch as well as the rest
of its acquired evidence. Stored snapshot lease fields alone confer no authority.
The publisher reader needs an explicit product `read` capability and only the
corresponding API execution permission; those grants are not applied here.

Expired leases never silently recover or transfer. Operator revocation disables
the binding and invalidates active leases/epochs. It preserves frozen/blocked
lanes, dirty-worktree blockers and unrelated compatibility ownership. Recovery
and re-binding require separately authorized operator procedures. Revocation
of assignment, verifier or dependency records makes subsequent authoritative
checks fail. A consumer must recheck current authority at its own effect boundary;
a historical receipt is not an offline bearer token.

## Races and operational acceptance

Database transactions serialize internal claims and lifecycle changes, not
filesystem mutation, remote ref movement or external effects. Files and refs can
change after observation. Proof age and lease lifetime bound stale observations;
renewal re-observes them. Dependency receipt deletion/failure on GitHub becomes
visible on the next online materialization; operator capability revocation is
visible on the next database check. These are explicit revocation limits, not
instant cross-system revocation. No filesystem fence or multi-host lock service
is installed. Downstream consumers must enforce current epoch/identity for their
own effects; GitHub status POSTs cannot carry a database fencing token.

The publisher still requires strict target verification, merge-result checks and
branch-protection enforcement. A GitHub ref movement and paired status posts
cannot be made atomic by a database broker. The accepted residual external race
remains documented in the publisher contract. Runtime activation must separately
accept actual identities, custody, policy limits, immutable deployment, issuer
receipts and consumer enforcement against the deployed repository contracts.

Future installation must first validate forward migration and restricted-role
behavior in a disposable environment, then obtain explicit operational approval.
Rollback should stop consumers and revoke their narrowly scoped capabilities
before any separately approved schema cleanup. Retain audit history and frozen
lane evidence; do not drop schemas, recover lanes or rewrite legacy state as an
automatic source rollback. This document is not an executable rollout runbook.

## Source validation

Tests use disposable PostgreSQL/TLS clusters, synthetic roles and keys, temporary
Git repositories and mocked HTTP connections. They cover session/OID identity,
independent proof authority, concurrency, expiry, renewal, epoch/replay behavior,
revocation, read-only consumer inspection, checkout drift, receipt provenance and
CLI rollback. No installed database or actual GitHub issuer is used as a test.
