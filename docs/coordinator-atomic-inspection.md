# Atomic coordinator inspection

The new executable supplies the missing authenticated evidence inspection for
an atomic candidate. It resolves the registered mapping, reads a genuine current
assignment lease, verifies every configured workstation dependency, observes the
actual checkout and checks the current GitHub PR and protected target.

Its result is a non-bearer observation. It does not register a product or task,
create an assignment, claim a lease, issue signed admission, certify a subsection,
publish status or merge. Existing promotion and publisher requirements remain.
No runtime installation or authority has been accepted by this source change.

## Server and runtime installation prerequisites

Review schema compatibility and apply the forward migration on a disposable
copy before an independently authorized installation.009 depends on005 and007
plus the existing public product, section, workstation, atomic-task and
scope_certifications tables. It replaces only the scoped-registration function's
scope-type validator to admit SUBSECTION metadata, retaining the existing
registration authorization and validation. No role, permission, product mapping,
assignment, dependency capability or lease is seeded.

The migration also pins the 19 explicitly named 007 issuer functions to UTC.
Previously their JSON snapshots inherited the caller timezone, so the same
unexpired binding could fail exact comparison from another timezone. Fresh
proofs/claims after009 use canonical UTC. Historical non-UTC snapshots remain
unchanged and fail closed; an accepted operator must revoke/re-observe/reclaim
through the existing APIs when such a lease requires replacement. Installation
never rewrites an old receipt, proof, lease, epoch or audit record.

An accepted schema/function owner administers the read API. A separately
authenticated coordinator login needs USAGE on atomic_inspection and only
EXECUTE on atomic_inspection.inspect(uuid), a current role/OID registration and
the product's assignment_leases read capability. It must differ from the builder,
have no protected schema ownership/CREATE/table-DML or privileged membership, and
connect using actual PostgreSQL16 SCRAM identity over verified TLS. Read-only
repeatable-read transactions close before Git or HTTP; reacquisition starts a
fresh transaction. Credentials and live evidence stay outside source control.

The operator must separately accept immutable root-owned source/interpreter/
dependencies/system-tool custody, runtime account isolation, the independently
controlled read-only GitHub App and its repository installation, controller
producer identities, and gate-to-check policy. In-process ownership checks cannot
establish trust after compromised code or imports have already executed.

## Mapping and dependency inventory

The atomic branch must target its registered subsection, whose parent is the
matching registered section. Both full SHAs, repository ID, worktree, host, owner,
task assignment, active lease UUID/epoch and physical directory identity must
match. This adds no feature-to-development route exception.

For this first inspection contract, prerequisites are exactly the unique set of
configured public workstation dependencies. Each dependency must have a same-
product registered subsection, CERTIFIED exact current database SHA and a matching
operator-bound independent SUBSECTION check-run receipt. The receipt scope name
is the registered subsection branch; the unchanged canonical
codestra.lease-dependency.v1 digest includes that scope and the full promotion
binding. Metadata certification alone grants no authority. The coordinator also
reads the actual dependency source/target refs around each online receipt check;
stale database SHAs cannot hide a moved GitHub ref. Missing, additional, inactive,
expired or ordinary-CI substitute receipts deny. Additional non-workstation
prerequisite scopes are unsupported by this inspection and deny.

The actual leased host/device/inode are mandatory. Replacing a directory cannot
transfer the lease. Materialization rechecks cleanliness, origin, exact Git
identity, both refs and all independent receipts twice. No hooks or repository
filters run. All workstation required gates must be supported: clean_tree and
remote_sha_match use actual materialization; review uses current independent
eligible exact-head approval; lint/unit/integration/contract/security/regression/
migration/performance/ci_exact_sha require explicit operator gate_checks bindings
to effective producer-bound protected checks.

## Protected configuration and use

The fixed root-owned private configuration is
/etc/codestra/control-plane/atomic-inspector.toml. Required fields are
database_dsn_file, app_id, installation_id, app_key_file, controller_app_id,
controller_contexts and gate_checks. IDs are actual positive accepted IDs, never
invented defaults. controller_contexts is the accepted subset of the two existing
Codestra contexts. gate_checks maps each required CI gate to exactly name and
app_id. This policy must be independently accepted; a nonempty string or source
template does not establish acceptance.

The protected DSN must use an explicit TCP host/database/user, sslmode=verify-full
and protected sslrootcert. The accepted App differs from Actions and the
controller writer. Its installation must contain only read permissions, including
metadata, contents, checks, pull_requests and administration. Each token is
restricted to those five read permissions and one exact repository ID. Arbitrary
REST writes and GraphQL queries are denied; token minting and the two existing
fixed GraphQL read queries are the only POST operations.

After actual independent provisioning and accepted registration/lease evidence:

```text
bin/codestra-inspect-atomic --binding ACTUAL_ACCEPTED_BINDING_UUID --pr ACTUAL_PR_NUMBER
```

There is no apply/enable/owner/DSN/snapshot argument. A successful observation has
eligible_for_source_update=true, non_bearer=true, certified=false,
lease_granted=false and promotion_authorized=false, with exact binding, lease
UUID/epoch and evidence digests. Failures emit ATOMIC_INSPECTION_UNAVAILABLE and
return nonzero without echoing credentials or remote/database diagnostics.

The current merge-result commit must have the exact bound base/head as its two
parents. Effective protection must enforce independent/codeowner/last-push/stale
review, conversations and strict producer-bound CI without bypasses. A genuine
noncircular check-run inventory is required on head and current merge result.
Unknown producer identities, unsupported rules, stale approvals, unresolved
threads or moved refs deny. Final Git/GitHub and server reacquisition reject
drift/expiry; no atomic transaction across PostgreSQL, files and GitHub is claimed.
The entire inspection is bounded by the existing five-minute snapshot age, and
lease, assignment and dependency expiry are rechecked at the recorded completion
time. Later consumers must still establish current evidence for their own action.

Any later admission, publication or merge must reacquire actual authority and
all evidence at its effect boundary. This observation cannot be replayed as a
lease or certificate. Genuine operator adoption, registered mapping/assignments,
independent scope-issuer receipts and the controller's admission action remain
separate operational work. PRODUCTION_GO=NO; LIVE_CAPABILITIES_ENABLED=NO;
EXTERNAL_EFFECTS=false.
