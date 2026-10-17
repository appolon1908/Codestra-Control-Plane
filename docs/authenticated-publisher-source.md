# Authenticated publisher source integration

Ralph L. Appolon explicitly accepted the single-host design and authorized source
implementation on 2026-10-15. Provisioning, secret distribution and activation
remain separate. This successor atomic assignment does not expand PR24's scope.
No runtime network mutation is performed during implementation; later explicit user authorization permits ordinary source branch/PR publication only.

`publisher_adapter.build_publisher_service(connection, jwt_provider, ledger_path,
certificate_name=..., certificate_app_id=...)` is the privileged source
composition root. It wires `RestrictedRegistry`, `GitHubAppClient`,
`GitHubVerifier`, `IntentLedger` and the designated-service/local-lock boundary.
It is not callable via author JSON, an HTTP endpoint, an environment toggle or
the legacy CLI. The primary source entrypoint now invokes `run_configured_cycle()`
only after designated-service/local-lock ownership. The fixed configuration path is
`/etc/codestra/control-plane/authenticated-publisher.toml`. Missing configuration
still refuses before database/network access. No startup configuration or credential
is installed, and the legacy `post()` path remains unconditionally unavailable.

The concrete local JWT custodian uses OpenSSL RS256, with issued-at60 seconds in
the past and expiry540 seconds ahead, within GitHub's documented maximum. It reads
a protected root-owned App key only into memory and an inherited anonymous pipe;
key bytes never enter argv/environment/scratch files/logs. Tests use a temporary
synthetic RSA key, never a real App credential. This implements local signing;
remote/HSM signing is an alternative outside this source implementation.

OpenSSL and its libcrypto/libssl files are digest-pinned in
`runtime-publisher-tools.json` and checked before signing. These pins record the
existing build host, not a security release approval or automatic dependency
installation. The candidate manifest includes the pins with target verification
and provisioning approval false. All added runtime Python modules are included.

Operator configuration has exactly ten fields: positive integer `app_id`, `installation_id` and
`certificate_app_id`; string `certificate_name`; absolute `app_key_file`,
`database_dsn_file`, `ledger_file`, `producer_acceptance_file` and
`certifier_observer_socket` paths; and an explicit nonempty `repositories` list.
The configured repository scope must be a subset of the protected accepted scope
and the source catalog. Config/key/DSN files must be root-owned,
regular, single-link, private (0600 or0640), with root-owned non-writable parents
and ancestors and no symlink components. The DSN explicitly supplies host, dbname,
user, verify-full sslmode and sslrootcert; the CA may be public-readable but must
have the same protected ownership/ancestry and no group/other write access.
No caller-controlled DSN or environment fallback supplies authority.

Startup now supplies `AcceptedProducerVerifier`, rather than leaving the provenance
port unset. The protected acceptance record must pin separate Apps and signing
custodies, current installation IDs, numeric repository IDs, check name, both
controller contexts and bounded freshness. The record is reread during each online
verification. Proposed or expired records deny before connecting to PostgreSQL.
The separate root custodian in `certifier_observer.py` authenticates the certifier
App's current installation and repository coverage without sharing its key, JWT
or tokens with the publisher. Its fixed configuration is
`/etc/codestra/control-plane/certifier-observer.toml`; no server is installed or
started by this source change. See [the integration guide](publisher-certifier-integration.md).

Before reading connection/key secrets, startup checks root ownership and no
group/other write access for the runtime entrypoint, import tree and tool manifest.
Current codestra-owned installed files do NOT meet that requirement. A separately
approved operator must install a verified root-owned release tree and secure its
systemd/import environment; no ownership changes occur here. Self-inspection
cannot make an already compromised loader trustworthy: immutable approved code
and startup-path custody remain external deployment prerequisites. The private
ledger directory must also be provisioned separately; startup does not create it.

The current candidate proposes an immutable root-owned runtime at
`/opt/codestra-control-plane/releases/<exact-source-sha>` and an explicitly approved
isolated Python invocation, rather than changing ownership of shared developer
ancestors. The proposed dedicated `codestra-publisher` OS account is uncreated;
using it requires approved account/unit/group changes. The observer's protected
configuration pins that caller account and resolves its actual non-root UID.

## Authority and data contract

The proposed DDL `006-publisher-authority-read-model.sql` defines an operator-owned
schema/table; it creates no login, grants, credentials, tasks, certificates or
leases. It has not been run against the installed database. A separately approved
operator owns the schema and all authority writes. Runtime receives USAGE/SELECT
only. The reader requires session_user=current_user and non-null PostgreSQL system_user authentication evidence, rejects privileged logins,
schema-owner membership, schema CREATE or table mutation privileges, and requires
`sslmode=verify-full`, a configured CA trust root and a named server; the factory observes the actual kernel hostname. TLS encryption alone is rejected. Shared superuser sessions and role-switch impersonation cannot pass.
Verified server TLS alone does not authenticate the database client. Plain trust with a null system_user is refused even when TLS and role privileges otherwise pass. This observation does not approve an authentication method, identity mapping, custodian or runtime principal; those remain operator-owned policy and acceptance prerequisites.

Role OID, authenticated session identity, exact SHA/ref binding digest, active row
and database expiration are checked on every acquisition. A dedicated principal
must be provisioned; a shared account cannot identify an individual.

Each binding row contains the exact numeric repository/PR IDs and issuer check
receipt ID, plus an operator-maintained Authority, CertificateIssuer capability and TrustedSnapshot serialized
with exact dataclass fields and ISO8601 aware timestamps. The digest is SHA256 of
canonical sorted compact JSON of PromotionRequest. This is a restricted database
read model, not caller JSON ingestion or a legacy PASS upgrade. Operator state
owns accepted route mapping, codeowner coverage, last-pusher provenance,
dependency/certificate bindings, assignment and genuine lease observations. It
must be acquired from their accepted authorities, not copied from test fixtures.
The implementation does not manufacture those missing upstream authorities.

Authority identifies Ralph L. Appolon, the sole host, actual App/installation IDs,
epoch, expiration, verified credential-custody receipt reference and repository
grants. The reader authenticates its operator-owned provenance; a nonempty string
outside this restricted store is not an authenticated custody receipt. Operator
revocation makes the row inactive or expired and is checked before each context.
The actual values, custody-verification mechanism, certificate issuer IDs and
expiration limits must be provisioned from accepted operational evidence; no
synthetic values in tests are approved runtime identifiers. Snapshot age retains
the existing five-minute maximum. No new general credential TTL is invented.

## Dedicated App and authoritative GitHub receipts

The JWT provider is a privileged credential-custodian dependency, with no PAT/gh
fallback. It must sign only for the accepted App, retain private-key custody and
prevent other hosts/issuers obtaining write tokens. The local signer is implemented; no key distribution, key creation, HSM, or remote signing service is provisioned. App identity and installation
suspension are queried online on every preflight. A short-lived token is requested
for exactly one repository with statuses:write and checks/contents/pull_requests/
administration/metadata:read. No workflow write permission is requested. Returned
scope and expiry must match. Tokens stay in memory and errors suppress API secrets.
See GitHub's official REST App/installation token contracts:
https://docs.github.com/en/rest/apps/apps
https://docs.github.com/en/rest/apps/installations

Online verification requires exact PR source/target refs and SHAs, same stable
repository IDs, an open non-draft mergeable PR and current test-merge SHA. The target
must have verified effective protection from classic protection, active rulesets,
or both. Classic protection must enforce admins; every observed ruleset must have
visible empty bypass actors and matching source/rule metadata. Strict producer-bound
required checks, independent approvals, codeowner review, stale-review dismissal,
last-push approval and conversation resolution remain mandatory. Parameter-free
`required_linear_history` is an additional GitHub-enforced restriction, retained
in the evidence digest; it supplies none of those mandatory gates. Unknown rule
types and unsupported linear-history parameters still fail closed. Required
producer checks must succeed on both head and current test merge. Complete latest
check/review inventories, current reviewer WRITE eligibility and all resolved
threads are queried independently. See GitHub's [linear-history rule](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-linear-history).

Every required check must have a positive producer App binding. The required
`codestra-control-plane` and/or `codestra/control-plane` contexts must exactly match
the accepted publisher App and accepted context set; conflicting bindings deny
with `CONTROLLER_CHECK_PRODUCER_MISMATCH`. Missing, null or wildcard producer
bindings fail closed. The publisher still excludes its own success requirement
from CI preflight to avoid a circular dependency; this does not add contexts or
change branch protection.
GitHub's [branch-protection contract](https://docs.github.com/en/rest/branches/branch-protection#update-branch-protection)
defines the required check's App binding and the explicit any-App value.

The `issuer` read-model field is an explicit CertificateIssuer capability: exact
App ID/name, complete binding digest, capability receipt reference, aware expiry,
Ralph L. Appolon approval and purpose SCOPE_CERTIFICATION. Its provenance comes
from the authenticated operator-owned database, not a Python type/actor string or
caller JSON. Configured issuer ID/name must exactly match this capability. Missing,
expired or mismatched capabilities deny. Generic Actions App15368, the publisher's
own App and required-CI/controller context names are rejected as certifiers. This
source does not support Actions workflow-based certification; a future accepted
workflow-ID/path/revision attestation design would be needed for that alternative.
No actual certifier App/name/capability or approval receipt is supplied here.

The scope certificate must resolve to a successful online check-run from the
explicitly accepted issuer App and check name, with exact head SHA and external_id
binding digest. A normal CI success cannot stand in for this certificate. The
issuer must itself implement scope certification and stamp this binding; this
source does not issue one. Issuer revocation is reflected in the operator-owned
active authority binding, and revoked/deleted/changed GitHub receipts deny. A
bootstrap review-ref admission receipt never substitutes for a scope certificate.

## Effects, custody and residual race

Each binding gets a durable SQLite RESERVED intent before any status write.
Preflight reacquires authority, evidence, refs, protection and test-merge checks
before EACH context. Epoch/authority changes stop further writes. Authority is read again after online verification, policy/lease time is evaluated again at that point, and refs/test-merge/protection are reread at the end of the online inventory. Live protection requirements must exactly match the non-controller check/approval policy; drift denies instead of silently skipping new requirements. A verified first
write records PARTIAL durably; only two verified readbacks yield COMPLETE. An
ambiguous POST/readback yields UNCERTAIN. RESERVED/PARTIAL/UNCERTAIN/COMPLETE records
all refuse automatic replay, including after process restart. Operator
reconciliation/recovery is separate; no reset or retry endpoint exists. Revocation
after the first context leaves PARTIAL and performs no compensating write.

The fixed service cgroup and private root-provisioned flock fence local cooperating
processes only. Strong exclusivity still depends on verified custody of ALL write
credentials, exclusion/revocation of prior holders and one authorized host. An epoch
or caller token cannot fence GitHub status POSTs. No broker can atomically combine
GitHub ref movement and two external status writes. The approved residual race
remains bounded by fresh target checks, required current merge-result checks and
enforced branch protection at every effect. This source never merges. A downstream
merge executor must independently enforce current target and merge-result gates.

## Operational gates remaining

Use [publisher-operational-acceptance.md](publisher-operational-acceptance.md)
for the source-to-runtime handoff. Merged source, an offline candidate package,
installed bytes and accepted publication authority require separate evidence.

Startup/signing source code is now implemented. Actual configuration, App keys, authenticated connections, authority rows, IDs, grants, leases, trusted root-owned code installation and a private ledger location remain unprovisioned. The restricted reader does not
create a lease, compute codeowner authority, infer last pusher, or issue certificates.
Source tests use synthetic privileged fixtures and are not issuer acceptance.
PR22 and PR24 were subsequently merged into the source target; this branch integrates that accepted target before final verification. Full governed source promotion,
verified credential custody and genuine per-request authorities, operational
installation/rollback approval and target dependency checks remain required.

GitHub JWT protocol reference: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app

## Complete discovery and explicit unavailable coverage

Before any status effect, startup obtains a separate metadata/pull_requests READ
installation token restricted to the exact explicitly configured and accepted
repository names. The proposed first pilot is only `appolon1908/codestra`; the
49-repository source catalog is an upper bound, not an activation grant. GitHub
must return the complete exact repository set and unique positive actual IDs.
Every open-PR page for every repository is collected before any authorized write;
an unavailable/malformed/incomplete inventory stops all writes. This token has no
statuses permission. Write tokens remain separately scoped to each genuinely
authorized exact binding and are acquired only at its validated effect boundary.

The full observed PR inventory is matched to authenticated active operator bindings.
Every missing binding yields an explicit UNAVAILABLE_MISSING_BINDING console outcome
and no status write; it never creates assignments, grants, leases or certificates.
An empty authority inventory is explicitly UNAVAILABLE_NO_ACTIVE_BINDINGS, even if
no PRs are open, and source main exits nonzero. Stale bindings also report unavailable.
Sparse authority rows cannot imply all49 repositories or all PRs are covered.
Only fully verified authorized requests can publish. All partial/unavailable results
make the cycle incomplete. Completed durable intents still refuse replay; operator
reconciliation is required rather than manufacturing new status receipts.

Deployment review must include the entire interpreter/import environment, trusted
site packages, pycache/bytecode directories and unit ExecStart environment; the
in-process guard is defense in depth, not a trusted bootstrap for mutable code.
A clean immutable root-owned release with isolated imports is an external prerequisite.
Root-owned0640 key files alone do not prove exclusive custody if another process
shares the readable service UID/group. Actual dedicated-principal isolation or an
accepted external signing custodian, and evidence covering every credential holder,
remain mandatory operational decisions; current shared sentinelx identity is not
accepted as proof of exclusivity. No process identity or permission is changed here.
