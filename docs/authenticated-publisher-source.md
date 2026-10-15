# Authenticated publisher source integration

Ralph L. Appolon explicitly accepted the single-host design and authorized source
implementation on 2026-10-15. Provisioning, secret distribution and activation
remain separate. This successor atomic assignment does not expand PR24's scope.
No external network mutation is performed during this implementation phase.

`publisher_adapter.build_publisher_service(connection, jwt_provider, ledger_path,
certificate_name=..., certificate_app_id=...)` is the privileged source
composition root. It wires `RestrictedRegistry`, `GitHubAppClient`,
`GitHubVerifier`, `IntentLedger` and the designated-service/local-lock boundary.
It is not callable via author JSON, an HTTP endpoint, an environment toggle or
the legacy CLI. The installed/old source entrypoint still refuses through
`require_publication_adapter()`: no provisioned startup application or credential
custodian has been installed. This library is source integration, not deployment.

## Authority and data contract

The proposed DDL `006-publisher-authority-read-model.sql` defines an operator-owned
schema/table; it creates no login, grants, credentials, tasks, certificates or
leases. It has not been run against the installed database. A separately approved
operator owns the schema and all authority writes. Runtime receives USAGE/SELECT
only. The reader requires session_user=current_user, rejects privileged logins,
schema-owner membership, schema CREATE or table mutation privileges, and requires
`sslmode=verify-full`, a configured CA trust root and a named server; the factory observes the actual kernel hostname. TLS encryption alone is rejected. Shared superuser sessions and role-switch impersonation cannot pass.
Role OID, authenticated session identity, exact SHA/ref binding digest, active row
and database expiration are checked on every acquisition. A dedicated principal
must be provisioned; a shared account cannot identify an individual.

Each binding row contains the exact numeric repository/PR IDs and issuer check
receipt ID, plus an operator-maintained Authority and TrustedSnapshot serialized
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
prevent other hosts/issuers obtaining write tokens. This implementation provides
no key distribution or automatic JWT signing service. App identity and installation
suspension are queried online on every preflight. A short-lived token is requested
for exactly one repository with statuses:write and checks/contents/pull_requests/
administration/metadata:read. No workflow write permission is requested. Returned
scope and expiry must match. Tokens stay in memory and errors suppress API secrets.
See GitHub's official REST App/installation token contracts:
https://docs.github.com/en/rest/apps/apps
https://docs.github.com/en/rest/apps/installations

Online verification requires exact PR source/target refs and SHAs, same stable
repository IDs, an open non-draft mergeable PR and current test-merge SHA. The target
must have classic protection enabled, enforce admins, strict producer-bound required
checks, independent approvals, codeowner review, stale-review dismissal, last-push
approval and conversation resolution. Equivalent ruleset-only enforcement is not
implemented and fails closed. Required producer checks must succeed on both head
and current test merge. Complete latest check/review inventories, current reviewer
WRITE eligibility and all resolved threads are queried independently.

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

No runtime connection/JWT custodian, authority rows, IDs, grants, leases, ledger
location or service startup wiring is installed. The restricted reader does not
create a lease, compute codeowner authority, infer last pusher, or issue certificates.
Source tests use synthetic privileged fixtures and are not issuer acceptance.
PR22 independent review/promotion remains separate. Full governed source promotion,
verified credential custody and genuine per-request authorities, operational
installation/rollback approval and target dependency checks remain required.
