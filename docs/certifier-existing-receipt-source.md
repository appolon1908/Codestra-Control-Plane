# Existing scope certification transport: source boundary

This section supplies source for an independent GitHub App to publish an existing,
independently authenticated `SCOPE_CERTIFICATION` receipt as a check-run. It does
not implement a first-certification decision or bootstrap a trusted issuer.
`evaluate_promotion.allowed`, ordinary CI, a caller-created dataclass, an author
configuration file and a legacy `CERTIFIED`/`PASS` row are insufficient authority.
There is no public certifier CLI, installed factory, enable flag, key, grant,
active read-model row, lease, service change or network effect in this change.
The default `AuthenticatedCertifier` has unset privileged dependencies and denies.

`ExistingScopeReceipt` binds repository/product, source and target refs, source
SHA and target base SHA, registered scope type/name, existing receipt reference,
expiration, assignment, lease ID/epoch and principal. A Python value does not
authenticate itself: only a separately administered online registry may return
it. The accompanying snapshot can have `certificate=None`. The adapter never
constructs a `ScopeCertificate` and never derives one from a promotion decision.

`RestrictedCertificationRegistry` is a concrete read-only implementation for the
empty source read model in `011-certifier-authority.sql`. It requires verified TLS
with a protected CA, an authenticated SCRAM session with equal session/current
users and no role switch, an OID-bound active per-product grant, and an exact
operator-accepted existing receipt. Elevated/inherited roles, schema or table
ownership, data mutation privileges and execution of other sensitive APIs deny.
It also queries `assignment_leases.inspect_binding(uuid)` for current ownership,
lease ID/epoch, expiration, repository ID, refs and both SHAs. An exact legacy
scope certification row is checked as an additional registration prerequisite;
it supplies no independent issuer authentication.

The SQL file contains no identities, grants, policies, certification procedure or
receipt inserts. Its tables remain empty. Applying it to any installed database,
assigning a reader, and registering a receipt each require separate operator
acceptance outside this source change. Registration must include independently
verified provenance for an already existing certification, plus an acceptance
reference. Copying a legacy PASS record or a successful check into this read model
would violate its trust contract. No source API currently decides or authenticates
first issuance, so the source cannot claim that capability is complete.

`AcceptedCertifierContractVerifier` reads the shared protected publisher acceptance
policy through a privileged zero-argument reader. Exact repository IDs, accepted
certifier App/installation, distinct publisher/ordinary CI identity, capability,
check name, controller contexts, policy revision and expiry are required.
`certifier_custody_receipt` pins the independent certifier custody; the separate
`custody_receipt` remains publisher-only and cannot satisfy this pin. Missing
or rejected acceptance denies. The certifier credential custodian is independent;
the publisher must never receive its private key or its check-write token.

`CertifierGitHubClient` obtains a repository-restricted token only after checking
the accepted App and unsuspended installation online. Its sole write grant is
`checks:write`. `metadata:read`, `contents:read` and `pull_requests:read` support
exact refs, merge checks and reviews; `administration:read` is required to inspect
classic enforced protection and bypass allowances. The installation must match
these minimal permissions exactly. There are no status, content, workflow,
protection or ref write permissions. The transport refuses status/ref API effects.

Before publishing, the online verifier checks the exact open PR head and target
base, protected target, accepted enforced protection, required checks on both the
head and current test merge, independent eligible reviews and resolved threads.
It rereads refs, protection and checks, then the orchestrator reacquires the
registry receipt and accepted contract. A durable one-use intent is committed
before a second complete preflight and the check-run effect. The check-run uses
`external_id=binding_digest(PromotionRequest)`. Its readback must match App, name,
exact SHA, binding digest and completed success. A lost response or mismatched
readback is `UNCERTAIN`; revocation before the effect is `REJECTED`. Both consume
the durable intent permanently; no automatic retry or compensation is provided.

Source tests use synthetic privileged ports and a temporary socket-only
PostgreSQL cluster for schema/predicate checks. They do not establish deployed
issuer acceptance, operational credentials, a populated authoritative receipt,
live protection acceptance, certification, publication or promotion approval.
`PRODUCTION_GO=NO`, `LIVE_CAPABILITIES_ENABLED=NO`, `EXTERNAL_EFFECTS=false` remain
in force.
