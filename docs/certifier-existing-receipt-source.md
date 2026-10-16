# Independent scope certification source

The certifier now has two separate source paths: transport an existing independently
authenticated `SCOPE_CERTIFICATION` receipt, or issue the first check from an
operator-authenticated exact-scope delegation. First issuance does not require an
existing check-run or `ScopeCertificate`. Both paths deny when privileged
acquisition or protected acceptance is unavailable. Nothing is installed, enabled,
applied, granted or published live by this change.

`AuthenticatedFirstCertifier` accepts only `PendingCertification` acquired through
a privileged registry. Its snapshot must have `certificate=None`; historical
certificates are rejected. An author object, ordinary CI, a legacy PASS row and
`evaluate_promotion.allowed` cannot establish certification authority. The source
never constructs a `ScopeCertificate` to pass a circular gate.

The empty source table in `013-first-certification-pending.sql` binds the
credential-authenticated reader's principal/OID and explicit product grant to the
exact repository/product, repository ID, PR, source/target refs, head/base SHAs,
registered scope, authority, current scope assignment/lease ID/epoch/principal,
accepted delegation reference and capability. The operator explicitly accepts a declared dependency policy; every acquisition
reconciles it against the current configured hierarchy. Delegations expire within five minutes and remain
inactive by default. No first-certification rows, credentials or grants are seeded.

`RestrictedFirstCertificationRegistry` requires verified TLS with a protected CA,
authenticated SCRAM, equal session/current users, no role switch, and an active
OID-bound product grant. Elevated/inherited roles, schema/table ownership, data
mutation rights and execution of sensitive mutating APIs deny. It independently
queries `scope_assignment_leases.inspect_binding(uuid)` from source migration 012
and checks current state, lease ID/epoch/principal, exact repository ID, registered
source/target levels, refs, both SHAs and expiration. That API rechecks the actual
registered product and scope mappings. Missing tables/API or revoked/drifted
records deny. The incompatible atomic-task lease API is never a fallback. Every acquisition
uses a READ COMMITTED transaction; repeatable snapshots cannot cache revoked
authority.

The dependency policy is operator-owned, and its declaration is independently
checked against the current registry on every acquisition. Product/environment
refs, registered product mirrors, all configured sections and all subsections
with their registered mirrors and lanes must agree with the snapshot mapping.
A snapshot or operator delegation cannot hide a current child. SECTION requires
every registered subsection under its section plus every current cross-section
`sections.depends_on` prerequisite certificate. Section prerequisites resolve
through canonical section IDs or keys only when unambiguous; invalid arrays,
unknown/self/duplicate references and dependency cycles deny for all scopes.
The product graph is bounded to 1,000 sections and checked without recursion.
DEVELOPMENT requires every
configured section; TESTING, STAGING and PRODUCTION require the immediate
registered predecessor certificate binding. Missing or extra declared bindings
deny. SUBSECTION requires its registered workstation dependencies and denies
whenever any actual atomic task or registered candidate exists in that subsection:
the shared certificate contract does not support authentic atomic bindings.
This limitation has no status/PASS or atomic-route exception. Empty declared
inventories are valid only when the current supported prerequisite inventory is
actually empty. Every listed dependency
must use a supported registered edge in the same product/repository, have an
unambiguous exact binding, and possess a current successful check-run from the
accepted certifier App/name. The online verifier rereads dependency refs around
receipt inspection and independently reads each check suite to match its App
and exact head SHA. GitHub `completed_at` must be UTC, present, not in the future,
and fresh under the protected policy’s `max_receipt_age_seconds`. An operator
expiry cannot extend that real receipt freshness deadline. The minimum of all
these deadlines bounds the returned effect contract and API token before POST. Missing, expired, wrong-issuer or revoked dependencies deny;
legacy metadata does not supply their provenance. Policy booleans alone cannot
replace this separately authenticated inventory.

`AcceptedFirstCertificationContractVerifier` reads the shared protected acceptance
policy through a privileged zero-argument reader. It pins the independent
certifier App/installation, `certifier_custody_receipt`, exact repository ID and
`certifier_capability_receipt`, then binds that policy to the exact pending scope
and delegation reference. The separate `custody_receipt` remains publisher-only.
There is no fabricated existing receipt reference. The first-issuance purpose is
`FIRST_SCOPE_CERTIFICATION`; existing receipt transport uses `SCOPE_CERTIFICATION`.

The dedicated GitHub App transport requests a single-repository token. Its sole
write grant is `checks:write`; `metadata:read`, `contents:read` and
`pull_requests:read` support refs/checks/reviews, while `administration:read` is
needed to inspect classic enforced protection and bypass allowances. Installed
permissions must match exactly, the installation must select repositories, and
online repository owner/ID and per-repository installation coverage must agree.
Full selected-repository inventory remains an operator acceptance prerequisite.
The publisher never receives the certifier private key or check-write token.

Before issuance, independent online reads verify required checks on the exact
head and current test merge, the exact open PR and protected target base, accepted
enforced protection, independent eligible codeowner reviews and resolved threads.
The issuer reacquires the authenticated pending record, scope lease and protected
contract. A durable one-use intent is then committed, followed by a complete
second preflight. Existing receipt transport shares the same binding key so one
ledger cannot emit twice for the same exact promotion.

After all final database/policy reads, the issuer samples time again and validates
all stable evidence. It repeats a local expiry check immediately before emission
and caps the API session to the minimum accepted contract, authority, scope lease
and existing receipt or pending delegation expiration. No further authority
broker read is inserted between that fence and the POST. The check-run uses
`external_id=binding_digest(PromotionRequest)`. Readback must match App, check
name, exact SHA, binding digest and completed success. A failure before the effect
is `REJECTED`; an ambiguous POST or readback mismatch is `UNCERTAIN`. Both consume
the intent permanently. There is no automatic retry or compensation.

The local time check and GitHub's acceptance of the network request cannot form
an atomic transaction. Network latency may cross an authority expiration after
the final local fence. This residual boundary is explicit; the source does not
claim an atomic guarantee across the database, credential custodian and GitHub.

## Concrete first-issuance operational proposal

The following prerequisites describe future operator actions. They are neither
executed nor authorized as runtime provisioning by this source preparation.

1. Independently accept the dedicated certifier App, selected repository IDs,
   exact permissions, separate credential custody and scope-certification
   capability. Record them in the protected shared producer acceptance policy.
2. Review and separately apply source migrations 011, 012 and 013 under an
   operator-owned schema authority. Provision a SCRAM/TLS certifier reader with
   OID-bound product/read grants, SELECT on its required read-model/product
   tables, and only the scope lease `inspect_binding(uuid)` API. Canonical dependency
   reconciliation additionally requires schema USAGE on `scoped_registration`
   and SELECT on `public.products`, `public.sections`, `public.workstations`,
   `public.atomic_tasks`, `scoped_registration.products`,
   `scoped_registration.workstations`, `scoped_registration.lanes`,
   `scoped_registration.candidates`, and `scope_assignment_leases.products`. It must have no
   claim/write/schema-owner privileges. No source migration creates these grants.
3. Register the actual product/scope mapping and exact scope assignment through
   the operator-owned scope lease records. A separately authenticated scope owner
   claims that assignment using source API `claim(uuid, request_uuid)`. The
   certifier uses an independent read principal and cannot claim its own lease.
4. Independently accept an exact pending first-issuance delegation, including a
   complete current dependency inventory, protected capability reference, source
   snapshot with no certificate, and the genuine current scope lease ID/epoch.
   Bound its expiration to the acceptance, authority and lease, at most five
   minutes after issuance. Author-supplied JSON and copied legacy PASS are invalid.
5. An administered internal caller uses `build_first_certifier_service` to wire
   the real restricted registry, protected contract reader, dedicated App client,
   online verifier and private durable intent ledger, then invokes
   `AuthenticatedFirstCertifier.publish(exact_promotion_request)`. The factory
   accepts only privileged connection/custodian/policy-reader dependencies and
   reads no credentials or policy during construction. Missing
   composition remains unavailable; no public CLI or installed service is added.
6. Independently read the real resulting check-run. If accepted, a separately
   authorized operator can register that exact live check receipt in the
   publisher's acquisition model. Publisher verification must still authenticate
   the dedicated App, current protection, refs and receipt freshness. A synthetic
   unit test is not a receipt, certification, publication or promotion approval.

The existing-receipt path retains its empty source model in 011 and separately
checks a previously authenticated receipt plus exact scope registration. Its
legacy scope metadata is only an additional prerequisite; the operator-owned
independent receipt acceptance provides provenance. It also now requires the
scope-level lease API from 012.

Source tests use synthetic privileged ports and temporary socket-only PostgreSQL
clusters. `PRODUCTION_GO=NO`, `LIVE_CAPABILITIES_ENABLED=NO` and
`EXTERNAL_EFFECTS=false` remain in force; live issuer acceptance and runtime
composition are unprovisioned.
