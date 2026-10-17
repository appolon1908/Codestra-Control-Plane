# Explicit global controller coverage acceptance

`config/contracts/global-coverage-acceptance.schema.json` specifies a separate
versioned acceptance document. The49-name source catalog is an eligibility list,
not installed coverage or a product grant. Existing producer acceptance v1 stays
unchanged. The proposed three-repository example is unaccepted and intentionally
does not satisfy the ACCEPTED schema. No global runtime consumer is activated.

The accepted document must arrive through a protected operator-origin reader.
Its state and receipt strings alone cannot authenticate it. Structural schema
validation is necessary but insufficient. An eventual privileged consumer must
also enforce all of the following, with a current authoritative reread before
every effect; missing adapters or evidence deny rather than supply defaults:

- Unique exact repository names and numeric IDs, each in both source eligibility
  and an independently accepted selected-installation inventory. No wildcard,
  owner-wide installation, implicit new repository or identity redirect.
- Distinct publisher/certifier App and installation IDs, neither App15368;
  exact narrow permissions as in existing publisher/certifier contracts. Actual
  App, installation, owner, repository coverage, suspension and repository-scoped
  token scope are verified online. Each product has its own purpose/custody and
  capability acceptance. Atomic inclusion needs its separate accepted purpose.
- Exact installed source commit/tree, complete candidate manifest digest and
  immutable installed custody. Interpreter, driver, tool and schema versions
  and hashes must match actual installed receipts. Packaging or source CI cannot
  stand in for installation. Schema files are not an executable migration list.
- Current canonical product/section/subsection/atomic inventories, exact mirrors,
  parent edges and complete bounded acyclic dependency graphs. Recompute both
  canonical digests; reconcile all current tasks, pending assignments, bindings,
  coordinator mappings and sealed receipts. Git ref absence proves no empty DB
  inventory. Withdrawal requires separate accepted semantics.
- Each current task has its own exact authenticated principal/current OID,
  assignment, repository, operation, PR, source/target/head/base and live lease
  ID/epoch/expiry. Source-write007 and promotion-scope012 leases remain distinct.
  Historical atomic inclusion receipts do not become current writer leases.
- Every target has independently verified effective enforcement, required check
  name/App pairs, approvals, codeowner and review freshness, conversation and
  strict merge-result checks. Reject unreadable rules, unknown bypass semantics,
  aliases and ordinary CI substituted for controller evidence.
- Resolve every referenced task, edge, receipt and target to exactly one object.
  Cross-check lease principal/assignment and product identity, source/target
  routes, contract versions and receipt purposes. Duplicate keys, unresolved
  references, unsupported versions, non-UTC times, stale observations and expiry
  deny. Cap authority by the earliest accepted-policy, task, lease, dependency,
  receipt and fresh-observation deadline.

Acceptance lasts at most86400 seconds from accepted_at; a consumer may impose a
shorter bound. Canonical digests use UTF-8 JSON with lexicographically sorted
object keys, no insignificant whitespace, ASCII escaping and integer-only
numbers. Compare UTC instants in the normalized `YYYY-MM-DDTHH:MM:SS.ffffffZ`
form. Sort repository arrays by exact repository name, task arrays by task_id,
graph edges by the complete source/target identity tuple, artifacts by name and
protection/check arrays by target/name/App tuple; reject duplicate identities
before sorting. `revision_digest` hashes the complete normalized document with
only revision_digest omitted, prefixed by `codestra.global-coverage.v1` and a NUL
byte. Inventory/graph digests use the same encoding with distinct
`codestra.global-inventory.v1` and `codestra.global-graph.v1` NUL-terminated
domains and their complete canonical registered objects. Artifact digests hash
the exact file bytes. An eventual consumer must implement these encodings and
cross-checks before this specification can confer accepted coverage.

The pending selected identity proposal names Codestra1319808791,
Klyrow1334863061 and WhatsApp-Frontend1387813688. That last ID does not authorize
the separate WhatsApp repository. The Codestra pilot never expands implicitly.
Accepted coverage does not create assignments/leases or authorize deployment,
authentication changes, service activation, status publication or promotion.

Existing Klyrow subsection/section refs and WhatsApp environment refs can be
represented by012's existing-scope routes after their actual registration,
assignments, accepted capabilities and receipts exist. First subsection issuance
now additionally requires014 for every configured atomic child. SECTION requires
every registered subsection and section prerequisite; DEVELOPMENT every current
section; later environments their immediate predecessor. The existing-ref path
is separate from strict absent-ref review bootstrap. Legacy implementation or
feature refs still do not establish a governed atomic route.
