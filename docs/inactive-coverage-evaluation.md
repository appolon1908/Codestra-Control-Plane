# Inactive per-PR coverage evaluation

`codestra_control.coverage.evaluate_coverage` returns one explicit outcome per
supplied PR without a repository allowlist or route skip. The supplied tuple is
not an approved inventory or completeness proof. It supports offline evaluation
of the coordinator's 13-repository scope without adding repositories to the
publisher's approved scope. No CLI, production verifier or effect adapter is
installed, and no existing publisher calls this module.

A frozen binding contains stable numeric GitHub repository ID, PR number,
request ID, assignment ID, owner principal, exact existing status context,
publisher principal, and a `PromotionRequest` containing
repository/product, source/target refs and exact source/target-base SHAs. An opaque,
independently accepted verifier must observe those identities, approved scope and
current evidence. Its internal evidence must match the whole binding. Dataclass
construction, actor strings, caller JSON, boolean flags and CI aliases are not
credentials or authenticated grants. Default verifier absence reports UNAVAILABLE.

The existing `evaluate_promotion` policy owns registered route, exact evidence,
review, certificate, freshness and owned-lease rules. Wrong routes and missing or
invalid evidence produce DENIED. The lease must additionally match this request's
assignment ID and authenticated owner. Publisher capability and exclusive context
ownership require separately request-bound verifier receipts; absence or mismatch
reports UNAVAILABLE. Even complete synthetic evidence reports INACTIVE_PUBLISHER.
Duplicate PRs or reused repository/request IDs deny all conflicting entries.
Capability and ownership receipts bind the exact context and publisher principal
as well as the complete PR request; slash and dash contexts are distinct.
Every result retains `authority=false`, `publish=false`; none is a certificate.
Actual publication requires a separately reviewed acquisition/effect contract and
operator-authorized installation. No new route or approval policy is created.

Priority fixtures cover Toolkit PR4/3 and Foundation PR7/6/2. Their reported exact
heads are test inputs, not live observations. Fixture numeric repository IDs and
branch names are synthetic. The coordinator reports that product mappings already
exist; stable GitHub IDs and accepted routes/workstation/task assignments,
authenticated principal/grants, owned leases and exact-head route certification
remain unverified. Feature-to-main is denied using existing route policy.

This work does not resolve installed six-repository filter drift, reconcile two
writers sharing a context, or bypass exhausted GitHub status history. It supplies
truthful evaluation results for future accepted integration. No live database,
status, branch, credential, grant, lease or production state is changed.
