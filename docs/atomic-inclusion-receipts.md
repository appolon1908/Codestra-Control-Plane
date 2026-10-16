# Authenticated atomic inclusion receipts (source only)

014 is an empty operator-owned source contract requiring005/007,009 coordinator,
011 and013 compatibility. It creates no identities, grants, rows, leases or
activation. The restricted issuer may execute prepare/seal; the scope reader may
only SELECT the exact required tables/view. Readers must not execute issuer or
revocation APIs, inherit an issuer/writer role or own/create authority schemas.

An operator pins an exact task/binding/lease/epoch and inclusion context in an
inactive delegation. After explicit acceptance, `prepare(uuid,uuid)` authenticates
the independent issuer's SCRAM/TLS session and current role OID, product issue
grant and007's genuine ACTIVE exclusive writer lease. It freezes the original
H0/base, materializer proof and credential provenance, issuer/delegation/grant
deadlines and task prerequisite row. The distinct candidate H1 is an accepted
inclusion pin. Preparation confers no certificate or write admission.

`build_atomic_issuer_service` is a privileged source composition port. Its exact
task snapshot reader, protected producer/purpose policy readers, independent App
custodian, database principal and private intent ledger must be administered
separately. No public CLI or installed caller is supplied. The concrete workflow
verifies actual merged PR identity, exact current source and subsection refs,
ordinary merge parents/tree, successful candidate and merge-result CI, effective
current target protection, exact-head independent premerge reviews and resolved
threads. Candidate CI/reviews must predate merge; observed actual merge-result CI
may complete afterward. This is not a retrospective protection attestation.

The issuer emits only a separately named ATOMIC_INCLUSION check, reads the check
and suite back, rechecks current evidence/authority and calls `seal`. SQL repeats
actual lease/delegation/credential checks while authority is still valid. Only
the dedicated trusted issuer can assert online observations to this SQL boundary;
SQL does not contact GitHub. Authors cannot pass arbitrary JSON or a boolean to
create a receipt. Frozen records and revocations are immutable. A lost effect or
commit response is UNCERTAIN; never retry with fresh IDs or erase intent history.

Normal release preserves the sealed fact and may advance the workstation slot
epoch. Aggregate readers use the frozen issuance epoch, not the current slot,
and never invoke ACTIVE-only lease inspection for released history. Explicit
receipt/binding revocation, identity/OID/grant changes, mirror drift or expiry
deny. A current separate scope lease is still required for subsection issuance.

The first subsection reader reconciles the complete union of public tasks,
assignments, candidates/lanes,007 bindings and coordinator mappings, including
pending/inactive entries. Every task needs one sealed receipt and an explicit
prerequisite row; missing/extra children, partial mirrors, cycles or unresolved
references deny. Nonempty historical coordinator scope prerequisites are
currently unsupported and explicitly deny; they are never silently discarded.

The online consumer verifies the accepted App/installation/purpose, exact check
and suite, domain-separated frozen payload and observation hashes, merged PR and
ordinary merge parents/tree. Every merge must be an ancestor of the same current
exact subsection head. Earlier child bases need not equal today's parent head.
It rereads the current parent after the batch and re-acquires SQL authority before
effects. Accepted historical lifetime and fresh observation deadlines are distinct;
old completion timestamps are not refreshed. Squash/rebase inclusion and retained
content after a revert remain unsupported. Inclusion never establishes that a
prior publication passed010 or the separate strict41 bootstrap fence.

GitHub check POST and SQL sealing are not atomic. Revocation/ref changes may
leave an orphan check after an uncertain attempt; absence of a sealed current
receipt keeps aggregate certification denied. There is no automatic retry,
revocation propagation or operational rollout in this source implementation.
