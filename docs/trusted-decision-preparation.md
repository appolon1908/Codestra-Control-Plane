# Trusted promotion decision source preparation

This implements the pure policy/evaluation portion of Task 2. It is not a
completed Task 2, an installed checker, a certified candidate, or deployment.
The source-only assignment is `governance/source-preparation/task-02.json`.
PR #1 remains an unaccepted dependency.

## Implemented

- Registered environment refs resolve to logical stages. BREERO fixtures preserve
  `testing` and `production/environment`; other products can retain `test`.
- Subsection/section paths require explicit registry edges. Prefixes alone grant
  nothing; candidate/atomic paths are rejected until Task 3 implements them.
- Immutable decision inputs bind repository, product, both refs, head and target
  base. Every consumed check, review, scope certificate and lease must match.
- Required checks need a matching producer, a completed successful run, and a
  complete inventory. The control plane's own contexts cannot certify CI.
- Approval counts use distinct eligible reviewers independent of the author and
  last pusher. Codeowner approval, known resolved threads, complete dependencies,
  an active owned lease, recent observations, and disabled effects are checked.
- Duplicate/ambiguous evidence, unknown fields represented with invalid types,
  missing evidence and legacy PASS dictionaries cannot produce an allowed result.
- Evaluation performs no database writes, GitHub calls, status publication,
  certificate writes, or merge. An allowed result says only that the supplied
  internal snapshot satisfies this policy.

## Trust boundary still required

`TrustedSnapshot` is an internal Python contract, not authentication. An attacker
who controls its constructor inputs can fabricate objects. Receipt IDs and
producer names are references, not signature validation. This component must
never be wired directly to caller JSON, PR files, environment flags, or existing
`promotion_evidence` PASS rows.

The future privileged adapter must retrieve policy from accepted owner state,
finish pagination, verify check producer/workflow authority and latest attempts,
verify reviewer eligibility and applicable codeowner coverage, collapse review
state, verify certificate receipts, retrieve registered assignment/lease and
dependency state, and independently observe both refs. It must stamp current
times and fail closed on any read failure. Required checks exclude the status
being computed, so this does not introduce circular self-certification.

After evaluation, re-read both refs immediately before publication/promotion.
A previously allowed snapshot must not be reused after either ref changes.
Actual certification and result-SHA receipts remain Task 3 work. No legacy PASS
record is upgraded merely because it was saved in PostgreSQL.

Existing `bin/codestra-github-check`, `bin/codestra-promotion-check`,
`bin/codestra-promote`, and evidence writers are deliberately not wired yet:
there is no trusted loader to satisfy the contract safely. Their historical
behavior remains unsuitable as proof that this new evaluator is enforced.

## Verification

Run `python3 -m unittest discover -s tests -v` from the repository root.
The initial policy/decision tests failed because the module did not exist.
Negative tests then exposed acceptance of an unrelated lease and an ineligible
reviewer; both were observed failing before their checks were implemented.
Independent review additionally found that one review receipt could be counted
under multiple reviewer names. Regressions reproduced that gap and equivalent
check-receipt reuse, then passed after duplicate receipt rejection was added.
All 25 tests pass after the fixes, including the five existing entry-point tests.
Tests use synthetic internal snapshots and do not exercise live acquisition,
database transactions, GitHub Actions, or protected promotion.

## Remaining Task 2 acceptance

1. Establish the runtime trust boundary using fresh accepted registry and schema
   evidence. Do not accept caller-supplied PASS values or raw snapshot JSON.
2. Adapt all three entry points with required target-base SHA and safe dry-run
   behavior; test the actual command invocation and legacy evidence boundary.
3. Verify the actual candidate through an owned registered lane, installed CI,
   repository protections and eligible independent GitHub approval.

Desktop source synchronization is separately pending after remote timeouts.
Nothing here changes deployed commands, the live database, BREERO refs, provider
activation, or production settings.

## Review disposition

Independent source review found no Critical issue and one Important duplicate
review receipt issue, fixed as above. A Minor remains deferred: a malformed
registry `ScopeEdge` with a non-string, unhashable level raises `TypeError`
instead of a structured denial. It cannot authorize promotion; validate the
trusted registry adapter's schema before runtime integration.

Review limits remain explicit gates: evidence authentication and producer,
review/receipt/codeowner authority must be implemented in the privileged adapter;
live ref race handling belongs at the effect boundary; legacy writers and CLI
enforcement remain incomplete; candidate and transactional certification are
Task 3; actual lease/CI/protection/review/dependency acceptance are external gates.
Treating any of those limits as passed would allow false certification. None is
waived by this source review.
