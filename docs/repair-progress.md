# Source adoption and BREERO governance repair

## October 7, 2026: source authority established

The user approved `appolon1908/Codestra-Control-Plane` as the dedicated source
repository. It was created private with GitHub's README initialization commit
`29524563f423fc257569cb8969d60ffda96996b2`. Environment, section and subsection
branches were initialized at that same commit; no application code was promoted.

The initial assignment was source import and checker syntax repair under
`cp-01-foundation / 01-source-provenance`. An isolated atomic-task worktree owns
the implementation. No existing product lease or certification was claimed.

## Source and verification evidence

- Snapshot commit `47ad959` preserves 51 audited files totaling 123,064 bytes:
  30 modern and 21 legacy files. The inventory records original SHA-256 hashes,
  modes, file sizes and modification times. A fresh remote read confirmed all
  51 digests still matched before import.
- A separate implementation commit indents the existing product normalization
  statement inside `main()`. This is the only change to imported runtime code.
- Before the fix, the full five-test suite had four failures, all tracing to the
  known `IndentationError` in `codestra-promotion-check`; shell syntax passed.
- After the fix, `python3 -m unittest discover -s tests -v` passed all five tests
  on Python 3.12.14. `git diff --check` passed.
- The same five tests also passed on the development desktop in its isolated
  source worktree. Independent local review found no issues in the import and fix.
- The CLI tests execute the actual script for `--help` and missing arguments in
  isolated child processes, stubbing the unavailable PostgreSQL import boundary
  and forbidding database, socket and subprocess effects there. Parsing the other
  entry points does not execute their code.

These checks establish syntax and CLI startup only. They do not validate current
database schema, evidence authenticity, promotion decisions or live deployment.

## Decisions and remaining gates

1. Adopt the observed source as a new versioned baseline. Prior source commits and
   deployment history are unknown; import metadata is not reconstructed history.
   Cost if treated as historical certification: unreviewed live drift could be
   accepted. Compare a fresh deployment snapshot before any deployment.
2. Exclude runtime data and product/family manifests from the code import. Five
   product filename pairs collide on case-insensitive filesystems. Cost: this
   branch is not a self-contained installer; configuration ownership and migration
   remain a separate reviewed task.
3. Preserve historical executable modes, including non-executable legacy scripts.
   This import does not install or change host permissions.
4. GitHub returned HTTP 403 for repository rulesets: "Upgrade to GitHub Pro or
   make this repository public to enable this feature." Keep the source private.
   Both proposed protection payloads are recorded but unapplied. No merge,
   certification or deployment is permitted while required enforcement is absent.
5. No trusted control-plane database lease exists for the new source repository.
   The explicit user-approved adoption assignment permits source preparation; it
   does not create a successful status or certificate. Register the source owner
   and obtain a genuine owned lane before governed acceptance.
6. A code review by a local agent is not a GitHub approval. Required independent
   current-head review and CI must be verified before advancing the candidate.
7. GitHub rejected the first atomic-branch push because the desktop OAuth
   credential lacks `workflow` scope. No workflow was installed. Preserve the
   original local candidate at `cb9d16e`; publish a new source-only candidate
   that carries the unchanged workflow as `ci/control-plane-tests.workflow.yml`.
   This is an inactive template, not a check runner. Do not use another identity
   to get around the rejection. Cost: GitHub CI remains unverified until an
   authorized credential installs the workflow through normal review.

The approved six-task BREERO plan remains open: trusted mapping/decision engine,
atomic certification and schema reconciliation, scoped compatible publishers,
production-alias protection and baseline reconciliation still require source
implementation and their own tests. Provider/API/portal closure follows that
baseline. Production and external effects remain disabled.

## Delivery review and publication update

The user requested certification, review and publication of all completed work.
The source suite was rerun successfully against `c0249af` in the local checkout.
GitHub confirmed PR #1 has that head, no merge conflict and zero check runs.
The development desktop went offline after the earlier successful desktop run;
its previous result is historical, not a fresh host verification.

The delivery audit identified two unpublished deliverables: the approved BREERO
design (`bebfb50`) and six-task implementation plan (`96700bc`). They are now
carried under this source owner's `docs/superpowers/`, with origin hashes in the
validation record. Their status text is updated for the adopted source owner.

The audit also identified a material trust-boundary omission in the plan:
`codestra-promotion-evidence` directly stores caller-provided PASS values, and
environment `codestra-certify-scope` accepts arbitrary evidence JSON. Tasks 2–3
now explicitly require negative tests proving neither can become trusted CI,
review evidence or environment certification without independent verification.
This closes a planning gap; the behavioral repair remains unimplemented.

Source validation passes within its tested scope. Promotion certification remains
blocked. GitHub again returned HTTP403 for private-repository rulesets. Workflow
authorization, trusted lane registration and independent GitHub approval remain
unmet. The next engineering task is the trusted evidence/mapping/decision boundary
in Task 2 after an authorized source lane is established; broad provider/domain
closure must not be claimed from this startup fix.

## Task 2 source preparation

The user explicitly approved the next described implementation mission on
October 7, 2026. A separate source-only assignment is recorded in
`governance/source-preparation/task-02.json`. The initial import assignment and
PR #1 remain pending governed acceptance. The single active source implementation
is now `cp-01-foundation / 02-trusted-decisions` in its isolated atomic branch.

Ruling: missing runtime lease, protection and CI stop governed acceptance and
promotion, while repository AGENTS explicitly allows useful source preparation.
The earlier blanket stop on implementation was too broad. This new user-approved
assignment creates no database registration, lease, receipt or certificate.
Cost if confused with governed authority: accepting unregistered work. All those
acceptance gates remain blocked.

The pure mapping and decision portion is implemented with 25 passing offline
tests. They cover bound repository/ref/head/base evidence, registered aliases,
independent eligible review, lease ownership/expiry, malformed input and zero-I/O
evaluation. Two negative assertions exposed an unrelated lease and ineligible
approval being accepted; both failed before their fixes and now pass.

Task 2 is partial. The privileged evidence loader and actual CLI adaptation are
not implemented. Typed snapshots and receipt strings do not authenticate evidence.
No live PASS rows are trusted by the new component, and no existing command calls
it yet. See `docs/trusted-decision-preparation.md` for the remaining trust boundary.

Independent review found duplicate review receipts could count as separate
approvals. Tests reproduced that and equivalent check receipt reuse; rejection
of both was implemented and all 25 tests now pass. One malformed-registry error
reporting Minor remains deferred and is documented in the preparation record.
