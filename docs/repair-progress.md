# Source adoption and BREERO governance repair

## October 7, 2026: source authority established

The user approved `appolon1908/Codestra-Control-Plane` as the dedicated source
repository. It was created private with GitHub's README initialization commit
`29524563f423fc257569cb8969d60ffda96996b2`. Environment, section and subsection
branches were initialized at that same commit; no application code was promoted.

The active assignment is source import and checker syntax repair under
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
