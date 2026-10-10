# BREERO Governance Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore a tested, protected BREERO promotion path while preserving both accepted branch histories and keeping live capabilities disabled.

**Architecture:** One trusted decision engine resolves registered logical stages to Git refs, validates immutable evidence, and supplies both required status publishers. Candidate validation is separate from subsection certification. Baseline reconciliation uses merge commits through development; production and main retain their protected squash behavior and record source/result provenance.

**Tech Stack:** Python 3, PostgreSQL/psycopg2, Git, GitHub statuses/rulesets, existing BREERO quality and release checks.

**Spec:** `docs/superpowers/specs/2026-10-07-breero-governance-repair-design.md`

**Recommended execution:** Native implementation in one owned lane, with an independent review after each security-sensitive task and a final integrated review. The tasks share certificate and database contracts; parallel implementation would risk conflicting changes. Read-only investigations and reviews may run in parallel.

## Execution status and prerequisite

This plan was approved for native execution. The user subsequently designated
`appolon1908/Codestra-Control-Plane` as source owner. Source adoption and the
startup repair are implemented in draft PR #1; governed acceptance and the
remaining tasks are not complete. See `docs/repair-progress.md` and
`docs/verification/2026-10-07-source-validation.json` for the bounded evidence.

Verified on 2026-10-07:

- `/srv/codestra/dev-platform/control-plane`, its parent, and `/opt/codestra-dev/control-plane` are non-Git directories.
- No modern parent `AGENTS.md` or historical source ownership declaration was found. The later complete import audit found `/opt/codestra-dev/AGENTS.md` applicable to the legacy directory; its task-scoped hierarchy and no-effects requirements are retained.
- Searches of likely development repositories did not identify the deployed implementation. Indexed GitHub search found a caller in Codestra-OpenBao, not ownership of the shared scripts. The broader filesystem search timed out; absence of a source repository is not proven.
- The deployed `bin/codestra-promotion-check` fails an isolated AST parse with `IndentationError: unexpected indent` at line 41. No deployed script was executed to establish this result.
- BREERO has 33 unstarted subsections, 11 sections, and zero certified sections. The first foundation lease is free; this plan does not claim it.
- A read-only database inventory confirmed that live promotion edges already use `testing`, unlike the checked-in `002-hierarchy-promotion.sql`. The live constraint permits six edges ending at production and has no production-to-main edge.
- `workstations.exact_sha_certified` is nullable with no default, and no user trigger fills it. The deployed workstation certifier's omission therefore is not compensated by a database trigger.
- The live scope-certificate table exists, but no migration/version table was found. Deployment and migration provenance still need to be established rather than reconstructed from filenames alone.

Source ownership is now bound by the user's explicit decision, with original
bytes and hashes preserved at snapshot commit `47ad959`. This adoption does not
reconstruct historical deployment lineage. The startup fix is commit `589dfa9`.
The current candidate is on `atomic/cp-01-foundation--01-source-import` and targets
`subsection/cp-01-foundation--01-source-provenance`. Protection enforcement, an
installed CI workflow, a trusted owned lane, and independent GitHub approval are
still required before acceptance. Never patch the deployed files directly.

In the file map below, **CP** is the root of `appolon1908/Codestra-Control-Plane`,
corresponding to `/srv/codestra/dev-platform/control-plane`; **LEGACY** is `legacy/`
in that repository, corresponding to `/opt/codestra-dev/control-plane`. These are
source paths, not permission to write to deployed paths. All new files listed
under CP are proposed additions unless explicitly completed below.

## Global constraints

- `PRODUCTION_GO=NO`, `LIVE_CAPABILITIES_ENABLED=NO`, and `EXTERNAL_EFFECTS=false`.
- No direct protected-environment writes, force pushes, self-approval, or fabricated certification.
- Preserve the FastAPI, PostgreSQL/PostGIS, Alembic, Redis/Celery, Next.js, and pnpm architecture.
- Preserve `production/environment`; do not create exact `production` or delete historical refs.
- Keep both `codestra-control-plane` and `codestra/control-plane` required wherever currently applicable.
- Preserve both pinned baseline ancestors through candidate, subsection, section, and development **merge** commits.
- Preserve main's squash-only, linear-history, last-push approval, and existing required CI rules.
- Do not change unrelated repositories' effective refs, permissions, statuses, or deployment state.
- Work only in a registered, owned lane. Stop on access denial, conflicting lease, unexpected dirty work, or moved refs; preserve that work.
- Test schema changes in a disposable control-plane database. No BREERO production database migration or live provider effect is included.

## Review focus

1. A stale green status reused after the target base moves must not authorize promotion. Task 2 binds and rechecks both SHAs; Task 6 verifies the final target.
2. A candidate status accidentally treated as certification must not unlock the next stage. Task 3 tests separate operation kinds and distinct result commits.
3. A partial certification transaction must leave no mixture of certified status and stale SHA fields. Task 3 injects transaction failures.
4. A publisher compatibility change must not update another product or disagree between context names. Task 4 tests repository filtering, pagination, and partial publication failure.
5. Squash-created commits and historical `test` mappings must not break future releases or other repositories. Tasks 2 and 6 test logical/ref separation and the next release cycle.

## File map

| Responsibility | Existing source counterparts | Proposed focused additions |
| --- | --- | --- |
| Canonical decision/ref mapping | CP `bin/codestra-github-check`, `bin/codestra-promotion-check`, `bin/codestra-promote` | CP `lib/codestra_control/{__init__,policy,evidence,decision}.py` |
| Candidate and certification persistence | CP `bin/codestra-devctl`, `bin/codestra-section-certify`, `bin/codestra-certify-scope`, SQL schema/readiness files | CP `lib/codestra_control/certification.py`, forward SQL migration selected after schema inventory |
| Evidence ingestion and trust | CP `bin/codestra-promotion-evidence`, `bin/codestra-certify-scope`, promotion-evidence and scope-certificate tables | Trusted evidence loader and negative tests in CP `tests/test_decision.py` and `tests/test_certification.py` |
| Compatible, scoped publishing | CP `bin/codestra-github-statusd`; LEGACY `bin/github-status-sync` | CP `lib/codestra_control/publisher.py` |
| Alias protection | CP `bin/codestra-apply-required-ruleset`, BREERO product/family manifests | CP `lib/codestra_control/rulesets.py` |
| Regression evidence | No tests found in the deployed directory | CP `tests/test_{entrypoints,policy,decision,candidates,certification,publisher,rulesets,baseline_lineage}.py` |
| BREERO contract | `.codestra/repository-profile.yaml`, `.codestra/governance/policy.json`, `AGENTS.md` | A dated baseline reconciliation record in the owning foundation lane |

Do not infer the source repository's test configuration from the absence of deployed tests. Reuse its existing test runner where present. The commands below specify a standard-library unittest fallback for the proposed tests and avoid new test dependencies.

## Task 1: Establish source provenance and restore an executable checker

**Interfaces:** Consumes verified owner repository/commit, applicable instructions, active lease, and deployment/source digest comparison. Produces a compile-clean source patch with a regression that proves the observed failure is fixed; it does not publish statuses.

**Files:** CP `bin/codestra-promotion-check`, `tests/test_entrypoints.py`; provenance record in that repository's evidence convention.

- [ ] Record the owner Git URL, branch, HEAD, parent, worktree state, applicable instructions, deployment digests, and lease. If the deployed content differs from versioned source, preserve and classify each difference before editing.
- [ ] Add `test_all_python_entrypoints_parse_without_execution`: read each Python entry point and call `ast.parse(source, filename=path)`; assert that none raises. The test must never import or run a command that writes a ledger, publishes a status, or opens a PR.
- [ ] Run `python3 -m unittest discover -s tests -p test_entrypoints.py -v` from CP. Reproduce the promotion-check syntax failure against the captured source; distinguish a mismatch from an already-fixed source version.
- [ ] Fix the misplaced indentation of `x.product=canonical_product(x.product)` inside `main()` without changing promotion behavior in this commit.
- [ ] Rerun the parse test and the owner's applicable lint checks. Review the one-purpose diff and commit it in the authorized source lane.

Source-work disposition: the parse regression, indentation fix, shell syntax and
actual CLI regressions are implemented and committed at `589dfa9`. All five
offline tests pass. The checklist remains incomplete as a governed task because
its trusted-lane, required CI, enforcement and independent approval gates have
not passed. Do not repeat the existing fix or treat it as deployment evidence.

## Task 2: Centralize trusted ref mapping and promotion decisions

**Interfaces:** Define frozen `ProductMapping` with `repository`, `product`, `development_ref`, `testing_ref`, `staging_ref`, `production_ref`, and `release_ref`. Define `Decision` with `allowed`, `operation_kind`, and an immutable tuple of `reasons`. `resolve_edge(mapping: ProductMapping, source_ref: str, target_ref: str) -> tuple[str, str]` returns lowercase logical source/target levels or raises `PolicyError`. `evaluate_promotion(request: PromotionRequest, snapshot: TrustedSnapshot) -> Decision` performs no I/O. `PromotionRequest` binds repository, product, refs, source SHA, and target base SHA. `TrustedSnapshot` carries the registered mapping, observed refs, current matching certificates, dependency/lease state, independently retrieved CI/review evidence, and required-gate inventory. Snapshot loading is a separate trusted adapter; untrusted callers cannot supply a successful certificate.

**Files:** CP `lib/codestra_control/{policy,evidence,decision}.py`, all three checker/promotion entry points, `tests/test_policy.py`, `tests/test_decision.py`.

Include `bin/codestra-promotion-evidence` in the trust-boundary review. It currently
inserts caller-supplied PASS fields directly. Such legacy rows and JSON values
must never be upgraded into trusted CI/review evidence merely by being stored.

- [ ] Add `test_breero_effective_edges`, asserting `staging -> production/environment` resolves to `('staging', 'production')` and `production/environment -> main` resolves to `('production', 'main')`. Uppercase certificate scope names remain separate from these logical edge values.
- [ ] Add `test_breero_wrong_refs_and_skipped_stages_rejected`, covering `test`, exact `production`, arbitrary aliases, unknown branches, and development-to-main.
- [ ] Add `test_other_products_keep_registered_refs`: a different registered product using `test` as its effective testing ref remains valid without adopting BREERO's alias.
- [ ] Add `test_promotion_requires_current_bound_evidence`: missing/failed/pending CI, mismatched repository, wrong source SHA, changed target-base SHA, missing independent review, unresolved review threads, missing scope, and incomplete dependencies each block. Required evidence is loaded by a trusted adapter, never accepted merely because a caller sends a `PASS` string.
- [ ] Add `test_legacy_pass_fields_do_not_authorize_promotion`: write historical-style PASS assertions through the evidence-ingestion boundary and prove they cannot authorize a decision without independently retrieved evidence bound to the actual repository, head, base and required gates.
- [ ] Run `PYTHONPATH=lib python3 -m unittest discover -s tests -p 'test_policy.py' -v` and the corresponding `test_decision.py` command; establish failing assertions before implementation.
- [ ] Implement the mapping and pure decision functions; adapt all three entry points to call them. Preserve CLI behavior unless the approved contract requires a new field, and require `--base-sha` for decisions that were previously unbound to the target.
- [ ] Run all policy/decision and entry-point tests. Verify that dry-run evaluation neither connects to a writable database nor invokes a publishing subprocess. Commit after independent review of the fail-closed paths.

## Task 3: Implement candidate binding and atomic certification

**Interfaces:** `register_candidate(connection, binding)` records repository/product/task/workstation, candidate ref/SHA, target subsection/base SHA, and owned lease. `validate_candidate(binding, trusted_evidence)` returns `Decision(operation_kind='SOURCE_UPDATE', ...)` without certification writes. `certify_subsection(connection, receipt)` and `certify_section(connection, receipt)` commit their matching SHA fields and audit evidence in one transaction. A trusted receipt binds observed result SHA, actual remote SHA, checked scope, verified gate/review evidence, and actor; arbitrary JSON success flags are insufficient.

**Files:** CP certification module, three certification entry points/devctl, readiness SQL, a forward migration, `tests/test_candidates.py`, `tests/test_certification.py`.

- [ ] Inventory the live table definitions, constraints, triggers, views, and installed migration history read-only. Copy schema only into the disposable database. Choose the next unused migration identifier from the verified source; do not edit an already-applied migration or guess that checked-in SQL equals live state.
- [ ] Add candidate tests for owned active lease, correct repository/task/subsection, exact source/base binding, missing registration, expired/foreign lease, wrong target, and changed refs. Assert candidate success leaves subsection status and certification fields untouched.
- [ ] Add certification tests for stale remote SHA, missing review/CI evidence, nonmatching `exact_sha_certified`, zero children, uncertified children, and mismatched section/scope SHAs. Inject a failure between updates and assert the transaction leaves no partial certificate.
- [ ] Cover DEVELOPMENT, TESTING, STAGING and PRODUCTION in `codestra-certify-scope`: arbitrary evidence JSON, caller-supplied status strings and historical PASS rows cannot create a trusted environment certificate. Require the same verified immutable receipt boundary as subsection and section certification.
- [ ] Run those tests against a disposable database and capture the expected failures.
- [ ] Add the candidate binding schema and forward migration. Preserve the verified live `testing` edges; do not replay the stale checked-in `test` constraint. Add `('production', 'main')` to the permitted edge set without granting that route to unregistered products. Preserve each product's registered effective ref and existing evidence rows; incompatible historical evidence remains blocked until genuinely renewed. Include a migration test starting from the actual live schema and another starting from the source schema so drift is detected explicitly.
- [ ] Implement atomic certificate writes: subsection `status`, `exact_sha_certified`, and observed `remote_sha` must agree; section state and SECTION scope certificate must identify the same snapshot. Validate all children and the current parent before committing.
- [ ] Run migration upgrade and rollback/forward-recovery checks on the disposable database, the candidate/certification tests, and the owner's applicable database suite. Verify live-effect flags remain false in all fixtures and proposed migration changes. Commit with independent security review.

## Task 4: Publish compatible statuses from one scoped evaluator

**Interfaces:** `publish_decision(github, repository, sha, required_contexts, decision, evidence_url, dry_run)` emits one result to each required context, or returns a dry-run description. It must report a partial publication failure and must not claim all required contexts succeeded. CLI entry points accept `--repository appolon1908/Breero.com` and `--dry-run`; existing scheduled invocation behavior for other products remains covered by regression tests.

**Files:** CP publisher module/status daemon; versioned LEGACY status-sync counterpart; `tests/test_publisher.py`.

- [ ] Add `test_breero_is_discovered_and_subsection_targets_are_evaluated`, `test_repository_filter_never_posts_elsewhere`, and `test_paginated_open_prs_are_all_evaluated`.
- [ ] Add `test_contexts_share_one_decision`, `test_partial_post_failure_is_not_success`, `test_changed_head_invalidates_pending_publication`, and `test_source_update_is_never_labeled_certified`.
- [ ] Add `test_dry_run_performs_zero_writes`, using a fake GitHub client that raises if a POST is attempted; exclude the control plane's own status from the CI inputs to prevent circular self-certification.
- [ ] Run the publisher tests to demonstrate the missing behavior, then implement scoped discovery, shared evaluation, context compatibility, and explicit dry-run support. Do not expand bootstrap exceptions.
- [ ] Make the legacy wrapper delegate to the shared implementation rather than retain a second policy engine. Run publisher and decision regressions together, inspect status descriptions for accurate operation kind, and commit.

## Task 5: Protect the real production ref without removing existing rules

**Interfaces:** `plan_alias_protection(repository, observed_rulesets, effective_ref)` returns exact proposed rule documents plus their observed IDs/update versions; it does not call GitHub. `verify_protection_union(effective_rules)` rejects a missing required status, approval/thread requirement, strictness, squash/linear-history constraint, or force-push/deletion protection.

**Files:** CP ruleset module/application command; BREERO mapping manifests; `tests/test_rulesets.py`.

- [ ] Add tests using captured BREERO rule fixtures: production alias is initially uncovered; proposed updates add only `refs/heads/production/environment` to the appropriate repository-scoped rules; every original rule, target, required check, and bypass list remains unchanged.
- [ ] Test wrong repository, unexpected rule drift, missing required fields, and partial application. All fail closed; an incomplete update must not produce a protection-complete result.
- [ ] Implement payload planning and readback verification. Preserve the existing exact `production` rules even though that ref is absent. Do not alter owner-wide rulesets.
- [ ] Run the ruleset tests and produce a reviewable before/after payload. Confirm authorized administration access and recheck rule versions before applying through the existing governed administrative process. Connector capability limitations are not grounds to switch identities or bypass permissions.
- [ ] Read back both the individual rulesets and effective alias rules. Record verified coverage and retain the before/after audit. If access is unavailable, preserve the tested payload and report this operation as blocked.

## Task 6: Reconcile BREERO and validate the complete governed path

**Interfaces:** Consumes the accepted, deployed control-plane repair and verified alias protections. Produces a genuinely certified reconciled development baseline, with both original baseline SHAs as ancestors, plus a release-provenance rehearsal. It does not enable live features or certify unfinished product domains.

**Files:** BREERO `AGENTS.md`, `.codestra/repository-profile.yaml`, `.codestra/governance/policy.json`, `.codestra/governance/workstations.json` only where required by verified mapping; CP `tests/test_baseline_lineage.py`; the foundation lane's evidence record.

- [ ] Add a temporary-Git-repository fixture with divergent main/development history, a later governance commit, an add/add agent-contract conflict, and a moved parent. Assert importing both pinned tips with merge commits preserves both ancestors; squash at any import leg must fail the ancestor assertion.
- [ ] Extend the fixture through squash release: assert source/result SHA differ, source/result trees match, a target-base race blocks, and the next development cycle imports the new main release-record commit before renewed certification.
- [ ] Run the lineage tests before altering actual BREERO refs. Verify all control-plane tests and a BREERO-scoped dry run pass before deploying the reviewed shared source under its owner's release procedure. Deployment is a separate recorded action, not implicit in test success.
- [ ] Refresh all refs, PR dependencies, and worktree state. Claim `breero-com::br-01-foundation::01-app-bootstrap` only if still free, then pass preflight using the registered worktree and actual repository owner. Do not override a failed access or trust check.
- [ ] Register the atomic candidate, import pinned current main and development, resolve the agent-contract conflict by retaining both sets of applicable requirements, and inspect runtime-file differences. Update only the approved effective-ref and final-release declarations. No #145/#152 application code belongs in this baseline import.
- [ ] Run BREERO's applicable quality/orchestrator checks and full affected backend, migration/drift, contract, frontend, and security gates. Obtain independent current-head review; use the normal candidate-to-subsection and subsection-to-section PRs with merge commits. No premature status or certification.
- [ ] Complete the remaining foundation children in dependency order with real implementation/evidence where needed. Certify the final section and its scope against the identical section SHA, then merge section into development through required controls. Verify both pinned main and development commits remain ancestors.
- [ ] Record result SHA, ancestry proofs, runtime diff, tests, approvals, resolved threads, and certification receipts. Refresh the closure ledger. Prepare the separate provider workflow design from the approved specification's defect inventory; broader staging/canary certification remains blocked by unfinished domain gates.

## Stop conditions and handoff

Stop before implementation if source ownership or its authorized lane remains unverified. Stop a promotion on any failing gate, stale ref, access denial, certificate mismatch, protection gap, or missing independent approval. Preserve completed source changes and evidence without describing the blocked step as done.

The design, native execution method and dedicated source authority are approved.
Continue from the recorded source repair rather than repeating discovery. Source
preparation may proceed within its approved assignment; governed acceptance and
promotion remain blocked by actual protection, CI, lane and approval gates.
BREERO does not own unrelated repositories' shared governance.
