# Scoped L1/L2 Admission Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for integration, with
> independent agents for the SQL authorization and stage-observation components.

**Goal:** Implement authenticated operation-specific L1 source-write and L2
candidate-push admission on top of current coordinator/assignment leases.

**Architecture:** A forward migration stores inactive operator scope grants,
snapshotted intents, independent proofs and one-use consumed outcomes. A protected
stage observer verifies real Git/worktree/remote/dependency evidence; a separate
builder client consumes committed proof. Existing baseline leases stay immutable.

**Tech Stack:** Python standard library, psycopg2, PostgreSQL 16, Git.
**Spec:** ../specs/2026-10-16-scoped-l1-l2-admission-design.md

## Global Constraints

- Source parent c1890bdcc478cf40231087b57f95ba64ff0a7049.
- Own isolated atomic source branch targeting the trusted-decisions subsection.
- No live schema/role/grant/assignment/admission/service/GitHub status changes.
- No force push, self approval, certification, new-ref bootstrap or merge effects.
- Default rollback and no usable dry-run receipt.
- Existing baseline snapshot checks and other worktrees remain untouched.

## Review Focus

- Source-equivalent net diffs must not hide out-of-scope intermediate commits.
- Grant revoke/re-enable, role recreation and lease renewal must invalidate stale snapshots.
- Verifier privilege/capability changes after attestation must deny consumption.
- Unknown commit response must not produce another usable intent or repeated effect.
- SQL authorization is not a filesystem/remote-ref atomic fence.

### Task 1: Real operation authorization

Files: 010-scoped-operation-admission.sql; tests/test_scoped_admission_sql.py.
Interfaces: request/describe/attest/consume/inspect defined in the spec; exact
description and observation JSON fields shared with Task 2.

- [x] Write positive/cross-stage SQL tests against disposable coordinator fixtures.
- [x] Run and record failure for missing scoped operation authority.
- [x] Implement protected grants/revisions/intents/proofs and current authority checks.
- [x] Add identity, scope, freshness, revocation, replay, rollback/concurrency denials.
- [x] Run the affected real PostgreSQL/TLS suite; record all cases executed.

### Task 2: Independent stage observations

Files: lib/codestra_control/admission_materialization.py;
lib/codestra_control/lease_materialization.py; tests/test_admission_materialization.py;
tests/test_materialization_git_safety.py. Review required shared Git transport and
object-integrity hardening while preserving existing admission conditions.
Interface: StageMaterializer(observer, host=machine_identity,
filesystem_anchor=None).inspect(description) -> exact observation JSON in spec.
Reuse GitMaterializer and GitHubLeaseObserver, never weaken their baseline flow.

- [x] Write real temporary Git tests for in-scope L1 and exact clean L2 candidate.
- [x] Observe expected failure for absent staged materializer.
- [x] Implement safe local identity, all-commit scope and remote/dependency rechecks.
- [x] Add rename/delete/revert, dirty/symlink/submodule/filter, ref drift/error denials.
- [x] Run the affected temporary Git suite.

### Task 3: Protected client and delivery

Files: lib/codestra_control/scoped_admission.py; bin/codestra-admission;
tests/test_scoped_admission_cli.py; custody inventory in publisher_startup.py;
README.md; docs/scoped-operation-admission.md; source-preparation record.

- [x] Test rollback default, distinct builder/verifier custody and unknown consumption commit.
- [x] Implement protected request/verify/consume/inspect orchestration and exact error handling.
- [x] Update code custody for the new immutable modules and executable.
- [x] Integrate Tasks 1/2 interfaces and document online consumer obligations/limits.
- [x] Run affected tests and full normal/python3 -S suites with PostgreSQL 16 available.
- [x] Independent whole-branch review; fix actionable findings and rerun affected checks.
- [x] Commit exact source, ordinary push and draft atomic-to-subsection PR.
- [ ] Attach PR and record exact validation and unresolved deployment/admission gates.

Executed source validation is recorded in docs/verification/2026-10-16-scoped-operation-admission.json. Publication checkpoints are recorded by the source PR; none grant runtime authority.

PR #46 initially exposed a hosted test-discovery import error masked by the local library PYTHONPATH. The test modules now bootstrap their own resolved repository lib path. Both CI-equivalent full commands pass 575 tests without a library PYTHONPATH override; executed commands are in the validation record.
