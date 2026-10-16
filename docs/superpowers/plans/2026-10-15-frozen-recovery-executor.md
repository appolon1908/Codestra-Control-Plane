# Frozen Recovery Executor Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans. Each independent code boundary receives review before publication.

**Goal:** Implement authenticated, incident-fenced recovery of one exact stale-dirty frozen lane without certification or runtime activation.
**Architecture:** A distinct PostgreSQL security-definer API authorizes, reviews, observes and atomically recovers the frozen snapshot. A protected-credential Python client reuses independent Git materialization and rolls back by default.
**Tech Stack:** Python3.12, PostgreSQL16, psycopg2, unittest.
**Spec:** docs/frozen-recovery-executor.md; builds on docs/scoped-frozen-recovery.md.

## Global Constraints

PRODUCTION_GO=NO; LIVE_CAPABILITIES_ENABLED=NO; EXTERNAL_EFFECTS=false. No live database, service, credentials, leases, statuses or protection changes. Existing frozen inspection and ordinary claim rejection remain unchanged.

## Review Focus

- Recreated identities/SET ROLE/trust authentication must deny.
- Frozen-row leave/refreeze with restored timestamps must invalidate old authorization.
- Checkout identity must refer to the frozen subsection, not a new atomic candidate.
- Concurrent recovery, active modern leases and post-consumption audit failure must remain atomic.
- Dry-run output and historical lookup must not confer new authority.

## Task1: Authenticated transactional recovery API

Files: 008-frozen-recovery.sql; tests/test_frozen_recovery_executor.py.
Interfaces: frozen_recovery.authorize(workstation text, checkout jsonb, executor name, reviewer name, verifier name, request text); describe(grant uuid); review(grant uuid,digest text); attest(grant uuid,digest text,observed jsonb); execute(grant uuid,proof uuid,digest text,request text); lookup(request text); revoke(grant uuid,digest text,reason text,request text). All return JSON receipts/descriptions.
- [x] Add disposable SCRAM/TLS fixture tests; reproduce missing migration/API.
- [x] Implement protected policies/permissions, durable incident trigger, grants/reviews/proofs/audit and restricted functions with fixed search_path and no PUBLIC execution.
- [x] Verify exact transition, ABA/replay, authenticated roles, revocation, active-lease denial, one-winner concurrency and rollback (27-test pass plus final seed/expiry/observation verification).

## Task2: Independent verifier and protected client

Files: lib/codestra_control/recovery_interface.py; bin/codestra-frozen-recovery; tests/test_recovery_interface.py.
- [x] Reproduce missing verifier/client composition with offline tests.
- [x] Compose describe -> commit -> independent GitMaterializer -> attest; prohibit raw observations/DSNs through CLI.
- [x] Add fixed protected role credential interfaces, exact request digest, generic failures and rollback unless --apply.
- [x] Verify composition, dry-run semantics, commit failure and source custody checks (12 tests).

## Task3: Review and publish source

- [ ] Run affected and complete offline suites; inspect exact diff and independent security review.
- [ ] Commit and non-force push atomic branch; open subsection PR and attach it.
- [ ] Verify exact-head hosted checks and request eligible external review. Keep runtime admission and Middleware task prerequisites reported separately.
