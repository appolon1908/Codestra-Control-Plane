# Coordinator Atomic Inspection Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development for the SQL boundary and superpowers:executing-plans for coordinator composition. Preserve the user's explicit automatic execution instruction.

**Goal:** Implement executable authenticated inspection of registered atomic candidates without fabricating admission or weakening promotion gates.

**Architecture:** A restricted SQL read API resolves actual mappings and current assignment leases. A protected read-only coordinator independently observes Git/GitHub and reacquires all authority before returning a non-bearer observation.

**Tech Stack:** Python3.12, PostgreSQL16, psycopg2, existing GitMaterializer and PR40 effective-protection helpers.

**Spec:** docs/superpowers/specs/2026-10-16-coordinator-atomic-inspection.md

## Global Constraints

- PRODUCTION_GO=NO; LIVE_CAPABILITIES_ENABLED=NO; EXTERNAL_EFFECTS=false.
- No live database tests, installation, credential reads, provisioning, status writes, lease issuance or merge.
- Atomic branch targets subsection/cp-01-foundation--02-trusted-decisions.
- Existing publisher/promotion files and other owners' worktrees remain untouched.

## Review Focus

- Authenticated admin impersonation through SET SESSION AUTHORIZATION must deny.
- Empty declared prerequisites must not hide configured workstation dependencies.
- Read-only App tokens must have every inspection permission and no write authority.
- Expiry or metadata changes during external observation must deny on reacquisition.
- No output or exception may expose DSNs, keys or HTTP/database bodies.

## Task1: Restricted SQL read API

Files: 009-atomic-inspection.sql; tests/test_atomic_inspection_sql.py.
Interface: atomic_inspection.inspect(binding_uuid uuid) -> jsonb with schema,
lease, product, section, workstation, candidate, dependencies, required_workstations.

- [x] Write disposable real SCRAM/TLS tests for genuine active receipt, role/capability independence, map/lane drift, omitted dependencies, subsection registration and read-only execution.
- [x] Run focused tests and record missing implementation failure.
- [x] Implement the forward registration-validator extension and restricted read API, without seeding authority.
- [x] Run focused SQL tests, including registration/issuer composition, timezone regressions and historical snapshot preservation.

## Task2: Read-only coordinator and CLI

Files: lib/codestra_control/atomic_inspection.py;
lib/codestra_control/atomic_inspection_github.py;
bin/codestra-inspect-atomic; tests/test_atomic_inspection.py.
Modify only the dependency scope whitelist in lease_materialization.py.

Interfaces: AtomicRegistry.acquire(binding_id) -> server description;
AtomicInspector.inspect(binding_id, pr_number) -> non-bearer observation;
InspectionGitHubClient.authorize_readonly(...) -> single-repository read token.

- [x] Write tests for concrete composition, canonical routing, receipt mismatch, final drift/expiry, required check/review/protection validation and secret-safe CLI failures.
- [x] Record meaningful failures before implementing each boundary.
- [x] Implement fixed protected configuration, custody check, independent materialization, complete online checks and fresh reacquisition.
- [x] Verify scope-token requests and no status/ref/table mutations.

## Task3: Reviewable source handoff

Files: docs/coordinator-atomic-inspection.md;
governance/source-preparation/task-coordinator-atomic-inspection.json.

- [x] Record source assignment with null runtime admission/lease/certification.
- [x] Run affected local suites, inspect complete diff and complete independent security review.
- [ ] Commit and push exact atomic head; open canonical PR and request eligible review.
- [ ] Run the full offline suite in hosted exact-head and merge-result jobs; report actual unresolved operational gates.

The full 482-case suite is executed by the existing hosted no-effect workflows,
after publishing the locally verified atomic candidate. This avoids duplicating
slow disposable SQL suites while still requiring complete exact-head validation
before any source integration claim.
