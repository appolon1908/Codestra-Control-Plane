# Scoped Registration Implementation Plan

Goal: add source-only PostgreSQL-authenticated registration interfaces.
Spec: ../specs/2026-10-14-scoped-registration-design.md
Execution: sole assigned implementer, inline, as expressly requested.

Constraints: no live effects; no owner-label authentication; keep legacy interfaces
unwired; registration never grants lease/certification/promotion authority.

1. Write disposable PostgreSQL integration tests that fail on missing migration:
   authentic session vs SET ROLE, product grants, exact immutable registration,
   workstation/candidate separation, task/prerequisite product isolation, revocation,
   dry-run, provenance, retries, simultaneous duplicates and migration compatibility.
2. Add a forward migration with protected grant/assignment/binding/audit tables and
   parameterized registration functions. Test until all integration cases pass.
3. Add a CLI with strict input handling, transaction rollback for dry-run, no owner
   option, and documentation for operator provisioning/rollback and legacy limits.
4. Run the complete offline suite, inspect the diff, obtain independent exact-diff
   review, record results, and publish a draft to the subsection target if allowed.

Review focus: session_user authentication despite role switching; no DML bypass for
runtime; conflicting legacy rows must not be overwritten; concurrent transactions
must serialize; missing prerequisites must not become readiness/certification.
