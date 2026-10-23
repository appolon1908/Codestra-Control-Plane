# Required Linear History Compatibility Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this source-only repair with test-first verification.

**Goal:** Observe GitHub required_linear_history without rejecting an otherwise valid protected promotion or weakening any gate.

**Architecture:** Keep exact ruleset source, active enforcement, empty bypass and rule/detail matching before interpreting the rule. Treat the documented parameter-free rule as an additional GitHub-enforced history restriction; retain it in the evidence digest. Unknown rule types and unsupported parameters continue to deny.

**Tech Stack:** Python 3.12, unittest, read-only GitHub REST observations.

**Spec:** Existing effective_protection.py contract, publisher-certifier-integration.md, the user's controller repair request, and GitHub's required-linear-history documentation.

## Global Constraints

Source preparation only. No live database, credential, ruleset, service, lease, certification or status mutation. Preserve PRODUCTION_GO=NO, LIVE_CAPABILITIES_ENABLED=NO and EXTERNAL_EFFECTS=false. Atomic branch targets the registered trusted-decisions subsection, never main. A source-task record is not a runtime assignment or lease.

## Review Focus

- Missing check producer bindings must still deny.
- Missing CODEOWNER/review/strictness requirements must still deny.
- Missing or nonempty bypass evidence must still deny.
- Rule/detail mismatches and unknown rule kinds must still deny.
- Adding or removing linear history must change the evidence digest.

## Task 1: Preserve linear-history protection in effective observations

Files: lib/codestra_control/effective_protection.py; tests/test_effective_protection.py; docs/authenticated-publisher-source.md; governance/source-preparation/task-linear-history-protection.json.

- [x] Read current source, verify no duplicate open controller repair PR, and create an isolated atomic worktree from 01975301098c60ebe578084a8a05c9bb6335419a. Existing 12 effective-protection tests pass.
- [x] Add regressions for supported linear history, missing gates, unknown parameters, unsupported rules, bypass and provenance mismatch.
- [x] Run the focused suite before the implementation; capture the expected unsupported-rule rejection.
- [x] Add the narrow parameter-free linear-history observer case after provenance verification.
- [x] Correct the related guide's obsolete classic-only and unbound-producer wording.
- [x] Run focused and full source suites; inspect the diff and retain actual results.
- [ ] Commit and publish only the atomic branch, open a subsection-targeted PR, and request independent review. Do not merge or claim runtime clearance.

## Verification limits

The full local source-suite attempt timed out (exit 124) and logged a failure in test_assignment_leases.AssignmentLeaseTests.test_concurrent_distinct_claims_have_one_winner before termination. This is not a passing full suite; a separate unchanged-base comparison is recorded outside Git. Source publication is a draft for hosted validation, not merge or certification. A separate read-only text review found no actionable correctness/security defects; it is not a GitHub approval.
