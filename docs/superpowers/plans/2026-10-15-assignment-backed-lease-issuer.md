# Assignment-backed Lease Issuer Implementation Plan

**Goal:** Fill the verified missing authenticated lease issuer without provisioning or issuing live leases.
**Authority:** Explicit user directive, executed by the existing Control Plane source owner.
**Baseline:** merged PR26,6b3284fc0dd3bb1e451abc0a0eb75f7c9d48c5e2.
**Architecture:** PostgreSQL security-definer API authenticates session_user/OID against operator records; exact assignment/materialization binding and mandatory operator policy. An independent verifier observes real filesystem/Git/remote evidence and authenticates its attestations through a separate restricted DB principal. Builders cannot write proofs, policy, assignments or lease tables. Source CLI defaults to rollback.

## Constraints and decisions

- No schema installation, role/credential/grant/assignment changes, live leases, runtime activation, protected-branch changes or PAS233 access.
- New SQL requires existing scoped_registration and registered product/workstation/candidate records. Operator-owned rows bind actual repository ID, refs/fullSHAs, normalized Linux path, host, UID and Git common directory.
- Lease/renewal/maximum-lifetime/materialization-age limits are mandatory operator policy; no accepted numeric defaults.
- Proofs require a distinct authenticated verifier and actual directory/Git/remote observations; caller booleans, owner strings, legacy PASS rows and fixture types confer no authority.
- Serialize shared workstation/path claims, consume proof once, preserve monotonic fencing and audit. Expired/revoked leases never renew/recover automatically.
- Dependency records require independent online issuer-bound exact receipts; absence/failure denies. Lease issuance is not certification or permission to perform unrelated effects.

## Tasks

1. Write failing disposable PostgreSQL tests for assignment authentication, proof separation and exact binding; implement007-assignment-leases.sql with operator policy, proof store and claim/lifecycle functions.
2. Write failing real temporary Git/worktree tests; implementlease_materialization.py with protected paths, actual HEAD/branch/origin/common-dir/cleanliness, independently observed remote refs/repo IDs and dependency receipts.
3. Implement source verifier and builder CLI composition with protected authenticated connections; dry-run rollback default, no legacy --agent path or default live DSN. Test lifecycle/negative/concurrency cases.
4. Integrate authoritative read receipts into source contracts; document supported Linux-only materialization, consumer fencing/races, install validation and nondestructive rollback proposals.
5. Serialize affected/full tests; skip discretionary review per explicit user instruction; retain required repository gates; ordinary push/draft PR only after checks. Record exact source revision/test evidence; runtime assignment/lease/certification remain null.

## Review focus

Role recreation/SET ROLE spoofing; revoked grants/assignments and changed hierarchy; reused/expired/mismatched materialization; two concurrent claimants; stale epochs/renewal replay; expired dependency receipts; mutable filesystem/ref observation race and downstream fencing limitations.
