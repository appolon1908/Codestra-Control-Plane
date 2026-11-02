# Native GitHub source governance

The owner explicitly selected GitHub Actions and repository protections for all
`appolon1908` repositories on 2026-11-02. This supersedes custom controller
admission and database certification prerequisites for source publication and
merging. It does not authorize deployment or live external effects.

The complete read-only inventory contains 120 repositories and 733 open pull
requests. Seven repositories require controller-named contexts, including both
external controller dependencies and genuine native test aggregators. Most other
repositories already require native Actions jobs. A Codestra job or ruleset name
alone does not identify an external controller dependency.

## Source acceptance

GitHub is authoritative for the current branch, commit, pull request, check run,
review, signature and effective protection. Preserve each repository's real CI
contexts and stronger existing rules. Bind native required checks to GitHub
Actions App 15368 only after verifying their producer and successful execution.
Missing checks, failing checks, missing reviews and unsigned introduced commits
remain blockers. A successful checkout or syntax check is not a product test.

Apply an additive native ruleset to default and existing governed branch names:
verified signatures, one fresh independent review, approval of the latest push,
resolved review threads, code-owner review where CODEOWNERS exists, and no
force-push or deletion. This layer grants no bypass and changes no existing CI
requirement. Existing stricter requirements continue to apply cumulatively.
Branch hierarchy remains available for source organization; source-repair PRs
are evaluated by these native protections, without a custom route daemon.

Unsigned existing branches are preserved. Where necessary, prepare a signed
successor from the exact current target base, retaining the reviewed source tree.
Verify GitHub's signature verdict and exact tree OID, including file modes,
symlinks and gitlinks. Obtain new exact-head CI and independent GitHub review.
Never force-push existing reviewed history or transfer approvals to a new SHA.

## Production boundary

Source integration does not approve production. Production workflows must use
protected GitHub environments with independent required reviewers, prevention
of self-review, no administrator bypass and explicit deployment branch policy.
Existing artifact digest, staging, restore and rollback safeguards remain.
Installed runtime commands and services are not retired as a side effect of
removing a source-merge dependency. No workflow is dispatched by this rollout.

## Replacement and verification

For each external required context, record its actual purpose, native workflow,
job, App identity, exact tested SHA and successful check-run evidence. Replace
the external requirement only after this mapping is reviewed and its native
counterpart is required. Preserve substantive native checks even when their
names contain Codestra. Never publish synthetic green compatibility statuses.

The Klyrow development-only static controller aliases and checkout-only
certification status must be retired in a focused source PR. Keep real Klyrow
backend, frontend, contract, image and secret checks. Protect workflow changes
through CODEOWNERS and ordinary reviewed PRs. Public PR tests must not receive
production credentials or run on deployment-capable persistent hosts.

PR78's temporary repair-admission prototype remains draft and is not the
rollout mechanism. Its source and review evidence are retained; no installation
or live certification follows from its tests.

## Rollout state and evidence

Track per repository: observed default SHA; existing protections; proposed
additive rules; actual applied rule ID and readback; CI replacement evidence;
open-PR signature/review/CI blockers; environment protections; and next action.
API errors, unsupported private-plan features, pagination, and unavailable
evidence remain explicit blockers. Repository settings alone do not certify
product behavior or runtime readiness.

Use isolated, exclusively owned worktrees. Preserve all existing local work.
Checkpoint GitHub, Linear PAS-233/PAS-259 (Klyrow PAS-31), Notion and local mission
records. Do not mark the portfolio complete until every claimed repository and
candidate has the required evidence.
