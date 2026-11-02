# Klyrow exact source repair admission proposal

PAS-31 continues the user's request to repair the Klyrow PRs. On 2026-11-02,
the user explicitly authorized preparing the narrow exception change for
196/197, then separately authorized the three added entries 186–188.
This change is source preparation only; nothing is installed or activated.

The compiled admission table contains exactly these requests, both in
`appolon1908/klyrow.com`, expiring **2026-11-03T22:10:00Z** (exclusive):

| PR | Head branch | Head SHA | Base branch | Base SHA |
| --- | --- | --- | --- | --- |
| 196 | `repair/pr195-main-sync-20261102` | `8f5490cd3e636613c2aecc227a22041231c3c35c` | `development` | `3cf2ccd0d511d50d14f96aabaccaacfbb03250b9` |
| 197 | `repair/pr194-staging-sync-20261102` | `de4a52f0578d89667ac6ccec8a5d210712722dea` | `staging` | `09bcb9addc26460b727c7bea0872db09a299ab56` |
| 186 | `implementation/klyrow-ses-transport-20261008` | `e6f7faf6ecd499542aca17689a1a568042b9e14e` | `main` | `45a94da2628974fd45224b821a26653580a36c20` |
| 187 | `implementation/klyrow-ses-feedback-sqs-20261008` | `6600b94cc3b1401f48a4e423815d64eb8c55cd25` | `implementation/klyrow-ses-transport-20261008` | `e6f7faf6ecd499542aca17689a1a568042b9e14e` |
| 188 | `implementation/klyrow-ux-api-route-certification-20261008` | `8e37a9995f19c849362d2e27f1d1df3da37b4ac7` | `implementation/klyrow-ses-feedback-sqs-20261008` | `6600b94cc3b1401f48a4e423815d64eb8c55cd25` |

For either admission, both local-origin identity and live remote branch SHAs
must match. The live open, non-draft PR must match all five identity fields
and its exact PR number, with both repositories matching (no fork substitution).
The checker independently reads GitHub evidence; caller-provided evidence,
booleans, files and CI lookalike controller contexts cannot grant admission.

All nine required GitHub Actions checks (App 15368) must have completed with
`success` on the exact head SHA: `contracts`, `frontend`, `test`, `secrets`,
`image`, `repository-foundation`, `deploy-readiness / source-ci`,
`deploy-readiness / deploy-readiness / source-ci`, and
`deploy-readiness / deploy-readiness / secret-scan`. A newer failure or pending
check does not inherit an older success. Neutral/skipped checks do not pass.

GitHub must report the PR approved. At least one latest substantive review must
be an exact-head approval from an eligible human repository writer other than
the PR author. Dismissal, changes requested, an old-head approval, a bot or
self-approval does not satisfy this condition. All review threads must resolve.
API failure, malformed/incomplete inventory or duplicate pagination denies.
Both refs, PR identity and expiry are checked again after evidence collection.
The transport is pinned to `github.com` and only permits GET or the two fixed
GraphQL review/thread queries. Effective protection is read independently:
the nine App-bound checks, strict checks, stale-review dismissal and thread
resolution must remain enforced with at least one approval and no bypass actors.
The complete effective protection observation must remain unchanged through
collection. The existing last-push setting is preserved on development/staging;
main's enabled last-push approval rule is mandatory for the three-member stack.

PRs 196/197 must be standalone: any native stack membership denies their
admission because a stack could target another environment. PRs 186–188 must
be one open native stack containing exactly those three open, non-draft,
unmerged PRs in that order with the pinned heads and bases. Each member must
independently satisfy every CI/review/thread condition. The ultimate protected
base must be main at the pinned SHA. The complete stack and one main protection
snapshot are re-read after all member evidence; any drift denies the group.

Stack response fixtures follow the GitHub REST stack resource and PR.stack
membership shapes. [GitHub's stack API documentation](https://docs.github.com/en/pull-requests/reference/stacked-pull-requests-apis-and-webhooks)
specifies asynchronous group merge and late rule evaluation. The integration
operator must request the entire group through top PR188, with squash and
`bypass_rules=false`, and poll the final result. A status cannot constrain a
future client's merge parameters: admission is not a merge request. Partial
stack merges, rebase/force-rebase and bypass are outside this authorization.
If GitHub rejects the existing merge-based history, preserve the branches and
seek separately reviewed ordinary PR integration with renewed exact admission.

## Integration and remaining gates

`codestra-github-check` and the compatibility publisher's `validate` function
consume the same admission implementation, before the historical migration
policy. An unsuccessful listed repair is denied explicitly. Other repositories,
branches and normal promotion/certification routes retain their existing policy.

The source `codestra-github-statusd` main function uses the authenticated
publisher. That path still requires independently accepted authority bindings,
custody, exact certification and receipts; this patch does not grant or synthesize
them and does not switch its entrypoint to the compatibility publisher. The
installed legacy controller is also unchanged. Consequently, merging this
source proposal alone cannot make an installed controller publish success.

Required next steps are independent review and hosted checks for this exact
controller candidate, acceptance through its atomic-to-subsection PR, then a
separately authorized operator adoption plan for the actual controller version.
That plan must preserve shared-SHA conservative outcomes and ownership, deploy
the shared admission policy consistently, and recheck the listed repairs'
current GitHub evidence within the expiry window. If acceptance/installation
cannot finish before expiry, a new explicit owner-approved exact request is
required; the code must not extend the deadline automatically.

This source patch changes no database registration, lease, certification record,
status, timer, service, protection rule, production alias or production route.
Separately, the coordinator applied the controller's recorded protection plans
and bound Klyrow main's four legacy required checks to GitHub Actions App 15368,
preserving the existing rules. README records the controller protection checkpoint.
No successful
controller status is claimed. After PR196 merges, the resulting development
SHA still requires genuine DEVELOPMENT certification for PR195 -> testing.
PR194's production-alias gap remains a separate unresolved boundary.

## Verification

Offline tests cover positive exact admissions, wrong repository/head/base,
changed remote refs, expiry including expiry during collection, every required
CI context, eligible current independent approval, resolved threads, API errors,
pagination errors and both entrypoints. They use synthetic evidence and forbid
database/publication effects. Test results and exact candidate SHA belong in the
review handoff; passing local tests do not substitute for independent approval.
The existing controller source workflow explicitly checks out the PR head SHA
(or the push SHA on push events), aligning its required status with the commit
under review. The checkout pin, permissions and mandatory test suite are preserved.
