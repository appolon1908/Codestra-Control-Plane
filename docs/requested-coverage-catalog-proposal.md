# Inactive requested catalog proposal

The user requested controller evaluation for 13 named repositories. At canonical
subsection f3a010c21bfa07111f1e7deeeac0f91ef5af1bfd, the publisher contains 43
repositories and excludes six requested names: Codestra-Control-Plane,
codestra-foundation, codestra-ruleset-toolkit, OpenAPI, Codestra-PostgreSQL and
openrerefine-. Earlier statements that Foundation and Toolkit were already in
that catalog were wrong. Their product DB mappings exist independently of the
publisher catalog. Installed coverage is a different six-repository filter.

`governance/coverage-proposals/requested-13-catalog.patch` proposes only those six
additions to `ADDITIONAL_GOVERNED_REPOS`, preserving the original 43 (49 total).
The patch is NOT applied to the source publisher, workflow or installed runtime.
The accompanying bindings JSON records the exact requested scope and leaves real
repository IDs, accepted product receipts, assignments, leases, certification,
publisher ownership and operator approval unverified. All authority/effect flags
remain false. The source-preparation assignment is separate from PAS-233 hooks.

The proposal preserves existing registry filtering: each added name still requires
one exact canonical product/repository mapping, accepted testing spelling and full
promotion chain. It adds no bootstrap exemption, accepted route, authenticated
issuer or certificate. An allowlist entry is not authorization to publish success.

## Exact change and operator gates

Source baseline and canonical/proposed publisher SHA256 hashes and patch digest
are pinned in requested-13-bindings.json. Acceptance requires independent source
scope/binding review. The next actual implementation must have its own reviewed
commit and hashes; this proposal is not an installation receipt. Priority main
PRs remain invalid unless their actual registered promotion path is satisfied.

Before any runtime approval request, independently establish: Control Plane's
missing product mapping; real stable repository IDs and accepted mappings; distinct
restricted authenticated session principals; operator-managed per-product task
assignments/grants; actual owned unexpired leases; genuine exact-head evidence;
and a trusted acquisition/certification/publisher adapter. The currently inspected
shared codestra superuser is not a runtime principal. scoped_registration is absent.
No proposed grant or owner string fills these gaps.

Both installed timers can invoke writers sharing codestra/control-plane. The
operator must accept one issuer/ownership and serialization contract before any
activation; changing coverage does not resolve competing writers or status limits.
Private-repository protection enforcement is also unresolved (rules API HTTP403).

## Proposed deployment impact and rollback (not authorized/executed)

Potential targets are /srv/codestra/dev-platform/control-plane/bin/codestra-github-statusd
and codestra-github-check, plus the independently decided disposition of
/opt/codestra-dev/control-plane/bin/github-status-sync. Expanding scope could cause
new GitHub status writes, including failures, across additional repos. Do not
install this patch or start a daemon merely because source CI passes.

A future reviewed installation plan must pin a final accepted source commit and
staged file hashes, preserve file modes/ownership, and capture these current
rollback baselines before any effect:

- primary publisher: dfbf0c1ba8691e1156657cf6886a53cc878d5ee2ec148eec154c4608eebe697c
- checker: d05a63c47f09b02fe8fdb3a95149ac295c232b62d6734d87918b0007faf97107
- secondary publisher: f7a1fb77dcf2fbc3bdd42514e30ff735ca3fc88529e19a0428748cb99ef62637
- primary/secondary timers currently enabled; alias codestra-github-statusd timer disabled
- both active publisher services last failed; no installed Git revision is established

Rollback must restore the captured bytes, modes/ownership and approved timer/service
states; restarting a writer is itself an effect requiring the accepted operator
plan. Do not automatically revive failed services. Credentials, grants and leases
are separate decisions and are not part of a file rollback. No runtime/schema,
policy, status, credential, grant, lease or PAS-233 lane was changed here.

Offline tests apply the patch only to a disposable copy, verify exact 49-member
union with no removals/duplicates/unknown additions, and exercise real candidate
registry selection against mismatched/duplicate fixture mappings. They establish
source proposal behavior only, not authenticated runtime authority.
