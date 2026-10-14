# PR9 source conflict reconciliation

PR8 merged into the subsection at
`9ab5690708cd8f72a8379da1121604a95a1f990f`. PR9 compares that head with `main`
at `e99ff6f0b1ac30cd9d591f90630e68c9affe1894`. The observed conflict involves
both `bin/codestra-github-check` and `bin/codestra-github-statusd`.

This atomic candidate integrates those observed parents and keeps both command
files byte-for-byte identical to the subsection's already reviewed controller
repair. That preserves the Keycloak candidate
`777331d8907480977880923c5b012926a7dfc6b8`, its October 15, 2026 expiry, the
four-argument migration interface, remote-SHA checks, exact certificate binding,
status deduplication and rate-limit cycle termination. The older blanket publisher
bootstrap path and three-argument interface from main are not reintroduced.
The still-installed Keycloak exception matches the retained SHA, scope and expiry;
no new exception, repin or expiry extension is proposed.

Main's other source additions are preserved, including its read-only source
workflow and offline verification tooling. Their historical verification files
are source artifacts, not newly issued runtime or promotion certificates.
The inherited continuity tests used the older policy interface and assumed every
publication performed only POST calls. They first failed against the retained
commands. The fixtures now supply the exact SHA and a mocked empty status read;
the policy clock is fixed to the historical review date so expiry is tested
deterministically without extending production policy.

GitHub review `5522153845` is an empty-body APPROVED review by repository admin
`appolon1908` for commit `9ab5690708cd8f72a8379da1121604a95a1f990f`, with no inline
comments. It does not cover this new merge commit and grants no live-policy or
deployment authority. Fresh exact-head review and CI remain necessary.

Publish this candidate as an atomic-to-subsection draft. Governed acceptance must
retain the main-parent ancestry (a normal merge commit or an independently
approved equivalent), or a squash can lose the ancestry that records the conflict
resolution. Recheck the actual subsection result and PR9's live base afterwards.
This preparation does not update PR9's head or target. Its direct subsection-to-main
route still skips section, development, testing, staging and production; a clean
mergeability result cannot authorize that promotion. An approved operator must
route through those stages and renew result-commit evidence. No direct subsection,
environment or main push, service change, registration, lease or deployment occurs
here. The source-only assignment records those limits explicitly.
