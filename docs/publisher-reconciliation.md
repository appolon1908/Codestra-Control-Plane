# Controller publisher reconciliation

This is a source repair candidate, not an installation or release certificate.
The source-only assignment is in
`governance/source-preparation/task-publisher-reconciliation.json`.

The deployed checker added an exact-SHA, expiring Keycloak exception, but the
publisher still called its three-argument interface. The deployed service
journal confirmed the resulting `TypeError`. This candidate adopts the observed
checker source with SHA-256
`d05a63c47f09b02fe8fdb3a95149ac295c232b62d6734d87918b0007faf97107`.
It preserves the existing Keycloak candidate SHA and October 15 expiry, rather
than replacing deployed policy with an older imported snapshot. Expiry is not
extended and matching remote branch identity remains mandatory.

The publisher now loads its companion checker and passes the exact remote SHA
to the shared policy for every product. Publisher-only blanket bootstrap rules
are removed; an unregistered bootstrap cannot obtain an exception through a
different publisher path. Normal database-derived certification remains required
when the shared policy supplies no exception. This is deliberately stricter than
the old publisher and needs policy-owner review before installation.

Repeated unchanged status publication reached GitHub's per-SHA/context limit.
The candidate reads newest-first remote status history for the exact commit and
compares state, truncated description and target URL for each of the two existing
contexts. Only a missing or changed context is appended. An older success never
overrides a newer failure. Lookup errors, malformed history and incomplete
pagination prevent all writes. A restart or partial dual-context failure needs
no new local database: the next cycle reads the remote outcome again.

The lookup is bounded to 100 pages. Independent publishers can still race or
alternate different verdicts; publisher ownership must be reconciled before
deployment. Deduplication cannot make an already exhausted history writable.
No context rename, substitute success status or protection bypass is proposed.

The subsection source already contains the promotion-check indentation repair;
the installed file still fails syntax parsing. The deployment proposal includes
that existing corrected file with both installed and candidate digests. It does
not include the unapproved live review-bootstrap tool or any database migration.

## Verification

Run the complete no-effect source suite:

```sh
PRODUCTION_GO=NO LIVE_CAPABILITIES_ENABLED=NO EXTERNAL_EFFECTS=false \
PYTHONDONTWRITEBYTECODE=1 python3 -S -m unittest discover -s tests -v
git diff --check
```

Regression tests first reproduced missing SHA-bound policy integration,
publisher/checker disagreement and redundant status writes. They now cover expiry,
remote mismatch, both contexts, changed verdicts, newest-first pagination,
malformed/incomplete history, read failure, and second-context failure followed
by retry. Database and GitHub effects are stubbed; no deployed command is run as
a test. An independent source review is not an eligible GitHub release approval.

## Assignment and deployment gates

Read-only registry inspection found no controller product/workstation row in
`codestra_dev_control` and no controller assignment in the legacy ledger.
The existing source-preparation records explicitly have null database leases.
`codestra-devctl register --root ROOT` imports existing subsection workstation
manifests; it does not register a product. `bootstrap-hierarchy` rewrites a broad,
hardcoded generic hierarchy and is unsuitable as scoped recovery.

An authorized registry maintainer must supply the authentic scoped product and
workstation registration, including actual owner, task, atomic branch/worktree,
parent and prerequisite records. Then the installed claim/preflight workflow can
establish and verify ownership. Do not invent certified dependencies or claim
that this source-preparation assignment is a database lease.

`governance/publisher-deployment-proposal.json` pins the three proposed files and
records rollback requirements. Installation remains blocked until genuine
assignment, independent exact-source/result gates, policy review and explicit
deployment approval exist. No services, installed files, leases, schema,
credentials, protections or product checkouts were changed by source preparation.
