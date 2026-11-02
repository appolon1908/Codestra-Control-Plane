# Codestra Control Plane

User-designated source repository for shared Codestra development governance,
promotion checks, certification tooling and compatible GitHub status publishers.
Source ownership was approved on October 7, 2026.

## Current state

The source contains promotion-policy evaluation, authenticated evidence and
publisher integration, assignment-backed leases, scoped admission and offline
regressions. Each component's documentation records its source and runtime
acceptance boundaries; inclusion here does not prove installation or certification.
[PR #1](https://github.com/appolon1908/Codestra-Control-Plane/pull/1) merged into
its source-provenance subsection on October 9, 2026. It is no longer pending.

The current Klyrow proposal is the
[exact, expiring source repair admission](docs/klyrow-repair-admissions-20261102.md)
for five specifically authorized PRs. It preserves independent CI/review and
protection checks and does not activate the installed controller.

The initial adoption imported reviewed source snapshots from the development
desktop and repaired the promotion checker's startup syntax error. It preserves modern
tools at the repository root and older tools under `legacy/`. It does not deploy
them. No certification records, product code, live database schemas or status
publishers have been changed by this source adoption.

The imported commands retain live-effect code and hardcoded deployment paths.
**Do not run them as an installation or promotion procedure.** Product manifests,
runtime state and credentials are deliberately absent. Captured SQL is historical
source, not an executable migration plan for the current database.

## Verification

Run the complete offline suite with Python 3.12, the hash-pinned test driver in
`requirements-ci.txt`, and PostgreSQL 16 available for disposable integration tests:

```sh
PRODUCTION_GO=NO LIVE_CAPABILITIES_ENABLED=NO EXTERNAL_EFFECTS=false \
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

The suite parses every imported Python entry point, checks shell syntax without
execution, and exercises the actual promotion-checker CLI for help and missing
arguments with database, socket and subprocess effects forbidden in the child.
It also exercises policy, evidence, custody and isolated PostgreSQL transaction
boundaries. These tests do not certify a live database, installed controller or
deployment. Active workflows are in `.github/workflows/`; the file under `ci/`
is retained as a historical template. As observed on November 2, 2026,
[main's offline source run 40774730728](https://github.com/appolon1908/Codestra-Control-Plane/actions/runs/40774730728)
passed at `4836b9833f5738374c78844cdef3bb009ad17664`. That result does not cover
this candidate or substitute for its exact-commit hosted checks and review.

## Provenance and release gates

- `provenance/import-inventory.json` identifies the 51 captured files and original
  SHA-256 hashes, source paths, exclusions and review limits.
- Git history separates the original snapshot from the syntax repair.
- `governance/source-authority.json` records the source owner and initial task.
- `governance/protection-plan.json` and `governance/main-release-protection-plan.json`
  contain the intended rulesets. Historical private-repository plan restrictions
  prevented their initial application. On November 2, 2026, the recorded plans
  were applied as active rulesets `26403952` (reviewed promotion) and `26403958`
  (main release record), with no bypass actors. Required current-commit CI,
  independent review and the full effective rule union remain mandatory before
  acceptance; every promotion must recheck current enforcement.
- `docs/repair-progress.md` records executed checks and remaining work.
- `docs/verification/2026-10-07-source-validation.json` records the bounded source
  verification and missing certification gates. It is not a promotion certificate.
- The approved design and execution plan are under `docs/superpowers/`; their
  current status identifies completed source work and the next unimplemented gates.

Branches follow atomic task -> subsection -> section -> development -> testing ->
staging -> production -> main. Their initialization is not promotion evidence.
An independent review, passing current-commit CI and enforced branch protections
are required before acceptance. Live capabilities remain disabled.

The source-only [assignment-backed lease contract](docs/assignment-backed-leases.md)
describes the proposed authenticated issuer, independent materialization verifier,
read-only publisher acquisition and activation boundaries. No runtime setup is
authorized or performed by this source change.

The source-only [controller coordinator](docs/controller-coordinator.md) resolves
approved task metadata, prepares candidate registration and admits a task through
the authenticated lease issuer after independent verification. It is not deployed;
runtime identities, mappings, dependency capabilities and installation still need
separate acceptance.

The source-only [scoped L1/L2 admission API](docs/scoped-operation-admission.md)
adds exact file-mutation and candidate-push intents on top of coordinator leases.
Independent verification, current authority checks and committed one-use
consumption keep source-write and push permission separate. The source client
does not install the API, grant live access, write product files or push them.
