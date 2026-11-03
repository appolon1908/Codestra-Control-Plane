# Codestra Control Plane

User-designated source repository for shared Codestra development governance,
promotion checks, certification tooling and compatible GitHub status publishers.
Source ownership was approved on October 7, 2026.

## Current state

The owner selected native GitHub Actions and repository protections for all
`appolon1908` repositories on November 2, 2026. The
[migration design](docs/superpowers/specs/2026-11-02-native-github-governance-design.md)
preserves real CI, signed commits, independent reviews and separate production
approval. The rollout is in progress. The target source-acceptance model removes
custom controller and database prerequisites; existing external required
contexts remain blockers until their verified native replacement is applied.
Existing controller source is preserved as historical and runtime implementation,
not a new merge gate.

Eight obsolete source-governance commands now stop with exit code 2 before
loading runtime dependencies or performing any action. They direct operators to
native GitHub checks and protections; they never emit a replacement green status.
See the [retirement guide](docs/source-gate-retirement.md) for the exact commands,
replacement responsibilities and preserved runtime boundaries. This source change
does not modify installed services or repository settings. Guarded publication
to `codestra-local` with exact SHA parity remains required independently of
GitHub source-merge checks.

The inventory covers 120 repositories and 733 open PRs. Some controller-named
checks are genuine native test aggregators; inspect their source and actual
execution before replacing any requirement. Signed successor PRs need new CI
and review even when their complete source tree matches an earlier candidate.

This branch adopts reviewed source snapshots from the development desktop and
repairs the promotion checker's startup syntax error. The import preserves modern
tools at the repository root and older tools under `legacy/`. It does not deploy
them. No certification records, product code, live database schemas or status
publishers have been changed by this source adoption.

The imported commands retain live-effect code and hardcoded deployment paths.
**Do not run them as an installation or promotion procedure.** Product manifests,
runtime state and credentials are deliberately absent. Captured SQL is historical
source, not an executable migration plan for the current database.

## Verification

Run the complete offline suite from this repository:

```sh
python3 -m unittest discover -s tests -v
```

The suite parses every imported Python entry point, checks shell syntax without
execution, and exercises the retired CLIs with legacy arguments, `--apply`, and
unavailable runtime dependencies. Sandboxed children reject database dependency
imports, network/process calls and filesystem writes; every retired command must
return explicit migration guidance and a nonzero exit. Historical callable
functions retain their offline regression coverage.
These tests do not certify a deployed controller or a product release.
`.github/workflows/control-plane-tests.yml` is active and includes mandatory
disposable PostgreSQL tests. Main commit `4836b9833f5738374c78844cdef3bb009ad17664`
passed hosted run `40774730728` with 1,029 tests. This historical baseline is not
a test result for subsequent commits; each PR requires its own current checks.

## Provenance and release gates

- `provenance/import-inventory.json` identifies the 51 captured files and original
  SHA-256 hashes, source paths, exclusions and review limits.
- Git history separates the original snapshot from the syntax repair.
- `governance/source-authority.json` records the source owner and initial task.
- `governance/protection-plan.json` and `governance/main-release-protection-plan.json`
  describe the controller's source protections, applied and read back as rulesets
  26403952 and 26403958 on November 2, 2026. The repository is now public.
- `governance/native-github-baseline.json` adds verified signatures and fresh
  independent review without removing any existing check. Its controller rule
  26405364 and Klyrow rule 26405369 were read back successfully. Portfolio
  coverage and remaining gaps are tracked separately; no global completion is
  implied by this initial pair.
- `docs/repair-progress.md` records executed checks and remaining work.
- `docs/verification/2026-10-07-source-validation.json` records the bounded source
  verification and missing certification gates. It is not a promotion certificate.
- The approved design and execution plan are under `docs/superpowers/`; their
  current status identifies completed source work and the next unimplemented gates.

Existing branch hierarchies organize work. Native GitHub protections govern
source acceptance, including verified signatures, independent review and passing
current-commit CI. Production uses a separate approval boundary. Live
capabilities remain disabled.

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
