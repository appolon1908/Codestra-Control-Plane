# Codestra Control Plane

User-designated source repository for shared Codestra development governance,
promotion checks, certification tooling and compatible GitHub status publishers.
Source ownership was approved on October 7, 2026.

## Current state

This candidate adds the pure promotion-policy and decision component described
in [trusted decision preparation](docs/trusted-decision-preparation.md). Its
25 offline tests include malformed/stale evidence, independent review, registered
ref mapping and bound-lease cases. Runtime evidence acquisition and command
integration remain incomplete; the new component is not deployed or enforcing
promotions. PR #1's source adoption remains a prerequisite awaiting acceptance.

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
execution, and exercises the actual promotion-checker CLI for help and missing
arguments with database, socket and subprocess effects forbidden in the child.
It does not certify promotion decisions, PostgreSQL transactions or deployment.
`ci/control-plane-tests.workflow.yml` is an inactive workflow template for the
same offline checks with read-only repository access. Installing it under
`.github/workflows/` is blocked because the desktop credential lacks `workflow`
scope. No GitHub Actions result is claimed.

## Provenance and release gates

- `provenance/import-inventory.json` identifies the 51 captured files and original
  SHA-256 hashes, source paths, exclusions and review limits.
- Git history separates the original snapshot from the syntax repair.
- `governance/source-authority.json` records the source owner and initial task.
- `governance/protection-plan.json` and `governance/main-release-protection-plan.json`
  contain the intended rulesets. GitHub rejected
  ruleset access for this new private repository under the account's current
  plan. The payload is **not applied**; merging and deployment remain blocked.
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
