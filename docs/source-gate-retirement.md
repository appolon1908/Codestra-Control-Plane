# Obsolete source-gate retirement

The owner's November 3, 2026 request implements the already approved
[native GitHub source-governance design](superpowers/specs/2026-11-02-native-github-governance-design.md).
GitHub Actions and repository protections govern source acceptance. A custom
controller route, database certificate or compatibility status is not an
additional source-publication or source-merge prerequisite.

## Retired entrypoints

These commands refuse every CLI invocation, including `--help`, `--apply` and
their former arguments. They print `RETIRED_SOURCE_GATE` guidance to stderr and
exit **2**, before runtime dependency imports, database access, network calls,
subprocesses or filesystem writes. Refusal is not approval: no synthetic `PASS`,
certificate or successful GitHub status is published.

| Command in `bin/` | Superseded source responsibility | Native replacement |
| --- | --- | --- |
| `codestra-apply-required-ruleset` | Install the external controller status requirement | Preserve actual repository CI requirements and reviewed native protection settings. Never identify an obsolete requirement by ruleset name alone. |
| `codestra-github-check` | Check source SHA against controller database certification | Current-head Actions results, effective branch protection, verified signatures and fresh independent PR review. |
| `codestra-promotion-check` | Record a database promotion verdict and publish `promotion-gate` | Native PR requirements, required tests and review/thread resolution for the exact candidate. |
| `codestra-promote` | Require database certification before opening a source PR | Ordinary reviewed PRs; existing Git protections continue to block unsafe direct writes and merges. |
| `codestra-install-family-governance` | Write repository policy requiring the controller status | Reviewed repository-specific workflow/instruction changes using the native governance design. |
| `codestra-rollout-v3-clean-prs` | Generate and publish controller-dependent governance PRs | Explicit scoped PRs preserving each repository's substantive CI and stronger existing protections. |
| `codestra-rollout-standalone-governance` | Run the legacy family installer and open rollout PRs | The same reviewed repository-specific migration, without executing a bulk legacy installer. |
| `codestra-github-statusd` | Publish controller certification aliases from database/observer evidence | Actual native check runs from their verified producer; no compatibility success status. |

The Python guard is before legacy imports, after any required future import.
The Bash guard uses only builtins. Existing implementation bodies and callable
functions remain for historical inspection and offline/runtime-library tests;
their presence does not recreate a source gate or authorize live invocation.
Other runtime libraries, business APIs and installation tools are unchanged.

## Requirements that remain

Run the real tests for the affected repository. Retain required GitHub Actions
checks, verified signatures, independent current-head review, latest-push
approval, resolved threads, code-owner requirements and stronger existing rules.
For this repository, `.github/workflows/control-plane-tests.yml` runs the genuine
`control-plane-tests` job, including disposable PostgreSQL tests. A job or ruleset
containing the word "controller" may still be a substantive native check.
Do not remove it by name or fabricate a passing replacement.

Before replacing any external required context in repository settings, verify
the native workflow, job, GitHub Actions App identity, exact tested SHA and actual
successful execution. Require its replacement through normal reviewed settings
changes. This source patch applies no settings and does not claim portfolio-wide
migration completion.

The owner's self-hosted publication policy remains in force: use the assigned
isolated worktree, complete meaningful validation and review, commit coherent
work, publish through the guarded publisher to `codestra-local`, and record exact
local/remote SHA parity. GitHub remains the mirror, PR and protected merge surface.
Never push directly to protected branches, force-push or overwrite divergent work.

Source acceptance does not authorize production, provider effects or DNS changes.
Protected deployment approval, immutable artifact evidence, readiness checks,
configuration preservation, DNS validation and rollback safeguards remain
separate. `PRODUCTION_GO=NO`, `LIVE_CAPABILITIES_ENABLED=NO` and
`EXTERNAL_EFFECTS=false` remain unchanged. No installed daemon, controller
database, credential, local publication guard or production service is changed
by this retirement patch. Installing or decommissioning runtime software requires
its own reviewed operational scope.

## Verification

Run the complete offline suite in the documented CI environment: Linux,
Python 3.12, the hash-pinned SQL test driver and PostgreSQL 16. The command is:

```sh
python3 -m unittest discover -s tests -v
```

`tests/test_retired_source_gates.py` exercises the actual eight entrypoints in
sandboxes, including missing runtime dependencies and old arguments. It checks
exit status, migration guidance and absence of attempted effects. Existing
promotion-checker and rollout CLI tests now require refusal; direct function
tests remain. Windows can run the focused retirement tests but cannot establish
the full Linux result: existing tests require POSIX facilities such as `fcntl`.
No controller CLI or live database is used as a verification procedure.
