# BREERO baseline and promotion repair

Date: 2026-10-07

Status: design approved on 2026-10-07. The user designated
`appolon1908/Codestra-Control-Plane` as source owner; source adoption and the
checker startup repair are implemented in its draft PR #1. Full governance
implementation, governed certification and deployment remain incomplete.

## Outcome and scope

Restore one executable, auditable route from BREERO development work to a certified release record on `main`. Preserve both existing baseline histories, the effective production namespace, current review requirements, and dark capabilities. A green status must mean that the real checks ran against the identified commit.

The user approved continuing with `main` as the final certified release record after production. This specification makes that decision concrete against the protections and implementation actually present. It supersedes the direct-to-main routing in the 2026-09-19 consolidation design for future repair work; that document remains historical evidence.

The first implementation project is governance and baseline repair. Provider API and portal defects are recorded as the next dependent project below. Neither project constitutes completion of messaging, documents, payments, integrations, analytics, or staging/canary activation.

## Evidence snapshot

Repository authority: `appolon1908/Breero.com`.

| Reference | Observed commit | Meaning |
| --- | --- | --- |
| `main` | `5992759bfb8bc63fe030cefbfcac0a3024c35c78` | Accepted code baseline; protected |
| `development` | `b68a4b9a9cc56eef08e91aee7012e178dfa8329e` | Includes governance PR #153; protected |
| `testing` | `5992759bfb8bc63fe030cefbfcac0a3024c35c78` | Protected; a matching commit alone is not testing certification |
| `staging` | `a5fc9921cbd6b71f83f1660fc505f02316572256` | Older protected baseline |
| `production/environment` | `5992759bfb8bc63fe030cefbfcac0a3024c35c78` | Existing effective production ref; branch listing reports unprotected |
| `production` | Absent | Exact name conflicts with the existing `production/*` namespace |
| `section/br-01-foundation` and its three subsections | `c356848f0b0f7be7d156fe9c5feacd4f56cc391d` | Existing foundation lanes, preceding #153 |
| PR #152 | `1ec81b374cd953c9c65530f8cecb09937df4965e` | Provider/API/portal candidate with unresolved defects |
| PR #145 | `5d3d39688db0f62f0540b37471f2366d49680e22` | Source of recoverable provider portal components and tests |

`main...development` is diverged: development is five commits ahead and 38 commits behind, with merge base `a5fc9921cbd6b71f83f1660fc505f02316572256`. The development-only changes add repository profile, integrations, governance policy, workstation declarations, and a replacement `AGENTS.md`. Retargeting feature PRs to development without reconciliation would discard the accepted runtime baseline from their target.

The production alias is already declared in development's `.codestra/repository-profile.yaml` as `effective_lifecycle.production: production/environment`. Do not create exact `production`, delete the alias, or describe the entire production reference as missing.

Refresh these facts before execution. Dates and commit identities in this section are observations, not reusable certification.

## Existing protection contract

The effective contract is the union of applicable rulesets, not the most permissive rule.

| Target | Required statuses | Review and history constraints |
| --- | --- | --- |
| `main` | `quality`, `orchestrator-contract`, `codestra-control-plane` | One approval; stale approvals dismissed; approval after last push; resolved threads; strict base checks; squash only; linear history; no force push or deletion |
| `development`, `testing`, `staging`, `section/*` | `codestra-control-plane` and `codestra/control-plane` | One approval; stale approvals dismissed; resolved threads; strict base checks; merge or squash permitted; no force push or deletion |
| `subsection/*` | `codestra-control-plane` | Required on creation and updates; no safe assumption that an unchecked initial push is permitted |
| Exact `production` | Both control-plane statuses | Combined rules require one approval, resolved threads, squash only, linear history, no force push or deletion |
| `production/environment` | None of the four observed rulesets match | Protection gap; must be closed before promotion |

Rulesets: [22202166](https://github.com/appolon1908/Breero.com/rules/22202166), [22208362](https://github.com/appolon1908/Breero.com/rules/22208362), [24625086](https://github.com/appolon1908/Breero.com/rules/24625086), [24623812](https://github.com/appolon1908/Breero.com/rules/24623812).

## Selected architecture

### Logical stages and effective references

Keep the approved logical order: subsection, section, development, testing, staging, production, main. Resolve stage names centrally before comparing Git refs.

| Logical stage | Effective ref |
| --- | --- |
| Subsection | Registered `subsection/<section>--<subsection>` |
| Section | Registered `section/<section>` |
| Development | `development` |
| Testing | `testing` |
| Staging | `staging` |
| Production | `production/environment` |
| Release record | `main` |

Every checker, promotion command, publisher, schema constraint, repository policy, and operator instruction must use this mapping for BREERO. Preserve other repositories' existing registered mappings and test them for regression. The certificate scope remains `PRODUCTION`; the Git ref is `production/environment`. Do not substitute `test` for `testing`, and reject arbitrary aliases supplied by an untrusted PR.

`main` is a release-tree record under its existing squash-only policy. Its result commit will differ from the certified production commit. Preserve an audit mapping containing repository, source ref, source SHA, source tree, target base SHA, PR, resulting SHA/tree, certification references, checks, and independent review. Require the result tree to equal the certified source tree; reject a changed target base before merging and renew evidence. Verify post-merge checks. Do not claim same-SHA promotion or full production ancestry on `main`.

### Baseline reconciliation

Reconcile in the existing foundation lane, with a valid exclusive lease and an owned, clean worktree. Worktree access or ownership failures are blockers; do not alter Git trust configuration, filesystem ownership, or access controls to get past them.

The candidate must contain both pinned `main` and pinned `development`, including #153. Since the existing section and subsections precede #153, import both histories into the foundation candidate; importing only main would omit the newest governance changes. Resolve the `AGENTS.md` add/add conflict by retaining the repository-specific engineering and safety rules alongside the governed-development contract. Review other conflicts individually.

The accepted candidate must satisfy all of these conditions:

- Both pinned baseline SHAs are ancestors of the candidate.
- Main's runtime files are unchanged unless an explicitly reviewed governance integration requires a change.
- Development's repository profile, workstation registry, integration declarations, and governance contract are retained and made consistent.
- The accepted main API/schema baseline is not replaced by the older staging tree.
- No unrelated open PR implementation is included in this baseline change.

Promote the candidate through its assigned subsection and section. Require merge commits for this baseline import at candidate-to-subsection, subsection-to-section, and section-to-development; those targets currently permit merge commits. Squashing any of these legs would defeat the requirement that both original histories remain ancestors of reconciled development. Complete the foundation children in their declared order, each based on the current parent and with genuine evidence; do not mark the other children complete solely to unlock the section.

Before the section-to-development PR, certify the final section snapshot in the authority consumed by the GitHub checker. A section ledger row alone is insufficient if the checker reads `scope_certifications`. The promotion must reject mismatched section and scope SHAs.

### Source updates and promotion certification

There is a real circular prerequisite today: subsection writes require a status, while the certification path first expects the pushed subsection SHA. Do not solve this by issuing premature certification or disabling the required status.

The proposed repair distinguishes candidate validation from promotion certification. Use an atomic-task candidate branch associated with one existing subsection lease. Its purpose is to publish immutable code for CI and review, not to create an alternative environment or promotion lane. Registration must bind repository, product, task, candidate branch and SHA, assigned subsection and base SHA, and lease. The trusted control plane records these values; it must not infer authorization from a prefix supplied by the author.

A candidate PR into its assigned subsection receives `codestra-control-plane` only when its immutable head, current parent, lease, permitted scope, dependencies, genuine applicable CI, and independent review satisfy the source-update contract. This step does not certify the subsection. After the accepted subsection result SHA is observed and validated, obtain subsection certification for subsection-to-section promotion.

Checks must distinguish these two operations explicitly in their recorded decision evidence. Candidate validation is never recorded as `CERTIFIED`. Publisher routing must support subsection targets and publish their required context. Reject task branches targeting a section or environment directly, unregistered candidate branches, expired leases, changed base/head SHAs, and missing CI or review. Preserve the existing required status on subsection targets throughout.

This candidate mechanism is a proposed implementation change, not a claim that the existing control plane already supports it. Implement and test it in the control-plane owner's governed source repository before using it for BREERO. Do not patch a live script in place or manually fabricate status/ledger success.

### One decision engine, compatible publishers

Use one decision engine and one authoritative certificate model. During this repair retain both required status names and publish the same evaluated result to each context where it is required. Do not delete the older ruleset or remove either status as a shortcut.

Repair these observed disagreements:

- The persistent hyphen-context publisher's repository set excludes BREERO.
- The older slash-context publisher does not handle main as a target and does not understand the final production-to-main edge.
- The shared GitHub checker accepts a logical production-to-main edge, while the promotion command and checked-in edge schema stop earlier.
- The checked-in schema uses `test` while the BREERO profile uses `testing`.
- Section certification writes section state, while the GitHub checker consumes scope certification state.
- The checked-in workstation certifier sets status and CI/review results without explicitly setting `exact_sha_certified`, although section readiness consumes that field and the GitHub checker consumes `remote_sha`. Inspect live triggers/schema, then make all three consumers require the same genuinely certified SHA; do not assume file inspection proves the live database behavior.
- The apparent indentation defect in `codestra-promotion-check` must be confirmed with compilation and fixed if reproduced.

The owner repository must contain the changes and their tests before deployment. The live database schema and promotion edges must be inspected read-only before choosing a forward migration. A checked-in SQL file is not proof of the live schema.

Existing explicit bootstrap exceptions are historical behavior, not evidence that ordinary promotion works. Do not add wildcard bootstrap exemptions or general success for governance branch names.

### Protect the effective production ref

Extend BREERO's repository-scoped production and control-plane rules to include `refs/heads/production/environment`, retaining their existing targets and protections. Do not widen owner-wide policy or change another repository. Verify the resulting effective union before any promotion. The target contract must include both control-plane statuses, strict current-base validation, independent approval, resolved threads, no force push/deletion, and the current production squash/linear-history constraints.

Read-only GitHub connector access does not provide ruleset administration. An authorized administration capability is an execution prerequisite for this operation. Never switch identities to evade a denied permission, and never leave a partially applied protection change represented as complete.

### Fresh evidence after every ref change

Merge, squash, base synchronization, and conflict resolution create new evidence obligations. Certify the actual resulting target SHA before advancing it. After a main squash release, import that new main commit into the next development cycle through the governed lane; otherwise subsequent strict-base checks can become unsatisfiable. If any base check requires incorporating a newer target, perform that synchronization in an authorized lane and repeat applicable checks and certification. Tree equality is useful provenance but does not replace exact-commit evidence.

## Scope boundaries and error behavior

- `PRODUCTION_GO=NO`, `LIVE_CAPABILITIES_ENABLED=NO`, and `EXTERNAL_EFFECTS=false` remain in force.
- No payments, payouts, automatic assignment/confirmation, provider dispatch, live email/SMS, Odoo writes, production database changes, or staged activation are included.
- No direct writes to protected environment refs, force pushes, protection bypasses, self-approval, or fabricated evidence.
- Do not run a publisher that updates every repository as part of a BREERO-only validation. Use a dry-run or a scoped operation with tests first.
- Dirty worktrees, changed head/base commits, lease conflicts, missing approvals, inaccessible administration, failed checks, or mismatched certificates stop promotion and produce a specific blocker.
- Roll back faulty code through a reviewed revert or forward fix in its owning lane. Do not rewrite accepted history or remove protections to recover.

## Required verification

The implementation must prove the following with executable tests and captured current-head evidence:

1. A synthetic divergent Git fixture preserves both baseline ancestors through candidate, subsection, section, and development merges; a conflicting policy file cannot silently discard either contract.
2. Every valid mapped edge is accepted only with the correct lease/certification; skipped stages, wrong parent, BREERO's incorrect `test` or exact `production` refs, arbitrary aliases, stale SHA, missing review, and incomplete dependencies fail. Other products' registered mappings retain their behavior.
3. Candidate-to-subsection validation never creates subsection certification. Subsection certification only refers to the observed accepted result SHA.
4. Workstation status, `exact_sha_certified`, and observed remote SHA agree; section ledger and scope certification agree on the exact final section SHA. Partial writes and stale child state do not yield success.
5. Both status contexts report the same decision. BREERO is included without publishing statuses to unrelated repositories during tests.
6. Python entry points compile; SQL migrations preserve existing rows and constraints, add the mapped final edge safely, and are exercised on a disposable database.
7. Effective production-alias rules contain the complete required union. No existing main, environment, section, or source protection is removed.
8. Squash promotion records different source/result SHAs with identical source/result trees; a changed tree, target-base race, or stale certification fails. Importing the release-record commit for the next cycle requires renewed evidence through the normal lane.
9. Applicable BREERO quality, orchestrator, backend, migration, OpenAPI, frontend contract, dependency/security, and review gates pass on the reconciled candidate. A documentation-only result cannot stand in for this baseline verification.

Success means the normal lane can advance real, tested work with genuine statuses and preserved history. A specification, installed policy file, merged bootstrap PR, or published success status alone is not completion.

## Next dependent project: provider API and portal

After the baseline is accepted, use #152 as a source of unique implementation and #145 as a source of missing components/tests. Do not merge either wholesale or restore obsolete browser bearer-token storage.

The next design must cover all of these defects together before calling the provider workflow complete:

- Runtime endpoint registration: 19 unmatched operations and conflicting `GET /provider/jobs` and `GET /provider/availability` registrations. Preserve the existing array response contracts; give new object-shaped views distinct canonical paths and update consumers.
- Schema registration: import provider availability and qualification models in both Alembic metadata and the schema-drift loader. Align readiness revision with the accepted migration head, presently missing the new 032 revision in #152.
- Dark safety: the offer-decision service can persist assignments and booking confirmations. Apply an executable fail-closed capability boundary; registry metadata alone is insufficient.
- Authorization: qualification review must enforce the intended global/brand authority or vendor scope, rather than accepting a permission string with unrestricted record lookup.
- Portal dependency closure: recover nine section components, shared UI/helpers, fixtures and tests; mount the partner app and stylesheet; retain the newer cookie-authentication design.
- Cross-origin CSRF: use the existing credentialed `/auth/csrf` contract for unsafe requests rather than assuming the API's host-only cookie is readable by the portal origin.
- Idempotency: new create commands need the applicable command/idempotency guarantees and readback/audit tests. Do not label unenforced guarantees as enforced in the registry.

Prove startup/OpenAPI uniqueness, legacy response compatibility, negative tenant/role access, dark-state no-write behavior, PostgreSQL migration/drift/readiness, concurrency/idempotency, and the actual portal browser flow. The wider closure queue remains open until each owning domain has its own evidence-backed disposition.

## Source references

- [Main baseline](https://github.com/appolon1908/Breero.com/commit/5992759bfb8bc63fe030cefbfcac0a3024c35c78)
- [Baseline comparison](https://github.com/appolon1908/Breero.com/compare/main...development)
- [Development profile](https://github.com/appolon1908/Breero.com/blob/b68a4b9a9cc56eef08e91aee7012e178dfa8329e/.codestra/repository-profile.yaml)
- [Development governance policy](https://github.com/appolon1908/Breero.com/blob/b68a4b9a9cc56eef08e91aee7012e178dfa8329e/.codestra/governance/policy.json)
- [Governance PR #153](https://github.com/appolon1908/Breero.com/pull/153)
- [Provider candidate #152](https://github.com/appolon1908/Breero.com/pull/152)
- [Provider component source #145](https://github.com/appolon1908/Breero.com/pull/145)

Control-plane observations came from read-only inspection of
`/srv/codestra/dev-platform/control-plane` and `/opt/codestra-dev/control-plane`.
Those deployed files were not modified or executed to publish statuses. Their
source was subsequently adopted into the user-designated
`appolon1908/Codestra-Control-Plane`, with digests in the import inventory.
Historical deployment lineage remains unknown. Reverify live schema and source
freshness before implementing migrations or deploying any repair.
