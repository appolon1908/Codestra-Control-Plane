# Codestra governed section routing — source implementation

The current Codestra Frontend manifest declares eight section branches under
`workstation/ws01-core` through `workstation/ws08-release`. The native controller
uses subsection keys `01-core` through `08-release`. The source resolver previously
rejected all of those declared workstation section paths before checking their
registered scope and certificates. A separate stale branch-existence repair does
not fix this namespace mismatch or establish authority.

## Implemented boundary

The shared reference classifier accepts only the eight explicit Codestra section
names, and only for product `codestra`. A native `subsection/<section>--<subsection>`
may target its exact corresponding workstation section; that section may target
`development`. Existing modern section references remain supported. The same
resolver is used by all three source entrypoints. Workstation/subworkstation
names cannot double as the configured testing environment ref.

This is classification, not an alias rewrite of evidence. The database still must
contain the exact source branch and exact parent, with the required current SHA
and certificates. No scope rows are inserted and no recorded ref or certificate
is relabeled. `workstation/dev-desktop`, `workstation/governance-control-plane`,
unlisted names, other products, cross-section targets and incomplete subsection
names are rejected. Feature/hotfix/governance shortcuts remain rejected.

| Native section key | Existing Codestra section reference |
|---|---|
| 01-core | workstation/ws01-core |
| 02-api | workstation/ws02-api |
| 03-security | workstation/ws03-security |
| 04-deployment | workstation/ws04-deployment |
| 05-observability | workstation/ws05-observability |
| 06-testing | workstation/ws06-testing |
| 07-saas | workstation/ws07-saas |
| 08-release | workstation/ws08-release |

The observed manifest is pinned to Codestra commit
`141471caff8b774a06fa97080acd87419fd8f6e9`, `.codestra/control-plane.yml`.
The labels in that manifest are not themselves operational grants.

## Genuine certification remains separate

Use the already implemented authenticated publisher and assignment-backed lease
issuer in the trusted-decisions subsection. Their accepted operator provenance,
restricted credential-authenticated PostgreSQL sessions, dedicated Apps,
independent issuer receipts, current source/test-merge checks, eligible independent
review, exact bindings, owned leases and target protection are still required.
The historical CLI PASS rows tested here do not become authenticated evidence.
Do not execute legacy commands or use a local test pass to publish a green status.

PR45 still cannot use `governance/dedicated-exact-sha-ci -> development`, and PR56
still cannot use `hotfix/public-ux-api-20261008 -> production`. Their code must be
introduced through genuinely assigned atomic/subsection lanes, matching sections,
and the environment chain. This source change neither retargets those PRs nor
claims that renaming a branch creates an assignment. Product scope splitting,
registration reconciliation and lease issuance require the genuine operator path.
No protected rule, source review, authority row or issuer capability is synthesized.

## Verification and deployment limits

The first regression run against unmodified source produced 48 rejected valid
route assertions and one admitted reserved-environment collision. Additional
review reproduced acceptance of an incomplete alias subsection; that assertion
failed before its correction. Fourteen new tests exercise all three real source
entrypoints with synthetic SQL and blocked network/process boundaries. Nine
existing route regressions remain passing. These are not live certificates.

The desktop full baseline suite timed out. A broader publisher-only discovery also
timed out; its log ended after passing reconciliation tests and before completion.
Neither run is reported as a local full-suite or publisher-suite pass.
Fresh complete GitHub CI for the changed commit is required before acceptance,
as is independent review. The existing subsection-to-section promotion is PR28.
This new atomic branch targets the trusted-decisions subsection, not main.

No installed controller file, database, grant, lease, credential, service, status,
product PR base, deployment or production setting is changed by this source patch.
Runtime installation and its rollback remain separately reviewed operations.
