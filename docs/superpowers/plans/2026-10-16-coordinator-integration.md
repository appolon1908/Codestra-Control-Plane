# Coordinator integration repair

The user requested continued clean implementation and updated PRs. PR42 and
PR43 are merged, but their tests install the two 009 migrations independently.
The builder resolver rejects the inspector's SUBSECTION prerequisite type,
its JSON timestamps inherit caller timezone while the issuer uses UTC, and its
credential checks do not bind the original authenticated identity to session_user.
The CLI can also expose a cleanup exception after printing a success result.

Use the existing atomic-to-subsection source route and isolated worktree. This is
a bounded integration fix, not runtime deployment or new admission policy.

## SQL composition

Files: 010-controller-coordinator-integration.sql;
tests/test_coordinator_integration.py.

- [x] Reproduce SUBSECTION rejection and timezone mismatch with both 009 migrations in one disposable PostgreSQL 16/TLS/SCRAM server.
- [x] Reproduce SET SESSION AUTHORIZATION builder/verifier impersonation, invalid stored proof provenance and omitted configured dependencies.
- [x] Add a forward migration, preserving both009 files, existing ACLs and all durable rows. Require exact SCRAM session binding and canonical UTC on the five coordinator functions.
- [x] Match the complete unique current public workstation dependency inventory to registered CERTIFIED exact-SHA SUBSECTION prerequisites and active independent receipts. Never synthesize missing authority. Preserve operator-approved SECTION/environment prerequisites; inspector v1 continues to deny extras.
- [x] Verify prepare -> independent proof -> admit -> atomic inspection across timezones, denied stale/revoked evidence, rollback and current receipt recovery.
- [x] Reproduce stale dependency admission in higher-isolation snapshots and require READ COMMITTED for direct coordinator SQL callers.

## CLI cleanup

Files: lib/codestra_control/controller_coordinator.py main only;
tests/test_controller_coordinator_cli.py.

- [x] Reproduce close errors leaking diagnostics or printing success first.
- [x] Close before printing success, suppress secondary cleanup errors and preserve the unknown-commit recovery marker.
- [x] Run focused CLI tests without credentials/network/database access.

## Shared dependency observation

Files: lib/codestra_control/lease_materialization.py;
tests/test_lease_materialization.py; atomic inspection's thin scope wrapper.

- [x] Reproduce stale source/target refs and ref movement during successful receipt reads.
- [x] Require both exact dependency refs around the receipt in the shared independent verifier; reuse it from inspection without duplicate reads.
- [x] Run the affected observer/inspection tests; retain the documented proof-age and later-effect reacquisition limits.

## Review and publication

- [x] Update the operator-facing source contract with migration order, compatibility and remaining adoption requirements.
- [x] Complete independent whole-change review and affected local tests; record exact results.
- [ ] Commit/push the atomic candidate and open its canonical subsection PR.
- [ ] Require full hosted no-effect source/merge-result tests on the published SHA; update PR42/PR453 with verified source progress.

No live installation, schema/role changes, authentication maintenance, task
registration, lease issuance, certification, successful status publication or
promotion is authorized by this source record. Other owners retain the active
authentication-maintenance handoff. PRODUCTION_GO=NO;
LIVE_CAPABILITIES_ENABLED=NO; EXTERNAL_EFFECTS=false.

Prepublication validation: 18 combined SQL regressions and 38 affected client/observer tests passed. The full 529-test run under TMPDIR=/dev/shm had one existing test that hardcodes /tmp as its mocked writable ancestor; that unchanged test passes with its normal temporary directory. Full normal-environment hosted source and merge checks remain required after publication. Original 005, 007 and both 009 migrations are unchanged.
