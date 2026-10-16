# Publisher and certifier integration implementation plan

**Goal:** Wire an operator-accepted producer contract and fresh authoritative GitHub
receipts into source startup, keeping absent operational acceptance unavailable.

**Architecture:** A protected acceptance file pins separate publisher and certifier
Apps. A separate local credential custodian exposes only three read-only GitHub
identity observations over a protected UNIX socket. The publisher never receives
the certifier key, JWT or installation token. Existing independently authenticated
scope certifications can be transported by a separate certifier adapter.

**Spec:** Ralph's source-only single-host publisher approval, current
`docs/effective-protection-and-publisher-provenance.md`, and implementation/helper
authorization relayed on 2026-10-16 at 18:40–18:45 UTC. No first-certification
database authority has been supplied; legacy PASS records cannot fill that gap.

## Constraints

- Isolated atomic source work only; root is integration lead and sole source owner.
- No installed writes, identities, credentials, grants, DB operations, service or
  timer actions, successful statuses, leases or runtime activation.
- `PRODUCTION_GO=NO`, `LIVE_CAPABILITIES_ENABLED=NO`, `EXTERNAL_EFFECTS=false`.
- Acceptance defaults to PROPOSED with zero IDs in examples. No fabricated trust.
- Explicit pilot scope: `appolon1908/codestra`; retain independent repository authority.
- Phase B remains postponed; sole designated merge owner remains unchanged.

## Sections and checks

1. **Publisher Integration** — `publisher_integration`, isolated
   `publisher-receipt-integration-20261016`: implement strict protected acceptance
   decoding and independent online producer verification. Test mismatched IDs,
   revoked acceptance/installations, stale certificates and exact binding drift.
2. **Certifier Integration** — `certifier_integration`, isolated
   `certifier-integration-20261016`: transport existing independently authenticated
   scope receipts using a separate App and durable intents. Missing authoritative
   acquisition denies; never manufacture a first certification from CI.
3. **Configuration and Rollback** — `configuration_and_rollback`, isolated
   `configuration-and-rollback-20261016`: proposed templates, exact action-time
   approval and committed-byte candidate preparation. No installation or activation.
4. **Startup and Integration** — root, existing isolated worktree: source-only
   read-only custodian IPC, startup composition, explicit pilot inventory scoping,
   integrated verification and independent section review.

Each section writes its assignment, runs relevant regression tests, and commits.
Root integrates the commits, verifies the complete offline suite, obtains review,
and publishes an atomic-to-subsection PR if GitHub permissions permit. Review and
source CI do not establish controller certification or installation acceptance.

## Review focus

- Broker cannot forward arbitrary paths, write methods or return secrets.
- Publisher cannot read the independent certifier key or receive its JWT.
- Missing/revoked acceptance denies before inventory or status effects.
- Pilot inventory cannot expand beyond both configured and accepted scope.
- An existing certification adapter must not imply a first-certification authority.

## Progress

- Separate worktrees and named sections established from main
  `2d312d3a63adcb06694aa66e1b72601f11e7dac3`.
- Native worktree creation reported `Not a git repository` from the installed
  working directory; Git worktree fallback used for helpers. Existing integration
  worktree reused; previous branch and local commit preserved.
