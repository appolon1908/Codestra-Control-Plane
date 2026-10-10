# Fleet self-certification: Kong, Caddy, Keycloak, OpenBao

Date: 2026-10-09 UTC. Scope: exact remote-main commits and selected source
security/contract tests only. Not production, runtime, release, or merged-PR
certification.

Repository | Main SHA | Results
--- | --- | ---
Kong | 8a0d522fa20e72af1bc466e45a4b336e5be2c5fe | 17 passed
Caddy | be131c15993e1abf23a63d1e5e9d6fa7183e6dfd | 28 passed, 2 skipped
Keycloak | d9db059c23f20255134828bb924137eaa0b9adb4 | 44 passed
Codestra-OpenBao | eafd0b9f47fee7e0d5276c1c4416764025d6767d | 14 passed

Source certificates and their SHA-256 checksums are held in
docs/verification/fleet-20261009/manifest.json.

The source verifier is scripts/self_certify_fleet.py. It matches clean Git
HEAD and remote main SHA, verifies the canonical origin and pinned container
digest, then runs an allowlisted test profile with Docker --network none,
a read-only source mount, read-only container filesystem and disabled
production/external effects. Evidence is written outside the checkout,
never overwriting existing evidence.

Caddy skipped cases require runtime-adapted Caddy JSON or binary evidence.
The profile is limited and does not certify live ingress, real Keycloak
tokens, runtime OpenBao custody/unseal, production TLS, or upstream
deployments.

At the time of checking the exact baseline commits, GitHub recorded a
failed Kong release-evidence check and failed Caddy secret-scan and
immutable-candidate checks. No failing Keycloak checks appeared in the
retrieved snapshot, but full production CI was not established. OpenBao
returned no main-commit check runs. These local passes are NOT GitHub
required-check successes.

No protected branch was changed, no secret material was accessed, and no
provider was activated. Independent review and CI remain mandatory.

STAGING_GO=NO
PRODUCTION_GO=NO
