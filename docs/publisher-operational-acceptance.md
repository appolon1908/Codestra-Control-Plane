# Publisher operational acceptance

The authenticated publisher is implemented in source. Merging that source or
preparing its offline candidate does not install it, authenticate an operator,
accept credential custody or certify a repository. Keep those checkpoints
separate in the private operational handoff.

The [PR24 cutover guide](approved-publisher-cutover.md) is a historical record.
Its statements about an unimplemented adapter and pending PR22 source work describe
that earlier preparation. The successor implementation and its contracts are
documented in [authenticated-publisher-source.md](authenticated-publisher-source.md).
Historical review or CI evidence does not establish review of a later source SHA.

## Record distinct checkpoints

| Checkpoint | Required evidence | Limits |
| --- | --- | --- |
| Source published | Exact commit, permitted source/target refs, PR and observed merge state | A merge is not a submitted independent review or a runtime installation. |
| Candidate prepared | Exact committed bytes, manifest hashes/modes, pinned dependency and artifact verification | The generator keeps release, installation and activation approval false. |
| Runtime installed | Separately approved cutover and rollback record, verified installed files, interpreter/import custody and dependencies | Matching files do not accept credentials, issuer authority or publication. |
| Operational authority accepted | Authenticated principals, accepted credential custody, actual issuer capabilities, exact bindings and genuine assignments/leases | Nomination, metadata, fixture rows and a successful connection alone are insufficient. |
| Controller result established | Fresh independently acquired evidence and genuine issuer-bound receipts for the exact request | Source CI or a manually asserted success is not controller certification. |

## Complete the private operational handoff

Keep secret values and live operational evidence outside Git. Record accepted
reference or receipt IDs, accountable owners and acceptance state for each item.
An empty field remains unresolved; a proposed designation is not custody acceptance.

| Area | Required accepted references and observations |
| --- | --- |
| Database target and clients | Exact instance/database and network path; affected active, scheduled and dormant clients; authentication policy and cutover scope. |
| Bootstrap/operator authentication | Separately accepted administrative identity and credential custody; valid credentials succeed, while missing and invalid credentials are rejected under the selected policy. Plain `trust` without server-side client-certificate authentication does not verify a client credential. |
| TLS | CA/issuer, certificate and server name; verified server identity on the actual client path. Server TLS does not authenticate the database client. |
| Recovery | Private backup receipt, tested restore procedure, independent recovery access, rollback boundaries and approved maintenance/cutover plan. |
| Publisher runtime | Separate restricted PostgreSQL principal and reviewed read-only grants; actual App/installation, signing custody, issuer identity/capability and protected startup configuration. Do not reuse the bootstrap administrative role. |
| Code and process custody | Approved root-owned source/import tree, interpreter, site packages/bytecode, pinned driver and Git/OpenSSL dependencies; service identity/isolation, precreated lock and private ledger location. |
| Authority and request evidence | Operator-owned authority/read-model provenance; exact repository/PR/ref/SHA bindings, genuine authenticated assignments/exclusive leases and independent issuer receipts. |

Inspect the complete HBA rule, including options: PostgreSQL permits `clientcert`
verification on any `hostssl` record. See the [PostgreSQL 16 HBA documentation](https://www.postgresql.org/docs/16/auth-pg-hba-conf.html).

`RestrictedRegistry` requires equal session/current roles and a non-null
PostgreSQL `system_user`, together with its privilege, TLS and binding checks.
That source guard does not itself approve an authentication method, identity
mapping, credential custodian or runtime principal.

The startup contract requires exactly seven configuration fields: `app_id`,
`installation_id`, `certificate_app_id`, `certificate_name`, `app_key_file`,
`database_dsn_file` and `ledger_file`. See the successor source guide for their
types and custody requirements. A template or a nonempty receipt string is not
accepted operator configuration or authenticated provenance.

## Continue through the governed route

Run source tests and obtain eligible independent review on the final source SHA.
Follow the repository's atomic-to-subsection-to-section and environment promotion
chain. An earlier merge outside that chain does not change the contract.

Before any installed write, a separately approved operator must verify writer
quiescence, private rollback capture, the exact approved manifest and target
custody. Copying files used by a scheduled service can change behavior without a
restart. Schema, role/grant, credential, HBA/TLS, dependency and service changes
require their applicable explicit scope and acceptance; the candidate generator
performs none of them.

After an approved installation, verify installed bytes and actual authenticated
runtime observations independently. Publication remains unavailable until all
applicable authority, policy, protection, review, binding, lease and issuer gates
are met. Preserve denied or unavailable results; do not replace missing evidence
with a CI alias, a manual status, a fabricated lease or an automatic reseal.

This document grants no installation, provisioning, activation, status publication
or merge authority. Preserve `PRODUCTION_GO=NO`, `LIVE_CAPABILITIES_ENABLED=NO`
and `EXTERNAL_EFFECTS=false` while the applicable acceptance gates remain open.
