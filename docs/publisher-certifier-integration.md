# Publisher and independent certifier source integration

This source preparation connects three separate trust boundaries: protected
operator acceptance, actual independent GitHub identity/receipt observations, and
the controller's authenticated exact-binding publication. It proposes the new,
uncreated Codestra Controller Publisher and Codestra Scope Certifier Apps. It
does not create, install, activate or accept either one. See the concrete
[action-time approval and rollback packet](publisher-certifier-action-time-approval.md).

The publisher uses `/etc/codestra/control-plane/authenticated-publisher.toml`
after designated-service and precreated-lock checks. Its proposed successor
schema retains `app_id`, `installation_id`, `certificate_app_id`,
`certificate_name`, `app_key_file`, `database_dsn_file`, `ledger_file`, and adds
`producer_acceptance_file`, `repositories` and `certifier_observer_socket`.
The repository list narrows startup discovery and accepted authority to
`appolon1908/codestra`; it does not accept all repositories in the source catalog.
The template's zero IDs deny before database access. It contains no enable flag.

The protected `codestra.producer-acceptance.v1` record names actual publisher and
certifier App/installation IDs, actual pilot repository ID, accepted operator,
two distinct independently accepted custody references (`custody_receipt` for
publisher only and `certifier_custody_receipt` for certifier only), the independent
certifier-capability reference, both controller contexts,
`scope-certification`, bounded timestamps and the 300-second receipt age limit.
Its template remains `PROPOSED` with zero App/installation IDs and empty acceptance
references. Pilot repository ID `1319808791` uses the existing authenticated
2026-10-16 17:37:38 UTC metadata; recording that known identity accepts no grant.
Root-owned metadata alone does not convert a proposal into an accepted record.
An authenticated acceptance process must accept the actual private evidence.
Missing, empty or equal custody references deny; no joint receipt substitutes for
separate acceptance of these independent credential custodians.

The production provenance verifier must reread that protected record on each
verification and query actual GitHub state online. Acceptance lasts at most
24 hours; observation age at most 300 seconds. It validates the exact
repository/PR/ref/head/base binding, independent issuer and controller contexts,
and returns a `VerifiedProducerContract` only while the protected acceptance,
upstream authority and independent issuer remain current. No caller JSON, actor
label, legacy PASS row, fixture receipt or environment toggle supplies authority.
Revoked, expired, altered, malformed, stale or unavailable observations deny;
there is no cached-valid fallback.

The publisher must never possess the certifier private key. The separately
protected certifier observer accepts only its reviewed public-metadata operations
over a root-owned Unix socket with verified root server peer and a verified
dedicated publisher caller peer. The proposed caller is the new, uncreated
`codestra-publisher` OS account; provision and accept its isolation separately.
The fixed
`/etc/codestra/control-plane/certifier-observer.toml` has exactly `app_key_file`,
`producer_acceptance_file`, `socket_file` and `publisher_user="codestra-publisher"`;
actual identities come from the same protected accepted policy. The certifier
key is `root:root 0600` for the separate root custodian. It performs
whitelisted identity, installation and repository-installation GETs using the
separate custodian. It returns public observations and never exports a token/JWT,
accepts a caller-chosen URL, issues a scope check or writes a status. The proposed
observer template is a proposal, not an accepted configuration or service unit.
The source server creates only the socket after its directory is approved and
preprovisioned; it never starts automatically. Installing that process, socket
and isolated custody requires separate approval.

The runtime proposal installs only exact manifest files into the immutable,
root-owned `/opt/codestra-control-plane/releases/<SOURCE_SHA>` tree. The separate
approved unit drop-in would run the existing designated service as
`codestra-publisher:codestra-publisher` with
`/usr/bin/python3 -I -B /opt/codestra-control-plane/releases/<SOURCE_SHA>/bin/codestra-github-statusd`.
No user/group, release directory or unit change is installed by source preparation;
the placeholder must resolve to the approved exact commit before execution.

The independent certifier adapter is a separate source composition point for
issuing a genuine scope-certification check receipt. Its own restricted trusted
authority acquisition must independently establish the exact request, actual
lease, required checks/reviews and current protected target/merge-result. The
publisher cannot certify itself or relabel ordinary CI as the issuer. The adapter
must not consume its own existing scope receipt as evidence for initial issuance;
the first-issuance authority path needs independent acceptance and must refuse
when unavailable. A helper port or synthetic test alone is not a deployed issuer.

`012-scope-assignment-leases.sql` adds a separate source protocol for genuine
operator-assigned scope/environment leases, leaving atomic assignment semantics
unchanged. The builder's `claim(uuid,uuid)` requires actual SCRAM/TLS provenance,
session-role/OID ownership and an accepted product claim grant. Assignments bind
current registered scope or environment edges, repository ID and exact SHAs;
atomic/hotfix shortcuts deny. A claim is exclusive, one-shot and bounded to five
minutes or the earlier operator authority expiration. An independent restricted
product reader calls `scope_assignment_leases.inspect_binding(uuid)` in a
read-only `READ COMMITTED` transaction, requires its actual OID grant, and receives the current
`ONLINE_DATABASE_RECEIPT`. The first-issuance acquisition port must match that
receipt's `ACTIVE` state, lease ID, positive epoch, owner and every binding field.
Expired/revoked or changed bindings never automatically renew or reseal.
Only one assignment may be active per product/source ref, and only one `ACTIVE`
lease may fence that source scope across all assignment IDs and owners. Expiry
does not release either static fence. An operator must explicitly deactivate the
old assignment and revoke its retained lease before a newly assigned task can
claim the same scope. Old receipts then remain non-`ACTIVE`; history is preserved.
Operator-only schema/grants/assignment provisioning and first scope check issuance
remain separately unapproved Phase B actions, not effects of source integration.

The concrete first path uses empty `013-first-certification-pending.sql` on the
011/012 foundations and the administered `build_first_certifier_service` factory.
Its new proposed PostgreSQL roles are `codestra_publisher_ro`,
`codestra_scope_certifier_ro` and Ralph-private `codestra_scope_builder`, with no
accepted OIDs or credentials. The reader roles receive only their exact table
SELECT and scope inspection; the builder receives only claim execution and its
operator product/assignment grant. The certifier root custodian has a separate
`root:root 0600` DSN at `/etc/codestra/scope-certifier/credentials/certifier.dsn`
and private `root:root 0700` ledger directory
`/var/lib/codestra-control-plane/certifier`, with files/sidecars `0600`.
The existing `codestra` bootstrap identity remains a separate candidate.

An authenticated pending delegation cannot override the canonical registered
child inventory. Sections require all subsections, development all sections, and
later environments their immediate predecessor; registered cross-subsection
dependencies must also match. SUBSECTION first issuance denies any actual atomic
task or registered candidate because atomic child receipts remain unsupported.
No eligible first binding is selected: PR/ref/head/base and delegation fields
remain empty, and PR56 hotfix→production is explicitly ineligible. Once a valid
binding is accepted, the separately approved first effect is one genuine scope
check plus readback; publisher binding registration and each controller status
remain separate later effects. See the packet's
[concrete first-issuance bundle](publisher-certifier-action-time-approval.md#concrete-first-issuance-bundle-still-blocked)
and the [six-step certifier source proposal](certifier-existing-receipt-source.md#concrete-first-issuance-operational-proposal).

After issuance, the publisher independently reads the actual check-run by ID and
requires the expected independent App, check name, successful completed state,
head SHA and exact binding digest. It reacquires authority and leases and checks
the head/base, current merge-result checks, reviews, conversations and effective
branch protection at every relevant effect boundary. Effective ruleset evidence
requires visible empty bypass actors. Missing bypass visibility under
administration read denies; the integration does not broaden permissions.

`publisher_installation.prepare_installation_packet` packages only the four
fixed committed proposal templates into a new private directory with source SHA,
SHA256 hashes and false install/activation flags. The separate release candidate
packager stages committed runtime code and the pinned driver. Both manifests must
refer to the approved final source commit before a separately approved cutover;
neither packager writes an installed path or invokes a service or database.

Local source tests establish only the tested source behavior: committed-blob
packaging, default refusal, scope and identity validation, revocation handling,
and synthetic transport/receipt verification. They do not accept App creation,
credential custody, live database authentication, target dependencies or issuer
capability. Record source/test evidence separately from installed-runtime and
operational-authority evidence.

The paired statuses remain non-atomic and issued installation tokens can outlive
local acceptance revocation until issuer expiry. Durable partial/uncertain
intents require operator reconciliation, with no automatic retry or reseal. A
downstream merger independently verifies the current protected target and
merge-result; this integration never merges or creates refs. Phase B is
postponed, database setup remains unapproved, and all live capability flags remain
off pending the separate action-time acceptance described in the packet.
