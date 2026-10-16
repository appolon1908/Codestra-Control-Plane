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
Its template remains `PROPOSED` with zero IDs and empty acceptance references.
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
over a root-owned Unix socket with verified root server peer and verified
`sentinelx` caller peer. The fixed
`/etc/codestra/control-plane/certifier-observer.toml` has exactly `app_key_file`,
`producer_acceptance_file`, `socket_file` and `publisher_user="sentinelx"`;
actual identities come from the same protected accepted policy. The certifier
key is `root:root 0600` for the separate root custodian. It performs
whitelisted identity, installation and repository-installation GETs using the
separate custodian. It returns public observations and never exports a token/JWT,
accepts a caller-chosen URL, issues a scope check or writes a status. The proposed
observer template is a proposal, not an accepted configuration or service unit.
The source server creates only the socket after its directory is approved and
preprovisioned; it never starts automatically. Installing that process, socket
and isolated custody requires separate approval.

The independent certifier adapter is a separate source composition point for
issuing a genuine scope-certification check receipt. Its own restricted trusted
authority acquisition must independently establish the exact request, actual
lease, required checks/reviews and current protected target/merge-result. The
publisher cannot certify itself or relabel ordinary CI as the issuer. The adapter
must not consume its own existing scope receipt as evidence for initial issuance;
the first-issuance authority path needs independent acceptance and must refuse
when unavailable. A helper port or synthetic test alone is not a deployed issuer.

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
