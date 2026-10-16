# Proposed publisher and certifier approval packet

This is a concrete proposal for later operator review, dated 2026-10-16. No App,
installation, credential, database role, service or protected configuration has
been created or changed by this work. The proposed **new, uncreated** Apps are
**Codestra Controller Publisher** and **Codestra Scope Certifier**. Their IDs are
unknown; zero is an intentional refusal value. No existing App or shared PAT is
nominated as a fallback. `PRODUCTION_GO=NO`, `LIVE_CAPABILITIES_ENABLED=NO`,
`EXTERNAL_EFFECTS=false` remain in force.

The bundled source examples are:

| Source template | Proposed purpose |
| --- | --- |
| `config/examples/authenticated-publisher.toml` | Fixed protected publisher startup configuration; zero IDs deny startup. |
| `config/examples/producer-acceptance.json` | Protected independent producer acceptance; `PROPOSED`, zero App/installation IDs and empty receipts/timestamps deny acceptance. Known pilot repository ID is proposed metadata only. |
| `config/examples/certifier-observer.proposed.toml` | Proposed separate root-custodian configuration; protected acceptance remains unaccepted. No service unit or installation is supplied. |
| `config/examples/publisher-certifier-action-time-approval.json` | Action-time approval checklist with every operational approval false and Phase B postponed. |

`publisher_installation.prepare_installation_packet` stages these four committed
blobs, their SHA256 digests and exact source commit into a new private local
directory. It ignores dirty/untracked files and rejects symlink templates and an
existing output path. This is an offline proposal packager; it contains no
installer, credential provisioner, SQL runner or service controller. Its manifest
always records `install_allowed=false` and `activation_allowed=false`. The runtime
release manifest is separate and must identify the same approved final commit.

## Named responsibilities and exact pilot scope

Ralph L. Appolon is the nominated accountable operator. Nomination, source
authorization, a populated receipt field or a PKI USB designation does not accept
GitHub App private-key custody. An authenticated operator must separately accept
each App, every key holder, the isolation boundary and the exact installation.
The protected acceptance record requires two distinct accepted custody references:
`custody_receipt` is publisher-only, and `certifier_custody_receipt` is
certifier-only. Missing, empty or equal references deny; a joint custody receipt
cannot substitute for these two independent acceptances.
Keep that evidence in the private handoff, with references in the protected
acceptance record. A PKI USB may have a separately accepted database/client-PKI
purpose; it is not evidence of GitHub App-key custody.

| Responsibility | Proposed identity and limit |
| --- | --- |
| Controller status publication | New Codestra Controller Publisher App; only `codestra-control-plane` and `codestra/control-plane` statuses for a genuinely authorized exact binding. |
| Independent scope receipt issuance | New Codestra Scope Certifier App, distinct from publisher and ordinary CI Apps; only the `scope-certification` check receipt after independent trusted acquisition. A legacy database PASS row cannot issue or renew it. |
| Producer identity observation | Separate protected observer uses the certifier custody boundary for whitelisted GitHub GETs; returns public identity/installation/repository observations through a peer-verified local socket. It never returns a token or JWT. |
| Credential custody | Distinct publisher and certifier custody acceptance, holders and process boundaries. The publisher cannot read the root-only certifier private key or ask the observer to sign arbitrary requests. |
| Database authority | Separately accepted restricted read principal and operator-maintained authority/read model; neither App creates assignments, leases, schema or grants. |
| Merge execution | Separate downstream authority rechecks the current protected target and merge-result checks; neither App merges or creates refs. |

The proposed primary OS identity is the **new, uncreated** dedicated user/group
`codestra-publisher`, as a non-login system account with no privileged or shared
memberships, for the existing designated
`codestra-control-plane-status.service`. Creating that account/group, its private
state and changing the unit `User`/`Group` drop-in require separate action-time
approval. No account or service configuration is changed here. Do not accept the
shared `sentinelx` identity as publisher key custody or reuse its group membership.

The only proposed installation and certification scope is
`appolon1908/codestra`, repository ID **1319808791** from the existing authenticated
GitHub metadata observed 2026-10-16 at 17:37:38 UTC (`pull.json` `base.repo.id`).
This known identity is proposed metadata, not an accepted grant or a new audit;
the App/installation identities remain zero and uncreated. The 49-repository
source catalog does not expand this pilot.
Reject extra repositories, duplicate IDs, wrong installations, suspended Apps,
zero/guessed IDs and independent-issuer collisions.

Publisher repository permissions exactly match `GitHubAppClient.PERMISSIONS`:
`statuses:write`, `checks:read`, `contents:read`, `pull_requests:read`,
`administration:read`, `metadata:read`. Inventory requests further narrow the
token to `metadata:read` and `pull_requests:read`. Write tokens cover one repository.

The proposed certifier permissions are `checks:write`, `contents:read`,
`pull_requests:read`, `administration:read`, `metadata:read`, subject to exact
agreement with the independently reviewed certifier adapter. The certifier has no
statuses permission. Neither App receives Workflows write, Contents write,
Actions write, administration write, organization grants or any bypass role.
App creation and installation require their own explicit later approval.

`effective_protection` requires active ruleset provenance and a visibly present,
empty `bypass_actors` list, plus visibly empty classic bypass allowances and
enforced admin protection. `administration:read` may not expose the bypass-actor
detail required by that contract. An omitted or opaque field remains unavailable;
do not infer emptiness, broaden a permission, grant administration write or alter
protection by guess. Resolve the exact visibility question in separately approved
inspection and deny publication until the existing evidence contract is met.

## Files and custody proposed for operator approval

Every path below is a proposed target, not an installed observation. Protected
files must be regular, single-link and non-symlinked; root-owned ancestry must have
no group/other write permission. Record actual identities and modes privately.

| Target | Proposed ownership/mode and purpose |
| --- | --- |
| `/etc/codestra/control-plane/authenticated-publisher.toml` | `root:codestra-publisher 0640`; fixed startup path, exact reviewed schema. |
| `/etc/codestra/control-plane/producer-acceptance.json` | `root:codestra-publisher 0640`; externally accepted producer record, reread every verification boundary. |
| `/etc/codestra/control-plane/credentials/publisher-app.pem` | `root:codestra-publisher 0640`, or `0600` only when a separately accepted privileged reader can read it; publisher key only. |
| `/etc/codestra/control-plane/credentials/publisher.dsn` | `root:codestra-publisher 0640`, or compatible `0600`; restricted authenticated database principal and verified TLS. No DSN value enters Git. |
| `/etc/codestra/control-plane/certifier-observer.toml` | `root:root 0600`; exact four fields `app_key_file`, `producer_acceptance_file`, `socket_file`, `publisher_user="codestra-publisher"`. IDs come only from protected accepted policy. |
| `/etc/codestra/scope-certifier/credentials/certifier-app.pem` | `root:root 0600`; independent root custodian, never readable by publisher. A separate certifier issuance service must use its independently accepted custody boundary. |
| `/etc/codestra/scope-certifier/credentials/certifier.dsn` | `root:root 0600`; separate restricted certifier reader credential, private handoff only. Never reuse publisher or bootstrap authentication. |
| `/etc/codestra`, `/etc/codestra/control-plane`, credential directories and certifier configuration parents | `root:root 0750` or `0755` as required for accepted traversal; all ancestors root-owned with no group/other write. Choose `0755` where the service must traverse without membership in root. |
| `/run/codestra-control-plane` and `publisher.lock` | Directory `root:codestra-publisher 0750`; precreated lock `root:codestra-publisher 0640`. Publisher does not create or replace it. Boot recreation needs separate accepted provisioning. |
| `/run/codestra-certifier-observer` and `observer.sock` | Protected directory `root:codestra-publisher 0750`; proposed socket `root:codestra-publisher 0660`, client verifies server peer UID root (`0`), server verifies caller UID resolved for the proposed `codestra-publisher` account. Socket protocol and isolated server deployment must be reviewed before use. |
| `/var/lib/codestra-control-plane` | Root-owned non-writable ancestor, proposed `root:root 0755`. |
| `/var/lib/codestra-control-plane/publisher` | `codestra-publisher:codestra-publisher 0700`; dedicated private ledger directory. Ledger/SQLite sidecars `codestra-publisher:codestra-publisher 0600`. Preserve intent history on rollback. |
| `/var/lib/codestra-control-plane/certifier` | `root:root 0700`; separate root-custodian durable certifier intent ledger and sidecars `root:root 0600`. Preserve first-issuance history independently. |
| `/opt/codestra-control-plane/releases/<SOURCE_SHA>` | New immutable release tree, root-owned directories `0755`, root-owned non-writable files with manifest modes; replace `<SOURCE_SHA>` only with the exact approved 40-character source commit. No mutable developer-owned ancestor is trusted. |

Protected-read checks validate owners, ancestry and modes; they do not prove
exclusive key custody. The currently shared `sentinelx` identity is not accepted
evidence of exclusive custody. The proposed new dedicated account is also only
a proposal until its actual isolation and credential custody are accepted.
Inventory every process, user and group that can
read either key, and accept actual dedicated isolation or an independently
accepted signing custodian before issuance. Never grant publisher access to the
certifier key. Root remains a privileged trust boundary.

The complete code tree, entrypoints, import environment, CPython 3.12 interpreter,
site packages, bytecode directories, OpenSSL/Git and shared libraries must have
accepted root custody before loading code. Validate target tool digests against
`runtime-publisher-tools.json`, the pinned psycopg2-binary 2.9.10 wheel against
`requirements-publisher.txt`, interpreter/import behavior and effective unit
environment. Build-host pins and an in-process self-check are not target
acceptance. Disable mutable import paths and use the reviewed isolated invocation.

## Exact proposed installation sequence

These are reviewable future actions, not commands executed by this task. Each
operation needs the final source commit, manifest digest, private receipt and
separately approved window recorded before execution. Empty values prohibit it.

1. Accept the final governed source commit and independently reviewed candidate;
   record the full 40-character source SHA, release-manifest SHA256, every file
   digest/mode/target, packet-manifest SHA256 and pinned wheel digest. Resolve
   exact changed paths from that accepted manifest; no wildcard copy, dirty source
   or unlisted dependency may be installed. Review the protected startup schema
   and observer protocol from that same candidate.
2. Confirm a fresh exact maintenance window with start/end/timezone and operator.
   Inventory all active, scheduled, dormant, manual and remote competing writers.
   Before copying **any** executable/import/configuration bytes, pause
   `codestra-control-plane-status.timer` and `codestra-github-status-sync.timer`,
   stop and verify `codestra-control-plane-status.service` and
   `codestra-github-status-sync.service`, and verify the unused
   `codestra-github-statusd.service`/`.timer` are stopped and paused. Include any
   newly discovered competing scheduler/process; an incomplete inventory denies
   cutover. Scheduled services load changed file bytes without a restart.
3. Capture a private rollback inventory before writes: each existing manifest
   target's bytes, owner/group/mode/hash and symlink/link status; missing-file
   markers for new paths; unit/drop-in bytes and effective environment;
   enabled/active timer/service states; protected configuration and credential
   reference metadata; ledger and sidecar consistency; recovery access. Keep
   secret-bearing backups under accepted private custody, outside Git. Verify the
   backup and restore procedure and record its receipt.
4. Under separate applicable provisioning approval, create the proposed dedicated
   `codestra-publisher` account/group without shared memberships, then prepare the
   exact protected directories, lock, independent observer and private ledger
   layout above.
   Install only accepted release-manifest targets: primary/checker/CLI and
   `lib/**/*.py` paths explicitly enumerated under the new immutable
   `/opt/codestra-control-plane/releases/<SOURCE_SHA>`, and the retired secondary at
   `/opt/codestra-dev/control-plane/bin/github-status-sync` when enumerated.
   Secure the entire new ancestry/import tree as root-owned; do not chown the
   shared `/srv` development tree. Separately approve the designated unit drop-in
   with `User=codestra-publisher`, `Group=codestra-publisher` and exact
   `ExecStart=/usr/bin/python3 -I -B /opt/codestra-control-plane/releases/<SOURCE_SHA>/bin/codestra-github-statusd`.
   The placeholder must be replaced with the manifest's approved commit before
   any execution. Install the exact pinned wheel only
   into the accepted root-owned interpreter environment, with no network package
   resolution. Dependency and ownership changes require explicit scoped approval.
5. Provision actual App/installation identities and key custody only under their
   separately accepted actions. Populate the exact fixed startup file and
   protected acceptance file from accepted actual values, keeping all secret
   values in the private handoff. Configure the separate observer to the accepted
   pilot IDs and peer boundary. These actions never infer or create database
   roles/grants/schema/assignments/leases. If those prerequisites are missing,
   stop and remain paused.
6. Compare installed bytes, metadata, ancestry, interpreter/driver/tool digests
   and effective units to the accepted manifests. Independently verify online
   App identities, exact installation permissions/repositories, suspended state,
   protected target policy, current head/base/merge-result checks, authentic
   authority/lease and genuine independent scope receipt. Any missing evidence
   remains denied/unavailable. Installation success does not authorize activation.
7. After distinct action-time acceptance of every gate and residual risk, an
   authorized operator may approve a single designated publisher cycle for the
   pilot and inspect both receipts and the durable intent. Any later timer resume
   requires explicit approval. The legacy writer and unused alias remain paused;
   the captured timer baseline does not authorize their reactivation.

OS account/group creation, unit identity changes, App creation, key generation/distribution, socket/service provisioning, dependency
installation, file ownership changes, installation, activation and rollback are
distinct approvals. No command implementing any of those actions ran here.

## Exact proposed rollback sequence

1. Reestablish and verify quiescence of **all** writers and schedulers before any
   restoration. Stop the new observer/certifier effect path if it is part of the
   approved rollback. Loss of isolation or revocation requires an operator
   incident decision about App suspension/key rotation/token revocation; source
   rollback alone cannot retract an issued token or a published GitHub receipt.
2. Use the private capture for the exact accepted installation record. Restore
   only the recorded prior file/configuration/unit bytes and owner/group/modes;
   remove only paths marked absent before installation. Restore the interpreter
   or driver only through its specifically approved recovery procedure. Verify
   each restored digest/metadata and effective unit environment.
3. Preserve the post-cutover intent ledger and independently reconcile
   `RESERVED`, `PARTIAL`, `UNCERTAIN` or completed intents with actual GitHub
   receipts. Do not replace it with an older backup to erase replay history;
   keep both snapshots privately if recovery requires one. Do not retry or reseal
   a partially published pair automatically.
4. Verify protected configuration and retained/revoked credential custody against
   current acceptance. A rolled-back `ACCEPTED` file is not renewed authority;
   revocation and expiry still deny. Database rollback is outside this package
   because this package performs no database mutation.
5. Leave every writer and timer paused. Record the observed rollback state and
   unresolved receipts privately. Do **not** automatically restore captured active
   states, reenable a competing publisher, restart a failed writer or resume
   publication. Record the new account and remaining owned paths; do not delete
   an account, reuse its UID or remove private state without a separately approved
   recovery action. A subsequent resume requires a fresh explicit operator decision.

## Action-time acceptance, revocation and remaining limits

Accepted producer records last at most **24 hours** from acceptance and never
extend upstream authority/issuer expiry. The verifier rereads the protected
operator record and independently reacquires actual GitHub receipt/identity and
installation observations, with a maximum receipt age of **300 seconds**, at
each relevant effect boundary. No cached successful validity survives revocation,
expiry, changed bytes or loss of scope. A receipt reference alone is not a receipt.
Empty fields, zero IDs, `PROPOSED` state, unavailable API detail or failed peer
verification deny before a status effect.

Revoking local acceptance immediately prevents subsequent local authorization;
already-issued installation tokens may remain usable until their issuer expiry.
Accept that residual lifetime explicitly; do not promise immediate global token
invalidation. Two status POSTs and concurrent GitHub ref movement are non-atomic.
Preserve partial/uncertain outcomes, recheck current target/merge-result and
protection at each effect, and require the independent merge executor to check
current head, base and merge-result again. No source patch closes that external
race or authorizes merging.

Phase B is **POSTPONED**. There is **no database setup approval**, including SQL,
HBA/TLS changes, role/grant changes, credential creation, lease creation or replay
of captured SQL. If an accepted prerequisite later makes Phase B necessary,
propose a fresh exact maintenance window and separate scoped action packet for
operator confirmation. The unconfirmed window in this proposal grants nothing.
Private handoff references carry the authentication, custody, backup and recovery
evidence; no secret values or live records belong in source control.

## Proposed genuine scope assignment and first issuance

The isolated source migration `012-scope-assignment-leases.sql` prepares the
missing non-atomic scope lease contract. It creates only a new
`scope_assignment_leases` schema and definitions when separately applied; it
neither alters the existing atomic `assignment_leases` protocol nor creates
roles, execution grants, product/principal mappings, assignments or leases. Its
source tests apply it only to a disposable synthetic PostgreSQL cluster using
actual SCRAM authentication and verified TLS.

The operator-only `principals`, `products`, `grants` and `assignments` tables pin
actual role OIDs, repository owner/account mappings, product/repository/positive
repository ID, registered promotion refs, exact head/base SHAs, task identity,
active flags and bounded expirations. Eligible edges are only
subsection→section→development→testing→staging→production→main, one edge per
assignment. Current `public.products` and `scoped_registration.products` must
match the proposed product mapping; subsection/section refs must exist in the
registered workstation/section tables. Labeling a hotfix or atomic ref as a scope
level cannot authorize a shortcut.

`claim(assignmentUUID, requestUUID)` authenticates the actual nonprivileged SCRAM
session over TLS, with no `SET ROLE`/session impersonation, matching registered
role OID, product claim grant and assignment owner. It consumes the assignment
and request UUID once, returning an exclusive UUID lease token and positive
epoch. Expiration is at most five minutes and never exceeds the current
assignment, principal, product or grant expiration. There is no renewal,
automatic replacement or epoch reseal after expiry/revocation. A fresh lease
needs a separately assigned new task; the caller cannot write authority tables.
Active assignments are unique for each `(product, source_ref)`, regardless of
owner, task ID or assignment UUID. A second active assignment for that source
scope is rejected. An independent unique `ACTIVE` lease fence covers the same
scope, including expired lease rows: expiry never silently frees it.
Before a replacement task may claim that scope, the operator must explicitly
deactivate the old assignment and mark its old lease `REVOKED`, preserving both
rows and their audit history. Deactivation immediately makes the old receipt
non-`ACTIVE`; until explicit lease revocation the replacement claim still denies.
There is no automatic scope handover or revival of a consumed assignment.

The independent verifier receives only schema usage and exact execution of
`scope_assignment_leases.inspect_binding(uuid)`, together with its operator-owned
product `read` grant pinned to its actual role OID. It receives no claim or
authority-table mutation privilege. Read-only inspection returns a genuine
`ONLINE_DATABASE_RECEIPT` with exact binding, token, epoch and current state;
revocation/expiry returns non-`ACTIVE` or denies, and changed immutable binding,
registry drift, missing lease or invalid credential provenance denies. The
transaction must use `READ COMMITTED`; a repeatable snapshot cannot retain
previously valid authority after revocation. The
certifier must require `ACTIVE`, match every ref/SHA/identity and independently
acquire policy/dependencies before a first GitHub scope check. Lease ownership
alone does not certify code or permit check issuance.

Any future action packet must separately approve migration ownership and exact
digest, authenticated role/credential custody, narrow function execution grants,
product/account mapping and task assignment, the exact one-shot claim, independent
first-issuance policy and check effect. All are unprovisioned and unapproved here.
Phase B remains postponed; confirm a fresh exact maintenance window only if those
operational steps later become necessary. Do not apply these definitions or seed
rows against the installed database from source tests or this proposal.

## Concrete first-issuance bundle, still blocked

The [certifier source guide's six-step first-issuance proposal](certifier-existing-receipt-source.md#concrete-first-issuance-operational-proposal)
names the implemented source path: `011-certifier-authority.sql`, isolated
`012-scope-assignment-leases.sql` and empty
`013-first-certification-pending.sql`. The administered factory is
`codestra_control.certifier_adapter.build_first_certifier_service(connection,
jwt_provider, ledger_path, policy_reader, host=...)`; its issuer is
`AuthenticatedFirstCertifier.publish(exact_promotion_request)`. This path requires
`snapshot.certificate=None`, with no existing certificate or check-run needed.
It still needs an accepted exact pending delegation, current genuine scope lease
and independently established complete canonical child receipt inventory.

No eligible first binding is selected. The packet deliberately leaves product,
PR, levels, refs, head/base SHAs, assignment, lease and delegation fields empty;
this is an explicit operational block, not permission to select one automatically.
The known pilot repository is `appolon1908/codestra`, ID `1319808791`.
**PR56's hotfix→production route is ineligible** under the registered promotion
policy and must not be presented as the first pilot check. Operator authority
cannot override a forbidden edge or omit canonical children.

The following PostgreSQL identities are **proposed, new and uncreated**, each with
accepted OID `0` until its actual SCRAM/TLS session and private credential handoff
are independently verified. Creation/authentication, product grants and one exact
assignment each require separate operator approval.

| Proposed role | Exact restricted runtime purpose |
| --- | --- |
| `codestra_publisher_ro` | `SELECT publisher_authority.bindings`, schema usage for that reader and `scope_assignment_leases.inspect_binding(uuid)` only, with an OID-pinned scope-product `read` grant. |
| `codestra_scope_certifier_ro` | `SELECT certifier_authority.product_grants` and `pending_bindings`; the canonical hierarchy reads listed below; schema usage and `scope_assignment_leases.inspect_binding(uuid)` only, with independent OID-pinned product/read grants. No claim execution. |
| `codestra_scope_builder` | Ralph-private, separately accepted credential; schema usage and `scope_assignment_leases.claim(uuid,uuid)` only, with its operator-created product `claim` grant and exact assignment ownership. No authority-table SELECT/write or verifier function grant. |

The certifier's canonical hierarchy reader needs only `SELECT` on
`public.products`, `public.sections`, `public.workstations`, `public.atomic_tasks`,
`scoped_registration.products`, `scoped_registration.workstations`,
`scoped_registration.lanes`, `scoped_registration.candidates` and
`scope_assignment_leases.products`, with corresponding schema usage. The first
path does not require `certifier_authority.existing_receipts`; that belongs to the
separately scoped existing-receipt transport. No runtime identity receives schema
mutation, table writes, DDL, owner membership, PUBLIC grants or broad roles.
The existing `codestra` installation/bootstrap role is a **CANDIDATE only** for its
separate administrative purpose; no accepted OID, authentication or runtime reuse
is inferred from its name or existence.

The proposed operational sequence remains entirely unapproved:

1. Accept independent App identities, exact pilot permissions, the three proposed
   database identities and their separate private authentication/custody evidence.
2. In a separately confirmed window, apply the exact approved 011/012/013 source
   digests under the independent operator owner; explicitly provision only the
   table SELECT, schema usage and function execution listed above. Keep runtime
   accounts outside every authority-writer/owner capability.
3. Accept the actual registered product/scope mapping and one exact builder-owned
   assignment. Ralph's separately authenticated builder claims it once; the
   independent certifier reader verifies its actual current token/epoch/binding.
4. Accept an exact `certifier_authority.pending_bindings` delegation, including
   `certificate=None`, the genuine current lease, protected capability/custody and
   the **complete canonical** dependency inventory, bounded to five minutes and
   every earlier authority expiry. A declaration of an empty policy cannot hide
   actual children; no operator override can waive them.
5. The separately approved root custodian reads its `root:root 0600` certifier
   DSN/key and composes the actual first-issuance factory with the protected
   accepted policy and private root-owned certifier ledger. Fresh online checks
   must establish the exact registered PR/head/base, protected target, current
   merge-result, independent eligible reviews/conversations and every child
   receipt. Only a separately approved effect emits **one** scope check, followed
   by independent readback of App/name/SHA/binding and success.
6. After that actual receipt is accepted, a separate operator action may register
   it in the publisher binding stage. The publisher still performs its own fresh
   authority, scope, protection and receipt checks; approval for the certifier's
   one check grants no authority for either of the two controller status POSTs.
   Those status effects require their own acceptance, with partial/uncertain
   intents retained and no automatic retry.

Canonical inventory includes all registered subsections for a section, all
registered sections for development, and the immediate predecessor for
testing/staging/production. Cross-subsection dependencies must match registered
workstation dependencies. **SUBSECTION first issuance currently supports only a
workstation with zero actual atomic tasks and zero registered candidates**;
nonempty atomic child inventories remain unsupported and deny. No fabricated
atomic receipt, hotfix exception or reduced inventory can close that gap.
All role creation, grants, schema application, claims, runtime composition, first
check, publisher registration and paired statuses remain false in the packet.
Phase B remains postponed, and secret values belong only in the private handoff.
