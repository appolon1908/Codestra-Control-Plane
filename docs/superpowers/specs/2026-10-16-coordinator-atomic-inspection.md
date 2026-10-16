# Coordinator atomic candidate inspection

The user requested a clean controller implementation that resolves mapping,
establishes registration/dependency evidence and proceeds toward genuine atomic
admission. Recovery source is merged; operational identities and adoption remain
unaccepted. Implement the missing executable evidence inspection without treating
source preparation as operational authority.

## Boundary

Use a separate read-only coordinator. Preserve the promotion engine, publisher,
required checks and legacy atomic rejection. An atomic source update is not a
subsection certificate or an environment promotion. Every eventual effect must
reacquire current authority; this inspection issues no bearer authorization,
lease, certificate, GitHub status or merge.

Use PostgreSQL16/TLS/SCRAM and protected, separately accepted runtime configuration.
Require system_user exactly scram-sha-256:session_user, the registered role OID,
no SET ROLE, restricted privileges and an explicit product read capability. The
coordinator must differ from the assigned builder. Never accept a caller DSN,
owner, snapshot, raw observation or successful gate JSON.

## Server read API

009-atomic-inspection.sql exposes atomic_inspection.inspect(uuid), with no public
EXECUTE or provisioned grants. Reuse assignment_leases.inspect_binding to enforce
the current assignment, candidate, owner, proof authority, epoch, expiry and state.
Resolve the actual scoped product/workstation/candidate and matching public section.
Check shared lane metadata, exact worktree/refs/SHAs, off flags and complete
configured workstation dependencies, independently of the candidate's declarations.

Each configured workstation dependency must be registered in the same product,
be CERTIFIED at its current exact remote SHA and have a matching independent
SUBSECTION receipt in assignment_leases.dependencies. Scope name is its registered
subsection branch. Missing/extra candidate evidence, duplicate prerequisites,
unregistered dependencies and ordinary historical certification alone deny.
Add SUBSECTION to the existing dependency digest protocol and the metadata
registration validator through this forward migration; retain all other checks.
No certificate producer or issuer capability is provisioned.

Canonicalize the 19 reviewed 007 issuer function timezones through explicit forward
ALTER FUNCTION settings. Fresh claims/proofs must remain comparable across caller
timezones. Preserve all historical non-UTC snapshots and deny them rather than
rewriting authority; their replacement requires existing operator APIs.

Return schema codestra.atomic-inspection.v1, the genuine lease receipt, registered
product/workstation/section/candidate metadata, dependencies and required
workstation inventory and required gates. Read transactions end before Git/HTTP and restart for the
final acquisition. No database rows or audit history are changed by inspection.

## Independent observation

Reuse GitMaterializer and GitHubLeaseObserver for actual protected checkout,
origin, host/UID/inode, both refs and online dependency check-run receipts.
An isolated App adapter requests one repository and only metadata, contents,
checks, pull_requests and administration read permissions. Deny installation
write privileges and all arbitrary effects; permit token mint and only existing
fixed read GraphQL queries. Do not edit the publisher's App implementation.

Reuse PR40's effective protection observation. Require strict producer-bound
checks, at least one independent approval, codeowner and last-push/stale-review
rules, resolved conversations and no bypass. Controller context producer IDs
come only from protected accepted configuration. Verify the actual PR number,
repository ID, canonical atomic-to-subsection refs, head/base SHA and merge result;
require all noncircular required check-runs on head and merge. Require eligible
independent exact-head reviews and GitHub's current APPROVED decision.

Reacquire the complete server description, reread PR/branch/protection/checks/
reviews, and require the materialized directory to match the leased host/device/inode.
Require merge-commit parents equal the bound base/head. Resolve all workstation
CI gates through explicit protected gate_checks bindings to effective required
producer-bound checks; clean_tree/remote_sha_match use materialization and review
uses current exact-head approval. Reject unsupported gates and empty noncircular
CI inventories. Deny drift and expiry before output. No cross-system atomicity or
instant revocation guarantee is claimed.
Bound the full cycle by the existing five-minute MAX_SNAPSHOT_AGE and check every
lease/binding/dependency expiry against the recorded completion timestamp.

## Output and validation

bin/codestra-inspect-atomic accepts only binding UUID and positive PR number.
Protected configuration path: /etc/codestra/control-plane/atomic-inspector.toml.
Output includes exact binding/lease ID/epoch, observation and evidence digests,
non_bearer=true, certified=false, lease_granted=false and
promotion_authorized=false. Failures use a generic diagnostic without secrets.

Use disposable PostgreSQL16/TLS/SCRAM fixtures and synthetic GitHub/Git evidence.
Test impersonation, privilege escalation, mapping/registration drift, omitted or
revoked dependencies, stale/changed leases, online check/review/protection drift,
read-only HTTP scope, final reacquisition and private failure output. Run the full
offline suite on the final source head. PRODUCTION_GO=NO;
LIVE_CAPABILITIES_ENABLED=NO; EXTERNAL_EFFECTS=false.
