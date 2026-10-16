> Historical PR24 preparation. The successor source implementation is documented in [authenticated-publisher-source.md](authenticated-publisher-source.md), and its operational acceptance gates in [publisher-operational-acceptance.md](publisher-operational-acceptance.md). The historical implementation and review statements below are not a current runtime or release acceptance record.

# Approved source design; runtime cutover remains prohibited

Human approval at 2026-10-15 15:38 UTC accepted the six catalog additions in PR23
and codestra-control-plane-status.service as sole publisher for both
codestra-control-plane and codestra/control-plane. It did not authorize deployment,
service/timer changes, permissions, identities/grants/leases or activation.
This task records a separate source assignment rather than extending PR23's
proposal-only limits. PAS233 hook lanes remain separate and untouched.

## Implemented source behavior

The catalog now contains exactly49 repositories: the prior43 plus Control Plane,
PostgreSQL, OpenAPI, Foundation, Ruleset Toolkit and openrerefine-. Added names
retain exact unique registry mapping and promotion evidence checks; none gains a
bootstrap exception. Registry rows and labels remain metadata, not authentication.

The primary entrypoint requires kernel cgroup membership in the designated
system service and holds a single nonblocking flock for the whole cycle. Its
fixed lock path is /run/codestra-control-plane/publisher.lock. No lock or directory
is automatically created. A missing/replaceable/untrusted/symlinked/hardlinked lock
or competing descriptor denies entry. This fences cooperating local processes;
it is not cross-host issuer exclusivity or a substitute for an accepted identity
and capability contract.

An authenticated publication adapter has NOT been accepted or implemented.
The adapter gate therefore always refuses before database/network work. Direct
post() also refuses before GitHub reads or writes. There is no env flag, JSON,
actor string or legacy PASS row that enables it. Offline reconciliation tests
explicitly supply synthetic fixtures; production has no such override interface.
This source is a guarded candidate, not a working certifier or deploy-ready release.

The competing legacy source entrypoint now prints PUBLICATION_REFUSED and exits78
without commands, database reads or status writes. Its previous bytes remain in
Git history; installed files were not changed. The unused primary alias fails the
same designated-service check if invoked under its own systemd unit.

## Candidate package

bin/codestra-prepare-publisher-release requires an exact committed40-character SHA,
a new output directory and the pinned CPython3.12/Linux x86_64 driver wheel.
It reads committed Git blobs, never dirty working files, and rejects symlink
runtime modules. It stages both primary/checker entrypoints, the retired secondary,
requirements-publisher.txt, ALL lib/**/*.py dependencies, and the hash-verified
psycopg2-binary2.9.10 wheel. The JSON manifest records each path, byte digest, mode,
size and proposed installed target. No installer, service action, SQL or grant
provisioner is present. Install/activation/release approval flags are always false.
The staged source remains contingent on PR22's independent exact-head review and
governed integration; a staged package does not count that prerequisite as met.

## Specific future cutover approval scope

Host: dev-desktop. Primary service effective User/Group is sentinelx/sentinelx;
its fragment has an existing10-authorized-github-identity.conf drop-in. This source
approval changes neither identity nor drop-in. Primary files currently belong to
codestra/codestra, mode0755. Secondary file is codestra/sentinelx, mode0755.

Potential write targets are the manifest's exact primary/checker/lib files below
/srv/codestra/dev-platform/control-plane, and the retired secondary entrypoint at
/opt/codestra-dev/control-plane/bin/github-status-sync. Dependency installation
is a distinct reviewed action using the included pinned wheel, never an unpinned
pip download. No schema/role/grant/task/lease mutation is included or implied.

Both installed timers currently invoke file bytes on every tick: copying a file
can activate behavior WITHOUT any restart. Therefore BEFORE ANY installed write,
a separately approved operator must pause codestra-control-plane-status.timer
and codestra-github-status-sync.timer, stop/verify both corresponding services,
and verify codestra-github-statusd.service/timer remain inactive. Failure to verify
quiescence stops the cutover. No stop/start commands were run for this preparation.

Before writes, capture a private rollback backup of every existing target file,
its owner/group/mode/hash, missing-file markers for new modules, unit/drop-in bytes,
and exact timer enabled/active states. Validate a complete staged manifest against
the accepted release commit and independently approved hashes. Do not infer
release approval from this candidate or from source CI.

Lock provisioning is a SEPARATE permission/provisioning approval: root:sentinelx
/run/codestra-control-plane mode0750 and a precreated root:sentinelx publisher.lock
mode0640. The service reads and locks it without writing or creating it. Ownership
changes, tempfiles configuration and boot reprovisioning are not performed here.

During a future approved cutover the secondary writer would be retired and its
timer disabled; the unused alias stays disabled. Publication must remain paused
until an accepted authenticated adapter, issuer capability/exclusive ownership,
real repo-ID/product/task bindings, genuine owned leases and exact-head evidence
exist. There is no safe activation command in the current candidate.

Impact: eventual primary publication could append statuses across49 repositories;
the current guarded candidate publishes none. Retiring the secondary removes its
ledger mutation and competing slash-context writes. Permission, dependency and
service changes require their own exact approval; no credential changes are proposed.

Rollback starts by pausing/confirming ALL writers stopped again, then restoring
backed-up bytes/metadata and removing only recorded new files. Verify hashes and
restore approved configuration. Do NOT automatically reenable the competing writer
or restart a failed service: remain paused pending the operator-approved rollback
state. The original enabled timers are a captured baseline, not permission to
resume two competing issuers. No database/grant/lease rollback is included because
none is changed by this package.

## Remaining release gates

PR22 head a35ecfa450868813875f3056e3c2389f864a1a97 still needs eligible independent
review; kazan555 is already requested. This task neither requests another review
nor submits approval as the user. The source must follow atomic→subsection→section
and the remaining governed promotion chain. Protection enforcement, authenticated
publication acquisition/effect integration and actual installation approval remain
unmet. No runtime is activated by a source merge or passing test.
