# Bootstrap publication repair for Middleware #456

Status: source candidate for independent review; no live activation performed.

The existing cycle is real: subsection creation requires full control-plane
certification, while certification requires that subsection to exist. The
read-only signature verifier cannot break this cycle. Restarting statusd or
relabeling review evidence as certification cannot repair it safely.

## Implemented source path

1. An administrator installs an exact repository/ref/parent/candidate/tree/owner/
   lease/nonce policy. Operator, security owner and independent validator sign
   the same canonical review-only payload. The author cannot act as security
   owner or validator.
2. The collector reads actual Git commit/tree objects, checks the single parent,
   inspects protected governance paths, and reads independently stored validator
   report bytes. It checks their signed digests, producer, source binding,
   freshness and nonempty passing test counts. Candidate code is never executed
   by the privileged collector.
3. SQLite reserves the request before effects using a durable transaction and
   unique constraints on nonce and active repository/head. A rejected or
   uncertain request remains consumed. Process death leaves a consumed RESERVED
   entry; operators must inspect refs and logs rather than retry the write.
4. The broker reloads authority, re-verifies signatures/timestamps, and collects
   evidence again after reservation. A bare Git reference transaction verifies
   the exact parent and creates an absent review head under the same ref locks.
   Symbolic refs are rejected and the transaction never dereferences them. A
   final authority/freshness check runs after inspection while locks are held;
   rejection aborts the prepared transaction cleanly. Readback must match before
   the ledger records PUBLISHED.
5. Review publication returns no certification, worker launch or promotion
   authority. The existing full-certification checker is unchanged.

The CLI accepts only a signed bundle path. Trust configuration, artifact store
and ledger use fixed service-owned paths. Missing configuration fails closed.
The configured repository identity must match the signed scope. Existing ledger
files and SQLite sidecars must be owned by the service with private permissions.
Tests exercise real Ed25519 signatures, Git objects and transactions, concurrent
SQLite processes, process death on both sides of publication, replay denial,
stale or mismatched evidence, moved parents, symbolic heads, and protection
failures using disposable repositories.

## Disposable CLI and real-watchdog integration

`tests/integration/bootstrap_cli.py` is a separate integration suite. It refuses
to run outside a disposable Linux container with read-only source at `/source`
and empty tmpfs mounts for all trusted paths. The runner mounts no host trust
configuration, database, credentials or product remote and disables networking.
Use a locally reviewed immutable Docker image ID containing Python 3, Git and
`/usr/bin/openssl`; the runner does not pull an image or install dependencies:

```sh
bash ci/run-bootstrap-cli-container.sh sha256:<reviewed-local-image-id>
```

The suite executes the actual fixed-path CLI with ephemeral three-party signing
keys, private disposable Git objects/reports and SQLite state. It checks
publication without certification or worker authority, replay denial, moved
parents, changed report bytes, revoked policy and skipped evidence. A separate
library-level case forwards a real Git transaction through prepare, then stalls
its transport. The actual 30-second watchdog must stop it, burn the nonce and
release prepared ref locks. This test verifies the prepare acknowledgement and
elapsed timeout; no synthetic timeout exception or clock is used.

These seven tests supplement the 87-test source suite; they do not establish
live identities, installed-rule attestation, current lease authority, a GitHub
adapter or end-to-end multi-provider staging certification. Fixture policy
declarations and signatures authorize only the isolated fixture. Hosted source
CI still runs the source suite; run this container suite separately against the
exact reviewed artifact before any independently approved live integration.

## Admission and certification integration requiring owner review

The proposed creation context is `codestra-review-admission`. Full certification
continues to use `codestra-control-plane` for promotion. Both checks retain
creation/promotion enforcement as applicable; no bypass actor is introduced.
The broker explicitly rejects a protocol that still requires full certification
before creation, removes admission checks, disables creation enforcement or
removes full certification from promotion. A root-owned protocol declaration is
an integration contract, not proof that GitHub rules have been installed.

No ruleset, trust pin, certificate, database lease or success status was changed
by this candidate. Security-owner approval of the protocol and installed-rule
evidence are still required. Middleware #455 remains independently governed.

## Provider boundary and remaining live work

The implemented publisher targets an administrator-owned bare Git repository.
It is not a GitHub publisher. GitHub REST create-ref cannot atomically verify a
different parent ref while creating a head. A precheck followed by an
unconditional POST must not replace the transaction here. Nor does this code
publish the proposed admission status on GitHub or validate deployed rulesets.

Before live use, the independent security owner must approve the split protocol,
choose and review a provider integration with equivalent conditional semantics,
install and attest actual rules, establish the authenticated validator artifact
producer and current lease policy, and exercise crash recovery and promotion
denial in staging. Existing blocked subsection branches remain blocked until
those steps are complete. Unit tests and agent review are not that approval.

## Validation and implementation plan

Completed: reproduce the missing broker; add the collector, replay ledger and
conditional transaction with regression tests; integrate with the existing
three-party verifier; enforce LF shell checkouts; run the complete Linux suite
with effects disabled. The first Windows working-copy fixture had 13 shell
subtest failures from CRLF conversion. A fresh Git archive of the original
commit passes all 58 inherited tests; those failures were not tracked-source
defects. Initial candidate: 78 tests passing. Independent review required
symbolic-ref, expiry, repository identity and ledger permission repairs; the
final reviewed candidate passes all 87 tests, zero skipped, on Linux. Record
that result and the exact commit in the publication checkpoint, rather than
treating the initial result as validation of later changes.

Next: independent source review and repairs, repeat the complete suite and
`git diff --check`, commit coherent source, guarded publication to codestra-local
with exact SHA parity, then mirror the existing source PR and inspect current
head CI. Live protocol installation remains a separate owner-controlled gate.
