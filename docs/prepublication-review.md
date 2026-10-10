# Pre-publication review evidence — Middleware #456

## Scope and disposition

This change adds a real, read-only verification entry point to the source owner,
`appolon1908/Codestra-Control-Plane`. It is the first implementation component of
the repair, **not the complete live bootstrap or a Middleware upstream repair**.
It does not alter the existing status publisher, promotion evaluator, rulesets,
AGENTS.md, required status names, trust pins, or workstation preflight.

A valid result is `REVIEW_EVIDENCE_VALID`. The output always also says:

- `publication_authorized: false`
- `certified: false`
- `worker_start_authorized: false`

The result is an authenticated evidence assessment, not a bearer token, a
completed-subsection certificate, or permission to retry a denied operation.
No success from this component may be posted as `codestra-control-plane` or
`codestra/control-plane`. The existing Middleware branch-creation gate remains
unsatisfied until a separate reviewed integration can represent truthful
admission without substituting it for certification.

## Reproduced defect and source ownership

Middleware ruleset 24625234 requires `codestra-control-plane` at creation of a
`subsection/*` branch. The inspected ordinary publisher discovers only open PRs
and validates an already-existing exact remote head. This creates a circular
first-publication dependency. Restarting that publisher is not a repair.

The previous eight-test diagnosis exercised unmodified functions from publisher
blob `da91853c9da415e04b0cee7d5c1ef05f83f76951`, at source-provenance commit
`9447ea0885165445afbffe4e326a2169e128fbec`. That source snapshot is NOT a claim
about the deployed version. The new review targets the existing trusted-decisions
subsection at `a5df29512c8f93af3d358a834193abf4004bd9dd`, without merging or
rewriting either existing subsection. No product code is moved to this repository
as a way around a product's denied publication path.

## Verification contract

`lib/codestra_control/prepublication.py` accepts an envelope containing canonical
JSON payload bytes and three detached Ed25519 signatures. The signed bytes are:

`b"CODESTRA-PREPUBLICATION-REVIEW-V1\x00" + canonical_payload_bytes`

Canonical encoding is Python JSON with sorted keys, compact separators,
ASCII escaping and no nonfinite numbers. Duplicate keys, unknown fields,
noncanonical base64, oversized input, malformed types and unknown schema versions
are denied. Signature verification uses the installed `/usr/bin/openssl` in
verification-only mode, with fixed arguments, a clean environment and a timeout.
The component does not generate keys or signatures.

An administrator-controlled policy identifies exactly one request ID and binds
repository, proposed subsection head, matching section target, exact parent and
candidate commit SHAs, candidate tree SHA, lease ID and owner principal. No
wildcard branch, protected implementation branch, or unrelated green parent is
accepted. The policy defines the exact required source checks and public keys for
an operator, independent security reviewer, and independent validator. Signer
keys and principal IDs must all differ; the security reviewer and validator
cannot be the author. Independent administrators must map aliases to the same
real principal. Different GitHub handles or keys alone are not evidence of
independent people. This code does not establish that identity registry.

All three parties sign the same complete request, including the validator's
source-check receipts. Each receipt must identify the exact candidate commit and
tree, the trusted validator principal, a unique receipt ID, the required check
name, a passed result, a completion timestamp and a report SHA-256. No skipped,
missing, duplicate, wrong-producer or wrong-source receipt is accepted.

The verifier authenticates those signed attestations; it does not rerun their
source tests or fetch their referenced report bytes. A trusted validation service
must actually execute and retain the checks before signing. Providing strings
that say `passed`, or generating test-fixture keys, supplies no real authority.

The signed observation must show the proposed head absent, the reviewed parent
and candidate tree unchanged, clean source, unchanged protected governance, and
no outstanding safety denial. Provider and production flags must be real JSON
`false` values, not strings or numeric lookalikes. The request, policy and lease
must be unexpired, and source-check/observation/replay-state evidence must be
fresh. The maximum observation age is 300 seconds; request lifetime is at most
3600 seconds and may be configured lower.

An administrator-controlled replay-state snapshot rejects already-consumed
request IDs. Assessment is deliberately non-consuming and repeatable: **atomic
one-time consumption at publication is not implemented by this component**.
It must be performed by a later approved broker in the same guarded publication
transaction. A verifier result is not a replacement for that transaction or a
fresh remote-parent comparison immediately before and after publication.

## Read-only entry point

The CLI accepts only the signed-envelope filename:

```text
PYTHONPATH=lib python3 -S -m codestra_control.prepublication signed-envelope.json
```

It reads policy and replay state from fixed, external paths:

```text
/etc/codestra/control-plane/prepublication-review-policy.json
/var/lib/codestra/control-plane/prepublication-review-state.json
```

These files and their ancestors must be root-owned, not group/world-writable,
and not symbolic links. The CLI does not accept caller-supplied policy paths,
keys, replay-state overrides, fake time, skip flags, or a publish switch. Missing
or disabled policy fails closed with exit 2 and structured `BLOCKED` output.
Successful evidence assessment exits 0 but still grants no execution authority.
There is no installed policy, real key material, real approval, live replay state
or runtime deployment in this source change. The in-process function's policy
and replay arguments are trusted-adapter inputs, not a public JSON API.

## Regression coverage and limits

Tests use disposable Ed25519 keys generated in temporary directories, real
OpenSSL signature verification, and synthetic source receipts. They cover the
no-existing-head case, three-party authenticity, same-person/key rejection,
wrong scope, expired/replayed requests, stale/moved observations, incomplete and
duplicate receipts, unsafe effects, malformed inputs, file safety, and absence of
runtime/certification authority. Synthetic keys and principals are not actual
operator/security approval. The test suite never contacts a provider, GitHub,
a workstation, or a live database.

The code was first absent and the 23 initial assertions failed; after
implementation and added edge cases, 33 changed-component tests passed. The
prior eight characterization tests were rerun separately. The local mirror is
sparse, not a GitHub clone: its Git HEAD is not the upstream source SHA. No full
inherited repository-suite result is claimed from that mirror. The added
read-only CI workflow runs the complete inherited repository test discovery on
the PR's exact head, with effects OFF and one serialized workflow workload.
Actual hosted results and independent review must be read back before acceptance.

## Remaining integration gates

Before this can unblock the real Middleware review PR, independent security and
operator review must approve the identity/key custody, evidence-producing
validator, fresh observation adapter, atomic replay consumption, and the
admission-versus-certification protocol. The live publisher and branch-policy
integration must be separately reviewed and tested together. Do not disable the
current creation check, post a manual green status, add bypass actors, relabel
review admission as certification, or use alternate branches/accounts/hosts to
escape a denial. Source review alone authorizes none of those operations.

Middleware #455 / #448 trust-root maintenance remains separate. Authentic
same-name origin upstreams, current reviewed parents, isolated clean worktrees,
unchanged AGENTS.md preflight, leases and resources must all pass before workers
start. Existing assignments remain exactly:

| Agent | Assigned section | Subsections |
|---|---|---|
| 1 | Command Kernel | S1.1-S1.6 |
| 2 | Connectors | S2.1-S2.6 |
| 3 | Canonical API / Frontend | S4.1-S4.6 |
| 4 | Provider Adapters | S5.1-S5.6 |

At most four workers, one owner per subsection, one serialized test workload,
and all provider/production effects OFF. No worker is started by this change.

## References

- https://github.com/appolon1908/Middleware-/issues/456
- https://github.com/appolon1908/Codestra-Control-Plane/pull/2
- https://docs.openssl.org/3.0/man1/openssl-pkeyutl/
