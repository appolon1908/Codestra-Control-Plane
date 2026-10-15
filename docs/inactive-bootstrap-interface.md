# Inactive bootstrap interface

`lib/codestra_control/bootstrap_interface.py` is an offline inspection seam. It is
not imported by any CLI, publisher, service or database registration function.
There is no production verifier, effect adapter or activation option.

A frozen request binds repository, product, source/target refs, exact source and
base SHAs, assignment ID and owner principal. An optional in-process verifier
returns internal attestations for operator grant, owned lease and independent
review. Each attestation must match the complete request and its expected kind.
Missing, malformed or mismatched output and verifier exceptions deny inspection.
The default has no verifier and denies.

The verifier boundary is deliberately opaque: a future independently reviewed
implementation must authenticate its operator grants, observe actual source and
base identities, enforce accepted route policy, acquire genuine assignment and
owned/unexpired lease evidence, and validate independent eligible current-head
approval and freshness. This module creates no new approval or bootstrap policy.
Constructing its Python dataclasses is not proof of those facts. Caller JSON is
not accepted as authorization. No production receipt format is established.

Even synthetically valid receipts return `INACTIVE_INTERFACE`,
`bindings_validated=true`, `authority=false`, `ready=false`. The result is not a
certificate, authorization token or publication receipt. No ref is created, no
lease claimed and no status published. Existing governance and promotion gates
remain applicable. Deployment, credential provisioning, grants, assignment
creation and live effects are outside this source task.

Tests use fixture repository identities and fabricated verifier output only.
They exercise all request-field bindings independently against all three receipts,
fail-closed inputs and the invariant that validated fixtures remain inactive.
Run `python3 -m unittest discover -s tests -p test_bootstrap_interface.py -v`.
