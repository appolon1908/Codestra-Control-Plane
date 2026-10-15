# Promotion route consistency

The legacy promotion checker selected reference validation from caller-supplied
logical stages. The SQL registry uses `test`, while the checker validated only
`testing`; an admitted `development -> test` or `test -> staging` edge could
therefore pass with unrelated refs and legacy PASS evidence. Atomic promotion
also had no authenticated candidate verifier and could pass that same evidence.

All three source entry points now use the reference resolver in
`bin/codestra-github-check`. Subsections must target their matching section,
sections target development, and environment refs use the product's registered
test branch. Test refs that collide with environment names or hierarchy namespaces
are rejected; noncolliding registered names remain supported. Existing scope
records, exact-SHA certificates and evidence checks
remain required. SQL edge and evidence queries retain the caller's exact logical
labels; recognizing both `test` and `testing` never creates an edge or relabels
evidence. Atomic promotion is denied until its trusted verifier exists.

This also corrects the misleading PR #453 diagnostic. A feature branch targeting
development is rejected as `section_source_required` before a section lookup;
its label cannot become a certified section merely by inserting a registry row.
The supported path remains registered subsection -> matching section ->
development. Existing explicitly scoped migration policies are unchanged.

## Validation and limits

The new offline tests call the real CLI main functions and publisher validator
with synthetic SQL responses and all network/process boundaries disabled.
Before the fix, six assertions reproduced false PASS decisions. Positive cases
preserve registered subsection/section certification, `test`/`testing` and a
custom product test ref. Review also reproduced false PASS decisions with
colliding test refs, now covered by negative cases across all three entry points.
Missing certificates, SHA drift, evidence and logical edges
still block. These fixtures do not certify any live repository or task.

Local validation passed all 209 tests with:

```sh
PRODUCTION_GO=NO LIVE_CAPABILITIES_ENABLED=NO EXTERNAL_EFFECTS=false \
  PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

Independent source review also passed the nine focused route regressions and
`git diff --check` after the collision fix.

This is source preparation only. No runtime files, registry rows, leases,
services, GitHub statuses or product PR routes were changed. The promotion
checker now loads the same companion checker as the publisher: deployment must
preserve the compatible three-file set, with independent acceptance and the
existing installation gates. Middleware's repository guard remains independently
enforced; its feature-to-development rejection is still correct.

Legacy evidence authentication and the trusted atomic candidate adapter remain
unimplemented. This patch must not be presented as closing those trust gaps or
making PR #453 certified. Genuine assignment, prerequisites, accepted route and
exact-head approval still have to be established through the operator workflow.
