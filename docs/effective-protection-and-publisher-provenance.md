# Effective protection and publisher provenance: source contract

This source lane starts at the current merged section commit
`a6350c1b9e5f1cb13b0226d0ecf1dd137463e472`, preserving its already merged
controller App-binding repair. Its publication target is the existing subsection
`subsection/cp-01-foundation--02-trusted-decisions`, observed at
`fb873592004862712543366a4d14de10ec5412ec`. Source preparation is human-authorized;
registration, runtime assignment, lease and certification remain null. No runtime
configuration, credentials, protection rules, permissions or services are changed.
The separate local review-admission commit `41ec4fb...` is neither edited nor imported.

## Effective branch observations

The concrete GitHub client reads every bounded page of
`GET /repos/{owner}/{repo}/rules/branches/{branch}`. That endpoint supplies applicable
active rules across repository/organization levels; local glob matching is not used.
Evaluate/disabled rules do not establish enforcement. Rule entries lack ordinary
item IDs, so a distinct bounded pagination path is used. Source ruleset details are
read with `includes_parents=true` and matched to exact source/type/ID/rule parameters.
Repository and organization sources are supported; other source kinds deny.

Classic protection and native rulesets are combined. Classic admin enforcement,
review counts, codeowner review, stale-review dismissal, last-push approval,
conversation resolution, strict checks and exact producer identities remain gates.
All required checks across both mechanisms must match the authenticated snapshot;
stronger or changed requirements cannot be silently ignored. Full-certification
controller contexts are checked against the independently verified producer contract
without requiring circular pre-existing success. No success alias is introduced.

Only an explicit HTTP404 can represent absent classic protection, after the existing
online verifier has authenticated repository/App scope and target identity. HTTP403,
transport errors and inaccessible ruleset details deny. Bare branch protected=true
is insufficient. Classic review-bypass allowances must be explicitly empty. Native
bypass actors must be explicitly visible and empty: omitted is not empty. GitHub only
returns that field to callers with write access to the ruleset. This implementation
does not request broader permissions or change any installed grant to obtain it.
An unreadable bypass policy therefore remains unavailable for publication.

Supported native requirements are pull_request and required_status_checks; deletion
and non_fast_forward restrictions may coexist. Unknown requirements (including merge
queue/deployment/signature policies) deny until separately implemented and verified.
This conservative subset is not a claim of universal ruleset support. Missing fields,
duplicate entries, unconstrained check producers and inconsistent source provenance
deny. Complete canonical evidence is reread after online validation to detect drift.

API reference: https://docs.github.com/en/rest/repos/rules

## Accepted issuer provenance port

`GitHubVerifier` requires a privileged `provenance_verifier`; the generic factory
default remains unset and denies. The successor configured startup now supplies
`AcceptedProducerVerifier`, using a protected operator acceptance record and a
separate read-only certifier identity custodian. Proposed, missing, expired or
revoked acceptance denies. No actual issuer is accepted merely by installing the
code or copying a template. Author JSON, HTTP ingestion, ordinary CI, a receipt
string or an environment flag cannot supply this authority. See
[publisher-certifier-integration.md](publisher-certifier-integration.md).

Only an independently accepted internal verifier may return VerifiedProducerContract.
The verifier must authenticate current operator acceptance, custody, actual issuer and
receipt policy, revocation and independence. This change implements its strict binding
contract; it does not invent that operational authority or supply a real producer.
Dataclasses, fixture callbacks and nonempty receipt references authenticate nothing by
themselves. Real App IDs/receipt policy require separate accepted operational evidence.

The verified result pins exact request digest, numeric repository/PR, publisher and
independent certificate App identities/name, accepted controller context set, purpose,
receipt reference and bounded expiry. Neither publisher nor certifier can reuse any
ordinary required CI producer identity. No fixed Actions App identity is selected as
an issuer. Existing issuer-capability and online check-run verification still apply.
Full controller contexts must be explicitly bound to the accepted publisher App;
unbound/wildcard contexts no longer qualify under this new explicit provenance port.
No installed repository rule or accepted runtime policy is modified by this source.

Provenance is checked again after online observations and with the orchestration
clock after acquisition, before reserving an intent or returning from each pre-effect
acquisition. Expiry/revocation/drift denies. Historical receipts are not bearer tokens.
Durable partial/uncertain intents and the two-context publisher behavior remain intact.

## First publication and operational boundaries

The contract purpose is STATUS_PUBLICATION for an existing fully certified PR. It
cannot authorize REF_CREATION/PREPUBLICATION, manufacture a first-publication lease,
or waive remote source-ref requirements. Plain GitHub REST still cannot atomically
fence a distinct parent ref. Strict parent-fencing support remains unavailable; this
change supplies no ref-creation provider or allow-nonatomic switch. The separate
review-admission source remains local/inactive. Status publication retains its already
documented residual external race and fresh target/test-merge/protection gates.

Validation uses synthetic API/provenance ports and disposable offline database fixtures.
No live authentication, App creation, protection mutation, publication or TLS operation
is performed. The desktop private-terminal handoff and two-rule authentication packet
are unchanged. PRODUCTION_GO=NO; LIVE_CAPABILITIES_ENABLED=NO; EXTERNAL_EFFECTS=false.
