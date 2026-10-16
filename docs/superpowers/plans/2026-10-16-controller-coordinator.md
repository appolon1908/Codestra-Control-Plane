# Controller coordinator source implementation

The user approved implementing the missing coordinator. Preserve the existing
issuer, independent materializer, hierarchy and no-effect defaults.

1. Add a forward migration with an operator-owned task description and explicit
   prerequisite inventory. A restricted resolver validates the authenticated
   credential/session/OID, exact binding, registration, dependency inventory,
   policy and lane before returning server-derived candidate metadata.
2. Add a builder-only coordinator API/CLI. Prepare registers that candidate;
   admit consumes a separately committed verifier proof with the existing
   transactional lease issuer. No verifier credential is loaded in this process.
   Default dry runs roll back and return no admission. Recover reads an existing
   request without issuing a new lease. Final resolution and claim share one
   transaction; current mappings and grants must still match.
3. Test first against disposable PostgreSQL 16 with TLS/SCRAM. Exercise mapping
   isolation, omitted/revoked dependencies, registration, rollback, independent
   proof, stale authority, concurrency and lost responses. Reuse materializer
   tests for real checkout/ref observations. Run the source suite and review diff.
4. Document source installation/credential/grant prerequisites and explicit
   limits. Commit and publish an atomic-to-subsection PR. Do not deploy, provision
   authority, publish successful statuses or claim a runtime admission occurred.

Admission is a committed ACTIVE online lease, never a local PASS value,
certificate, promotion or review-ref publication. Missing registrations outside
the candidate, operator mapping, remote source ref or independent verifier
evidence remain denials. No missing authority is inferred from legacy metadata.
