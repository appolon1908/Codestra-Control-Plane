# Authenticated atomic receipts implementation plan

Source implementer: existing sole control-plane owner. Review: existing
certifier and configuration reviewers, read-only. Execution remains inline in
the assigned isolated atomic worktree; no new product worker or runtime lease.

1. Reproduce incomplete packaging; implement distinct immutable complete-source
   packager, proposed verifier configuration, explicit schema/config manifests
   and malicious replacement/missing-file/custody tests. Preserve old candidate.
2. Add empty, operator-owned purpose-bound atomic receipt source schema and
   strict acceptance parser. Integrate a read-only authenticated acquisition
   port with nonempty first-subsection inventory reconciliation and independent
   online GitHub receipt/inclusion verification. Test sequential released
   children, revocation, omission, cycles, wrong purpose/App/identity/head/base,
   stale evidence and missing accepted inputs. Apply DDL only in disposable tests.
3. Specify explicit global coverage acceptance; implement source validator and
   proposed example with the three pending selected identities. No automatic
   scope expansion or installation. Add new source artifacts to packaging.
4. Obtain independent source reviews, fix actionable findings, commit the final
   cohort, run the required full suite once, produce exact-commit candidate
   manifests, push eligible atomic branch and open/update its governed PR.
   Record actual commit, test and remote parity receipts; do not merge or publish
   a control-plane success from source CI.
