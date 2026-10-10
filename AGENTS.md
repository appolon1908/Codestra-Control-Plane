# Codestra Control Plane development contract

This repository is the user-designated source owner for shared Codestra
development governance. Preserve each product repository's independent authority.

Use one active assignment: Product -> Section -> Subsection -> Atomic Task.
Implement in the assigned atomic branch and an isolated worktree. Promote by PR:
atomic task -> subsection -> section -> development -> testing -> staging ->
production -> main. Main is the final release record. Never push code directly
to an environment branch, force push, self-approve, or weaken required checks.

The initial source adoption is assigned in `governance/source-authority.json`.
That assignment is not a database lease, certification, or permission to publish
a successful control-plane status. The initial branches contain only GitHub's
repository initialization commit until their corresponding PRs are accepted.

Keep PRODUCTION_GO=NO, LIVE_CAPABILITIES_ENABLED=NO and EXTERNAL_EFFECTS=false.
Do not execute imported commands against live databases or GitHub as a test.
Source imports retain historical behavior; inspection is not certification.

Before edits, inspect instructions, branch, current refs, and existing changes.
Preserve other agents' work. Reproduce defects with meaningful tests, implement
the fix, run the affected suite, inspect the diff, and commit to the assigned
branch. Record exact commits, actual test output, and unresolved gates. Do not
describe a source patch as deployed or a passing unit test as a release approval.

Credential values, live database contents, logs, backups, leases and runtime
evidence do not belong in source control. Import only reviewed source files with
recorded digests. Do not replay captured SQL against the live database: inspect
drift and test forward migrations in a disposable database first.

If protection, approval, lease, CI, or current-SHA evidence is missing, stop
promotion. Continue useful in-scope source preparation without bypassing the gate.
