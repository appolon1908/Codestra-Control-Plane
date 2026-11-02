# Codestra Control Plane development contract

This repository is the user-designated source owner for shared Codestra
development governance. Preserve each product repository's independent authority.

Use one active assignment and an isolated worktree with one source writer.
GitHub Actions and repository protections are the source-merge authority for all
appolon1908 repositories, as directed by the owner on 2026-11-02. Existing branch
hierarchies may organize work; source repair PRs are evaluated by native GitHub
protections rather than a custom controller route or database certificate.
Require verified signed commits, actual required CI, fresh independent review,
resolved threads and current base/head evidence. Never push code directly to a
protected branch, force push, self-approve, or weaken required checks.

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

If native protection, independent approval, verified signatures, required CI or
current-SHA evidence is missing, stop source merging. Preserve unsigned branches;
prepare signed successors without rewriting existing history and obtain new CI
and review. Do not publish compatibility success statuses or treat a checkout as
product certification. See docs/superpowers/specs/2026-11-02-native-github-governance-design.md.

Production requires separate protected GitHub environment approval, exact
artifact evidence and the existing runtime safeguards. Source merge approval
does not grant deployment authority. Installed controller services and runtime
prerequisites remain unchanged until their separately scoped replacement is
reviewed. Continue useful source preparation without bypassing these boundaries.
