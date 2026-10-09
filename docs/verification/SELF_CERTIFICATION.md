# Codestra Control Plane — local source self-certification

Scope: source verification only. This provides evidence when hosted Actions
cannot start; it is NOT a replacement for GitHub required checks, code-owner
approval, promotion/merge authority, deployment validation or production signoff.

From a clean checkout at the exact remote head of this PR:

    git fetch origin atomic/cp-01-foundation--01-source-import
    git switch --detach FETCH_HEAD
    python3 -S scripts/self_certify_source.py \
      --branch atomic/cp-01-foundation--01-source-import \
      --expected-sha "$(git rev-parse HEAD)" \
      --output "/tmp/codestra-cp-source-$(git rev-parse --short HEAD).json"
    sha256sum /tmp/codestra-cp-source-*.json

The verifier runs from the exact Git commit and compares HEAD against
the caller's full 40-digit SHA and the canonical GitHub remote branch.
It rejects dirty trees (including untracked files), noncanonical origin URLs,
unsafe refs, existing evidence files, and evidence paths inside the checkout.
It runs the entire standard-library-only unit suite with -S and
PRODUCTION_GO=NO, LIVE_CAPABILITIES_ENABLED=NO, EXTERNAL_EFFECTS=false.

The JSON report binds source commit/tree SHA, remote SHA, test count,
test-output SHA-256, time and host environment. It explicitly records
github_ci_certified=false, independent_codeowner_approved=false and
merge_or_promotion_authorized=false. The hash of the local evidence file
provides only integrity comparison, NOT a cryptographic signature and not
independent assurance. Retain the report outside the repository to avoid
self-reference or repository pollution.

Fail-closed stopping conditions: mismatched Git/remote SHA, dirty tree,
test failure, insufficient test count, or inability to read the remote all
produce a nonzero result and no success certificate. Do not post artificial
success commit statuses to bypass GitHub billing or repository protection.

After an authorized GitHub account owner restores Actions billing, rerun the
actual Actions workflow and obtain an independent eligible reviewer before
merging. Live effects and staging/production promotion stay disabled.
