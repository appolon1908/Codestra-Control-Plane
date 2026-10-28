# Read-only bootstrap repository source inspection

`bin/codestra-validate-v3-bootstrap-prs` checks the 24 existing standalone V3
repository entries by default. It uses the invoking user's existing `gh`
authentication, with GET requests only; it does not switch identity or publish
`codestra-control-plane` / `codestra/control-plane` statuses. File checks cannot
authenticate an assignment, lease, review, test result or admission receipt.

```sh
python3 -B bin/codestra-validate-v3-bootstrap-prs
python3 -B bin/codestra-validate-v3-bootstrap-prs --repo appolon1908/Codestra-Connect \
  --head workstation/standalone-v3-r2-20261007
```

Repeated `--repo` selects exact repositories. This changes inspection scope only,
not the controller's configured coverage. Both the original dated V3 head and
replacement `-rN-` heads are discovered against `development`. Multiple matching
PRs require explicit `--head`; neither creation date nor the largest revision
number establishes authority to supersede a candidate. A full 100-item response
is treated as incomplete rather than silently selecting from truncated results.

All three files are read at the captured head SHA. Policy checks bind the exact repository and retain the
required controller context, complete promotion chain, disabled production
flags, and prohibitions on force-push and direct protected writes. The
workstation map must be a nonempty JSON object; AGENTS.md must be nonempty UTF-8.
This does not validate the workstation map against a live registry or establish
that prose requirements have been fulfilled. Duplicate JSON keys, nonfinite
numbers, symlinks, invalid encoding and size mismatches are rejected.

The PR is read again after file inspection; source/base movement, closing,
retargeting and fork substitutions deny validation. The snapshot can still
become stale after the command exits. It is never consumable as authorization.

Exit 0 means all selected candidates passed these source checks. Exit 1 means
at least one repository was missing, ambiguous, malformed or unavailable. One
repository failure does not suppress the remaining results. Every JSON report
states `authority=NONE`, `certified=false` and `status_writes=0`. Transport error
bodies are redacted. Genuine controller admission, eligible independent review,
exact-head CI and protected-route approval remain separate requirements.

The former shell implementation selected only `workstation/standalone-v3-20261007`
and attempted two success-status writes per repository after basic file checks.
The regression test executes that entry point through a disposable fake transport;
the original reproduced 48 attempted writes, all intercepted. The replacement
runs without writes. REST pull metadata avoids version-specific `gh pr --json`
fields; older installed gh clients do not support `baseRefOid`.

The companion `codestra-rollout-standalone-governance` retains its existing
installer/PR-preparation behavior but no longer posts a successful controller
status. Its disposable-shell regression intercepted 24 such writes before the
fix. The rollout is not executed against any real product by this task; its
remaining installation effects still require their existing authorization.
