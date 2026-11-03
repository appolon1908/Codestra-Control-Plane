# Source-gate retirement execution

Authority: the owner's explicit November 3 request to retire obsolete controller
gates, following the approved November 2 native GitHub governance design.
Source base: `8c748802fe47e1946c061a0fe0e0d544fe441687`.
Branch: `atomic/retire-controller-gates-20261103` in its isolated worktree.
Scope: eight legacy CLI entrypoints, a refusal helper, relevant tests and docs.

1. Inspect the actual producers and consumers. Preserve genuine native CI and
   runtime/business controls; do not infer obsolescence from a check name.
2. Add sandboxed real-entrypoint tests and observe failures before implementation.
   Verify missing dependencies, former arguments, explicit refusal and no effects.
3. Add early CLI retirement guards. Preserve historical callable functions for
   offline tests; publish no synthetic success status and change no live service.
4. Update only obsolete CLI expectations. Run focused tests, the full Linux
   Python 3.12/PostgreSQL 16 suite and `git diff --check`; record limitations honestly.
5. Obtain independent review of the exact patch. Commit reviewed work, publish
   through the guarded self-hosted publisher and verify local/remote SHA parity.
   Obtain exact-head GitHub CI and review before any protected source merge.
6. Track installed-hook/service and repository-setting migrations separately.
   This source patch does not execute them or authorize production/DNS changes.

Source preparation has observed RED then GREEN for 24 sandboxed argument cases
across the eight CLIs. The existing promotion-checker CLI tests also pass. The
Windows full-suite attempt encountered pre-existing POSIX requirements and is
not a passing Linux gate. Independent review, full Linux/hosted validation and
publication evidence remain separate checkpoints; this plan anticipates none of
their results.
