# Bootstrap repository validation repair

Assignment: Codestra-Control-Plane -> cp-01-foundation -> 02-trusted-decisions -> bootstrap-repository-validation.

The user requested repairs for every repository needing bootstrap. The shared legacy validator misses replacement V3 branches and publishes successful controller statuses on file-shape checks alone. Repair this shared source first, then inspect its configured repositories and preserve per-repository findings. Existing product writers, live activation and frozen installation packets remain separate.

- [x] Reproduce the legacy status-write defect with a fake transport and real CLI.
- [x] Replace the validator with a read-only implementation: exact candidate SHA content reads, current V3 branch discovery, ambiguity denial, bounded response validation, independent per-repository failures and redacted diagnostics.
- [x] Test replacement branches, changed heads, malformed content, duplicate keys, missing files, unavailable repositories, ambiguous candidates, and absence of all write commands.
- [x] Inspect current repositories through read-only GitHub tools, report actual remaining source or external blockers without fabricating admission.
- [x] Run focused tests and static checks and inspect the changed-file scope.
- [ ] Commit and prepare the atomic-to-subsection PR if existing publication controls permit; publication evidence is recorded separately after completion.

No installed tool, credential, service, database, check status, ruleset or source grant is changed. Source-file validation is not runtime admission or certification.

Companion defect: the legacy rollout also self-published successful certification.
Removed only that status write; a real-shell test replaces its installer/Git/GitHub
boundaries and proves the source no longer emits it. No rollout was performed.
Independent review and hosted CI remain gates on the prepared PR.
