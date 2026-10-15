# Authenticated Publisher Implementation Plan

**Goal:** Implement the approved single-host source publisher while keeping operational activation separate.
**Authority:** Ralph L. Appolon, explicit user instruction to implement in this session.
**Baseline:** 625c40a3e4a1ad7726523d8677b63121f965056a.
**Architecture:** Operator-owned authority read model and restricted authenticated PostgreSQL session; privileged GitHub App installation transport; fresh GitHub receipts and ref/protection/merge-result gates; durable per-context intent ledger. No installed configuration or credential is created. Legacy publisher validation cannot enable this path.

## Constraints

- Source only; no external network mutations during development, provisioning, grants, leases, service changes or activation.
- Exact two contexts and approved repository scope; complete inventories, accepted producers, independent reviews, certificates and owned leases.
- Five-minute existing snapshot limit; other expiration limits are authority data, not invented constants.
- Local lock does not fence other credential holders. Credential custody/exclusivity must be independently operator-attested; no raw caller JSON enables effects.
- GitHub ref movement and two status writes remain non-atomic. Revalidate target/head, merge result, protection and revocation before each write; partial/uncertain outcomes never blindly retry.

## Files and tasks

1. Add source contract documentation and operator-owned PostgreSQL read-model DDL. Runtime has read-only table access; no authority/lease writers are added.
2. Add `publisher_adapter.py`: restricted session validation, online GitHub acquisition/evaluation, target/merge-result/protection checks, capability/expiry/host validation. Add offline negative tests first.
3. Add `publisher_effect.py`: SQLite durable intents, per-context preflight, readback and partial/uncertain outcomes; no automatic retries after reserved/partial/uncertain records. Test crash/revocation/ref changes before writes.
4. Add source-only integration factory using explicit privileged dependencies, separate from caller inputs. Keep default installed entrypoint refusal until operator provisioning and accepted concrete wiring exist; do not replace a refusal with a generic JSON enabled flag.
5. Run affected tests, full offline suite and independent source review. Record exact evidence; no push or review-request mutation in this source-only phase.

## Review focus

- Superuser/shared/role-switch sessions cannot authenticate restricted registry acquisition.
- Producer names or PASS rows cannot substitute for online GitHub receipt identity.
- A moving target, unknown merge result or absent protection denies each context write.
- Revocation between writes leaves PARTIAL; ambiguous POST leaves UNCERTAIN, no compensation.
- Local fences and authenticated objects do not imply global credential exclusivity or atomic external writes.

## Completed source follow-up before publication

Concrete fixed-path protected TOML startup and local OpenSSL RS256 signer added;
main wires authenticated cycles only after designated-service/local-lock ownership.
All secret/config/CA ancestors and runtime code custody are checked. Signing tool
binary/libcrypto/libssl digests are candidate-pinned and included in release metadata.
Certificate acquisition additionally requires a separately operator-granted expiring
exact-binding issuer capability; generic CI/Actions/self-issued aliases deny.
Accepted PR22/PR24 target source is merged locally before final full-suite verification.
