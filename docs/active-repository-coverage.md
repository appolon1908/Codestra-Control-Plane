# Approved active repository publication coverage

User approval on October 14, 2026 authorizes source coverage for verified active development repositories, not all GitHub repositories. This candidate covers 43 canonical repositories: six existing entries and 37 additions. It is not deployed and grants no certification or production/provider authority.

The earlier repair PR8 has merged into subsection commit `9ab5690708cd8f72a8379da1121604a95a1f990f`. This source preparation follows the atomic reconciliation candidate `7ec0dc586b92bba651103aea51e71eaf894c6228` in PR10; its governed acceptance remains a prerequisite. PR9 and its direct-to-main route are not modified.

## Included scope

Every listed repository has a matching authoritative `products.repository`/product mapping, canonical desktop Git origin, tracked source/CI/configuration and open owned development or CI work. These observations support source coverage only: they do not establish a current runtime lease, completed assignment, successful CI or certification. No missing registry rows were created.

All 37 additions use product name equal to repository name, `test_branch=testing`, and the registered environment chain `development -> testing -> staging -> production`. Those bindings are checked again at selection time. The six prior entries keep their existing mapping behavior; in particular OpenBao retains its registered `test` ref despite older promotion-chain metadata spelling `testing`. No ref is silently normalized.

| Repository under appolon1908 | Scope | Source/CI activity evidence |
| --- | --- | --- |
| backend2 | Added | [PR 22](https://github.com/appolon1908/backend2/pull/22) `feat/leadconnector-signed-intake-20261008` |
| Backstage | Added | [PR 7](https://github.com/appolon1908/Backstage/pull/7) `feat/backstage-home-private-server-20261008` |
| beyvra-backend | Added | [PR 149](https://github.com/appolon1908/beyvra-backend/pull/149) `integration/beyvra-security-authority-convergence-20261009` |
| beyvra-frontend | Added | [PR 49](https://github.com/appolon1908/beyvra-frontend/pull/49) `docs/repo-architecture-charts-20261002` |
| Breero.com | Added | [PR 151](https://github.com/appolon1908/Breero.com/pull/151) `mission/v3-pr-convergence-20260929` |
| Caddy | Retained | [PR 209](https://github.com/appolon1908/Caddy/pull/209) `fix/activation-runtime-safety` |
| codestra | Added | [PR 49](https://github.com/appolon1908/codestra/pull/49) `mission/gh47-refresh-concurrency` |
| Codestra-Alertmanager | Added | [PR 40](https://github.com/appolon1908/Codestra-Alertmanager/pull/40) `mission/observability-workstation-ci-cd` |
| Codestra-Alloy | Added | [PR 49](https://github.com/appolon1908/Codestra-Alloy/pull/49) `mission/observability-workstation-ci-cd` |
| Codestra-Blackbox-Exporter | Added | [PR 46](https://github.com/appolon1908/Codestra-Blackbox-Exporter/pull/46) `mission/observability-workstation-ci-cd` |
| Codestra-cAdvisor | Added | [PR 50](https://github.com/appolon1908/Codestra-cAdvisor/pull/50) `mission/observability-workstation-ci-cd` |
| Codestra-Grafana- | Added | [PR 42](https://github.com/appolon1908/Codestra-Grafana-/pull/42) `mission/observability-workstation-ci-cd` |
| Codestra-Loki | Added | [PR 50](https://github.com/appolon1908/Codestra-Loki/pull/50) `mission/observability-workstation-ci-cd` |
| Codestra-Mission-Control | Added | [PR 30](https://github.com/appolon1908/Codestra-Mission-Control/pull/30) `fix/mission-control-staging-getonly-parity-20261009` |
| Codestra-Node-Exporter | Added | [PR 47](https://github.com/appolon1908/Codestra-Node-Exporter/pull/47) `mission/observability-workstation-ci-cd` |
| Codestra-OpenBao | Retained | [PR 108](https://github.com/appolon1908/Codestra-OpenBao/pull/108) `fix/ob15-patched-xtext-image-gate-20261009` |
| Codestra-Postgres-Exporter | Added | [PR 28](https://github.com/appolon1908/Codestra-Postgres-Exporter/pull/28) `mission/observability-workstation-ci-cd` |
| Codestra-Prometheus | Added | [PR 85](https://github.com/appolon1908/Codestra-Prometheus/pull/85) `repair/pr70-successor-20261008` |
| codestra-provisioning-service | Added | [PR 35](https://github.com/appolon1908/codestra-provisioning-service/pull/35) `chore/canonical-owner-appolon1908-20261002` |
| Codestra-Redis-Exporter | Added | [PR 49](https://github.com/appolon1908/Codestra-Redis-Exporter/pull/49) `mission/observability-workstation-ci-cd` |
| Codestra-Telemetry | Added | [PR 68](https://github.com/appolon1908/Codestra-Telemetry/pull/68) `mission/observability-workstation-ci-cd` |
| Codestra-Tempo | Added | [PR 43](https://github.com/appolon1908/Codestra-Tempo/pull/43) `mission/observability-workstation-ci-cd` |
| Evolution-API | Added | [PR 17](https://github.com/appolon1908/Evolution-API/pull/17) `hardening/phone-production-readiness-20261008` |
| Frontend-Resturant- | Added | [PR 14](https://github.com/appolon1908/Frontend-Resturant-/pull/14) `chore/canonical-owner-appolon1908-20261002` |
| Infustruction-repo | Added | [PR 129](https://github.com/appolon1908/Infustruction-repo/pull/129) `chore/canonical-owner-appolon1908-20261002` |
| Keycloak | Retained | [PR 151](https://github.com/appolon1908/Keycloak/pull/151) `fix/postgres-cold-start` |
| klyrow.com | Added | [PR 192](https://github.com/appolon1908/klyrow.com/pull/192) `repair/pr178-successor-20261008` |
| Kong | Retained | [PR 136](https://github.com/appolon1908/Kong/pull/136) `feature/mission-control-staging-readonly-20261008` |
| kyqra-crawler | Added | [PR 54](https://github.com/appolon1908/kyqra-crawler/pull/54) `fix/kyqra-api-contract-parity-20260925` |
| LARIM-A-Backend | Added | [PR 10](https://github.com/appolon1908/LARIM-A-Backend/pull/10) `mission/account-profiles-devices` |
| LARIM-A-Fornt-end | Added | [PR 14](https://github.com/appolon1908/LARIM-A-Fornt-end/pull/14) `fix/larimia-frontend-exact-sha-ci-20261007` |
| Leads-Workstation | Added | [PR 15](https://github.com/appolon1908/Leads-Workstation/pull/15) `fix/leads-dashboard-mobile-nav-20261008` |
| Meltano-Leads-Importer | Added | [PR 3](https://github.com/appolon1908/Meltano-Leads-Importer/pull/3) `repair/deployment-design-20260924` |
| Middleware- | Retained | [PR 453](https://github.com/appolon1908/Middleware-/pull/453) `feature/leads-workstation-integration-clean-20261008` |
| Moneybee-Backend | Added | [PR 94](https://github.com/appolon1908/Moneybee-Backend/pull/94) `governance/dedicated-exact-sha-ci` |
| Moneybee-frontend- | Added | [PR 43](https://github.com/appolon1908/Moneybee-frontend-/pull/43) `fix/moneybee-frontend-exact-sha-ci-20261007` |
| N8N | Retained | [PR 68](https://github.com/appolon1908/N8N/pull/68) `mission/leads-workstation-integration-20260923` |
| Odoo | Added | [PR 167](https://github.com/appolon1908/Odoo/pull/167) `feat/spanish-market-leads-staging-preflight-20261009` |
| Sentry | Added | [PR 6](https://github.com/appolon1908/Sentry/pull/6) `mission/observability-workstation-ci-cd` |
| Superset | Added | [PR 56](https://github.com/appolon1908/Superset/pull/56) `repair/observability-normalization-20260924` |
| Wazuh | Added | [PR 6](https://github.com/appolon1908/Wazuh/pull/6) `mission/observability-workstation-ci-cd` |
| WhatsApp | Added | [PR 19](https://github.com/appolon1908/WhatsApp/pull/19) `fix/workstation-whatsapp-safety-20261008` |
| WhatsApp-Frontend | Added | [PR 1](https://github.com/appolon1908/WhatsApp-Frontend/pull/1) `feature/agent-console-foundation-20260925` |

Canonical desktop sources are `/srv/codestra/apps/<repository>`. WhatsApp-Frontend main is not application-bearing; its owned active PR1 contains `Dockerfile`, `package.json` and `src/` application code at `0c699ae82d8d019e51face6f415235ab63fbc835`. Sentry/Wazuh active PR6 adds actual corporate/candidate CI workflows and `scripts/codestra-ci.sh`; inclusion is based on owned source/CI activity, not a monitoring design assignment alone. Other monitoring candidates have deployable/configuration or implementation activity; family design records alone were not treated as sufficient evidence.

## Blocked or excluded

| Candidate | Reason |
| --- | --- |
| Codestra-Control-Plane | Active source exists, but authoritative product/workstation/candidate registration and owned writer mapping are missing. Excluded from effective coverage. |
| codestra-production-platform | Product mapping and source exist, but this review found no open development PR or assigned owner/current task in its workstation records. Release/default-branch configuration alone is insufficient active-assignment evidence. Needs owner confirmation. |
| codestra-backend | DECOMMISSION in authoritative REPOSITORY-AUTHORITY.json; backend2 is canonical. Historical product manifests do not override this. |
| kyqra | Retired successor relationship: kyqra-crawler is the scoped active source. |
| DJONE | Docs/audio/content scope excluded by the user. |
| Codestra-Device-Forge; Codestra-Workstation | Active source/assignment scope remains uncertain. |
| transportation-backend-; transportaion-Frontend | Architecture/profile evidence alone; excluded user scope. |
| akshay-4362/ralph-japanese-demo; external ralpha-node-api | Outside the approved canonical owner/repository scope. |
| Unresolved restaurant backend | No proven canonical backend identifier or mapping; Frontend-Resturant- coverage does not infer one. |
| Duplicate checkouts and all other repositories | One canonical entry per repository; no automatic expansion to the account inventory. |

## Evaluation and compatibility

New entries require their exact reviewed product/test-ref/chain binding and a unique case-insensitive repository mapping. Missing, mismatched or ambiguous records produce no effective alias or successful status. Existing prior coverage is retained. No bootstrap exception is added, and all existing remote-head, parent, certificate and commit checks remain unchanged.

Adding Infrastructure coverage does not approve PR128: `architecture/middleware-integration-layer-20260924 -> main` at `ca8f3ff1d51180bf8ff33a38e89484dbcf00a806` still evaluates to BLOCK for invalid promotion path even with a matching observed remote SHA. No unconditional green status is introduced.

Regression tests first exposed the missing approved scope. They cover the exact 43-repository set, retired/external/unregistered exclusions, missing/mismatched/case-ambiguous mappings, OpenBao ref preservation, exact certificate binding, remote-SHA mismatch and denial of new bootstrap exceptions for every addition. External effects are mocked.

No source coverage is activated on the installed publisher. Installation, publisher ownership, credentials, protection/reviewer policy, registry/leases and services remain unchanged. Current certification and independent acceptance gates still apply.
