"""Coverage selects approved mapped work; it never grants certification."""
import contextlib
import io
import runpy
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PRIOR = {"Middleware-", "Caddy", "Kong", "Keycloak", "Codestra-OpenBao", "N8N"}
ADDITIONS = set("""
Backstage Breero.com Codestra-Alertmanager Codestra-Alloy Codestra-Blackbox-Exporter
Codestra-Grafana- Codestra-Loki Codestra-Mission-Control Codestra-Node-Exporter
Codestra-Postgres-Exporter Codestra-Prometheus Codestra-Redis-Exporter Codestra-Telemetry
Codestra-Tempo Codestra-cAdvisor Evolution-API Frontend-Resturant- Infustruction-repo
LARIM-A-Backend LARIM-A-Fornt-end Leads-Workstation Meltano-Leads-Importer Moneybee-Backend
Moneybee-frontend- Odoo Sentry Superset Wazuh WhatsApp WhatsApp-Frontend backend2
beyvra-backend beyvra-frontend codestra codestra-provisioning-service klyrow.com kyqra-crawler
Codestra-Control-Plane Codestra-PostgreSQL OpenAPI codestra-foundation codestra-ruleset-toolkit openrerefine-
""".split())


class ActiveRepositoryCoverageTests(unittest.TestCase):
    def setUp(self):
        driver = types.ModuleType("psycopg2")
        extras = types.ModuleType("psycopg2.extras")
        driver.connect = mock.Mock(side_effect=AssertionError("live DB forbidden"))
        extras.RealDictCursor = object
        driver.extras = extras
        with mock.patch.dict(sys.modules, {"psycopg2": driver, "psycopg2.extras": extras}):
            self.module = runpy.run_path(str(ROOT / "bin/codestra-github-statusd"), run_name="offline_coverage")

    def row(self, name, **changes):
        return dict(product=name, repository="appolon1908/" + name, test_branch="testing",
                    promotion_chain=["development", "testing", "staging", "production"], **changes)

    def aliases(self, rows):
        connection = mock.MagicMock()
        connection.cursor.return_value.__enter__.return_value.fetchall.return_value = rows
        with contextlib.redirect_stdout(io.StringIO()):
            return self.module["aliases"](connection)

    def test_verified_scope_contains_exactly_prior_and_approved_active_repositories(self):
        rows = [self.row(name) for name in PRIOR | ADDITIONS]
        aliases = self.aliases(rows)
        self.assertEqual({r[0] for r in aliases}, PRIOR | ADDITIONS)
        self.assertEqual(len(aliases), 49)
        self.assertEqual(len(self.module["GOVERNED_REPOS"]), 49)

    def test_retired_unverified_external_and_unregistered_candidates_stay_out(self):
        excluded = ("codestra-backend", "kyqra", "Unapproved-Repository", "codestra-production-platform",
                    "DJONE", "Codestra-Device-Forge", "Codestra-Workstation", "transportation-backend-",
                    "transportaion-Frontend", "ralpha-node-api")
        rows = [self.row(name) for name in excluded] + [self.row("backend2")]
        rows.append(dict(self.row("backend2"), repository="akshay-4362/ralph-japanese-demo"))
        self.assertEqual([r[0] for r in self.aliases(rows)], ["backend2"])

    def test_mapping_drift_for_new_repository_is_not_used(self):
        for changes in ({"product": "Middleware-"}, {"test_branch": "test"}, {"test_branch": None},
                        {"promotion_chain": None}, {"promotion_chain": ["development", "production"]}):
            with self.subTest(changes=changes):
                row = self.row("Infustruction-repo")
                row.update(changes)
                self.assertEqual(self.aliases([row]), [])

    def test_duplicate_or_case_ambiguous_mapping_is_not_used(self):
        row = self.row("Infustruction-repo")
        for other in (dict(row), dict(row, repository="appolon1908/infustruction-repo")):
            with self.subTest(other=other["repository"]):
                self.assertEqual(self.aliases([row, other]), [])

    def test_missing_registration_does_not_create_coverage(self):
        self.assertEqual(self.aliases([]), [])

    def test_existing_openbao_test_ref_is_preserved(self):
        row = self.row("Codestra-OpenBao")
        row["test_branch"] = "test"
        self.assertEqual(self.aliases([row])[0][2], "test")

    def test_new_coverage_keeps_exact_sha_certificate_requirement(self):
        validate = self.module["validate"]
        sha = "a" * 40
        for name in ADDITIONS:
            with self.subTest(repository=name), mock.patch.dict(validate.__globals__, {"remote_sha": lambda *_: sha}):
                connection = mock.MagicMock()
                row = dict(status="CERTIFIED", remote_sha=sha, parent_branch="section/fixture", exact_sha_certified=None)
                connection.cursor.return_value.__enter__.return_value.fetchone.return_value = row
                args = (connection, name, "testing", "/unused", "subsection/fixture", "section/fixture", sha)
                self.assertFalse(validate(*args)[0])
                row["exact_sha_certified"] = sha
                self.assertTrue(validate(*args)[0])
                self.assertFalse(validate(*args[:-1], "b" * 40)[0])

    def test_infrastructure_existing_architecture_pr_stays_blocked(self):
        validate = self.module["validate"]
        sha = "ca8f3ff1d51180bf8ff33a38e89484dbcf00a806"
        with mock.patch.dict(validate.__globals__, {"remote_sha": lambda *_: sha}):
            allowed, reason = validate(mock.MagicMock(), "Infustruction-repo", "testing", "/unused",
                                       "architecture/middleware-integration-layer-20260924", "main", sha)
        self.assertFalse(allowed)
        self.assertIn("invalid promotion path", reason)

    def test_added_repositories_receive_no_bootstrap_exception(self):
        validate = self.module["validate"]
        sha = "a" * 40
        for name in ADDITIONS:
            with self.subTest(repository=name), mock.patch.dict(validate.__globals__, {"remote_sha": lambda *_: sha}):
                self.assertFalse(validate(mock.MagicMock(), name, "testing", "/unused",
                                          "governance/development-control-plane-v1", "main", sha)[0])


if __name__ == "__main__":
    unittest.main()
