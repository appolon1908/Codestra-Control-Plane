"""Exercise real controller entry points against an entirely fake SQL boundary."""
import contextlib
import io
from pathlib import Path
import runpy
import sys
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
FEATURE = "feature/leads-workstation-integration-clean-20261008"
SUBSECTION = "subsection/mw-05-api--03-connector-api"
SECTION = "section/mw-05-api"


class Database:
    """Deliberately permissive legacy evidence must never override route checks."""
    def __init__(self, test_branch="testing"):
        self.product = dict(test_branch=test_branch, repository="fixture/repository",
                            production_go=False, live_capabilities_enabled=False,
                            external_effects_enabled=False)
        self.workstation = dict(status="CERTIFIED", branch=SUBSECTION,
                                parent_branch=SECTION, remote_sha=SHA,
                                exact_sha_certified=SHA)
        self.section = dict(status="CERTIFIED", branch=SECTION, section_key="mw-05-api",
                            exact_sha=SHA, all_subsections_certified=True,
                            all_exact_sha_certified=True)
        self.certificate = dict(status="CERTIFIED", sha=SHA)
        self.evidence = {key: "PASS" for key in
                         ("ci_exact_sha", "review", "regression", "security",
                          "clean_tree", "remote_sha_match", "contract", "migration", "performance")}
        self.edges = {("atomic_task", "subsection"), ("subsection", "section"),
                      ("section", "development"), ("development", "test"),
                      ("test", "staging"), ("staging", "production")}
        self.attempts = []
        self.reads = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def close(self):
        pass

    def cursor(self, **_):
        db = self

        class Cursor:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def execute(self, query, parameters):
                query = " ".join(query.split())
                db.reads.append((query, parameters))
                if "INSERT INTO promotion_attempts" in query:
                    db.attempts.append(parameters)
                    self.row = None
                elif "FROM products" in query:
                    self.row = db.product
                elif "FROM promotion_edges" in query:
                    self.row = {"edge": True} if tuple(parameters) in db.edges else None
                elif "FROM workstations" in query:
                    self.row = db.workstation
                elif "FROM sections" in query:
                    self.row = db.section
                elif "FROM scope_certifications" in query:
                    self.row = db.certificate
                elif "FROM product_readiness" in query:
                    self.row = {"all_sections_ready": True}
                elif "FROM promotion_evidence" in query:
                    self.row = db.evidence
                else:
                    raise AssertionError(f"unexpected SQL: {query}")

            def fetchone(self):
                return self.row

        return Cursor()


class RegisteredPromotionRouteTests(unittest.TestCase):
    def setUp(self):
        self.driver = types.ModuleType("psycopg2")
        extras = types.ModuleType("psycopg2.extras")
        extras.RealDictCursor = object
        extras.Json = lambda value: value
        self.driver.extras = extras
        self.driver.connect = mock.Mock(side_effect=AssertionError("live DB forbidden"))
        modules = mock.patch.dict(sys.modules, {"psycopg2": self.driver,
                                                "psycopg2.extras": extras})
        modules.start()
        self.addCleanup(modules.stop)
        for target in ("socket.socket", "socket.create_connection", "subprocess.run"):
            patch = mock.patch(target, side_effect=AssertionError("live effect forbidden"))
            patch.start()
            self.addCleanup(patch.stop)
        self.github = runpy.run_path(str(ROOT / "bin/codestra-github-check"), run_name="offline")
        self.publisher = runpy.run_path(str(ROOT / "bin/codestra-github-statusd"), run_name="offline")
        self.promotion = runpy.run_path(str(ROOT / "bin/codestra-promotion-check"), run_name="offline")

    def promotion_result(self, source_level, source_ref, target_level, target_ref, db=None):
        db = db or Database()
        argv = ["codestra-promotion-check", "--product", "middleware",
                "--source-level", source_level, "--source-ref", source_ref,
                "--target-level", target_level, "--target-ref", target_ref, "--sha", SHA]
        self.driver.connect.return_value = db
        self.driver.connect.side_effect = None
        main = self.promotion["main"]
        output = io.StringIO()
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(output), \
             mock.patch.dict(main.__globals__, {"post_github_status": lambda *_: True}):
            try:
                main()
                code = 0
            except SystemExit as exc:
                code = exc.code
        return code, output.getvalue(), db

    def github_result(self, head, base, db=None):
        db = db or Database()
        self.driver.connect.return_value = db
        self.driver.connect.side_effect = None
        argv = ["codestra-github-check", "--product", "middleware", "--repo-path", "/unused",
                "--head-ref", head, "--base-ref", base, "--head-sha", SHA]
        main = self.github["main"]
        output = io.StringIO()
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(output), \
             mock.patch.dict(main.__globals__, {"remote_sha": lambda *_: SHA}):
            code = main()
        return code, output.getvalue()

    def publisher_result(self, head, base, db=None):
        db = db or Database()
        validate = self.publisher["validate"]
        with mock.patch.dict(validate.__globals__, {"remote_sha": lambda *_: SHA}):
            return validate(db, "Middleware-", db.product["test_branch"], "/unused", head, base, SHA)

    def test_atomic_labels_cannot_authorize_pr453_from_legacy_pass_evidence(self):
        code, output, db = self.promotion_result("atomic_task", FEATURE, "subsection", "development")
        self.assertEqual(code, 1, output)
        self.assertIn("ATOMIC_CANDIDATE_VERIFIER_UNAVAILABLE", output)
        self.assertEqual(db.attempts[-1][6], "BLOCK")

    def test_logical_test_edges_cannot_skip_registered_branch_validation(self):
        for args in (("test", FEATURE, "staging", "main"),
                     ("development", "development", "test", "main")):
            with self.subTest(args=args):
                code, output, _ = self.promotion_result(*args)
                self.assertEqual(code, 1, output)
                self.assertIn("BRANCH_CHAIN_MISMATCH", output)

    def test_all_entry_points_reject_feature_to_development_even_with_section_certificate(self):
        code, output = self.github_result(FEATURE, "development")
        self.assertEqual(code, 1, output)
        self.assertIn("section_source_required", output)
        ok, reason = self.publisher_result(FEATURE, "development")
        self.assertFalse(ok, reason)
        self.assertIn("section_source_required", reason)
        code, output, _ = self.promotion_result("section", FEATURE, "development", "development")
        self.assertEqual(code, 1, output)
        self.assertIn("BRANCH_CHAIN_MISMATCH", output)

    def test_subsection_cannot_skip_or_cross_its_matching_section(self):
        for target in ("development", "section/mw-03-connectors"):
            db = Database()
            db.workstation["parent_branch"] = target
            with self.subTest(target=target):
                self.assertEqual(self.github_result(SUBSECTION, target, db)[0], 1)
                self.assertFalse(self.publisher_result(SUBSECTION, target, db)[0])
                self.assertEqual(self.promotion_result("subsection", SUBSECTION, "section", target, db)[0], 1)

    def test_registered_certified_section_and_subsection_remain_valid(self):
        for source, target, levels in ((SUBSECTION, SECTION, ("subsection", "section")),
                                        (SECTION, "development", ("section", "development"))):
            with self.subTest(source=source):
                self.assertEqual(self.github_result(source, target)[0], 0)
                self.assertTrue(self.publisher_result(source, target)[0])
                self.assertEqual(self.promotion_result(levels[0], source, levels[1], target)[0], 0)

    def test_environment_refs_preserve_registered_test_branch_names(self):
        for branch in ("test", "testing", "qa"):
            for levels, refs in ((("development", "test"), ("development", branch)),
                                  (("test", "staging"), (branch, "staging"))):
                with self.subTest(branch=branch, levels=levels):
                    self.assertEqual(self.promotion_result(levels[0], refs[0], levels[1], refs[1], Database(branch))[0], 0)
                    self.assertEqual(self.github_result(*refs, Database(branch))[0], 0)
                    self.assertTrue(self.publisher_result(*refs, Database(branch))[0])

    def test_registered_test_ref_cannot_collide_with_environment_or_scope_refs(self):
        for branch in ("development", "staging", "production", "main",
                       "section/mw-05-api", SUBSECTION, "atomic/fixture"):
            for levels, refs in ((("development", "test"), ("development", branch)),
                                 (("test", "staging"), (branch, "staging"))):
                with self.subTest(branch=branch, levels=levels):
                    code, output, _ = self.promotion_result(
                        levels[0], refs[0], levels[1], refs[1], Database(branch))
                    self.assertEqual(code, 1, output)
                    self.assertIn("BRANCH_CHAIN_MISMATCH", output)
                    self.assertEqual(self.github_result(*refs, Database(branch))[0], 1)
                    self.assertFalse(self.publisher_result(*refs, Database(branch))[0])

    def test_testing_spelling_does_not_create_a_missing_registry_edge(self):
        code, output, _ = self.promotion_result("development", "development", "testing", "testing")
        self.assertEqual(code, 1, output)
        self.assertIn("ILLEGAL_PROMOTION_EDGE", output)
        db = Database()
        db.edges.add(("development", "testing"))
        self.assertEqual(self.promotion_result("development", "development", "testing", "testing", db)[0], 0)

    def test_certification_and_legacy_evidence_checks_are_not_relaxed(self):
        for field, value in (("status", "COMPLETE"), ("exact_sha_certified", "b" * 40)):
            db = Database()
            db.workstation[field] = value
            with self.subTest(field=field):
                self.assertEqual(self.github_result(SUBSECTION, SECTION, db)[0], 1)
                self.assertFalse(self.publisher_result(SUBSECTION, SECTION, db)[0])
                self.assertEqual(self.promotion_result("subsection", SUBSECTION, "section", SECTION, db)[0], 1)
        db = Database()
        db.evidence = None
        self.assertEqual(self.promotion_result("section", SECTION, "development", "development", db)[0], 1)


if __name__ == "__main__":
    unittest.main()
