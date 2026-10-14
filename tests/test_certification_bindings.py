"""Commit binding regressions; all database and remote reads are fixtures."""
import contextlib
import io
import json
import runpy
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40


class CertificationBindingTests(unittest.TestCase):
    def drivers(self, connection):
        driver = types.ModuleType("psycopg2")
        extras = types.ModuleType("psycopg2.extras")
        driver.connect = mock.Mock(return_value=connection)
        extras.RealDictCursor = object
        driver.extras = extras
        return driver, {"psycopg2": driver, "psycopg2.extras": extras}

    def record(self, certificate_sha):
        return dict(status="CERTIFIED", remote_sha=SHA, parent_branch="section/fixture",
                    exact_sha_certified=certificate_sha)

    def test_checker_rejects_certified_flag_without_matching_certificate_commit(self):
        for certificate_sha, expected in ((None, 1), ("b" * 40, 1), (SHA, 0)):
            with self.subTest(certificate_sha=certificate_sha):
                connection = mock.MagicMock()
                cursor = connection.cursor.return_value.__enter__.return_value
                cursor.fetchone.side_effect = [dict(test_branch="testing"), self.record(certificate_sha)]
                _, drivers = self.drivers(connection)
                with mock.patch.dict(sys.modules, drivers):
                    module = runpy.run_path(str(ROOT / "bin/codestra-github-check"), run_name="offline_binding")
                argv = ["check", "--product", "Fixture", "--repo-path", "/unused", "--head-ref", "subsection/fixture",
                        "--base-ref", "section/fixture", "--head-sha", SHA]
                with mock.patch.object(sys, "argv", argv), mock.patch.dict(module["main"].__globals__, {
                    "remote_sha": lambda *_: SHA,
                }), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(module["main"](), expected)

    def test_publisher_rejects_certified_flag_without_matching_certificate_commit(self):
        for certificate_sha, expected in ((None, False), ("b" * 40, False), (SHA, True)):
            with self.subTest(certificate_sha=certificate_sha):
                connection = mock.MagicMock()
                connection.cursor.return_value.__enter__.return_value.fetchone.return_value = self.record(certificate_sha)
                _, drivers = self.drivers(connection)
                with mock.patch.dict(sys.modules, drivers):
                    module = runpy.run_path(str(ROOT / "bin/codestra-github-statusd"), run_name="offline_binding")
                with mock.patch.dict(module["validate"].__globals__, {"remote_sha": lambda *_: SHA}):
                    self.assertEqual(module["validate"](connection, "Fixture", "testing", "/unused",
                                                       "subsection/fixture", "section/fixture", SHA)[0], expected)

    def scope_cli(self, evidence, sha=SHA):
        connection = mock.MagicMock()
        driver, drivers = self.drivers(connection)
        argv = ["certify-scope", "--product", "Fixture", "--scope-type", "SECTION", "--scope-name", "fixture",
                "--sha", sha, "--actor", "fixture-owner", "--evidence-json", json.dumps(evidence)]
        error = None
        with mock.patch.dict(sys.modules, drivers), mock.patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(io.StringIO()):
            try:
                runpy.run_path(str(ROOT / "bin/codestra-certify-scope"), run_name="__main__")
            except SystemExit as exc:
                error = str(exc)
        return error, driver.connect

    def test_scope_rejects_unbound_and_stale_evidence_before_database_access(self):
        names = ("ci_exact_sha", "review", "regression", "security")
        for gate in ("PASS", dict(result="PASS", exact_sha="b" * 40), dict(result="PASS")):
            with self.subTest(gate=gate):
                error, connect = self.scope_cli({name: gate for name in names})
                self.assertIsNotNone(error)
                self.assertIn("CERTIFY_SCOPE_REFUSED", error)
                connect.assert_not_called()

    def test_scope_requires_valid_commit_and_structured_matching_gate_records(self):
        evidence = {name: dict(result="PASS", exact_sha=SHA) for name in
                    ("ci_exact_sha", "review", "regression", "security")}
        error, connect = self.scope_cli(evidence)
        self.assertIsNone(error)
        connect.assert_called_once()
        error, connect = self.scope_cli(evidence, sha="not-a-commit")
        self.assertIsNotNone(error)
        connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
