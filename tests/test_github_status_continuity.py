"""Read-only certification of the GitHub control-plane status authority.

The test imports, stubs and exercises policy helpers without network calls,
publishing GitHub statuses, changing PostgreSQL, or changing a server.
"""

from __future__ import annotations

import runpy
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "bin" / "codestra-github-check"
STATUS = ROOT / "bin" / "codestra-github-statusd"
MIGRATION_BRANCH = "sync/agent02-mw03-connectors-20261007-api"
MIGRATION_BASE = "section/mw-03-connectors"


class GitHubStatusContinuityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.check = runpy.run_path(str(CHECK), run_name="test_authority")
        self.status = runpy.run_path(str(STATUS), run_name="test_status_publisher")

    def test_publisher_aliases_same_certification_verdict(self) -> None:
        self.assertEqual(
            self.status["CONTEXTS"],
            ("codestra-control-plane", "codestra/control-plane"),
        )
        posted = []

        def fake_run(argv, check=True):
            posted.append(argv)

        # Isolate the actual function global environment, not a copy.
        with mock.patch.dict(self.status["post"].__globals__, {"run": fake_run}):
            for state in ("success", "failure"):
                posted.clear()
                self.status["post"](
                    "Middleware-", "a" * 40, state,
                    "test-only verdict", "https://example.invalid/evidence",
                )
                self.assertEqual(len(posted), 2)
                contexts = [next(x for x in cmd if x.startswith("context=")) for cmd in posted]
                self.assertEqual(
                    contexts,
                    ["context=codestra-control-plane", "context=codestra/control-plane"],
                )
                self.assertTrue(
                    all(f"state={state}" in cmd for cmd in posted),
                )
                self.assertTrue(all("a" * 40 in cmd[4] for cmd in posted))

    def test_exact_scoped_migration_requires_matching_head_sha(self) -> None:
        self.assertEqual(
            self.check["migration_reason"](
                "Middleware-", MIGRATION_BRANCH, MIGRATION_BASE,
            ),
            "migration:expires=2026-10-15",
        )
        self.assertIsNone(
            self.check["migration_reason"](
                "Middleware-", MIGRATION_BRANCH + "-unreviewed", MIGRATION_BASE,
            )
        )
        self.assertIsNone(
            self.check["migration_reason"](
                "Middleware-", MIGRATION_BRANCH, "main",
            )
        )

        class DatabaseMustNotBeQueried:
            def cursor(self, *args, **kwargs):
                raise AssertionError("exact allowed migration needs no DB lookup")

        sha = "a" * 40
        with mock.patch.dict(
            self.status["validate"].__globals__,
            {"remote_sha": lambda repo, ref: sha},
        ):
            ok, reason = self.status["validate"](
                DatabaseMustNotBeQueried(), "Middleware-", "testing",
                "/tmp/not-used", MIGRATION_BRANCH, MIGRATION_BASE, sha,
            )
            self.assertTrue(ok, reason)
            self.assertIn("exact-SHA migration", reason)

            ok, reason = self.status["validate"](
                DatabaseMustNotBeQueried(), "Middleware-", "testing",
                "/tmp/not-used", MIGRATION_BRANCH, MIGRATION_BASE, "0" * 40,
            )
            self.assertFalse(ok)
            self.assertIn("SHA mismatch", reason)

    def test_wrong_scope_never_inherits_migration(self) -> None:
        self.assertIsNone(
            self.check["migration_reason"](
                "Kong", MIGRATION_BRANCH, MIGRATION_BASE,
            )
        )
        self.assertIsNone(
            self.check["migration_reason"](
                "Middleware-", "sync/agent05-mw06-adapter-conformance-20261007-api",
                "section/mw-06-adapters",
            )
        )

    def test_status_source_is_credential_free(self) -> None:
        code = STATUS.read_text()
        self.assertNotIn("GH_TOKEN=", code)
        self.assertNotIn("GITHUB_TOKEN=", code)
        self.assertNotIn("/opt/sentinelx-cloud-core", code)
        self.assertNotIn("check_call(['gh', 'auth'", code)
        self.assertIn('with_name("codestra-github-check")', code)


if __name__ == "__main__":
    unittest.main()
