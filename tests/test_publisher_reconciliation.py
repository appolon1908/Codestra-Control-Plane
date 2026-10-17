"""Offline regression coverage for the deployed controller reconciliation."""
import ast
import runpy
import sys
import types
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SHA = "777331d8907480977880923c5b012926a7dfc6b8"
HEAD = "governance/development-control-plane-v1"
KLYROW_PRODUCT = "klyrow.com"
KLYROW_HEAD = "implementation/klyrow-ses-transport-20261008"
KLYROW_BASE = "implementation/klyrow-server3-safe-staging-20261008"
KLYROW_SHA = "f6e56f4fcd75f53a794dfee3d36913611a791248"


class PublisherReconciliationTests(unittest.TestCase):
    def load(self, name):
        driver = types.ModuleType("psycopg2")
        extras = types.ModuleType("psycopg2.extras")
        driver.connect = mock.Mock(side_effect=AssertionError("live database forbidden"))
        extras.RealDictCursor = object
        driver.extras = extras
        path = ROOT / "bin" / name
        if name == "codestra-github-check":
            self.assertTrue(any(isinstance(n, ast.FunctionDef) and n.name == "migration_reason"
                                for n in ast.parse(path.read_text()).body),
                            "checker must expose the shared SHA-bound migration policy")
        with mock.patch.dict(sys.modules, {"psycopg2": driver, "psycopg2.extras": extras}):
            return runpy.run_path(str(path), run_name="offline_reconciliation")

    def test_keycloak_exception_is_sha_bound_and_expires(self):
        policy = self.load("codestra-github-check")["migration_reason"]
        class Clock(date):
            @classmethod
            def today(cls):
                return cls(2026, 10, 14)
        with mock.patch.dict(policy.__globals__, {"date": Clock}):
            self.assertIn("exact_sha", policy("Keycloak", HEAD, "main", SHA))
            self.assertIsNone(policy("Keycloak", HEAD, "main", "0" * 40))
            self.assertIsNone(policy("Keycloak", HEAD, "development", SHA))
            self.assertIsNone(policy("Caddy", HEAD, "main", SHA))
        class Expired(Clock):
            @classmethod
            def today(cls):
                return cls(2026, 10, 16)
        with mock.patch.dict(policy.__globals__, {"date": Expired}):
            self.assertIsNone(policy("Keycloak", HEAD, "main", SHA))

    def test_klyrow_pr186_exception_is_exact_sha_bound_and_expires(self):
        policy = self.load("codestra-github-check")["migration_reason"]

        class Active(date):
            @classmethod
            def today(cls):
                return cls(2026, 10, 16)

        with mock.patch.dict(policy.__globals__, {"date": Active}):
            reason = policy(KLYROW_PRODUCT, KLYROW_HEAD, KLYROW_BASE, KLYROW_SHA)
            self.assertIn("klyrow_pr186_exact_sha", reason)
            self.assertIsNone(policy(KLYROW_PRODUCT, KLYROW_HEAD, KLYROW_BASE, "0" * 40))
            self.assertIsNone(policy(KLYROW_PRODUCT, KLYROW_HEAD, "development", KLYROW_SHA))
            self.assertIsNone(policy("Kong", KLYROW_HEAD, KLYROW_BASE, KLYROW_SHA))

        class Expired(Active):
            @classmethod
            def today(cls):
                return cls(2026, 10, 24)

        with mock.patch.dict(policy.__globals__, {"date": Expired}):
            self.assertIsNone(policy(KLYROW_PRODUCT, KLYROW_HEAD, KLYROW_BASE, KLYROW_SHA))

    def test_klyrow_legacy_pair_reaches_sha_validation_instead_of_being_skipped(self):
        candidate = self.load("codestra-github-statusd")["reconciliation_candidate"]
        policy = mock.Mock(return_value="klyrow_pr186_exact_sha:expires=2026-10-23")
        governed = mock.Mock(side_effect=AssertionError("migration admission must not query hierarchy"))
        with mock.patch.dict(candidate.__globals__, {
            "MIGRATION_REASON": policy,
            "governed": governed,
        }):
            self.assertTrue(candidate(
                None, KLYROW_PRODUCT, "testing", KLYROW_HEAD, KLYROW_BASE, KLYROW_SHA,
            ))
        policy.assert_called_once_with(KLYROW_PRODUCT, KLYROW_HEAD, KLYROW_BASE, KLYROW_SHA)
        governed.assert_not_called()

    def test_publisher_uses_four_argument_policy_for_every_product(self):
        validate = self.load("codestra-github-statusd")["validate"]
        policy = mock.Mock(return_value="reviewed exact-SHA authority")
        connection = mock.Mock()
        for product in ("Keycloak", "Middleware-", "Caddy", "Kong", "Codestra-OpenBao"):
            with self.subTest(product=product), mock.patch.dict(validate.__globals__, {
                "remote_sha": lambda *_: SHA, "MIGRATION_REASON": policy,
            }):
                policy.reset_mock()
                self.assertTrue(validate(connection, product, "testing", "/unused", HEAD, "main", SHA)[0])
                policy.assert_called_once_with(product, HEAD, "main", SHA)
        connection.cursor.assert_not_called()

    def test_remote_mismatch_is_denied_before_exception(self):
        validate = self.load("codestra-github-statusd")["validate"]
        policy = mock.Mock(side_effect=AssertionError("policy must not run"))
        with mock.patch.dict(validate.__globals__, {"remote_sha": lambda *_: "0" * 40,
                                                    "MIGRATION_REASON": policy}):
            self.assertFalse(validate(None, "Keycloak", "testing", "/unused", HEAD, "main", SHA)[0])

    def test_unregistered_bootstrap_never_inherits_authority(self):
        validate = self.load("codestra-github-statusd")["validate"]
        connection = mock.MagicMock()
        with mock.patch.dict(validate.__globals__, {"remote_sha": lambda *_: SHA,
                                                    "MIGRATION_REASON": lambda *_: None}):
            self.assertFalse(validate(connection, "Caddy", "testing", "/unused", HEAD, "main", SHA)[0])
            self.assertFalse(validate(connection, "Keycloak", "testing", "/unused", HEAD, "main", SHA)[0])

    def status(self, context, state="success", description="verdict", url="https://example.invalid/pr/1"):
        return dict(context=context, state=state, description=description, target_url=url)

    def publish(self, pages, state="success", desc="verdict"):
        post = self.load("codestra-github-statusd")["post"]
        read = mock.Mock(side_effect=pages)
        write = mock.Mock()
        with mock.patch.dict(post.__globals__, {"require_publication_adapter": lambda: None, "gh_json": read, "run": write}):
            post("Middleware-", SHA, state, desc, "https://example.invalid/pr/1")
        return read, write

    def test_unchanged_dual_context_result_is_not_posted(self):
        contexts = ("codestra-control-plane", "codestra/control-plane")
        read, write = self.publish([[self.status(c) for c in contexts]])
        read.assert_called_once()
        write.assert_not_called()

    def test_only_missing_alias_is_posted_after_partial_failure(self):
        _, write = self.publish([[self.status("codestra-control-plane")]])
        self.assertEqual(write.call_count, 1)
        self.assertIn("context=codestra/control-plane", write.call_args.args[0])

    def test_changed_result_is_posted_to_both_aliases(self):
        _, write = self.publish([[self.status(c) for c in ("codestra-control-plane", "codestra/control-plane")]],
                                state="failure")
        self.assertEqual(write.call_count, 2)
        for call in write.call_args_list:
            self.assertIn("state=failure", call.args[0])

    def test_status_lookup_failure_prevents_any_post(self):
        post = self.load("codestra-github-statusd")["post"]
        write = mock.Mock()
        with mock.patch.dict(post.__globals__, {"require_publication_adapter": lambda: None, "gh_json": mock.Mock(side_effect=RuntimeError("read failed")),
                                                "run": write}):
            with self.assertRaisesRegex(RuntimeError, "read failed"):
                post("Middleware-", SHA, "success", "verdict", "https://example.invalid/pr/1")
        write.assert_not_called()

    def test_newest_status_wins_and_lookup_paginates(self):
        first = [self.status("codestra-control-plane", state="failure")]
        first += [self.status("unrelated") for _ in range(99)]
        second = [self.status("codestra-control-plane"), self.status("codestra/control-plane")]
        read, write = self.publish([first, second])
        self.assertEqual(read.call_count, 2)
        self.assertIn("page=2", read.call_args.args[0])
        self.assertEqual(write.call_count, 1)
        self.assertIn("context=codestra-control-plane", write.call_args.args[0])

    def test_description_truncation_is_compared_consistently(self):
        desc = "x" * 160
        _, write = self.publish([[self.status(c, description=desc[:140]) for c in
                                  ("codestra-control-plane", "codestra/control-plane")]], desc=desc)
        write.assert_not_called()

    def test_malformed_or_incomplete_history_prevents_publication(self):
        post = self.load("codestra-github-statusd")["post"]
        invalid = ({"statuses": []}, [None], [{"context": "codestra-control-plane", "state": "unknown"}])
        for response in invalid:
            write = mock.Mock()
            with self.subTest(response=response), mock.patch.dict(post.__globals__, {
                "require_publication_adapter": lambda: None, "gh_json": lambda *_: response, "run": write,
            }):
                with self.assertRaises(RuntimeError):
                    post("Middleware-", SHA, "success", "verdict", "https://example.invalid/pr/1")
            write.assert_not_called()
        write = mock.Mock()
        read = mock.Mock(return_value=[self.status("unrelated") for _ in range(100)])
        with mock.patch.dict(post.__globals__, {"require_publication_adapter": lambda: None, "gh_json": read, "run": write}):
            with self.assertRaisesRegex(RuntimeError, "pagination limit"):
                post("Middleware-", SHA, "success", "verdict", "https://example.invalid/pr/1")
        write.assert_not_called()

    def test_retry_after_second_context_failure_does_not_repeat_first(self):
        post = self.load("codestra-github-statusd")["post"]
        remote = []
        attempts = []
        def write(argv, check=True):
            context = next(v.split("=", 1)[1] for v in argv if v.startswith("context="))
            attempts.append(context)
            if len(attempts) == 2:
                raise RuntimeError("second context failed")
            remote.insert(0, self.status(context))
        with mock.patch.dict(post.__globals__, {"require_publication_adapter": lambda: None, "gh_json": lambda *_: list(remote), "run": write}):
            with self.assertRaisesRegex(RuntimeError, "second context failed"):
                post("Middleware-", SHA, "success", "verdict", "https://example.invalid/pr/1")
            post("Middleware-", SHA, "success", "verdict", "https://example.invalid/pr/1")
        self.assertEqual(attempts, ["codestra-control-plane", "codestra/control-plane", "codestra/control-plane"])

    def test_middleware_migration_expires_in_both_entrypoints(self):
        policy = self.load("codestra-github-check")["migration_reason"]
        validate = self.load("codestra-github-statusd")["validate"]
        class Expired(date):
            @classmethod
            def today(cls):
                return cls(2026, 10, 16)
        with mock.patch.dict(policy.__globals__, {"date": Expired}):
            self.assertIsNone(policy("Middleware-", "dependabot/pip/mako-1.4.2", "main", SHA))
            with mock.patch.dict(validate.__globals__, {"remote_sha": lambda *_: SHA, "MIGRATION_REASON": policy}):
                self.assertFalse(validate(mock.MagicMock(), "Middleware-", "testing", "/unused", "dependabot/pip/mako-1.4.2", "main", SHA)[0])


if __name__ == "__main__":
    unittest.main()
