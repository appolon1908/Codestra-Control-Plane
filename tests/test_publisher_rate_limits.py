"""A throttled GitHub request must stop the cycle without retry storms."""
import runpy
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


class PublisherRateLimitTests(unittest.TestCase):
    def setUp(self):
        driver = types.ModuleType("psycopg2")
        extras = types.ModuleType("psycopg2.extras")
        driver.connect = mock.Mock(side_effect=AssertionError("live DB forbidden"))
        extras.RealDictCursor = object
        driver.extras = extras
        with mock.patch.dict(sys.modules, {"psycopg2": driver, "psycopg2.extras": extras}):
            self.module = runpy.run_path(str(ROOT / "bin/codestra-github-statusd"), run_name="offline_rate_limit")

    def rate_limit_type(self):
        self.assertTrue("RateLimited" in self.module, "publisher must distinguish rate limits and stop the cycle")
        return self.module["RateLimited"]

    def test_primary_secondary_and_http_429_are_not_retried(self):
        rate_limited = self.rate_limit_type()
        for message in ("gh: API rate limit exceeded (HTTP 403)",
                        "gh: You have exceeded a secondary rate limit (HTTP 403)",
                        "gh: Too Many Requests (HTTP 429)"):
            with self.subTest(message=message), mock.patch("subprocess.run", return_value=types.SimpleNamespace(
                returncode=1, stdout="", stderr=message,
            )) as execute:
                with self.assertRaises(rate_limited):
                    self.module["run"](["gh", "api", "repos/fixture/repo/pulls"])
                execute.assert_called_once()

    def test_permission_error_is_not_mislabeled_as_rate_limit(self):
        rate_limited = self.rate_limit_type()
        with mock.patch("subprocess.run", return_value=types.SimpleNamespace(
            returncode=1, stdout="", stderr="gh: Resource not accessible (HTTP 403)",
        )):
            with self.assertRaises(RuntimeError) as error:
                self.module["run"](["gh", "api", "repos/fixture/repo/pulls"])
        self.assertNotIsInstance(error.exception, rate_limited)

    def main_context(self, **overrides):
        return mock.patch.dict(self.module["reconcile"].__globals__, {
            "psycopg2": types.SimpleNamespace(connect=lambda *_: object()),
            "aliases": lambda *_: [("Middleware-", "Middleware-", "testing", "/unused"),
                                     ("Kong", "Kong", "testing", "/unused")],
            **overrides,
        })

    def test_rate_limited_listing_stops_before_next_repository(self):
        read = mock.Mock(side_effect=self.rate_limit_type()("throttled"))
        with self.main_context(gh_json=read), mock.patch("os.path.isdir", return_value=True):
            with self.assertRaisesRegex(SystemExit, "RATE_LIMITED"):
                self.module["reconcile"]()
        read.assert_called_once()

    def test_rate_limited_post_stops_before_next_pr(self):
        pr = dict(head=dict(ref="fixture" ,sha="a" * 40), base=dict(ref="main"),
                  number=1, html_url="https://example.invalid/pr/1")
        post = mock.Mock(side_effect=self.rate_limit_type()("throttled"))
        validate = mock.Mock(return_value=(False, "fixture denial"))
        with self.main_context(gh_json=lambda *_: [pr, dict(pr, number=2, head=dict(ref="fixture-two", sha="b" * 40))], post=post, validate=validate), \
                mock.patch("os.path.isdir", return_value=True):
            with self.assertRaisesRegex(SystemExit, "RATE_LIMITED"):
                self.module["reconcile"]()
        post.assert_called_once()
        validate.assert_called_once()


if __name__ == "__main__":
    unittest.main()
