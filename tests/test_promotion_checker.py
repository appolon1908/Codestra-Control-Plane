"""Regression checks that never connect to PostgreSQL or publish GitHub statuses."""

import ast
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get("CONTROL_PLANE_TEST_SOURCE", ROOT))
CHECKER = SOURCE / "bin" / "codestra-promotion-check"

# The deployed command imports psycopg2 even for --help. Supply only that
# external boundary and fail if a CLI-only check attempts any external effect.
BOOTSTRAP = r'''
import runpy
import socket
import subprocess
import sys
import types

def forbidden(*args, **kwargs):
    raise AssertionError("external effect attempted during CLI regression test")

driver = types.ModuleType("psycopg2")
driver.connect = forbidden
extras = types.ModuleType("psycopg2.extras")
extras.RealDictCursor = object
extras.Json = forbidden
driver.extras = extras
sys.modules["psycopg2"] = driver
sys.modules["psycopg2.extras"] = extras
socket.socket = forbidden
socket.create_connection = forbidden
subprocess.run = forbidden
subprocess.Popen = forbidden
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
'''


class PromotionCheckerRegressionTests(unittest.TestCase):
    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, "-I", "-c", BOOTSTRAP, str(CHECKER), *arguments],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
            env={"PATH": os.defpath},
        )

    def test_checker_parses_before_any_evaluation_can_run(self):
        try:
            ast.parse(CHECKER.read_text(encoding="utf-8"), filename=str(CHECKER))
        except SyntaxError as exc:
            self.fail(f"Promotion checker cannot start: {exc}")

    def test_help_exits_successfully_without_external_effects(self):
        result = self.run_cli("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage:", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_missing_required_arguments_returns_usage_error(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("usage:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
