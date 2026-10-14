"""Fail-closed checks for the four-repository, source-only certificate verifier."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "scripts" / "self_certify_fleet.py"
spec = importlib.util.spec_from_file_location("fleet_verifier", FILE)
assert spec and spec.loader
fleet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fleet)


class FleetSourceTests(unittest.TestCase):
    def test_fixed_reviewed_repository_profiles(self):
        self.assertEqual(set(fleet.PROFILES), {
            "Kong", "Caddy", "Keycloak", "Codestra-OpenBao"
        })
        self.assertTrue(all(fleet.PROFILES.values()))

    def test_canonical_repo_origins(self):
        self.assertIn("https://github.com/appolon1908/Kong.git", {
            f"https://github.com/{fleet.OWNER}/Kong.git",
        })
        self.assertEqual(fleet.OWNER, "appolon1908")

    def test_test_summary_parser_policy_is_present(self):
        source = FILE.read_text()
        self.assertIn("source_mount", source)
        self.assertIn('"none"', source)
        self.assertIn('"--read-only"', source)
        self.assertIn("github_ci_certified", source)
        self.assertIn("independent_codeowner_approved", source)

    def test_bad_sha_rejected_before_any_command(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                fleet.certify("Kong", temp, "garbage", Path(temp) / "evidence.json")

    def test_non_allowlisted_repo_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                fleet.certify("Unknown-Repository", temp, "0" * 40, Path(temp) / "evidence.json")

    def test_evidence_location_inside_checkout_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                fleet.certify("Keycloak", temp, "0" * 40, Path(temp) / "output.json")


if __name__ == "__main__":
    unittest.main()
