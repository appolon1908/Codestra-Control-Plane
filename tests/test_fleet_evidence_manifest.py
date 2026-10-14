"""Read-only validation of four scoped source certificates."""
from pathlib import Path
import hashlib
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "docs/verification/fleet-20261009"


class FleetEvidenceTests(unittest.TestCase):
    def test_certificate_manifest_and_fail_closed_disposition(self):
        records = json.loads((DATA / "manifest.json").read_text())["evidence"]
        self.assertEqual(len(records), 4)
        verifier_sha = hashlib.sha256(
            (ROOT / "scripts/self_certify_fleet.py").read_bytes()
        ).hexdigest()
        for record in records:
            with self.subTest(record=record["repository"]):
                data = (ROOT / record["path"]).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), record["file_sha256"])
                report = json.loads(data)
                self.assertEqual(report["head_sha"], record["sha"])
                self.assertEqual(report["remote_sha"], report["head_sha"])
                self.assertEqual(report["source_verifier_sha256"], verifier_sha)
                self.assertGreater(report["tests_passed"], 0)
                self.assertFalse(report["github_ci_certified"])
                self.assertFalse(report["runtime_deployment_certified"])
                self.assertFalse(report["merge_or_promotion_authorized"])

    def test_caddy_skips_are_visible(self):
        self.assertEqual(json.loads((DATA / "Caddy-main.json").read_text())["tests_skipped"], 2)
