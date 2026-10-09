"""Fail-closed self-certification input and evidence guards."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "self_certify_source.py"
spec = importlib.util.spec_from_file_location("codestra_self_cert_test", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SelfCertificationTest(unittest.TestCase):
    def test_reject_malicious_branches(self):
        for ref in ("../main", "-a", "//main", "feature//other", "hi..there", "/main", ""):
            with self.subTest(ref=ref), self.assertRaises(module.CertificationError):
                module.validate_ref(ref)

    def test_reject_evidence_inside_repo(self):
        for path in (ROOT / "status.json", ROOT / "tests" / "status.json", ROOT):
            with self.subTest(path=str(path)), self.assertRaises(module.CertificationError):
                module.assert_destination(ROOT, path)

    def test_expected_origin_is_bound_to_canonical_repository(self):
        self.assertEqual(len(module.APPROVED_ORIGINS), 3)
        for candidate in module.APPROVED_ORIGINS:
            self.assertIn("github.com", candidate)
            self.assertIn("appolon1908/Codestra-Control-Plane.git", candidate)
        self.assertNotIn("https://example.com/fake-repo.git", module.APPROVED_ORIGINS)

    def test_refuse_existing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text("must remain unchanged")
            with self.assertRaises(module.CertificationError):
                module.assert_destination(ROOT, path)
            self.assertEqual(path.read_text(), "must remain unchanged")

    def test_reject_mismatched_head_without_writing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "certificate.json"
            with self.assertRaises(module.CertificationError):
                module.certify(
                    ROOT, expected_sha="0" * 40,
                    branch="atomic/cp-01-foundation--01-source-import",
                    output=output,
                )
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
