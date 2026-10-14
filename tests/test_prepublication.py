"""Offline tests. Keys below are generated, disposable test identities only."""
import base64
import copy
import importlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
try:
    admission = importlib.import_module("codestra_control.prepublication")
except ModuleNotFoundError:
    admission = None

DOMAIN = b"CODESTRA-PREPUBLICATION-REVIEW-V1\x00"
NOW = 1791637200
ROLES = ("operator", "security", "validator")

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

class PrepublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = pathlib.Path(cls.temp.name)
        cls.keys = {}
        for role in ROLES:
            private = cls.directory / (role + ".pem")
            subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)], check=True, capture_output=True)
            der = subprocess.check_output(["/usr/bin/openssl", "pkey", "-in", str(private), "-pubout", "-outform", "DER"])
            cls.keys[role] = (private, base64.b64encode(der[-32:]).decode())

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.assertIsNotNone(admission, "Missing pre-publication evidence validation entry point")
        binding = {"repository": "appolon1908/Middleware-", "head_ref": "subsection/mw-08-release--issue-456-review", "target_ref": "section/mw-08-release", "parent_sha": "a" * 40, "candidate_sha": "b" * 40, "tree_sha": "c" * 40, "lease_id": "review-456-lease", "owner_principal": "author-person"}
        self.policy = {"schema": "codestra.prepublication-policy.v1", "enabled": True, "binding": binding, "request_id": "d" * 64, "expires_at": NOW + 600, "max_age_seconds": 300, "max_ttl_seconds": 600, "required_checks": ["source-tests", "governance-integrity"], "signers": [{"key_id": role + "-key", "role": role, "principal": role + "-person", "public_key": self.keys[role][1]} for role in ROLES]}
        self.payload = {"schema": "codestra.prepublication-review.v1", "purpose": "REVIEW_ONLY", "binding": copy.deepcopy(binding), "request_id": "d" * 64, "author_principal": "author-person", "issued_at": NOW - 60, "expires_at": NOW + 300, "lease_expires_at": NOW + 400, "observed_at": NOW - 10, "observed_parent_sha": "a" * 40, "observed_tree_sha": "c" * 40, "head_absent": True, "clean_source": True, "governance_unchanged": True, "safety_denied": False, "production_go": False, "live_capabilities_enabled": False, "external_effects": False, "checks": [{"name": name, "producer_principal": "validator-person", "receipt_id": "receipt-" + name, "source_sha": "b" * 40, "tree_sha": "c" * 40, "conclusion": "passed", "completed_at": NOW - 20, "report_sha256": str(i + 1) * 64} for i, name in enumerate(self.policy["required_checks"])]}
        self.state = {"schema": "codestra.prepublication-state.v1", "observed_at": NOW, "consumed_request_ids": []}

    def envelope(self, payload=None):
        obj = self.payload if payload is None else payload
        raw = canonical(obj)
        data = self.directory / "message"
        data.write_bytes(DOMAIN + raw)
        signatures = []
        for role in ROLES:
            sig = subprocess.check_output(["/usr/bin/openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(self.keys[role][0]), "-in", str(data)])
            signatures.append({"key_id": role + "-key", "signature": base64.b64encode(sig).decode()})
        return canonical({"payload": base64.b64encode(raw).decode(), "signatures": signatures})

    def check(self, envelope=None):
        return admission.verify_review_evidence(self.envelope() if envelope is None else envelope, self.policy, self.state, now=NOW)

    def denied(self, envelope=None):
        with self.assertRaises(admission.AdmissionDenied):
            self.check(envelope)

    def test_accepts_authenticated_review_evidence_without_existing_head(self):
        result = self.check()
        self.assertEqual(result["verdict"], "REVIEW_EVIDENCE_VALID")
        self.assertEqual(result["binding"], self.payload["binding"])
        self.assertFalse(result["publication_authorized"])
        self.assertFalse(result["certified"])
        self.assertFalse(result["worker_start_authorized"])

    def test_requires_all_three_valid_signatures(self):
        envelope = json.loads(self.envelope())
        envelope["signatures"].pop()
        self.denied(canonical(envelope))

    def test_rejects_signature_tampering(self):
        envelope = json.loads(self.envelope())
        envelope["signatures"][1]["signature"] = base64.b64encode(bytes(64)).decode()
        self.denied(canonical(envelope))

    def test_rejects_payload_tampering(self):
        envelope = json.loads(self.envelope())
        payload = copy.deepcopy(self.payload)
        payload["binding"]["candidate_sha"] = "e" * 40
        envelope["payload"] = base64.b64encode(canonical(payload)).decode()
        self.denied(canonical(envelope))

    def test_rejects_unknown_and_duplicate_signers(self):
        raw = json.loads(self.envelope())
        for change in ("unknown", "duplicate"):
            with self.subTest(change=change):
                envelope = copy.deepcopy(raw)
                if change == "unknown":
                    envelope["signatures"][0]["key_id"] = "untrusted-key"
                else:
                    envelope["signatures"][1] = envelope["signatures"][0]
                self.denied(canonical(envelope))

    def test_rejects_non_independent_principals_or_keys(self):
        for field in ("principal", "public_key"):
            with self.subTest(field=field):
                p = copy.deepcopy(self.policy)
                self.policy["signers"][1][field] = self.policy["signers"][0][field]
                self.denied()
                self.policy = p

    def test_rejects_author_as_security_or_validator(self):
        for i in (1, 2):
            with self.subTest(role=ROLES[i]):
                self.policy["signers"][i]["principal"] = "author-person"
                self.denied()
                self.policy["signers"][i]["principal"] = ROLES[i] + "-person"

    def test_rejects_disabled_policy(self):
        self.policy["enabled"] = False
        self.denied()

    def test_rejects_wrong_scope_even_with_valid_signatures(self):
        original = copy.deepcopy(self.payload)
        for key in self.payload["binding"]:
            with self.subTest(field=key):
                self.payload["binding"][key] = "wrong"
                self.denied()
                self.payload = copy.deepcopy(original)

    def test_rejects_non_matching_section_or_protected_head(self):
        for head, target in (("main", "section/mw-08-release"), ("subsection/mw-08-release--review", "main"), ("subsection/mw-02-command-kernel--review", "section/mw-08-release")):
            with self.subTest(head=head, target=target):
                self.policy["binding"].update(head_ref=head, target_ref=target)
                self.payload["binding"].update(head_ref=head, target_ref=target)
                self.denied()

    def test_rejects_expired_future_or_overlong_request(self):
        original = copy.deepcopy(self.payload)
        cases = ({"expires_at": NOW}, {"issued_at": NOW + 1}, {"expires_at": NOW + 1000}, {"issued_at": NOW - 601}, {"lease_expires_at": NOW}, {"observed_at": NOW - 301}, {"observed_at": NOW + 1})
        for changes in cases:
            with self.subTest(changes=changes):
                self.payload.update(changes)
                self.denied()
                self.payload = copy.deepcopy(original)

    def test_rejects_consumed_or_unknown_nonce(self):
        self.state["consumed_request_ids"] = [self.payload["request_id"]]
        self.denied()
        self.state["consumed_request_ids"] = []
        self.payload["request_id"] = "e" * 64
        self.denied()

    def test_rejects_stale_or_malformed_replay_state(self):
        for changes in ({"observed_at": NOW - 301}, {"consumed_request_ids": None}, {"observed_at": True}):
            with self.subTest(changes=changes):
                state = copy.deepcopy(self.state)
                self.state.update(changes)
                self.denied()
                self.state = state

    def test_rejects_changed_parent_tree_or_existing_head(self):
        for key, value in (("observed_parent_sha", "e" * 40), ("observed_tree_sha", "e" * 40), ("head_absent", False)):
            with self.subTest(key=key):
                old = self.payload[key]
                self.payload[key] = value
                self.denied()
                self.payload[key] = old

    def test_rejects_safety_denial_dirty_source_or_governance_change(self):
        for key, value in (("safety_denied", True), ("clean_source", False), ("governance_unchanged", False)):
            with self.subTest(key=key):
                old = self.payload[key]
                self.payload[key] = value
                self.denied()
                self.payload[key] = old

    def test_rejects_effects_and_boolean_lookalikes(self):
        for key in ("production_go", "live_capabilities_enabled", "external_effects"):
            for value in (True, 0, "false", None):
                with self.subTest(key=key, value=value):
                    self.payload[key] = value
                    self.denied()
                    self.payload[key] = False
        self.payload["head_absent"] = 1
        self.denied()

    def test_rejects_incomplete_or_duplicate_checks(self):
        original = copy.deepcopy(self.payload["checks"])
        for checks in ([], original[:1], original + [original[0]]):
            with self.subTest(checks=checks):
                self.payload["checks"] = checks
                self.denied()

    def test_rejects_wrong_check_identity_result_or_source(self):
        original = copy.deepcopy(self.payload["checks"])
        for key, value in (("producer_principal", "author-person"), ("source_sha", "e" * 40), ("tree_sha", "e" * 40), ("conclusion", "skipped"), ("report_sha256", ""), ("completed_at", NOW + 1), ("completed_at", NOW - 301), ("receipt_id", "")):
            with self.subTest(key=key, value=value):
                self.payload["checks"][0][key] = value
                self.denied()
                self.payload["checks"] = copy.deepcopy(original)

    def test_rejects_duplicate_receipt_ids(self):
        self.payload["checks"][1]["receipt_id"] = self.payload["checks"][0]["receipt_id"]
        self.denied()

    def test_rejects_certificate_or_release_purpose(self):
        self.payload["purpose"] = "CERTIFIED"
        self.denied()

    def test_rejects_duplicate_json_keys_and_extra_fields(self):
        self.denied(b'{"payload":"x","payload":"y","signatures":[]}')
        self.payload["override"] = True
        self.denied()

    def test_fails_closed_on_bad_shapes_and_missing_openssl(self):
        for value in (b'null', b'[]', b'"hello"', b'{}', b'{', b'{}' * 200000):
            with self.subTest(value=value[:20]):
                self.denied(value)
        envelope = self.envelope()
        with patch.object(admission.subprocess, "run", side_effect=FileNotFoundError):
            self.denied(envelope)

    def test_output_is_not_replay_consumption_or_runtime_authorization(self):
        before = copy.deepcopy((self.payload, self.policy, self.state))
        first = self.check()
        self.assertEqual(self.check(), first)
        self.assertEqual((self.payload, self.policy, self.state), before)
        self.assertFalse(first["publication_authorized"])
        self.assertNotIn("status_context", first)

    def test_rejects_valid_shape_tampering_at_signature_boundary(self):
        envelope = json.loads(self.envelope())
        payload = copy.deepcopy(self.payload)
        payload["lease_expires_at"] += 1
        envelope["payload"] = base64.b64encode(canonical(payload)).decode()
        with self.assertRaisesRegex(admission.AdmissionDenied, "INVALID_SIGNATURE"):
            self.check(canonical(envelope))

    def test_rejects_signature_from_another_protocol(self):
        envelope = json.loads(self.envelope())
        raw = base64.b64decode(envelope["payload"])
        data = self.directory / "different-domain"
        data.write_bytes(b"OTHER-PROTOCOL" + raw)
        signature = subprocess.check_output(["/usr/bin/openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(self.keys["operator"][0]), "-in", str(data)])
        envelope["signatures"][0]["signature"] = base64.b64encode(signature).decode()
        self.denied(canonical(envelope))

    def test_rejects_empty_required_checks_and_expired_policy(self):
        self.policy["required_checks"] = []
        self.denied()
        self.policy["required_checks"] = ["source-tests", "governance-integrity"]
        self.policy["expires_at"] = NOW
        self.denied()

    def test_rejects_checks_later_than_signed_observation(self):
        self.payload["checks"][0]["completed_at"] = NOW
        self.denied()

    def test_cli_cannot_accept_a_caller_supplied_trust_policy(self):
        import contextlib
        import io
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = admission.main(["--policy", "attacker.json", "bundle.json"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["verdict"], "BLOCKED")

    def test_cli_fails_closed_without_installed_policy(self):
        import contextlib
        import io
        output = io.StringIO()
        with patch.object(admission, "read_document", side_effect=FileNotFoundError), contextlib.redirect_stdout(output):
            code = admission.main(["bundle.json"])
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(output.getvalue())["publication_authorized"])

    def test_trust_file_in_writable_directory_is_rejected(self):
        p = self.directory / "untrusted-policy.json"
        p.write_text("{}")
        with self.assertRaises(admission.AdmissionDenied):
            admission.read_document(p, trusted=True)

    def test_file_reader_rejects_symlink_oversize_and_nonregular_input(self):
        import os
        target = self.directory / "raw.json"
        target.write_text("{}")
        link = self.directory / "link.json"
        link.symlink_to(target)
        with self.assertRaises((OSError, admission.AdmissionDenied)):
            admission.read_document(link, trusted=False)
        target.write_bytes(b"x" * (admission.MAX_BYTES + 1))
        with self.assertRaises(admission.AdmissionDenied):
            admission.read_document(target, trusted=False)
        fifo = self.directory / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(admission.AdmissionDenied):
            admission.read_document(fifo, trusted=False)

    def test_malformed_nested_fields_are_structured_denials(self):
        original = copy.deepcopy(self.payload)
        for name in original:
            with self.subTest(name=name):
                self.payload[name] = []
                self.denied()
                self.payload = copy.deepcopy(original)


    def test_extreme_json_numbers_and_nesting_are_structured_denials(self):
        self.denied(b'{"number":' + b'9' * 10000 + b'}')
        self.denied(b'[' * 3000 + b'0' + b']' * 3000)
        self.denied(b'{"payload":NaN,"signatures":[]}')


if __name__ == "__main__":
    unittest.main()
