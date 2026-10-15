"""Offline bootstrap integration tests; never access a product remote."""
import concurrent.futures
import base64
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
try:
    from codestra_control import bootstrap
except ImportError:
    bootstrap = None


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(bootstrap, "Trusted bootstrap collector/broker is missing")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo.git"
        subprocess.run(["git", "init", "--bare", str(self.repo)], check=True, capture_output=True)
        self.git("config", "user.name", "Synthetic")
        self.git("config", "user.email", "synthetic@example.invalid")
        tree = self.git("mktree", input=b"")
        self.parent = self.git("commit-tree", tree, input=b"parent\n")
        self.candidate = self.git("commit-tree", tree, "-p", self.parent, input=b"review\n")
        self.tree = tree
        self.base = "section/mw-08-release"
        self.head = "subsection/mw-08-release--issue-456-review"
        self.git("update-ref", "refs/heads/" + self.base, self.parent)
        self.binding = {"repository": "example/review-fixture", "head_ref": self.head,
                        "target_ref": self.base, "parent_sha": self.parent,
                        "candidate_sha": self.candidate, "tree_sha": tree,
                        "lease_id": "synthetic-lease", "owner_principal": "author"}
        self.policy = {"binding": self.binding, "max_age_seconds": 300,
                       "required_checks": ["unit"], "request_id": "a" * 64,
                       "signers": [{"role": "validator", "principal": "validator"}]}
        self.report = {"schema": "codestra.validator-report.v1", "name": "unit",
                       "receipt_id": "receipt-unit", "producer_principal": "validator",
                       "source_sha": self.candidate, "tree_sha": tree,
                       "conclusion": "passed", "completed_at": 100,
                       "tests": {"passed": 1, "failed": 0, "errors": 0, "skipped": 0}}
        self.raw_report = json.dumps(self.report).encode()
        self.check = {k: self.report[k] for k in ("name", "receipt_id", "producer_principal",
                      "source_sha", "tree_sha", "conclusion", "completed_at")}
        self.check["report_sha256"] = hashlib.sha256(self.raw_report).hexdigest()
        self.payload = {"binding": self.binding, "checks": [self.check],
                        "observed_at": 100, "expires_at": 200}
        self.ledger = bootstrap.ReplayLedger(self.root / "replay.sqlite")
        self.backend = bootstrap.GitRefTransaction(self.repo, self.binding["repository"])

    def git(self, *args, input=None):
        result = subprocess.run(["git", "--git-dir", str(self.repo), *args],
                                input=input, capture_output=True, check=True)
        return result.stdout.decode().strip()

    def collect(self, report=None):
        return bootstrap.collect_evidence(self.policy, self.payload, self.backend,
                    lambda _receipt: self.raw_report if report is None else report, now=110)

    def test_collector_reads_real_commit_tree_and_missing_ref(self):
        result = self.collect()
        self.assertEqual(result["candidate_sha"], self.candidate)
        self.assertFalse(result["head_exists"])

    def test_collector_denies_changed_parent_existing_head_and_wrong_parentage(self):
        self.git("update-ref", "refs/heads/" + self.base, self.candidate)
        with self.assertRaisesRegex(bootstrap.BootstrapDenied, "PARENT_MOVED"):
            self.collect()
        self.git("update-ref", "refs/heads/" + self.base, self.parent)
        self.git("update-ref", "refs/heads/" + self.head, self.candidate)
        with self.assertRaisesRegex(bootstrap.BootstrapDenied, "HEAD_EXISTS"):
            self.collect()

    def test_collector_fetches_and_hashes_report_bytes(self):
        with self.assertRaisesRegex(bootstrap.BootstrapDenied, "REPORT_DIGEST"):
            self.collect(b"{}")

    def test_collector_rejects_failed_skipped_or_empty_report(self):
        for counts in ({"passed": 0, "failed": 0, "errors": 0, "skipped": 0},
                       {"passed": 1, "failed": 1, "errors": 0, "skipped": 0},
                       {"passed": 1, "failed": 0, "errors": 0, "skipped": 1}):
            with self.subTest(counts=counts):
                self.report["tests"] = counts
                raw = json.dumps(self.report).encode()
                self.check["report_sha256"] = hashlib.sha256(raw).hexdigest()
                with self.assertRaisesRegex(bootstrap.BootstrapDenied, "REPORT_NOT_PASSED"):
                    self.collect(raw)

    def test_report_wrong_binding_producer_or_receipt_is_rejected(self):
        for field in ("source_sha", "tree_sha", "producer_principal", "receipt_id"):
            with self.subTest(field=field):
                report = dict(self.report, **{field: "wrong"})
                raw = json.dumps(report).encode()
                self.check["report_sha256"] = hashlib.sha256(raw).hexdigest()
                with self.assertRaises(bootstrap.BootstrapDenied):
                    self.collect(raw)

    def test_replay_reservation_has_one_winner_across_connections(self):
        def reserve(_):
            try:
                bootstrap.ReplayLedger(self.root / "replay.sqlite").reserve(
                    "a" * 64, "b" * 64, self.binding, now=110, expires_at=200)
                return True
            except bootstrap.BootstrapDenied:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            self.assertEqual(sum(pool.map(reserve, range(12))), 1)

    def test_sidecar_disappearing_during_initialization_preserves_replay_fencing(self):
        original_exists = Path.exists
        for suffix in ("-journal", "-wal", "-shm"):
            with self.subTest(suffix=suffix):
                path = self.root / ("transient" + suffix + ".sqlite")
                sidecar = Path(str(path) + suffix)

                def previously_present(candidate):
                    # SQLite removed the sidecar after an earlier existence probe.
                    return True if candidate == sidecar else original_exists(candidate)

                with patch.object(Path, "exists", previously_present):
                    ledger = bootstrap.ReplayLedger(path)
                ledger.reserve("a" * 64, "b" * 64, self.binding,
                               now=110, expires_at=200)
                with self.assertRaisesRegex(bootstrap.BootstrapDenied,
                                            "REQUEST_ALREADY_CONSUMED"):
                    bootstrap.ReplayLedger(path).reserve(
                        "a" * 64, "b" * 64, self.binding, now=111, expires_at=200)

    def test_sidecar_inspection_errors_are_not_treated_as_absence(self):
        original_lstat = Path.lstat
        sidecar = Path(str(self.ledger.path) + "-journal")

        def inaccessible(candidate, *args, **kwargs):
            if candidate == sidecar:
                raise PermissionError("fixture denies inspection")
            return original_lstat(candidate, *args, **kwargs)

        with patch.object(Path, "lstat", inaccessible), self.assertRaises(PermissionError):
            bootstrap.ReplayLedger(self.ledger.path)

    def test_dangling_sidecar_symlinks_are_rejected(self):
        for suffix in ("-journal", "-wal", "-shm"):
            with self.subTest(suffix=suffix):
                sidecar = Path(str(self.ledger.path) + suffix)
                sidecar.symlink_to(self.root / "missing")
                try:
                    with self.assertRaisesRegex(bootstrap.BootstrapDenied,
                                                "UNTRUSTED_LEDGER_SIDECAR"):
                        bootstrap.ReplayLedger(self.ledger.path)
                finally:
                    sidecar.unlink()

    def test_failed_or_uncertain_attempt_never_reopens_nonce(self):
        self.ledger.reserve("a" * 64, "b" * 64, self.binding, now=110, expires_at=200)
        self.ledger.finish("a" * 64, "b" * 64, "UNCERTAIN")
        with self.assertRaisesRegex(bootstrap.BootstrapDenied, "REQUEST_ALREADY_CONSUMED"):
            self.ledger.reserve("a" * 64, "b" * 64, self.binding, now=111, expires_at=200)

    def test_reservation_rejects_expiry_and_receipt_rebinding(self):
        with self.assertRaises(bootstrap.BootstrapDenied):
            self.ledger.reserve("a" * 64, "b" * 64, self.binding, now=200, expires_at=200)
        self.ledger.reserve("a" * 64, "b" * 64, self.binding, now=110, expires_at=200)
        with self.assertRaises(bootstrap.BootstrapDenied):
            self.ledger.finish("a" * 64, "c" * 64, "PUBLISHED")

    def test_transaction_atomically_verifies_parent_and_creates_absent_head(self):
        self.backend.create_review(self.binding)
        self.assertEqual(self.backend.read_ref(self.head), self.candidate)

    def test_moved_parent_rejects_transaction_without_creating_head(self):
        self.git("update-ref", "refs/heads/" + self.base, self.candidate)
        with self.assertRaises(bootstrap.BootstrapDenied):
            self.backend.create_review(self.binding)
        self.assertIsNone(self.backend.read_ref(self.head))

    def test_existing_head_is_never_overwritten(self):
        self.git("update-ref", "refs/heads/" + self.head, self.parent)
        with self.assertRaises(bootstrap.BootstrapDenied):
            self.backend.create_review(self.binding)
        self.assertEqual(self.backend.read_ref(self.head), self.parent)

    def test_protected_or_mismatched_lane_is_rejected(self):
        for change in ({"head_ref": "main"}, {"target_ref": "section/mw-02-command-kernel"}):
            with self.subTest(change=change), self.assertRaises(bootstrap.BootstrapDenied):
                self.backend.create_review(dict(self.binding, **change))

    def test_legacy_full_certification_creation_rule_is_an_explicit_blocker(self):
        with self.assertRaisesRegex(bootstrap.BootstrapDenied, "FULL_CERTIFICATION_REQUIRED_BEFORE_CREATE"):
            bootstrap.verify_protocol({"schema": "codestra.review-publication-protocol.v1",
                "independently_approved": True, "admission_context": "codestra-review-admission",
                "certification_context": "codestra-control-plane",
                "creation_required_contexts": ["codestra-control-plane"],
                "promotion_required_contexts": ["codestra-control-plane"],
                "bypass_actors": [], "enforce_on_create": True})

    def test_protocol_cannot_remove_promotion_certification_or_creation_checks(self):
        protocol = {"schema": "codestra.review-publication-protocol.v1",
                "independently_approved": True, "admission_context": "codestra-review-admission",
                "certification_context": "codestra-control-plane",
                "creation_required_contexts": ["codestra-review-admission"],
                "promotion_required_contexts": ["codestra-control-plane"],
                "bypass_actors": [], "enforce_on_create": True}
        bootstrap.verify_protocol(protocol)
        for field, value in (("independently_approved", False),
                             ("promotion_required_contexts", []),
                             ("enforce_on_create", False),
                             ("bypass_actors", ["author"])):
            with self.subTest(field=field), self.assertRaises(bootstrap.BootstrapDenied):
                bootstrap.verify_protocol(dict(protocol, **{field: value}))

    def test_broker_runs_verifier_collector_and_consumes_before_publish(self):
        envelope = b"synthetic signed bundle"
        verdict = {"verdict": "REVIEW_EVIDENCE_VALID", "binding": self.binding,
                   "request_id": "a" * 64, "payload_sha256": hashlib.sha256(bootstrap.canonical(self.payload)).hexdigest(),
                   "expires_at": 200, "certified": False,
                   "worker_start_authorized": False, "publication_authorized": False}
        protocol = {"schema": "codestra.review-publication-protocol.v1",
                "independently_approved": True, "admission_context": "codestra-review-admission",
                "certification_context": "codestra-control-plane",
                "creation_required_contexts": ["codestra-review-admission"],
                "promotion_required_contexts": ["codestra-control-plane"],
                "bypass_actors": [], "enforce_on_create": True}
        with patch.object(bootstrap, "verify_review_evidence", return_value=verdict):
            result = bootstrap.publish_review(envelope, self.policy, self.payload, protocol,
                self.ledger, self.backend, lambda _: self.raw_report, clock=lambda:110)
        self.assertEqual(result["result"], "REVIEW_REF_PUBLISHED")
        self.assertFalse(result["certified"])
        self.assertFalse(result["worker_start_authorized"])
        self.assertEqual(self.ledger.state("a" * 64), "PUBLISHED")
        self.assertEqual(self.backend.read_ref(self.head), self.candidate)

    def test_broker_denied_protocol_never_reserves_or_writes(self):
        with self.assertRaises(bootstrap.BootstrapDenied):
            bootstrap.publish_review(b"unused", self.policy, self.payload, {},
                self.ledger, self.backend, lambda _:self.raw_report, clock=lambda:110)
        self.assertIsNone(self.backend.read_ref(self.head))

    @unittest.skipUnless(sys.platform.startswith("linux"), "Deployed OpenSSL primitive is Linux")
    def test_end_to_end_with_actual_three_party_signatures_objects_reports_and_transaction(self):
        from codestra_control import prepublication
        signers, private_keys = [], []
        for role in ("operator", "security", "validator"):
            path = self.root / (role + ".pem")
            subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519", "-out", str(path)],
                           check=True, capture_output=True)
            der = subprocess.check_output(["/usr/bin/openssl", "pkey", "-in", str(path), "-pubout", "-outform", "DER"])
            signers.append({"role": role, "principal": role, "key_id": role,
                            "public_key": base64.b64encode(der[-32:]).decode()})
            private_keys.append(path)
        self.policy.update(schema="codestra.prepublication-policy.v1", enabled=True,
                           expires_at=300, max_ttl_seconds=600, signers=signers)
        self.payload.update(schema="codestra.prepublication-review.v1", purpose="REVIEW_ONLY",
                            request_id="a" * 64, author_principal="author", issued_at=90,
                            lease_expires_at=250, observed_parent_sha=self.parent,
                            observed_tree_sha=self.tree, head_absent=True, clean_source=True,
                            governance_unchanged=True, safety_denied=False, production_go=False,
                            live_capabilities_enabled=False, external_effects=False)
        message = self.root / "message"
        raw = bootstrap.canonical(self.payload)
        message.write_bytes(prepublication.DOMAIN + raw)
        signatures = []
        for signer, private in zip(signers, private_keys):
            signature = subprocess.check_output(["/usr/bin/openssl", "pkeyutl", "-sign", "-rawin",
                         "-inkey", str(private), "-in", str(message)])
            signatures.append({"key_id": signer["key_id"], "signature": base64.b64encode(signature).decode()})
        envelope = bootstrap.canonical({"payload": base64.b64encode(raw).decode(), "signatures": signatures})
        protocol = {"schema": "codestra.review-publication-protocol.v1", "independently_approved": True,
            "admission_context": "codestra-review-admission", "certification_context": "codestra-control-plane",
            "creation_required_contexts": ["codestra-review-admission"],
            "promotion_required_contexts": ["codestra-control-plane"],
            "bypass_actors": [], "enforce_on_create": True}
        result = bootstrap.publish_review(envelope, self.policy, self.payload, protocol,
                    self.ledger, self.backend, lambda _: self.raw_report, clock=lambda:110)
        self.assertEqual(result["result"], "REVIEW_REF_PUBLISHED")
        self.assertFalse(result["certified"])
        with self.assertRaises(prepublication.AdmissionDenied):
            bootstrap.publish_review(envelope, self.policy, self.payload, protocol,
                    self.ledger, self.backend, lambda _: self.raw_report, clock=lambda:110)

    def test_cli_missing_protocol_is_a_structured_denial(self):
        import contextlib
        import io
        output = io.StringIO()
        with patch.object(bootstrap, "read_document", side_effect=FileNotFoundError), contextlib.redirect_stdout(output):
            self.assertEqual(bootstrap.main(["signed-bundle.json"]), 2)
        self.assertEqual(json.loads(output.getvalue())["result"], "BLOCKED")

    def test_collector_rejects_wrong_single_parent_or_tree(self):
        self.binding["parent_sha"] = self.candidate
        with self.assertRaisesRegex(bootstrap.BootstrapDenied, "CANDIDATE_PARENT_MISMATCH"):
            self.collect()

    def test_ledger_connection_is_closed_after_use(self):
        with self.ledger.connect() as connection:
            connection.execute("SELECT 1")
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")

    def test_dangling_symbolic_head_cannot_create_protected_destination(self):
        self.git("symbolic-ref", "refs/heads/" + self.head, "refs/heads/main")
        with self.assertRaises(bootstrap.BootstrapDenied):
            self.backend.create_review(self.binding)
        self.assertEqual(self.git("for-each-ref", "--format=%(refname)", "refs/heads/main"), "")

    def test_symbolic_parent_is_rejected(self):
        self.git("update-ref", "refs/heads/real-parent", self.parent)
        self.git("symbolic-ref", "refs/heads/" + self.base, "refs/heads/real-parent")
        with self.assertRaises(bootstrap.BootstrapDenied):
            self.collect()

    def test_configured_repository_identity_cannot_be_rebound(self):
        self.backend.repository_id = "example/another-repository"
        with self.assertRaisesRegex(bootstrap.BootstrapDenied, "REPOSITORY_IDENTITY_MISMATCH"):
            self.collect()

    @unittest.skipUnless(sys.platform.startswith("linux"), "POSIX file permissions")
    def test_existing_writable_ledger_or_sidecar_is_rejected(self):
        for suffix in ("", "-journal", "-wal", "-shm"):
            with self.subTest(suffix=suffix):
                path = self.root / ("unsafe" + suffix)
                path.write_bytes(b"")
                path.chmod(0o666)
                with self.assertRaisesRegex(bootstrap.BootstrapDenied, "UNTRUSTED_LEDGER"):
                    bootstrap.ReplayLedger(self.root / "unsafe")
                path.unlink()

    def broker_fixture(self):
        verdict = {"verdict": "REVIEW_EVIDENCE_VALID", "binding": self.binding,
            "request_id": "a" * 64, "payload_sha256": hashlib.sha256(bootstrap.canonical(self.payload)).hexdigest(),
            "expires_at": 200, "certified": False,
            "worker_start_authorized": False, "publication_authorized": False}
        protocol = {"schema": "codestra.review-publication-protocol.v1", "independently_approved": True,
            "admission_context": "codestra-review-admission", "certification_context": "codestra-control-plane",
            "creation_required_contexts": ["codestra-review-admission"],
            "promotion_required_contexts": ["codestra-control-plane"],
            "bypass_actors": [], "enforce_on_create": True}
        return verdict, protocol

    def test_expiry_during_collection_or_final_inspection_cannot_publish(self):
        verdict, protocol = self.broker_fixture()
        for during in ("report", "inspection"):
            with self.subTest(during=during):
                clock = [110]
                reads = [0]
                inspections = [0]
                inspect = self.backend.inspect_source
                def read(_):
                    reads[0] += 1
                    if during == "report" and reads[0] == 2:
                        clock[0] = 201
                    return self.raw_report
                def checked(binding):
                    inspections[0] += 1
                    inspect(binding)
                    if during == "inspection" and inspections[0] == 3:
                        clock[0] = 201
                ledger = bootstrap.ReplayLedger(self.root / (during + ".sqlite"))
                with patch.object(bootstrap, "verify_review_evidence", return_value=verdict), \
                     patch.object(self.backend, "inspect_source", side_effect=checked), \
                     self.assertRaisesRegex(bootstrap.BootstrapDenied, "APPROVAL_EXPIRED"):
                    bootstrap.publish_review(b"signed", self.policy, self.payload, protocol,
                        ledger, self.backend, read, clock=lambda:clock[0])
                self.assertIsNone(self.backend.read_ref(self.head))
                self.assertIn(ledger.state("a" * 64), {"REJECTED", "UNCERTAIN"})

    def test_authority_revocation_during_collection_cannot_publish(self):
        verdict, protocol = self.broker_fixture()
        reads = [0]
        def read(_):
            reads[0] += 1
            return self.raw_report
        def authority():
            return self.policy, dict(protocol, independently_approved=reads[0] < 2)
        with patch.object(bootstrap, "verify_review_evidence", return_value=verdict), \
             self.assertRaises(bootstrap.BootstrapDenied):
            bootstrap.publish_review(b"signed", self.policy, self.payload, protocol,
                self.ledger, self.backend, read, clock=lambda:110, reload_authority=authority)
        self.assertIsNone(self.backend.read_ref(self.head))

    def test_distinct_nonces_compete_for_one_head_in_independent_processes(self):
        code = '''import json,sys
sys.path.insert(0,sys.argv[1])
from codestra_control.bootstrap import ReplayLedger,BootstrapDenied
from pathlib import Path
try:
 ReplayLedger(Path(sys.argv[2])).reserve(sys.argv[3],"b"*64,json.loads(sys.argv[4]),now=110,expires_at=200)
except BootstrapDenied:
 sys.exit(9)
'''
        def reserve(index):
            return subprocess.run([sys.executable, "-S", "-c", code,
                str(Path(__file__).resolve().parents[1] / "lib"), str(self.ledger.path),
                f"{index+1:064x}", json.dumps(self.binding)], capture_output=True, timeout=30).returncode
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(reserve, range(8)))
        self.assertEqual(results.count(0), 1)
        self.assertEqual(results.count(9), 7)

    def test_process_death_keeps_request_consumed_before_and_after_ref_commit(self):
        code = '''import json,sys,os
sys.path.insert(0,sys.argv[1])
from codestra_control.bootstrap import ReplayLedger,GitRefTransaction
from pathlib import Path
binding=json.loads(sys.argv[4])
ReplayLedger(Path(sys.argv[2])).reserve("a"*64,"b"*64,binding,now=110,expires_at=200)
if sys.argv[5]=="after":
 GitRefTransaction(Path(sys.argv[3]),binding["repository"]).create_review(binding)
os._exit(91)
'''
        for when in ("before", "after"):
            path = self.root / ("crash-" + when + ".sqlite")
            result = subprocess.run([sys.executable, "-S", "-c", code,
                str(Path(__file__).resolve().parents[1] / "lib"), str(path), str(self.repo),
                json.dumps(self.binding), when], capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 91, result.stderr)
            ledger = bootstrap.ReplayLedger(path)
            self.assertEqual(ledger.state("a" * 64), "RESERVED")
            with self.assertRaises(bootstrap.BootstrapDenied):
                ledger.reserve("a" * 64, "b" * 64, self.binding, now=111, expires_at=200)
            self.assertEqual(self.backend.read_ref(self.head), self.candidate if when == "after" else None)

    def test_uncertain_transaction_readback_and_ledger_failure_never_retry(self):
        verdict, protocol = self.broker_fixture()
        for failure in ("timeout", "readback", "ledger"):
            with self.subTest(failure=failure):
                ledger = bootstrap.ReplayLedger(self.root / (failure + ".sqlite"))
                backend = unittest.mock.Mock(wraps=self.backend)
                # Use an isolated mock effect while retaining real source/ref
                # collection; this exercises orchestration failure boundaries.
                backend.create_review = unittest.mock.Mock()
                if failure == "timeout":
                    backend.create_review.side_effect = subprocess.TimeoutExpired("git", 1)
                if failure == "ledger":
                    backend.read_ref.side_effect = lambda ref: self.parent if ref == self.base else (
                        self.candidate if backend.create_review.called else None)
                original = ledger.finish
                def finish(request, payload_hash, state):
                    if failure == "ledger" and state == "PUBLISHED":
                        raise sqlite3.OperationalError("synthetic completion failure")
                    return original(request, payload_hash, state)
                with patch.object(bootstrap, "verify_review_evidence", return_value=verdict), \
                     patch.object(ledger, "finish", side_effect=finish), self.assertRaises(Exception):
                    bootstrap.publish_review(b"signed", self.policy, self.payload, protocol,
                        ledger, backend, lambda _:self.raw_report, clock=lambda:110)
                self.assertEqual(ledger.state("a" * 64), "UNCERTAIN")
                backend.create_review.assert_called_once()
                with self.assertRaises(bootstrap.BootstrapDenied):
                    ledger.reserve("a" * 64, "c" * 64, self.binding, now=111, expires_at=200)
if __name__ == "__main__":
    unittest.main()
