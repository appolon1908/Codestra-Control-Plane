"""Real CLI/fault checks inside an explicitly disposable, offline container.

Run only with the documented read-only source and three empty tmpfs mounts.
Ephemeral signing identities and policy declarations establish no live approval.
This suite must never install anything in the host's trusted configuration.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SOURCE / "lib"))
from codestra_control import bootstrap


class BootstrapCliIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (sys.platform != "linux" or os.geteuid() != 0
                or SOURCE != Path("/source")
                or os.environ.get("CODESTRA_DISPOSABLE_BOOTSTRAP_TEST") != "1"
                or not Path("/.dockerenv").is_file()):
            raise RuntimeError("Run only in the documented disposable container")
        mounts = {}
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            left, right = line.split(" - ", 1)
            fields = left.split()
            mounts[fields[4]] = (set(fields[5].split(",")), right.split()[0])
        if "ro" not in mounts.get("/source", (set(), ""))[0]:
            raise RuntimeError("Source must be a read-only mount")
        for path in ("/etc/codestra", "/var/lib/codestra", "/staging"):
            if (mounts.get(path, (set(), ""))[1] != "tmpfs"
                    or any(Path(path).iterdir())):
                raise RuntimeError("Trusted paths must use empty disposable tmpfs mounts")
        bootstrap.BROKER_PATH.parent.mkdir(mode=0o755)
        bootstrap.LEDGER_PATH.parent.mkdir(mode=0o700)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="case-", dir="/staging")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo.git"
        subprocess.run(["git", "init", "--bare", str(self.repo)],
                       capture_output=True, check=True)
        self.git("config", "user.name", "Disposable fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.tree = self.git("mktree", input=b"")
        self.parent = self.git("commit-tree", self.tree, input=b"parent\n")
        self.candidate = self.git("commit-tree", self.tree, "-p", self.parent,
                                  input=b"review\n")
        self.target = "section/fixture"
        self.head = "subsection/fixture--bootstrap"
        self.git("update-ref", "refs/heads/" + self.target, self.parent)
        self.binding = {"repository": "example/disposable-fixture", "head_ref": self.head,
            "target_ref": self.target, "parent_sha": self.parent,
            "candidate_sha": self.candidate, "tree_sha": self.tree,
            "lease_id": "disposable-lease", "owner_principal": "fixture-author"}
        self.reports = self.root / "reports"
        self.reports.mkdir(mode=0o700)
        now = int(time.time())
        self.report = {"schema": "codestra.validator-report.v1", "name": "unit",
            "receipt_id": "fixture-unit", "producer_principal": "fixture-validator",
            "source_sha": self.candidate, "tree_sha": self.tree,
            "conclusion": "passed", "completed_at": now,
            "tests": {"passed": 1, "failed": 0, "errors": 0, "skipped": 0}}
        self.report_path = self.reports / "fixture-unit.json"
        self.report_raw = self.write_json(self.report_path, self.report)
        self.keys, signers = [], []
        for role in ("operator", "security", "validator"):
            private = self.root / (role + ".pem")
            subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519",
                            "-out", str(private)], capture_output=True, check=True)
            public = subprocess.check_output(["/usr/bin/openssl", "pkey", "-in",
                          str(private), "-pubout", "-outform", "DER"])
            self.keys.append(private)
            signers.append({"role": role, "principal": "fixture-" + role,
                            "key_id": role, "public_key": base64.b64encode(public[-32:]).decode()})
        self.policy = {"schema": "codestra.prepublication-policy.v1", "enabled": True,
            "binding": self.binding, "request_id": "a" * 64, "expires_at": now + 300,
            "max_age_seconds": 300, "max_ttl_seconds": 300,
            "required_checks": ["unit"], "signers": signers}
        check = {k: self.report[k] for k in ("name", "receipt_id", "producer_principal",
                 "source_sha", "tree_sha", "conclusion", "completed_at")}
        check["report_sha256"] = hashlib.sha256(self.report_raw).hexdigest()
        self.payload = {"schema": "codestra.prepublication-review.v1", "purpose": "REVIEW_ONLY",
            "binding": self.binding, "request_id": "a" * 64,
            "author_principal": "fixture-author", "issued_at": now, "expires_at": now + 300,
            "lease_expires_at": now + 300, "observed_at": now,
            "observed_parent_sha": self.parent, "observed_tree_sha": self.tree,
            "head_absent": True, "clean_source": True, "governance_unchanged": True,
            "safety_denied": False, "production_go": False,
            "live_capabilities_enabled": False, "external_effects": False, "checks": [check]}
        self.protocol = {"schema": "codestra.review-publication-protocol.v1",
            "independently_approved": True, "admission_context": "codestra-review-admission",
            "certification_context": "codestra-control-plane",
            "creation_required_contexts": ["codestra-review-admission"],
            "promotion_required_contexts": ["codestra-control-plane"],
            "bypass_actors": [], "enforce_on_create": True}
        self.write_json(bootstrap.BROKER_PATH, {"schema": "codestra.bootstrap-broker.v1",
            "repository": self.binding["repository"], "repository_path": str(self.repo),
            "reports_path": str(self.reports)})
        self.write_json(bootstrap.POLICY_PATH, self.policy)
        self.write_json(bootstrap.PROTOCOL_PATH, self.protocol)
        self.bundle = self.root / "bundle.json"
        self.sign()

    def tearDown(self):
        # These paths are in empty tmpfs mounts verified before any fixture write.
        for path in (bootstrap.BROKER_PATH, bootstrap.POLICY_PATH, bootstrap.PROTOCOL_PATH):
            path.unlink(missing_ok=True)
        for suffix in ("", "-journal", "-wal", "-shm"):
            Path(str(bootstrap.LEDGER_PATH) + suffix).unlink(missing_ok=True)

    @staticmethod
    def write_json(path, value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        path.write_bytes(raw)
        path.chmod(0o600)
        return raw

    def git(self, *args, input=None):
        return subprocess.check_output(["git", "--git-dir", str(self.repo), *args],
                                       input=input, stderr=subprocess.PIPE).decode().strip()

    def sign(self):
        raw = json.dumps(self.payload, sort_keys=True, separators=(",", ":")).encode()
        message = self.root / "signing-input"
        message.write_bytes(b"CODESTRA-PREPUBLICATION-REVIEW-V1\x00" + raw)
        signatures = []
        for signer, key in zip(self.policy["signers"], self.keys):
            signature = subprocess.check_output(["/usr/bin/openssl", "pkeyutl", "-sign",
                        "-rawin", "-inkey", str(key), "-in", str(message)])
            signatures.append({"key_id": signer["key_id"],
                               "signature": base64.b64encode(signature).decode()})
        self.envelope = self.write_json(self.bundle,
            {"payload": base64.b64encode(raw).decode(), "signatures": signatures})

    def cli(self):
        result = subprocess.run([sys.executable, str(SOURCE / "bin/codestra-review-bootstrap"),
                                 str(self.bundle)], capture_output=True, timeout=50)
        self.assertEqual(result.stderr, b"")
        return result.returncode, json.loads(result.stdout)

    def assert_no_publication(self):
        self.assertEqual(self.git("rev-parse", "refs/heads/" + self.target), self.parent)
        self.assertEqual(self.git("for-each-ref", "--format=%(objectname)",
                                  "refs/heads/" + self.head), "")

    def test_cli_publishes_once_with_real_signatures_and_rejects_replay(self):
        code, result = self.cli()
        self.assertEqual(code, 0, result)
        self.assertEqual(result["result"], "REVIEW_REF_PUBLISHED")
        for field in ("certified", "worker_start_authorized", "promotion_authorized"):
            self.assertIs(result[field], False)
        self.assertEqual(self.git("rev-parse", "refs/heads/" + self.head), self.candidate)
        with sqlite3.connect(bootstrap.LEDGER_PATH) as connection:
            self.assertEqual(connection.execute("SELECT state FROM admissions").fetchall(),
                             [("PUBLISHED",)])
        code, replay = self.cli()
        self.assertEqual(code, 2)
        self.assertEqual(replay["reason"], "REQUEST_ALREADY_CONSUMED")
        self.assertEqual(self.git("rev-parse", "refs/heads/" + self.head), self.candidate)

    def test_cli_denies_a_moved_parent(self):
        self.git("update-ref", "refs/heads/" + self.target, self.candidate)
        code, result = self.cli()
        self.assertEqual((code, result["reason"]), (2, "PARENT_MOVED"))
        self.assertEqual(self.git("for-each-ref", "--format=%(objectname)",
                                  "refs/heads/" + self.head), "")

    def test_cli_reads_real_report_bytes(self):
        self.report_path.write_bytes(b"{}")
        code, result = self.cli()
        self.assertEqual((code, result["reason"]), (2, "REPORT_DIGEST_MISMATCH"))
        self.assert_no_publication()

    def test_cli_denies_an_unapproved_protocol(self):
        self.protocol["independently_approved"] = False
        self.write_json(bootstrap.PROTOCOL_PATH, self.protocol)
        code, result = self.cli()
        self.assertEqual((code, result["reason"]), (2, "PROTOCOL_NOT_APPROVED"))
        self.assert_no_publication()
        self.assertFalse(bootstrap.LEDGER_PATH.exists())

    def test_cli_denies_revoked_policy(self):
        self.policy["enabled"] = False
        self.write_json(bootstrap.POLICY_PATH, self.policy)
        code, result = self.cli()
        self.assertEqual((code, result["reason"]), (2, "POLICY_NOT_ENABLED"))
        self.assert_no_publication()

    def test_cli_denies_skipped_validator_evidence(self):
        self.report["tests"]["skipped"] = 1
        raw = self.write_json(self.report_path, self.report)
        self.payload["checks"][0]["report_sha256"] = hashlib.sha256(raw).hexdigest()
        self.sign()
        code, result = self.cli()
        self.assertEqual((code, result["reason"]), (2, "REPORT_NOT_PASSED"))
        self.assert_no_publication()

    def test_real_watchdog_burns_nonce_and_releases_prepared_git_locks(self):
        # A transport shim forwards a real Git prepare and then stops forwarding
        # input. No timeout exception, clock, signature, ledger or Git result is mocked.
        shim = self.root / "stalled-transport.py"
        prepared = self.root / "prepared-at"
        shim.write_text('''import pathlib,subprocess,sys,time
p=subprocess.Popen(sys.argv[2:],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
while True:
 line=sys.stdin.buffer.readline()
 p.stdin.write(line); p.stdin.flush()
 if line==b"prepare\\n": break
for expected in (b"start: ok\\n",b"prepare: ok\\n"):
 response=p.stdout.readline()
 if response!=expected: sys.exit(7)
 sys.stdout.buffer.write(response); sys.stdout.buffer.flush()
pathlib.Path(sys.argv[1]).write_text(str(time.monotonic()))
time.sleep(120)
''')
        class StalledTransport(bootstrap.GitRefTransaction):
            def command(backend, *args):
                original = super().command(*args)
                return [sys.executable, str(shim), str(prepared), *original] if args[0] == "update-ref" else original
        backend = StalledTransport(self.repo, self.binding["repository"])
        ledger = bootstrap.ReplayLedger(bootstrap.LEDGER_PATH)
        started = time.monotonic()
        with self.assertRaises(bootstrap.BootstrapDenied) as denial:
            bootstrap.publish_review(self.envelope, self.policy, self.payload, self.protocol,
                ledger, backend, lambda _: self.report_path.read_bytes())
        self.assertLess(time.monotonic() - started, 45)
        self.assertIn(str(denial.exception), {"TRANSACTION_TIMEOUT", "GIT_EVIDENCE_OR_TRANSACTION_FAILED"})
        self.assertTrue(prepared.is_file(), "Real Git never acknowledged prepare")
        self.assertGreaterEqual(time.monotonic() - float(prepared.read_text()), 25)
        self.assertEqual(ledger.state("a" * 64), "UNCERTAIN")
        with self.assertRaises(bootstrap.BootstrapDenied):
            ledger.reserve("a" * 64, "b" * 64, self.binding,
                           now=int(time.time()), expires_at=int(time.time()) + 60)
        self.assert_no_publication()
        deadline = time.monotonic() + 5
        while list((self.repo / "refs").rglob("*.lock")) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(list((self.repo / "refs").rglob("*.lock")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
