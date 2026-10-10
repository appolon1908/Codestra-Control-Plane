"""Trusted bootstrap collection and durable, conditional review publication.

This is source for independent protocol review. A REVIEW result is never a
subsection certificate. Existing product rules are not modified by this module.
The production CLI has no trust-path overrides and refuses absent/unapproved
protocol configuration. Tests use disposable bare repositories only.
"""
from __future__ import annotations

import hashlib
from contextlib import contextmanager
import json
import os
from pathlib import Path
import queue
import sqlite3
import stat
import subprocess
import threading
import time
import tempfile
from typing import Callable

from .prepublication import (AdmissionDenied, canonical, decode, digest,
    load_json, read_document, verify_binding, verify_review_evidence)

BROKER_PATH = Path("/etc/codestra/control-plane/bootstrap-broker.json")
POLICY_PATH = Path("/etc/codestra/control-plane/prepublication-review-policy.json")
PROTOCOL_PATH = Path("/etc/codestra/control-plane/review-publication-protocol.json")
LEDGER_PATH = Path("/var/lib/codestra/control-plane/bootstrap.sqlite")
ADMISSION_CONTEXT = "codestra-review-admission"
CERTIFICATION_CONTEXT = "codestra-control-plane"


class BootstrapDenied(AdmissionDenied):
    pass


def ensure(condition: bool, reason: str) -> None:
    if not condition:
        raise BootstrapDenied(reason)


def verify_protocol(protocol: dict) -> None:
    """Require a separately approved split; never reinterpret the old check."""
    fields = {"schema", "independently_approved", "admission_context",
              "certification_context", "creation_required_contexts",
              "promotion_required_contexts", "bypass_actors", "enforce_on_create"}
    ensure(type(protocol) is dict and set(protocol) == fields, "PROTOCOL_NOT_INSTALLED")
    ensure(protocol["schema"] == "codestra.review-publication-protocol.v1"
           and protocol["independently_approved"] is True, "PROTOCOL_NOT_APPROVED")
    ensure(protocol["admission_context"] == ADMISSION_CONTEXT
           and protocol["certification_context"] == CERTIFICATION_CONTEXT,
           "ADMISSION_CANNOT_IMPERSONATE_CERTIFICATION")
    creation = protocol["creation_required_contexts"]
    promotion = protocol["promotion_required_contexts"]
    ensure(type(creation) is list and all(type(x) is str for x in creation)
           and type(promotion) is list and all(type(x) is str for x in promotion),
           "INVALID_PROTOCOL_CHECKS")
    ensure(CERTIFICATION_CONTEXT not in creation,
           "FULL_CERTIFICATION_REQUIRED_BEFORE_CREATE")
    ensure(ADMISSION_CONTEXT in creation and CERTIFICATION_CONTEXT in promotion
           and protocol["bypass_actors"] == [] and protocol["enforce_on_create"] is True,
           "PROTOCOL_PROTECTION_MISSING")


class GitRefTransaction:
    """A service-owned bare repository, not a client checkout or GitHub API.

    Git's reference transaction verifies the parent and creates an absent head
    under the same ref locks. GitHub create-ref does NOT offer that transaction;
    this adapter must not be replaced with a precheck plus unconditional POST.
    """
    def __init__(self, repository: Path, repository_id: str):
        self.repository = Path(repository).absolute()
        self.repository_id = repository_id
        ensure(self.repository.is_dir() and not self.repository.is_symlink(),
               "TRUSTED_BARE_REPOSITORY_REQUIRED")
        ensure(self.run("rev-parse", "--is-bare-repository") == b"true\n",
               "TRUSTED_BARE_REPOSITORY_REQUIRED")

    def environment(self) -> dict:
        return {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_CONFIG_GLOBAL": os.devnull, "GIT_NO_REPLACE_OBJECTS": "1",
               "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}

    def command(self, *args: str) -> list[str]:
        return ["git", "-c", "core.hooksPath=" + os.devnull, "--git-dir",
                str(self.repository), *args]

    def run(self, *args: str, input: bytes | None = None) -> bytes:
        result = subprocess.run(
            self.command(*args),
            input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, env=self.environment(), check=False)
        ensure(result.returncode == 0, "GIT_EVIDENCE_OR_TRANSACTION_FAILED")
        ensure(len(result.stdout) <= 4 * 1024 * 1024, "GIT_EVIDENCE_TOO_LARGE")
        return result.stdout

    def read_ref(self, ref: str) -> str | None:
        ensure(type(ref) is str and ref.startswith(("section/", "subsection/"))
               and ".." not in ref and "\n" not in ref and " " not in ref,
               "INVALID_REF")
        self.reject_symbolic(ref)
        raw = self.run("for-each-ref", "--format=%(refname) %(objectname)",
                       "refs/heads/" + ref).decode().splitlines()
        exact = [line.split()[1] for line in raw
                 if line.split()[0] == "refs/heads/" + ref]
        ensure(len(exact) <= 1, "AMBIGUOUS_REF")
        return exact[0] if exact else None

    def reject_symbolic(self, ref: str) -> None:
        result = subprocess.run(self.command("symbolic-ref", "-q", "refs/heads/" + ref),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            env=self.environment(), check=False)
        ensure(result.returncode == 1, "SYMBOLIC_OR_UNREADABLE_REF")

    def inspect_source(self, binding: dict) -> None:
        try:
            verify_binding(binding)
        except AdmissionDenied as exc:
            raise BootstrapDenied(str(exc)) from exc
        ensure(binding["repository"] == self.repository_id, "REPOSITORY_IDENTITY_MISMATCH")
        self.run("fsck", "--strict", "--no-dangling", binding["candidate_sha"])
        commit = self.run("cat-file", "commit", binding["candidate_sha"])
        headers = commit.split(b"\n\n", 1)[0].splitlines()
        parents = [line[7:].decode() for line in headers if line.startswith(b"parent ")]
        trees = [line[5:].decode() for line in headers if line.startswith(b"tree ")]
        ensure(parents == [binding["parent_sha"]], "CANDIDATE_PARENT_MISMATCH")
        ensure(trees == [binding["tree_sha"]], "CANDIDATE_TREE_MISMATCH")
        # Read the complete tree graph via fsck, never execute candidate code.
        self.run("cat-file", "tree", binding["tree_sha"])
        protected = ("AGENTS.md", ".github/CODEOWNERS", "scripts/agent_preflight.sh")
        changed = self.run("diff-tree", "--no-commit-id", "--name-only", "-r",
                           binding["parent_sha"], binding["candidate_sha"], "--", *protected)
        ensure(not changed.strip(), "GOVERNANCE_CHANGED")
        if binding["repository"] == "appolon1908/Middleware-":
            for path in ("AGENTS.md", "scripts/agent_preflight.sh"):
                self.run("cat-file", "-e", binding["candidate_sha"] + ":" + path)

    def create_review(self, binding: dict,
                      before_commit: Callable[[], float] | None = None) -> None:
        self.inspect_source(binding)
        self.reject_symbolic(binding["target_ref"])
        self.reject_symbolic(binding["head_ref"])
        command = ("start\nverify refs/heads/" + binding["target_ref"] + " "
                   + binding["parent_sha"] + "\ncreate refs/heads/" + binding["head_ref"]
                   + " " + binding["candidate_sha"] + "\nprepare\n")
        # Hold ref locks before the last authority/clock check. No-deref also
        # prevents a dangling review symref from creating a protected ref.
        with tempfile.TemporaryFile() as errors:
            process = subprocess.Popen(self.command("update-ref", "--no-deref", "--stdin"),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors,
                env=self.environment())
            responses = queue.Queue(maxsize=4)
            def reader():
                for _ in range(3):
                    responses.put(process.stdout.readline(1025))
            thread = threading.Thread(target=reader, daemon=True)
            thread.start()
            timer = threading.Timer(30, process.kill)
            timer.start()
            deadline = time.monotonic() + 30
            def expect(value):
                try:
                    line = responses.get(timeout=max(0.001, deadline - time.monotonic()))
                except queue.Empty as exc:
                    raise BootstrapDenied("TRANSACTION_TIMEOUT") from exc
                ensure(line == value, "GIT_EVIDENCE_OR_TRANSACTION_FAILED")
            try:
                process.stdin.write(command.encode("ascii"))
                process.stdin.flush()
                expect(b"start: ok\n")
                expect(b"prepare: ok\n")
                self.reject_symbolic(binding["target_ref"])
                self.reject_symbolic(binding["head_ref"])
                if before_commit:
                    remaining = before_commit()
                    ensure(remaining > 0, "APPROVAL_EXPIRED")
                    deadline = min(deadline, time.monotonic() + remaining)
                    timer.cancel()
                    timer = threading.Timer(max(0.001, deadline - time.monotonic()), process.kill)
                    timer.start()
                process.stdin.write(b"commit\n")
                process.stdin.flush()
                process.stdin.close()
                expect(b"commit: ok\n")
                ensure(process.wait(timeout=max(0.001, deadline - time.monotonic())) == 0,
                       "GIT_EVIDENCE_OR_TRANSACTION_FAILED")
            finally:
                timer.cancel()
                if process.poll() is None:
                    # A rejected guard must abort cleanly and release Git's
                    # prepared locks. SIGKILL is only a timeout fallback.
                    try:
                        if not process.stdin.closed:
                            process.stdin.write(b"abort\n")
                            process.stdin.flush()
                            process.stdin.close()
                        process.wait(timeout=2)
                    except (OSError, subprocess.TimeoutExpired):
                        process.kill()
                process.wait(timeout=5)
                thread.join(timeout=1)
                if not process.stdin.closed:
                    process.stdin.close()
                process.stdout.close()


def collect_evidence(policy: dict, payload: dict, backend: GitRefTransaction,
                     read_report: Callable[[str], bytes], *, now: int) -> dict:
    """Inspect actual objects/refs and independently retrieve validator artifacts.

    Policy, backend and report loader are privileged inputs, not author JSON.
    Signed report hashes alone are insufficient; all referenced bytes are read.
    Checks are executed by the independent validator, never as root by this code.
    """
    binding = policy["binding"]
    ensure(payload["binding"] == binding, "WRONG_SCOPE")
    backend.inspect_source(binding)
    ensure(backend.read_ref(binding["target_ref"]) == binding["parent_sha"], "PARENT_MOVED")
    ensure(backend.read_ref(binding["head_ref"]) is None, "HEAD_EXISTS")
    validator = [s["principal"] for s in policy["signers"] if s["role"] == "validator"]
    ensure(len(validator) == 1, "INVALID_VALIDATOR")
    checks = payload["checks"]
    ensure(type(checks) is list and len(checks) == len(policy["required_checks"]),
           "INCOMPLETE_CHECKS")
    seen = set()
    report_fields = {"schema", "name", "receipt_id", "producer_principal", "source_sha",
                     "tree_sha", "conclusion", "completed_at", "tests"}
    for check in checks:
        name, receipt = check["name"], check["receipt_id"]
        ensure(name in policy["required_checks"] and name not in seen,
               "DUPLICATE_OR_UNKNOWN_CHECK")
        ensure(type(receipt) is str and receipt and "/" not in receipt and "\\" not in receipt,
               "INVALID_RECEIPT")
        raw = read_report(receipt)
        ensure(type(raw) is bytes and hashlib.sha256(raw).hexdigest()
               == check["report_sha256"], "REPORT_DIGEST_MISMATCH")
        report = load_json(raw)
        ensure(set(report) == report_fields and report["schema"]
               == "codestra.validator-report.v1", "INVALID_REPORT_SCHEMA")
        for field in report_fields - {"schema", "tests"}:
            ensure(report[field] == check[field], "REPORT_BINDING_MISMATCH")
        ensure(report["producer_principal"] == validator[0]
               and report["source_sha"] == binding["candidate_sha"]
               and report["tree_sha"] == binding["tree_sha"], "REPORT_BINDING_MISMATCH")
        ensure(type(report["completed_at"]) is int
               and 0 <= now - report["completed_at"] <= policy["max_age_seconds"],
               "STALE_REPORT")
        counts = report["tests"]
        ensure(type(counts) is dict and set(counts) == {"passed", "failed", "errors", "skipped"}
               and all(type(v) is int and v >= 0 for v in counts.values()),
               "INVALID_REPORT_COUNTS")
        ensure(report["conclusion"] == "passed" and counts["passed"] > 0
               and counts["failed"] == counts["errors"] == counts["skipped"] == 0,
               "REPORT_NOT_PASSED")
        seen.add(name)
    ensure(seen == set(policy["required_checks"]), "INCOMPLETE_CHECKS")
    return {"candidate_sha": binding["candidate_sha"], "tree_sha": binding["tree_sha"],
            "parent_sha": binding["parent_sha"], "head_exists": False, "observed_at": now}


class ReplayLedger:
    """Durably burn a nonce before effects. Errors never unconsume approvals."""
    def __init__(self, path: Path):
        self.path = Path(path)
        ensure(not self.path.is_symlink(), "UNTRUSTED_LEDGER_PATH")
        # Production ancestors are checked by the fixed-path CLI before entry.
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            self.check_file(os.fstat(fd))
        finally:
            os.close(fd)
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(str(self.path) + suffix)
            if sidecar.exists() or sidecar.is_symlink():
                ensure(not sidecar.is_symlink(), "UNTRUSTED_LEDGER_SIDECAR")
                self.check_file(sidecar.lstat())
        with self.connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS admissions (
                request_id TEXT PRIMARY KEY, payload_sha256 TEXT NOT NULL,
                repository TEXT NOT NULL, head_ref TEXT NOT NULL, binding TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('RESERVED','PUBLISHED','UNCERTAIN','REJECTED')),
                reserved_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)""")
            conn.execute("""CREATE UNIQUE INDEX IF NOT EXISTS one_active_head
                ON admissions(repository,head_ref)
                WHERE state IN ('RESERVED','UNCERTAIN','PUBLISHED')""")

    @staticmethod
    def check_file(info) -> None:
        ensure(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "UNTRUSTED_LEDGER_PATH")
        if hasattr(os, "geteuid"):
            ensure(info.st_uid == os.geteuid() and not info.st_mode & 0o077,
                   "UNTRUSTED_LEDGER_PERMISSIONS")

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute("PRAGMA synchronous=FULL")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def reserve(self, request_id: str, payload_sha256: str, binding: dict,
                *, now: int, expires_at: int) -> None:
        digest(request_id, 64, "INVALID_REQUEST_ID")
        digest(payload_sha256, 64, "INVALID_PAYLOAD_DIGEST")
        ensure(type(now) is int and type(expires_at) is int and now < expires_at,
               "APPROVAL_EXPIRED")
        try:
            with self.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("INSERT INTO admissions VALUES(?,?,?,?,?,'RESERVED',?,?)",
                    (request_id, payload_sha256, binding["repository"], binding["head_ref"],
                     canonical(binding).decode(), now, expires_at))
        except sqlite3.IntegrityError as exc:
            raise BootstrapDenied("REQUEST_ALREADY_CONSUMED_OR_HEAD_RESERVED") from exc

    def finish(self, request_id: str, payload_sha256: str, state: str) -> None:
        ensure(state in {"PUBLISHED", "UNCERTAIN", "REJECTED"}, "INVALID_LEDGER_TRANSITION")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            updated = conn.execute("""UPDATE admissions SET state=?
                WHERE request_id=? AND payload_sha256=? AND state='RESERVED'""",
                (state, request_id, payload_sha256))
            ensure(updated.rowcount == 1, "LEDGER_FENCE_MISMATCH")

    def state(self, request_id: str) -> str | None:
        with self.connect() as conn:
            row = conn.execute("SELECT state FROM admissions WHERE request_id=?", (request_id,)).fetchone()
            return row[0] if row else None

    def snapshot(self, now: int) -> dict:
        with self.connect() as conn:
            rows = conn.execute("SELECT request_id FROM admissions ORDER BY reserved_at DESC LIMIT 10001").fetchall()
        ensure(len(rows) <= 10000, "REPLAY_SNAPSHOT_CAPACITY")
        return {"schema": "codestra.prepublication-state.v1", "observed_at": now,
                "consumed_request_ids": [r[0] for r in rows]}


def publish_review(envelope: bytes, policy: dict, payload: dict, protocol: dict,
                   ledger: ReplayLedger, backend: GitRefTransaction,
                   read_report: Callable[[str], bytes], *, clock=time.time,
                   reload_authority: Callable[[], tuple[dict, dict]] | None = None) -> dict:
    verify_protocol(protocol)
    now = int(clock())
    verdict = verify_review_evidence(envelope, policy, ledger.snapshot(now), now=now)
    ensure(hashlib.sha256(canonical(payload)).hexdigest() == verdict["payload_sha256"],
           "PAYLOAD_BINDING_MISMATCH")
    ensure(verdict["verdict"] == "REVIEW_EVIDENCE_VALID"
           and verdict["certified"] is False and verdict["worker_start_authorized"] is False
           and verdict["publication_authorized"] is False, "WRONG_ADMISSION_VERDICT")
    collect_evidence(policy, payload, backend, read_report, now=now)
    request, payload_hash = verdict["request_id"], verdict["payload_sha256"]
    ledger.reserve(request, payload_hash, verdict["binding"],
                   now=now, expires_at=verdict["expires_at"])
    attempted = False
    try:
        # Re-verify signatures, revocation policy and all timestamps after waiting
        # for the durable nonce transaction. No effect can use expired evidence.
        fresh = int(clock())
        fresh_policy, fresh_protocol = reload_authority() if reload_authority else (policy, protocol)
        verify_protocol(fresh_protocol)
        ensure(fresh_policy == policy and fresh_protocol == protocol, "AUTHORITY_CHANGED")
        verify_review_evidence(envelope, fresh_policy,
            {"schema": "codestra.prepublication-state.v1", "observed_at": fresh,
             "consumed_request_ids": []}, now=fresh)
        ensure(fresh < verdict["expires_at"], "APPROVAL_EXPIRED")
        collect_evidence(policy, payload, backend, read_report, now=fresh)
        def final_guard():
            latest_policy, latest_protocol = reload_authority() if reload_authority else (policy, protocol)
            verify_protocol(latest_protocol)
            ensure(latest_policy == policy and latest_protocol == protocol, "AUTHORITY_CHANGED")
            # This follows all signature/object/report I/O and runs while Git
            # holds both ref locks. Signatures already passed twice above.
            current = clock()
            limit = min(verdict["expires_at"], policy.get("expires_at", verdict["expires_at"]),
                payload.get("lease_expires_at", verdict["expires_at"]),
                payload["observed_at"] + policy["max_age_seconds"] + 1,
                *(check["completed_at"] + policy["max_age_seconds"] + 1 for check in payload["checks"]))
            ensure(current < limit, "APPROVAL_EXPIRED")
            return limit - current
        attempted = True
        backend.create_review(verdict["binding"], before_commit=final_guard)
        ensure(backend.read_ref(verdict["binding"]["head_ref"]) ==
               verdict["binding"]["candidate_sha"], "PUBLICATION_READBACK_MISMATCH")
        ensure(backend.read_ref(verdict["binding"]["target_ref"]) ==
               verdict["binding"]["parent_sha"], "PARENT_MOVED_AFTER_PUBLICATION")
        ledger.finish(request, payload_hash, "PUBLISHED")
    except BaseException:
        # A process death leaves RESERVED. It stays consumed and needs read-only
        # operator reconciliation; never roll it back or retry a write blindly.
        ledger.finish(request, payload_hash, "UNCERTAIN" if attempted else "REJECTED")
        raise
    return {"result": "REVIEW_REF_PUBLISHED", "binding": verdict["binding"],
            "request_id": request, "status_context": ADMISSION_CONTEXT,
            "certified": False, "worker_start_authorized": False,
            "promotion_authorized": False}


def main(argv: list[str] | None = None) -> int:
    """Fixed service-owned configuration. No alternate trust path or GitHub write."""
    import sys
    args = sys.argv[1:] if argv is None else argv
    try:
        ensure(len(args) == 1 and not args[0].startswith("-"),
               "USAGE_EXPECTS_SIGNED_BUNDLE_PATH")
        protocol = load_json(read_document(PROTOCOL_PATH, trusted=True))
        verify_protocol(protocol)
        config = load_json(read_document(BROKER_PATH, trusted=True))
        ensure(type(config) is dict and set(config) == {"schema", "repository", "repository_path", "reports_path"}
               and config["schema"] == "codestra.bootstrap-broker.v1", "INVALID_BROKER_CONFIG")
        # Only an independently installed, service-owned bare repository and
        # artifact directory may back this command.
        for value in (config["repository_path"], config["reports_path"], str(LEDGER_PATH.parent)):
            path = Path(value)
            ensure(path.is_absolute(), "UNTRUSTED_CONFIGURATION_PATH")
            for ancestor in (path, *path.parents):
                info = ancestor.lstat()
                ensure(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                       and not info.st_mode & 0o022 and not ancestor.is_symlink(),
                       "UNTRUSTED_CONFIGURATION_PERMISSIONS")
        policy = load_json(read_document(POLICY_PATH, trusted=True))
        ensure(config["repository"] == policy["binding"]["repository"], "REPOSITORY_IDENTITY_MISMATCH")
        # The privileged installer owns the entire bare repository, not merely
        # its top-level directory. Reject writable or symlinked descendants.
        for parent, directories, files in os.walk(config["repository_path"], followlinks=False):
            for name in directories + files:
                info = (Path(parent) / name).lstat()
                ensure(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0
                       and not info.st_mode & 0o022, "UNTRUSTED_REPOSITORY_PERMISSIONS")
        raw = read_document(Path(args[0]), trusted=False)
        envelope = load_json(raw)
        payload = load_json(decode(envelope["payload"], None, "INVALID_PAYLOAD_ENCODING"))
        def read_report(receipt):
            return read_document(Path(config["reports_path"]) / (receipt + ".json"), trusted=True)
        def reload_authority():
            return (load_json(read_document(POLICY_PATH, trusted=True)),
                    load_json(read_document(PROTOCOL_PATH, trusted=True)))
        result = publish_review(raw, policy, payload, protocol, ReplayLedger(LEDGER_PATH),
                               GitRefTransaction(Path(config["repository_path"]), config["repository"]), read_report,
                               reload_authority=reload_authority)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (AdmissionDenied, OSError, sqlite3.Error, subprocess.SubprocessError,
            KeyError, TypeError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, AdmissionDenied) else "REQUIRED_EVIDENCE_UNAVAILABLE"
        print(json.dumps({"result": "BLOCKED", "reason": reason, "certified": False,
                          "worker_start_authorized": False, "promotion_authorized": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
