"""Authenticate review-admission evidence before a new Git ref exists.

This component does NOT publish a ref/status, create a certificate, consume an
admission, or authorize execution. The existing promotion checker is unchanged.
Trust policy and replay state MUST come from the independently administered
control plane, never from the candidate or its author. Signer attestations are
verified here; their source tests are not re-executed by this component.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any

DOMAIN = b"CODESTRA-PREPUBLICATION-REVIEW-V1\x00"
MAX_BYTES = 262144
OPENSSL = "/usr/bin/openssl"
POLICY_PATH = Path("/etc/codestra/control-plane/prepublication-review-policy.json")
STATE_PATH = Path("/var/lib/codestra/control-plane/prepublication-review-state.json")
ROLES = {"operator", "security", "validator"}
BINDING_FIELDS = {"repository", "head_ref", "target_ref", "parent_sha", "candidate_sha", "tree_sha", "lease_id", "owner_principal"}
PAYLOAD_FIELDS = {"schema", "purpose", "binding", "request_id", "author_principal", "issued_at", "expires_at", "lease_expires_at", "observed_at", "observed_parent_sha", "observed_tree_sha", "head_absent", "clean_source", "governance_unchanged", "safety_denied", "production_go", "live_capabilities_enabled", "external_effects", "checks"}
POLICY_FIELDS = {"schema", "enabled", "binding", "request_id", "expires_at", "max_age_seconds", "max_ttl_seconds", "required_checks", "signers"}
CHECK_FIELDS = {"name", "producer_principal", "receipt_id", "source_sha", "tree_sha", "conclusion", "completed_at", "report_sha256"}


class AdmissionDenied(ValueError):
    """A structured fail-closed result; messages contain no supplied secrets."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise AdmissionDenied(code)


def object_fields(value: Any, fields: set[str], code: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == fields, code)
    return value


def bounded_int(value: Any, low: int, high: int, code: str) -> int:
    require(type(value) is int and low <= value <= high, code)
    return value


def text(value: Any, code: str) -> str:
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value) is not None, code)
    return value


def digest(value: Any, length: int, code: str) -> str:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(length) + r"}", value) is not None and value != "0" * length, code)
    return value


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise AdmissionDenied("INVALID_JSON_VALUE") from exc


def load_json(raw: bytes) -> Any:
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, "INVALID_DOCUMENT_SIZE")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    def reject_constant(_: str) -> None:
        raise AdmissionDenied("INVALID_JSON_NUMBER")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject_constant)
    except AdmissionDenied:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise AdmissionDenied("INVALID_JSON") from exc


def decode(value: Any, size: int | None, code: str) -> bytes:
    require(type(value) is str and len(value) <= MAX_BYTES, code)
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AdmissionDenied(code) from exc
    require(base64.b64encode(raw).decode("ascii") == value, code)
    require(len(raw) == size if size is not None else 0 < len(raw) <= MAX_BYTES, code)
    return raw


def verify_signature(public_key: bytes, signature: bytes, payload: bytes) -> None:
    # RFC 8410 Ed25519 SubjectPublicKeyInfo. Only 32-byte Ed25519 public keys
    # and 64-byte signatures reach this helper; no PEM/private-key fallback.
    der = bytes.fromhex("302a300506032b6570032100") + public_key
    try:
        with tempfile.TemporaryDirectory(prefix="codestra-review-verify-") as directory:
            root = Path(directory)
            (root / "public.der").write_bytes(der)
            (root / "signature").write_bytes(signature)
            (root / "payload").write_bytes(DOMAIN + payload)
            result = subprocess.run(
                [OPENSSL, "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", str(root / "public.der"), "-rawin", "-in", str(root / "payload"), "-sigfile", str(root / "signature")],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
                env={"PATH": "/usr/bin:/bin", "OPENSSL_CONF": "/dev/null", "LC_ALL": "C"},
            )
            require(result.returncode == 0, "INVALID_SIGNATURE")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdmissionDenied("SIGNATURE_VERIFIER_UNAVAILABLE") from exc


def verify_binding(binding: Any) -> dict[str, Any]:
    binding = object_fields(binding, BINDING_FIELDS, "INVALID_BINDING")
    repository = binding["repository"]
    require(type(repository) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository) is not None, "INVALID_REPOSITORY")
    head, target = binding["head_ref"], binding["target_ref"]
    require(type(head) is str and type(target) is str, "INVALID_REF")
    match = re.fullmatch(r"subsection/([a-z0-9]+(?:-[a-z0-9]+)*)--([a-z0-9]+(?:-[a-z0-9]+)*)", head)
    require(match is not None and target == "section/" + match.group(1), "INVALID_REVIEW_LANE")
    for key in ("parent_sha", "candidate_sha", "tree_sha"):
        digest(binding[key], 40, "INVALID_SOURCE_SHA")
    text(binding["lease_id"], "INVALID_LEASE")
    text(binding["owner_principal"], "INVALID_OWNER")
    return binding


def verify_review_evidence(envelope_bytes: bytes, policy: dict[str, Any], replay_state: dict[str, Any], *, now: int) -> dict[str, Any]:
    """Verify scoped, three-party signed evidence; return NO execution authority.

    policy and replay_state are trusted inputs supplied by the administrator-
    controlled adapter. The CLI below uses fixed root-owned paths. In-memory
    test policies do not establish any real person's identity or approval.
    """
    bounded_int(now, 1, 2**63 - 1, "INVALID_CLOCK")
    object_fields(policy, POLICY_FIELDS, "INVALID_TRUST_POLICY")
    require(policy["schema"] == "codestra.prepublication-policy.v1" and policy["enabled"] is True, "POLICY_NOT_ENABLED")
    binding = verify_binding(policy["binding"])
    nonce = digest(policy["request_id"], 64, "INVALID_REQUEST_ID")
    policy_expiry = bounded_int(policy["expires_at"], now + 1, 2**63 - 1, "POLICY_EXPIRED")
    max_age = bounded_int(policy["max_age_seconds"], 1, 300, "INVALID_MAX_AGE")
    max_ttl = bounded_int(policy["max_ttl_seconds"], 1, 3600, "INVALID_MAX_TTL")
    names = policy["required_checks"]
    require(type(names) is list and 1 <= len(names) <= 32, "INVALID_REQUIRED_CHECKS")
    for name in names:
        text(name, "INVALID_REQUIRED_CHECK")
    require(len(set(names)) == len(names), "DUPLICATE_REQUIRED_CHECK")

    object_fields(replay_state, {"schema", "observed_at", "consumed_request_ids"}, "INVALID_REPLAY_STATE")
    require(replay_state["schema"] == "codestra.prepublication-state.v1", "INVALID_REPLAY_STATE")
    bounded_int(replay_state["observed_at"], max(1, now - max_age), now, "STALE_REPLAY_STATE")
    used = replay_state["consumed_request_ids"]
    require(type(used) is list and len(used) <= 10000, "INVALID_REPLAY_STATE")
    for item in used:
        digest(item, 64, "INVALID_REPLAY_STATE")
    require(len(set(used)) == len(used), "INVALID_REPLAY_STATE")
    require(nonce not in used, "REQUEST_ALREADY_CONSUMED")

    envelope = object_fields(load_json(envelope_bytes), {"payload", "signatures"}, "INVALID_ENVELOPE")
    raw = decode(envelope["payload"], None, "INVALID_PAYLOAD_ENCODING")
    payload = object_fields(load_json(raw), PAYLOAD_FIELDS, "INVALID_PAYLOAD")
    require(raw == canonical(payload), "NONCANONICAL_PAYLOAD")
    require(payload["schema"] == "codestra.prepublication-review.v1" and payload["purpose"] == "REVIEW_ONLY", "WRONG_PURPOSE")
    verify_binding(payload["binding"])
    require(payload["binding"] == binding and payload["request_id"] == nonce, "WRONG_SCOPE")
    require(payload["author_principal"] == binding["owner_principal"], "WRONG_OWNER")
    issued = bounded_int(payload["issued_at"], max(1, now - max_ttl), now, "INVALID_ISSUED_AT")
    expiry = bounded_int(payload["expires_at"], now + 1, min(policy_expiry, issued + max_ttl), "INVALID_EXPIRY")
    bounded_int(payload["lease_expires_at"], expiry, 2**63 - 1, "LEASE_EXPIRED")
    observed = bounded_int(payload["observed_at"], max(issued, now - max_age), now, "STALE_OBSERVATION")
    require(payload["observed_parent_sha"] == binding["parent_sha"] and payload["observed_tree_sha"] == binding["tree_sha"], "SOURCE_OBSERVATION_MISMATCH")
    for key in ("head_absent", "clean_source", "governance_unchanged"):
        require(payload[key] is True, "SOURCE_NOT_ADMISSIBLE")
    for key in ("safety_denied", "production_go", "live_capabilities_enabled", "external_effects"):
        require(payload[key] is False, "SAFETY_NOT_PROVEN")

    signers = policy["signers"]
    require(type(signers) is list and len(signers) == 3, "INVALID_SIGNER_POLICY")
    by_id: dict[str, dict[str, Any]] = {}
    principals, public_keys, roles = set(), set(), set()
    for signer in signers:
        object_fields(signer, {"key_id", "role", "principal", "public_key"}, "INVALID_SIGNER_POLICY")
        key_id = text(signer["key_id"], "INVALID_KEY_ID")
        role = text(signer["role"], "INVALID_ROLE")
        principal = text(signer["principal"], "INVALID_PRINCIPAL")
        public_key = decode(signer["public_key"], 32, "INVALID_PUBLIC_KEY")
        require(role in ROLES and role not in roles and key_id not in by_id, "DUPLICATE_SIGNER")
        require(principal not in principals and public_key not in public_keys, "SIGNERS_NOT_INDEPENDENT")
        if role != "operator":
            require(principal != payload["author_principal"], "AUTHOR_CANNOT_APPROVE")
        by_id[key_id] = signer
        principals.add(principal)
        public_keys.add(public_key)
        roles.add(role)
    require(roles == ROLES, "MISSING_SIGNER_ROLE")
    validator = next(s["principal"] for s in signers if s["role"] == "validator")

    checks = payload["checks"]
    require(type(checks) is list and len(checks) == len(names), "INCOMPLETE_CHECKS")
    seen_names, receipts = set(), set()
    for check in checks:
        object_fields(check, CHECK_FIELDS, "INVALID_CHECK")
        name = text(check["name"], "INVALID_CHECK")
        receipt = text(check["receipt_id"], "INVALID_RECEIPT")
        require(name in names and name not in seen_names and receipt not in receipts, "DUPLICATE_OR_UNKNOWN_CHECK")
        require(check["producer_principal"] == validator and check["conclusion"] == "passed", "CHECK_NOT_PASSED_BY_VALIDATOR")
        require(check["source_sha"] == binding["candidate_sha"] and check["tree_sha"] == binding["tree_sha"], "CHECK_SOURCE_MISMATCH")
        bounded_int(check["completed_at"], max(issued, now - max_age), observed, "STALE_CHECK")
        digest(check["report_sha256"], 64, "INVALID_REPORT_DIGEST")
        seen_names.add(name)
        receipts.add(receipt)
    require(seen_names == set(names), "INCOMPLETE_CHECKS")

    signatures = envelope["signatures"]
    require(type(signatures) is list and len(signatures) == 3, "MISSING_SIGNATURES")
    verified = set()
    for signed in signatures:
        object_fields(signed, {"key_id", "signature"}, "INVALID_SIGNATURE_RECORD")
        key_id = text(signed["key_id"], "INVALID_KEY_ID")
        require(key_id in by_id and key_id not in verified, "UNKNOWN_OR_DUPLICATE_SIGNATURE")
        verify_signature(decode(by_id[key_id]["public_key"], 32, "INVALID_PUBLIC_KEY"), decode(signed["signature"], 64, "INVALID_SIGNATURE_ENCODING"), raw)
        verified.add(key_id)

    return {"verdict": "REVIEW_EVIDENCE_VALID", "binding": dict(binding), "request_id": nonce, "payload_sha256": hashlib.sha256(raw).hexdigest(), "expires_at": expiry, "publication_authorized": False, "certified": False, "worker_start_authorized": False}


def read_document(path: Path, *, trusted: bool) -> bytes:
    """Bounded regular-file read; trusted files and ancestors are root-owned."""
    if trusted:
        require(path.is_absolute(), "UNTRUSTED_CONFIGURATION_PATH")
        for current in (path, *path.parents):
            info = current.lstat()
            require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not (info.st_mode & 0o022), "UNTRUSTED_CONFIGURATION_PERMISSIONS")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        require(stat.S_ISREG(os.fstat(handle.fileno()).st_mode), "NOT_REGULAR_FILE")
        raw = handle.read(MAX_BYTES + 1)
    require(0 < len(raw) <= MAX_BYTES, "INVALID_DOCUMENT_SIZE")
    return raw


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    try:
        require(len(args) == 1 and not args[0].startswith("-"), "USAGE_EXPECTS_SIGNED_BUNDLE_PATH")
        policy = load_json(read_document(POLICY_PATH, trusted=True))
        replay = load_json(read_document(STATE_PATH, trusted=True))
        result = verify_review_evidence(read_document(Path(args[0]), trusted=False), policy, replay, now=int(time.time()))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (AdmissionDenied, OSError) as exc:
        reason = str(exc) if isinstance(exc, AdmissionDenied) else "REQUIRED_EVIDENCE_UNAVAILABLE"
        print(json.dumps({"verdict": "BLOCKED", "reason": reason, "publication_authorized": False, "certified": False, "worker_start_authorized": False}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
