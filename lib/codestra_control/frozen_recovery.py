"""Inactive frozen-lane recovery inspection; no lease or certification effects.

Requests and attestations are internal objects, not authenticated by constructing
or deserializing them. A separately administered verifier must observe genuine
operator authority, independent review, the exact frozen incident, repaired
worktree/Git identity, revocation and durable one-use evidence. No such production
adapter is supplied here. Even a successful fixture inspection stays inactive.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import posixpath
import re
from typing import Callable


@dataclass(frozen=True)
class FrozenRecoveryRequest:
    repository: str
    product: str
    workstation_id: str
    task_id: str
    previous_owner: str
    worktree: str
    branch: str
    target_branch: str
    head_sha: str
    remote_sha: str
    frozen_snapshot_id: str
    freeze_incident_id: str
    repair_evidence_id: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class RecoveryAttestation:
    binding: FrozenRecoveryRequest
    kind: str
    receipt_id: str


@dataclass(frozen=True)
class VerifiedRecovery:
    operator_grant: RecoveryAttestation
    independent_review: RecoveryAttestation
    frozen_state: RecoveryAttestation
    repaired_worktree: RecoveryAttestation
    replay_fence: RecoveryAttestation


@dataclass(frozen=True)
class FrozenRecoveryInspection:
    reason: str
    bindings_validated: bool = False
    authority: bool = False
    ready: bool = False
    released: bool = False


def _token(value):
    return (type(value) is str and 0 < len(value) <= 512
            and all(c.isprintable() and not c.isspace() for c in value))


def _aware(value):
    return (type(value) is datetime and value.tzinfo is not None
            and value.utcoffset() is not None)


def _utc(value):
    return value.astimezone(timezone.utc)


def _same_binding(left, right):
    try:
        return all(
            _utc(getattr(left, name)) == _utc(getattr(right, name))
            if name in ('issued_at', 'expires_at')
            else getattr(left, name) == getattr(right, name)
            for name in FrozenRecoveryRequest.__dataclass_fields__
        )
    except Exception:
        return False


def _ref(value):
    return (re.fullmatch(r'[A-Za-z0-9_/-]+(?:[.][A-Za-z0-9_/-]+)*', value)
            and not value.startswith('/') and not value.endswith('/')
            and '//' not in value
            and not any(p.startswith('.') or p.endswith('.lock') for p in value.split('/')))


def _valid_request(request):
    if type(request) is not FrozenRecoveryRequest:
        return False
    try:
        for name in request.__dataclass_fields__:
            if name not in ('issued_at', 'expires_at') and not _token(getattr(request, name)):
                return False
        owner, _, repo = request.repository.partition('/')
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*', owner)
                or not re.fullmatch(r'[A-Za-z0-9_.-]+', repo) or repo in ('.', '..')):
            return False
        if (not request.worktree.startswith('/') or request.worktree.startswith('//')
                or posixpath.normpath(request.worktree) != request.worktree):
            return False
        if (not _ref(request.branch) or not _ref(request.target_branch)
                or request.branch == request.target_branch):
            return False
        if (not re.fullmatch(r'[0-9a-f]{40}', request.head_sha)
                or request.head_sha == '0' * 40 or request.head_sha != request.remote_sha):
            return False
        return (_aware(request.issued_at) and _aware(request.expires_at)
                and _utc(request.issued_at) < _utc(request.expires_at))
    except Exception:
        return False


def inspect_frozen_recovery(
    request: FrozenRecoveryRequest,
    verifier: Callable[[FrozenRecoveryRequest], VerifiedRecovery | None] | None = None,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> FrozenRecoveryInspection:
    """Inspect exact bindings for source tests/review; never authorize recovery.

    Only independently administered in-process adapters may supply verifier and
    clock. They are not request parameters for an external API. The verifier owns
    authentication and policy eligibility; this module defines no grant issuer,
    replacement review policy, database revision scheme or lease transition.
    A later executor must revalidate everything atomically before any effect.
    """
    if not _valid_request(request):
        return FrozenRecoveryInspection('INVALID_REQUEST')

    def validity():
        try:
            now = clock()
            if not _aware(now):
                return 'CLOCK_UNAVAILABLE'
            if not _utc(request.issued_at) <= _utc(now) < _utc(request.expires_at):
                return 'OUTSIDE_VALIDITY_WINDOW'
        except Exception:
            return 'CLOCK_UNAVAILABLE'
        return None

    reason = validity()
    if reason:
        return FrozenRecoveryInspection(reason)
    if verifier is None:
        return FrozenRecoveryInspection('VERIFIER_UNAVAILABLE')
    try:
        authorization = verifier(request)
    except Exception:
        return FrozenRecoveryInspection('VERIFIER_FAILED')
    if type(authorization) is not VerifiedRecovery:
        return FrozenRecoveryInspection('AUTHORIZATION_UNAVAILABLE')
    receipts = set()
    for kind in VerifiedRecovery.__dataclass_fields__:
        receipt = getattr(authorization, kind)
        if (type(receipt) is not RecoveryAttestation
                or not _valid_request(receipt.binding) or not _same_binding(receipt.binding, request)
                or type(receipt.kind) is not str or receipt.kind != kind
                or not _token(receipt.receipt_id) or receipt.receipt_id in receipts):
            return FrozenRecoveryInspection('ATTESTATION_MISMATCH')
        receipts.add(receipt.receipt_id)
    reason = validity()
    if reason:
        return FrozenRecoveryInspection(reason)
    return FrozenRecoveryInspection('INACTIVE_RECOVERY_INTERFACE', bindings_validated=True)
