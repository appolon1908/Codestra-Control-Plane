"""Pure promotion evaluation. This module never certifies, publishes or merges."""

from dataclasses import dataclass
from datetime import datetime, timedelta
import re

from .evidence import (CheckEvidence, LeaseEvidence, PromotionRequest, RequiredCheck,
                       ReviewEvidence, ScopeCertificate, TrustedSnapshot)
from .policy import PolicyError, resolve_edge


MAX_SNAPSHOT_AGE = timedelta(minutes=5)
CONTROL_PLANE_CONTEXTS = frozenset({"codestra-control-plane", "codestra/control-plane", "promotion-gate"})


@dataclass(frozen=True)
class Decision:
    allowed: bool
    operation_kind: str
    reasons: tuple[str, ...]


def _result(reasons):
    return Decision(not reasons, "PROMOTION", tuple(dict.fromkeys(reasons)))


def _aware(value):
    return isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None


def _strings(*values):
    return all(type(value) is str and bool(value.strip()) for value in values)


def _binding_shape(value):
    return type(value) is PromotionRequest and _strings(
        value.repository, value.product, value.source_ref, value.target_ref,
        value.source_sha, value.target_base_sha)


def _snapshot_shape(snapshot):
    if not _binding_shape(snapshot.observed_binding) or not _strings(snapshot.author, snapshot.last_pusher):
        return False
    for name in ("review_inventory_complete", "check_inventory_complete", "require_codeowner",
                 "dependencies_complete", "dependencies_certified", "production_go",
                 "live_capabilities_enabled", "external_effects_enabled"):
        if type(getattr(snapshot, name)) is not bool:
            return False
    if type(snapshot.required_approvals) is not int or snapshot.required_approvals < 1:
        return False
    if snapshot.unresolved_threads is not None and (type(snapshot.unresolved_threads) is not int or snapshot.unresolved_threads < 0):
        return False
    for collection, kind in ((snapshot.required_checks, RequiredCheck),
                             (snapshot.checks, CheckEvidence), (snapshot.reviews, ReviewEvidence)):
        if type(collection) is not tuple or any(type(item) is not kind for item in collection):
            return False
    for check in snapshot.required_checks:
        if not _strings(check.name, check.producer):
            return False
    for check in snapshot.checks:
        if (not _binding_shape(check.binding) or not _strings(check.name, check.producer, check.status, check.evidence_id)
                or (check.conclusion is not None and type(check.conclusion) is not str)):
            return False
    for review in snapshot.reviews:
        if (not _binding_shape(review.binding) or not _strings(review.reviewer, review.state, review.evidence_id)
                or type(review.codeowner) is not bool or type(review.eligible) is not bool):
            return False
    cert = snapshot.certificate
    if cert is not None and (type(cert) is not ScopeCertificate or not _binding_shape(cert.binding)
                            or not _strings(cert.scope_type, cert.status, cert.certified_sha, cert.remote_sha)
                            or type(cert.receipt_id) is not str):
        return False
    lease = snapshot.lease
    if lease is not None and (type(lease) is not LeaseEvidence or not _binding_shape(lease.binding)
                             or not _strings(lease.owner, lease.expected_owner, lease.state, lease.assignment_id)):
        return False
    return True


def evaluate_promotion(request: PromotionRequest, snapshot: TrustedSnapshot) -> Decision:
    """Evaluate only an internal snapshot; an allowed result is not a certificate.

The future trusted adapter must prevent authors from choosing snapshot contents.
Immediately before effects, callers must re-read both refs and renew evidence if
either changes. Evaluating an old object again cannot establish current truth.
"""
    if not _binding_shape(request):
        return _result(["INVALID_REQUEST"])
    if type(snapshot) is not TrustedSnapshot:
        return _result(["UNTRUSTED_SNAPSHOT_TYPE"])
    if not _snapshot_shape(snapshot):
        return _result(["MALFORMED_SNAPSHOT"])
    reasons = []
    if any(re.fullmatch(r"[0-9a-f]{40}", sha) is None for sha in (request.source_sha, request.target_base_sha)):
        reasons.append("INVALID_EXACT_SHA")
    try:
        source_level, _ = resolve_edge(snapshot.mapping, request.source_ref, request.target_ref)
    except PolicyError as exc:
        return _result(reasons + [str(exc)])
    if (request.repository, request.product) != (snapshot.mapping.repository, snapshot.mapping.product):
        reasons.append("REGISTRY_IDENTITY_MISMATCH")
    if snapshot.observed_binding != request:
        reasons.append("OBSERVED_BINDING_MISMATCH")
    valid_time = _aware(snapshot.observed_at) and _aware(snapshot.evaluated_at)
    if not valid_time or snapshot.observed_at > snapshot.evaluated_at:
        reasons.append("EVIDENCE_TIME_INVALID")
    elif snapshot.evaluated_at - snapshot.observed_at > MAX_SNAPSHOT_AGE:
        reasons.append("EVIDENCE_SNAPSHOT_EXPIRED")

    if not snapshot.check_inventory_complete:
        reasons.append("CHECK_INVENTORY_INCOMPLETE")
    if not snapshot.required_checks:
        reasons.append("REQUIRED_CHECK_INVENTORY_MISSING")
    if len(set(snapshot.required_checks)) != len(snapshot.required_checks):
        reasons.append("DUPLICATE_REQUIRED_CHECK")
    if len({check.evidence_id for check in snapshot.checks}) != len(snapshot.checks):
        reasons.append("DUPLICATE_CHECK_EVIDENCE")
    for requirement in snapshot.required_checks:
        if requirement.name in CONTROL_PLANE_CONTEXTS:
            reasons.append("CIRCULAR_REQUIRED_CHECK")
            continue
        checks = [check for check in snapshot.checks
                  if (check.name, check.producer) == (requirement.name, requirement.producer)]
        if not checks:
            reasons.append("REQUIRED_CHECK_MISSING:" + requirement.name)
        elif len(checks) != 1:
            reasons.append("REQUIRED_CHECK_AMBIGUOUS:" + requirement.name)
        else:
            check = checks[0]
            if check.binding != request:
                reasons.append("CHECK_BINDING_MISMATCH:" + requirement.name)
            if check.status != "completed" or check.conclusion != "success":
                reasons.append("REQUIRED_CHECK_NOT_SUCCESS:" + requirement.name)

    if not snapshot.review_inventory_complete:
        reasons.append("REVIEW_INVENTORY_INCOMPLETE")
    if snapshot.unresolved_threads is None:
        reasons.append("REVIEW_THREADS_UNKNOWN")
    elif snapshot.unresolved_threads:
        reasons.append("UNRESOLVED_REVIEW_THREADS")
    if len({review.evidence_id for review in snapshot.reviews}) != len(snapshot.reviews):
        reasons.append("DUPLICATE_REVIEW_EVIDENCE")
    seen, approved, codeowners = set(), set(), set()
    for review in snapshot.reviews:
        identity = review.reviewer.casefold()
        if identity in seen:
            reasons.append("AMBIGUOUS_REVIEWER_STATE")
        seen.add(identity)
        if review.binding != request:
            reasons.append("REVIEW_BINDING_MISMATCH")
            continue
        if review.state == "CHANGES_REQUESTED":
            reasons.append("CHANGES_REQUESTED")
        elif review.state == "APPROVED":
            if review.eligible and identity not in {snapshot.author.casefold(), snapshot.last_pusher.casefold()}:
                approved.add(identity)
                if review.codeowner:
                    codeowners.add(identity)
        elif review.state not in {"COMMENTED", "DISMISSED", "PENDING"}:
            reasons.append("UNKNOWN_REVIEW_STATE")
    if len(approved) < snapshot.required_approvals:
        reasons.append("INDEPENDENT_APPROVAL_MISSING")
    if snapshot.require_codeowner and not codeowners:
        reasons.append("CODEOWNER_APPROVAL_MISSING")

    cert = snapshot.certificate
    if cert is None:
        reasons.append("SCOPE_CERTIFICATE_MISSING")
    else:
        if cert.binding != request:
            reasons.append("CERTIFICATE_BINDING_MISMATCH")
        if cert.scope_type != source_level.upper():
            reasons.append("CERTIFICATE_SCOPE_MISMATCH")
        if cert.status != "CERTIFIED":
            reasons.append("SCOPE_NOT_CERTIFIED")
        if cert.certified_sha != request.source_sha or cert.remote_sha != request.source_sha:
            reasons.append("CERTIFICATE_SHA_MISMATCH")
        if not cert.receipt_id.strip():
            reasons.append("CERTIFICATE_RECEIPT_MISSING")
    if not snapshot.dependencies_complete:
        reasons.append("DEPENDENCY_INVENTORY_INCOMPLETE")
    if not snapshot.dependencies_certified:
        reasons.append("DEPENDENCIES_NOT_CERTIFIED")
    lease = snapshot.lease
    if lease is None:
        reasons.append("OWNED_ASSIGNMENT_MISSING")
    else:
        if lease.binding != request:
            reasons.append("LEASE_BINDING_MISMATCH")
        if lease.owner != lease.expected_owner:
            reasons.append("LEASE_NOT_OWNED")
        if lease.state != "ACTIVE":
            reasons.append("LEASE_NOT_ACTIVE")
        if not _aware(lease.expires_at) or not valid_time or lease.expires_at <= snapshot.evaluated_at:
            reasons.append("LEASE_EXPIRED")
    if snapshot.production_go or snapshot.live_capabilities_enabled or snapshot.external_effects_enabled:
        reasons.append("PRODUCTION_EFFECT_POLICY_DRIFT")
    return _result(reasons)
