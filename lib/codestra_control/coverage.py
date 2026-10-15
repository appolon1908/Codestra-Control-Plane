"""Inactive per-PR coverage planner. No I/O, publisher or production verifier.

Internal objects are not authenticated receipts by construction. A separately
approved verifier must observe repository IDs, accepted scope, current refs,
assignments, evidence and exclusive publisher ownership. Raw JSON is not trusted.
"""
from collections import Counter
from dataclasses import dataclass, fields
import re
from typing import Callable
from .decision import evaluate_promotion
from .evidence import PromotionRequest, TrustedSnapshot
from .policy import valid_ref


@dataclass(frozen=True)
class CoverageBinding:
    repository_id: int
    pr_number: int
    request_id: str
    assignment_id: str
    owner_principal: str
    promotion: PromotionRequest
    status_context: str
    publisher_principal: str


@dataclass(frozen=True)
class CoverageReceipt:
    binding: CoverageBinding
    kind: str
    receipt_id: str


@dataclass(frozen=True)
class CoverageEvidence:
    binding: CoverageBinding
    snapshot: TrustedSnapshot
    publisher_capability: CoverageReceipt | None = None
    context_ownership: CoverageReceipt | None = None


@dataclass(frozen=True)
class CoverageResult:
    binding: CoverageBinding
    status: str
    reasons: tuple[str, ...]
    authority: bool = False
    publish: bool = False


def _text(value):
    return type(value) is str and 0 < len(value) <= 512 and value.strip() == value and not any(ord(c) < 32 for c in value)


def _valid(binding):
    if type(binding) is not CoverageBinding:
        return False
    if any(type(value) is not int or value <= 0 for value in (binding.repository_id, binding.pr_number)):
        return False
    if not all(_text(value) for value in (binding.request_id, binding.assignment_id, binding.owner_principal, binding.status_context, binding.publisher_principal)):
        return False
    if binding.status_context not in ('codestra-control-plane', 'codestra/control-plane'):
        return False
    request = binding.promotion
    if type(request) is not PromotionRequest or not all(_text(getattr(request, field.name)) for field in fields(PromotionRequest)):
        return False
    return (bool(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', request.repository))
            and all(valid_ref(ref) for ref in (request.source_ref, request.target_ref))
            and all(re.fullmatch(r'[0-9a-f]{40}', sha) and sha != '0' * 40
                    for sha in (request.source_sha, request.target_base_sha)))


def _receipt(receipt, binding, kind):
    return (type(receipt) is CoverageReceipt and _valid(receipt.binding)
            and receipt.binding == binding and type(receipt.kind) is str
            and receipt.kind == kind and _text(receipt.receipt_id))


def _evaluate(binding, verifier):
    def result(status, *reasons):
        return CoverageResult(binding, status, tuple(reasons))
    if not _valid(binding):
        return result('DENIED', 'INVALID_BINDING')
    if verifier is None:
        return result('UNAVAILABLE', 'AUTHENTICATED_VERIFIER_UNAVAILABLE')
    try:
        evidence = verifier(binding)
    except Exception:
        return result('UNAVAILABLE', 'VERIFIER_FAILED')
    if type(evidence) is not CoverageEvidence:
        return result('UNAVAILABLE', 'AUTHENTICATED_EVIDENCE_UNAVAILABLE')
    if not _valid(evidence.binding) or evidence.binding != binding:
        return result('DENIED', 'EVIDENCE_BINDING_MISMATCH')
    if type(evidence.snapshot) is not TrustedSnapshot:
        return result('DENIED', 'UNTRUSTED_SNAPSHOT_TYPE')
    # Existing policy owns route, CI/review/certificate, freshness and lease rules.
    try:
        decision = evaluate_promotion(binding.promotion, evidence.snapshot)
    except Exception:
        return result('UNAVAILABLE', 'EVIDENCE_EVALUATION_FAILED')
    if not decision.allowed:
        return result('DENIED', *decision.reasons)
    lease = evidence.snapshot.lease
    if (lease is None or type(lease.assignment_id) is not str or lease.assignment_id != binding.assignment_id
            or type(lease.owner) is not str or lease.owner != binding.owner_principal):
        return result('DENIED', 'ASSIGNMENT_OWNER_MISMATCH')
    reasons = tuple(kind.upper() + '_UNVERIFIED' for kind in ('publisher_capability', 'context_ownership')
                    if not _receipt(getattr(evidence, kind), binding, kind))
    if reasons:
        return result('UNAVAILABLE', *reasons)
    return result('UNAVAILABLE', 'INACTIVE_PUBLISHER')


def evaluate_coverage(bindings: tuple[CoverageBinding, ...],
                      verifier: Callable[[CoverageBinding], CoverageEvidence | None] | None = None
                      ) -> tuple[CoverageResult, ...]:
    """Return one explicit outcome per supplied PR, never silently filter routes.

    Supplied inventory is not an approved registry or completeness proof. The
    verifier must independently bind accepted scope and evidence. Even fully valid
    synthetic evidence cannot enable effects. No repository allowlist is expanded.
    """
    if type(bindings) is not tuple:
        raise TypeError('coverage inventory must be a tuple')
    counts = Counter((binding.repository_id, binding.pr_number) for binding in bindings if _valid(binding))
    request_counts = Counter((binding.repository_id, binding.request_id) for binding in bindings if _valid(binding))
    return tuple(CoverageResult(binding, 'DENIED', ('DUPLICATE_PR',))
                 if _valid(binding) and counts[(binding.repository_id, binding.pr_number)] != 1
                 else CoverageResult(binding, 'DENIED', ('DUPLICATE_REQUEST_ID',))
                 if _valid(binding) and request_counts[(binding.repository_id, binding.request_id)] != 1
                 else _evaluate(binding, verifier) for binding in bindings)
