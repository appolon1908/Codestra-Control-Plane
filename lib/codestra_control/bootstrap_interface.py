"""Inactive bootstrap inspection seam. No production verifier or effect adapter.

Attestations are internal verifier output, not authenticated by constructing these
Python objects. The independently administered verifier must acquire genuine
operator authorization, assignment-backed owned lease and eligible independent
review, including freshness and accepted route policy. No JSON receipt ingestion,
policy exception, status publication or Git/DB operation is provided here.
"""
from dataclasses import dataclass
import re
from typing import Callable


@dataclass(frozen=True)
class BootstrapRequest:
    repository: str
    product: str
    source_ref: str
    target_ref: str
    source_sha: str
    target_base_sha: str
    assignment_id: str
    owner_principal: str


@dataclass(frozen=True)
class Attestation:
    binding: BootstrapRequest
    kind: str
    receipt_id: str


@dataclass(frozen=True)
class VerifiedAuthorization:
    operator_grant: Attestation
    owned_lease: Attestation
    independent_review: Attestation


@dataclass(frozen=True)
class BootstrapInspection:
    reason: str
    bindings_validated: bool = False
    authority: bool = False
    ready: bool = False


def _valid_request(request: BootstrapRequest) -> bool:
    if type(request) is not BootstrapRequest:
        return False
    for field in request.__dataclass_fields__:
        value = getattr(request, field)
        if type(value) is not str or not value or len(value) > 512 or any(c.isspace() or ord(c) < 32 for c in value):
            return False
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', request.repository):
        return False
    for sha in (request.source_sha, request.target_base_sha):
        if not re.fullmatch(r'[0-9a-f]{40}', sha) or sha == '0' * 40:
            return False
    for ref in (request.source_ref, request.target_ref):
        if (not re.fullmatch(r'[A-Za-z0-9_/-]+(?:[.][A-Za-z0-9_/-]+)*', ref)
                or ref.startswith('/') or ref.endswith('/') or '//' in ref
                or any(part.startswith('.') or part.endswith('.lock') for part in ref.split('/'))):
            return False
    return request.source_ref != request.target_ref


def inspect_bootstrap(
    request: BootstrapRequest,
    verifier: Callable[[BootstrapRequest], VerifiedAuthorization | None] | None = None,
) -> BootstrapInspection:
    """Inspect bindings for tests/review only; never authorize bootstrap.

    The optional verifier is an in-process dependency for synthetic tests and
    future separately reviewed integration. Its output is not a transferable
    certificate. Accepted routes and approval eligibility are its responsibility;
    this module defines no replacement policy. Even valid output stays inactive.
    """
    if not _valid_request(request):
        return BootstrapInspection('INVALID_REQUEST')
    if verifier is None:
        return BootstrapInspection('VERIFIER_UNAVAILABLE')
    try:
        authorization = verifier(request)
    except Exception:
        return BootstrapInspection('VERIFIER_FAILED')
    if type(authorization) is not VerifiedAuthorization:
        return BootstrapInspection('AUTHORIZATION_UNAVAILABLE')
    for kind in ('operator_grant', 'owned_lease', 'independent_review'):
        receipt = getattr(authorization, kind)
        if (type(receipt) is not Attestation or not _valid_request(receipt.binding)
                or receipt.binding != request
                or type(receipt.kind) is not str or receipt.kind != kind
                or type(receipt.receipt_id) is not str
                or not receipt.receipt_id.strip() or len(receipt.receipt_id) > 512):
            return BootstrapInspection('ATTESTATION_MISMATCH')
    return BootstrapInspection('INACTIVE_INTERFACE', bindings_validated=True)
