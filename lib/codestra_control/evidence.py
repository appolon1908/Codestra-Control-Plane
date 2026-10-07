"""Internal immutable evidence contract, NOT a JSON ingestion or trust mechanism.

A privileged adapter must independently retrieve and authenticate registry,
GitHub, lease and certificate evidence before constructing a TrustedSnapshot.
The adapter must finish every page, normalize review/check attempts, validate
receipt provenance, and stamp current observation/evaluation times. No such
runtime adapter is installed by this source-preparation change.

Python object types, producer names and receipt IDs do not authenticate their
contents. Never expose construction of these objects to a PR author or turn
legacy PASS rows into this interface. Unit fixtures intentionally bypass the
not-yet-implemented acquisition boundary to test only pure decision behavior.
"""

from dataclasses import dataclass
from datetime import datetime
from .policy import ProductMapping


@dataclass(frozen=True)
class PromotionRequest:
    repository: str
    product: str
    source_ref: str
    target_ref: str
    source_sha: str
    target_base_sha: str


@dataclass(frozen=True)
class RequiredCheck:
    name: str
    producer: str


@dataclass(frozen=True)
class CheckEvidence:
    binding: PromotionRequest
    name: str
    producer: str
    status: str
    conclusion: str | None
    evidence_id: str


@dataclass(frozen=True)
class ReviewEvidence:
    binding: PromotionRequest
    reviewer: str
    state: str
    evidence_id: str
    codeowner: bool
    eligible: bool


@dataclass(frozen=True)
class ScopeCertificate:
    binding: PromotionRequest
    scope_type: str
    status: str
    certified_sha: str
    remote_sha: str
    receipt_id: str


@dataclass(frozen=True)
class LeaseEvidence:
    binding: PromotionRequest
    owner: str
    expected_owner: str
    state: str
    expires_at: datetime
    assignment_id: str


@dataclass(frozen=True)
class TrustedSnapshot:
    mapping: ProductMapping
    observed_binding: PromotionRequest
    observed_at: datetime
    evaluated_at: datetime
    required_checks: tuple[RequiredCheck, ...]
    checks: tuple[CheckEvidence, ...]
    reviews: tuple[ReviewEvidence, ...]
    author: str
    last_pusher: str
    unresolved_threads: int | None
    review_inventory_complete: bool
    check_inventory_complete: bool
    require_codeowner: bool
    required_approvals: int
    certificate: ScopeCertificate | None
    dependencies_complete: bool
    dependencies_certified: bool
    lease: LeaseEvidence | None
    production_go: bool
    live_capabilities_enabled: bool
    external_effects_enabled: bool
