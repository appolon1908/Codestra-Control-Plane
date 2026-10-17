"""Privileged accepted-provenance port. No production issuer/policy is supplied.

Only an independently accepted internal verifier may return this contract. Types,
JSON, source labels and nonempty receipt strings do not authenticate themselves.
This module provides no CLI, author ingestion, issuer selection or trust bootstrap.
"""
from dataclasses import dataclass
from datetime import datetime
from .publisher_adapter import require,binding_digest,CONTEXTS

@dataclass(frozen=True)
class VerifiedProducerContract:
    binding_hash:str
    repository_id:int
    pr_number:int
    publisher_app_id:int
    certificate_app_id:int
    certificate_name:str
    controller_contexts:tuple[str,...]
    receipt_ref:str
    expires_at:datetime
    purpose:str


def verify_contract(verifier,acquired,now):
    require(verifier is not None,'PUBLISHER_PROVENANCE_UNCONFIGURED')
    value=verifier.verify(acquired,now)
    require(type(value) is VerifiedProducerContract,'PUBLISHER_PROVENANCE_UNVERIFIED')
    require(all(type(v) is int and v>0 for v in (value.repository_id,value.pr_number,value.publisher_app_id,value.certificate_app_id)),
            'INVALID_PROVENANCE_IDENTITIES')
    require(value.binding_hash==binding_digest(acquired.snapshot.observed_binding)
            and value.repository_id==acquired.repository_id and value.pr_number==acquired.pr_number
            and value.publisher_app_id==acquired.authority.app_id
            and value.certificate_app_id==acquired.issuer.app_id
            and value.certificate_name==acquired.issuer.name
            and value.publisher_app_id!=value.certificate_app_id,'PUBLISHER_PROVENANCE_BINDING_MISMATCH')
    ordinary={v.producer for v in acquired.snapshot.required_checks}
    require('github-actions:'+str(value.certificate_app_id) not in ordinary
            and 'github-actions:'+str(value.publisher_app_id) not in ordinary,
            'INDEPENDENT_PROVENANCE_ISSUER_REQUIRED')
    require(value.purpose=='STATUS_PUBLICATION','PROVENANCE_CANNOT_AUTHORIZE_REF_CREATION')
    require(type(value.controller_contexts) is tuple and bool(value.controller_contexts)
            and all(type(name) is str for name in value.controller_contexts)
            and len(set(value.controller_contexts))==len(value.controller_contexts)
            and set(value.controller_contexts)<=set(CONTEXTS),'INVALID_CONTROLLER_PROVENANCE_CONTEXTS')
    require(type(value.receipt_ref) is str and bool(value.receipt_ref.strip()),'PROVENANCE_RECEIPT_UNAVAILABLE')
    require(type(value.expires_at) is datetime and value.expires_at.tzinfo is not None
            and now<value.expires_at<=min(acquired.authority.expires_at,acquired.issuer.expires_at),
            'PUBLISHER_PROVENANCE_EXPIRED_OR_UNBOUNDED')
    return value
