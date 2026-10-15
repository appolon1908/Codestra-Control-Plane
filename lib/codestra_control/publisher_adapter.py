"""Privileged source integration. Dependencies are administered, never author inputs.

No production factory or credentials are installed by this module. The default
publisher entrypoint stays unavailable. A successful synthetic test is not trust.
"""
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
from .decision import evaluate_promotion
from .evidence import PromotionRequest, TrustedSnapshot

CONTEXTS=('codestra-control-plane','codestra/control-plane')

class PublicationDenied(RuntimeError):pass

def require(condition,reason):
    if not condition:raise PublicationDenied(reason)

@dataclass(frozen=True)
class Authority:
    authority_name:str
    host:str
    app_id:int
    installation_id:int
    epoch:int
    expires_at:datetime
    custody_receipt:str
    repositories:tuple[str,...]

@dataclass(frozen=True)
class CertificateIssuer:
    app_id:int
    name:str
    binding_hash:str
    capability_receipt:str
    expires_at:datetime
    approved_by:str
    purpose:str

@dataclass(frozen=True)
class Acquired:
    authority:Authority
    snapshot:TrustedSnapshot
    repository_id:int
    pr_number:int
    certificate_check_id:int
    issuer:CertificateIssuer | None = None

@dataclass(frozen=True)
class PublicationResult:
    state:str
    receipts:tuple

def binding_digest(binding):
    return hashlib.sha256(json.dumps(asdict(binding),sort_keys=True,separators=(',',':')).encode()).hexdigest()


def verify_issuer(acquired,now):
    issuer=acquired.issuer
    require(type(issuer) is CertificateIssuer,'CERTIFIER_CAPABILITY_UNAVAILABLE')
    require(type(issuer.app_id) is int and issuer.app_id>0 and issuer.app_id not in (15368,acquired.authority.app_id),'DEDICATED_INDEPENDENT_CERTIFIER_REQUIRED')
    require(issuer.approved_by=='Ralph L. Appolon' and issuer.purpose=='SCOPE_CERTIFICATION'
            and type(issuer.capability_receipt) is str and bool(issuer.capability_receipt.strip()),'CERTIFIER_CAPABILITY_INVALID')
    require(issuer.binding_hash==binding_digest(acquired.snapshot.observed_binding),'CERTIFIER_CAPABILITY_BINDING_MISMATCH')
    require(issuer.expires_at.tzinfo is not None and issuer.expires_at>now,'CERTIFIER_CAPABILITY_EXPIRED')
    from .decision import CONTROL_PLANE_CONTEXTS
    require(type(issuer.name) is str and bool(issuer.name.strip()) and issuer.name not in CONTROL_PLANE_CONTEXTS
            and issuer.name not in {v.name for v in acquired.snapshot.required_checks},'CI_ALIAS_IS_NOT_CERTIFICATION')

class AuthenticatedPublisher:
    """Single-host orchestration with durable intent before any status effect.

    store acquires authenticated operator state; github independently observes
    online receipts, both refs, merge-result and enforced protection. Neither is
    accepted from a PR/request/JSON. Constructors are privileged integration seams.
    """
    def __init__(self,store,github,ledger,*,host,clock=lambda:datetime.now(timezone.utc)):
        self.store,self.github,self.ledger=store,github,ledger
        self.host,self.clock=host,clock
    def _acquire(self,binding):
        require(type(binding) is PromotionRequest,'INVALID_BINDING')
        acquired=self.store.acquire(binding)
        original=acquired
        require(type(acquired) is Acquired and type(acquired.authority) is Authority,'AUTHORITY_UNAVAILABLE')
        authority=acquired.authority;now=self.clock()
        require(authority.authority_name=='Ralph L. Appolon','AUTHORITY_MISMATCH')
        require(authority.host==self.host and bool(authority.custody_receipt),'CUSTODY_OR_HOST_UNVERIFIED')
        require(all(type(x) is int and x>0 for x in (authority.app_id,authority.installation_id,authority.epoch,acquired.repository_id,acquired.pr_number,acquired.certificate_check_id)),'INVALID_AUTHORITY_IDS')
        require(authority.expires_at.tzinfo is not None and authority.expires_at>now,'AUTHORITY_EXPIRED')
        from .publisher_scope import APPROVED_REPOSITORIES
        require(binding.repository in authority.repositories and binding.repository in APPROVED_REPOSITORIES,'REPOSITORY_NOT_GRANTED')
        require(type(acquired.snapshot) is TrustedSnapshot,'UNTRUSTED_SNAPSHOT')
        snapshot=replace(acquired.snapshot,evaluated_at=now)
        decision=evaluate_promotion(binding,snapshot)
        require(decision.allowed,'PROMOTION_DENIED:'+','.join(decision.reasons))
        acquired=replace(acquired,snapshot=snapshot)
        verify_issuer(acquired,now)
        self.github.verify(acquired,now)
        require(self.store.acquire(binding)==original,'AUTHORITY_CHANGED_DURING_VERIFICATION')
        fresh=self.clock()
        require(authority.expires_at>fresh,'AUTHORITY_EXPIRED')
        verify_issuer(acquired,fresh)
        snapshot=replace(snapshot,evaluated_at=fresh)
        decision=evaluate_promotion(binding,snapshot)
        require(decision.allowed,'FINAL_PROMOTION_DENIED:'+','.join(decision.reasons))
        return replace(acquired,snapshot=snapshot)
    def publish(self,binding):
        acquired=self._acquire(binding)
        key=binding_digest(binding)
        require(self.ledger.reserve(key,str(acquired.authority.epoch)),'INTENT_ALREADY_CONSUMED')
        receipts=[];attempted=False
        try:
            for context in CONTEXTS:
                fresh=self._acquire(binding)
                require(fresh.authority==acquired.authority and fresh.repository_id==acquired.repository_id
                        and fresh.pr_number==acquired.pr_number,'AUTHORITY_CHANGED')
                attempted=True
                receipt=self.github.post(fresh,context,'success')
                require(self.github.readback(fresh,context,receipt),'READBACK_MISMATCH')
                receipts.append({'context':context,'receipt':receipt})
                attempted=False
                if len(receipts)==1:self.ledger.record(key,'PARTIAL',receipts)
            state='COMPLETE'
        except BaseException as exc:
            state='UNCERTAIN' if attempted else ('PARTIAL' if receipts else 'REJECTED')
            self.ledger.record(key,state,receipts)
            if not isinstance(exc,Exception):raise
            return PublicationResult(state,tuple(receipts))
        self.ledger.record(key,state,receipts)
        return PublicationResult(state,tuple(receipts))

class PublisherService:
    """Source application boundary: every operation requires service + local lock."""
    def __init__(self,publisher):self._publisher=publisher
    def publish(self,binding):
        from .publisher_ownership import publisher_session
        with publisher_session():return self._publisher.publish(binding)


def build_publisher_service(connection,jwt_provider,ledger_path,*,certificate_name,certificate_app_id):
    """Wire administered dependencies; not a request/JSON/environment factory.

    Operational startup must separately supply an authenticated TLS PostgreSQL
    connection, a credential-custodian JWT provider, accepted issuer IDs and a
    provisioned private ledger directory. No keys, credentials or roles are
    installed, fetched from caller input, or guessed here.
    """
    import socket
    from .publisher_acquisition import RestrictedRegistry,GitHubVerifier
    from .publisher_effect import IntentLedger
    from .publisher_github import GitHubAppClient
    api=GitHubAppClient(jwt_provider)
    verifier=GitHubVerifier(api,certificate_name=certificate_name,certificate_app_id=certificate_app_id)
    return PublisherService(AuthenticatedPublisher(RestrictedRegistry(connection),verifier,IntentLedger(ledger_path),host=socket.gethostname()))
