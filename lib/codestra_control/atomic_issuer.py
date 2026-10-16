"""Inactive privileged atomic inclusion issuer; no author CLI or provisioning.

The snapshot reader is an independently administered exact-task registry port.
The database principal may execute014 prepare/seal but cannot write its tables.
Only this credential-custodied issuer may assert GitHub observations to that API.
"""
from dataclasses import dataclass
from datetime import datetime, timezone

from .atomic_receipts import (load_atomic_policy, receipt_digest, observation_digest,
                              _instant, _utc)
from .publisher_adapter import PublicationDenied, PublicationResult, require


@dataclass(frozen=True)
class AtomicIssuerAcquisition:
    authority: object
    snapshot: object
    repository_id: int
    pr_number: int


class RestrictedAtomicIssuerRegistry:
    def __init__(self, connection): self.connection = connection

    def _call(self, query, args):
        from .certifier_adapter import RestrictedCertificationRegistry
        # Validate the protected CA/verify-full route.014 then authenticates the
        # actual session, current OID, restricted role and explicit issue grant.
        RestrictedCertificationRegistry(self.connection)._session()
        self.connection.set_session(readonly=False)
        with self.connection, self.connection.cursor() as cur:
            cur.execute(query,args)
            return cur.fetchone()[0]

    def prepare(self, delegation, request):
        return self._call('SELECT atomic_receipts.prepare(%s,%s)',(delegation,request))

    def seal(self, prepared, check, observation):
        return self._call('SELECT atomic_receipts.seal(%s,%s,%s,%s,%s,%s)',
            (prepared['preparation_id'],check['id'],check['check_suite']['id'],
             check['external_id'],observation,_utc(check['completed_at'])))


class AtomicIssuerGitHubVerifier:
    def __init__(self, api, *, clock=lambda:datetime.now(timezone.utc)):
        self.api,self.clock = api,clock

    def observe(self, prepared, acquired, purpose, producer, now):
        from .certifier_adapter import _validate_snapshot_data, CertifierGitHubVerifier
        from .effective_protection import observe_protection, validate_protection
        from urllib.parse import quote
        from .policy import registered_edges
        import re
        _validate_snapshot_data(acquired,acquired.snapshot.observed_binding,now,acquired.authority.host)
        b=acquired.snapshot.observed_binding; s=acquired.snapshot; a=acquired.authority
        require(b.target_ref.startswith('subsection/')
                and re.fullmatch(re.escape('atomic/'+b.target_ref.removeprefix('subsection/')+'--')+r'[a-z0-9]+(-[a-z0-9]+)*',b.source_ref)
                and any(edge.source_level=='subsection' and edge.source_ref==b.target_ref
                        for edge in registered_edges(s.mapping)), 'ATOMIC_REGISTERED_SUBSECTION_BINDING_REQUIRED')
        payload=prepared['payload']; original=payload['binding']; context=payload['delegation']['context']
        require(type(acquired) is AtomicIssuerAcquisition and a.app_id == purpose.app_id == producer.certificate_app_id
                and a.installation_id == purpose.installation_id == producer.certificate_installation_id
                and a.custody_receipt == purpose.custody_receipt == producer.certifier_custody_receipt
                and (b.repository,acquired.repository_id) in producer.repositories
                and purpose.repository == b.repository and purpose.repository_id == acquired.repository_id
                and purpose.name != producer.certificate_name
                and all(context.get(k)==v for k,v in dict(purpose='ATOMIC_INCLUSION',repository=b.repository,
                    repository_id=acquired.repository_id,task_id=original['task_id'],source_ref=b.source_ref,
                    target_ref=b.target_ref,head_sha=original['head_sha'],base_sha=b.target_base_sha,
                    candidate_sha=b.source_sha,app_id=a.app_id,installation_id=a.installation_id,
                    policy_revision=purpose.revision,name=purpose.name,custody_receipt=purpose.custody_receipt,
                    capability_receipt=purpose.capability_receipt,pr_number=acquired.pr_number).items())
                and original['product']==b.product and original['repository']==b.repository
                and original['source_ref']==b.source_ref and original['target_ref']==b.target_ref
                and original['base_sha']==b.target_base_sha,
                'ATOMIC_ISSUER_EXACT_PURPOSE_BINDING_REQUIRED')
        require(all(value.producer not in ('github-actions:'+str(a.app_id),'github-actions:'+str(producer.publisher_app_id))
                    and value.name not in {purpose.name,producer.certificate_name,*producer.controller_contexts}
                    for value in s.required_checks), 'ATOMIC_INDEPENDENT_CI_REQUIRED')
        require(_instant(prepared['prepared_at']) <= now < _instant(payload['lease']['expires_at'])
                and now < _instant(payload['proof']['expires_at'])
                and purpose.accepted_at <= _instant(prepared['prepared_at']), 'ATOMIC_ISSUER_AUTHORITY_EXPIRED')
        self.api.assert_identity(a,acquired.repository_id,now)
        repo=b.repository; pr=self.api.get(f'/repos/{repo}/pulls/{acquired.pr_number}')
        require(pr.get('id')==context['pr_id'] and pr.get('number')==acquired.pr_number
                and pr.get('state')=='closed' and pr.get('merged') is True
                and pr['head']['repo']['id']==pr['base']['repo']['id']==acquired.repository_id
                and pr['head']['ref']==b.source_ref and pr['head']['sha']==b.source_sha
                and pr['base']['ref']==b.target_ref and pr['merge_commit_sha']==context['merge_sha']
                and pr['user']['login'].casefold()==s.author.casefold()
                and _utc(pr['merged_at']) <= _instant(prepared['prepared_at']), 'ATOMIC_ISSUER_MERGED_PR_REQUIRED')
        merge=self.api.get(f'/repos/{repo}/git/commits/{context["merge_sha"]}')
        candidate=self.api.get(f'/repos/{repo}/git/commits/{b.source_sha}')
        require(merge.get('sha')==context['merge_sha'] and merge['tree']['sha']==context['merge_tree']
                and [p['sha'] for p in merge['parents']]==[b.target_base_sha,b.source_sha]
                and candidate.get('sha')==b.source_sha and candidate['tree']['sha']==context['candidate_tree'],
                'ATOMIC_ISSUER_ORDINARY_MERGE_REQUIRED')
        target_path=f'/repos/{repo}/branches/{quote(b.target_ref,safe="")}'
        branch=self.api.get(target_path)
        source_path=f'/repos/{repo}/branches/{quote(b.source_ref,safe="")}'
        source=self.api.get(source_path)
        require(source['commit']['sha']==b.source_sha,'ATOMIC_ISSUER_SOURCE_REF_MOVED')
        require(branch.get('protected') is True and branch['commit']['sha']==context['merge_sha'],
                'ATOMIC_ISSUER_CURRENT_PARENT_OR_PROTECTION_CHANGED')
        protection=observe_protection(self.api,repo,b.target_ref)
        validate_protection(protection,s.required_approvals,{(v.name,v.producer) for v in s.required_checks},
                            producer.publisher_app_id,producer.controller_contexts)
        checker=CertifierGitHubVerifier(self.api)
        for sha in (b.source_sha,context['merge_sha']):
            checks=checker._checks(repo,sha,s.required_checks)
            for requirement in s.required_checks:
                actual=next(v for v in checks if v['name']==requirement.name and 'github-actions:'+str(v['app']['id'])==requirement.producer)
                completed=_utc(actual['completed_at'])
                require(completed <= now and (sha!=b.source_sha or completed <= _utc(pr['merged_at'])),
                        'ATOMIC_CI_TIMING_UNESTABLISHED')
        latest={}
        for review in self.api.pages(f'/repos/{repo}/pulls/{acquired.pr_number}/reviews'):
            if review['state'] in ('COMMENTED','PENDING'): continue
            login=review['user']['login'].casefold()
            if login not in latest or review['id']>latest[login]['id']: latest[login]=review
        require(not any(v['state']=='CHANGES_REQUESTED' for v in latest.values()), 'ATOMIC_CHANGES_REQUESTED')
        for stored in s.reviews:
            review=latest.get(stored.reviewer.casefold())
            require(review is not None and review['state']=='APPROVED' and review['commit_id']==b.source_sha
                    and stored.evidence_id=='review:'+str(review['id']) and self.api.eligible_reviewer(repo,stored.reviewer)
                    and _utc(review['submitted_at']) <= _utc(pr['merged_at']), 'ATOMIC_PREMERGE_INDEPENDENT_REVIEW_REQUIRED')
        require(self.api.threads_resolved(repo,acquired.pr_number), 'ATOMIC_THREADS_UNRESOLVED')
        require(self.api.get(f'/repos/{repo}/pulls/{acquired.pr_number}')==pr
                and self.api.get(target_path)==branch and self.api.get(source_path)==source
                and observe_protection(self.api,repo,b.target_ref)==protection,
                'ATOMIC_ISSUER_EVIDENCE_CHANGED')
        return pr,merge,candidate

    def emit(self,prepared,acquired,purpose,producer,now,*,before_effect=None):
        facts=self.observe(prepared,acquired,purpose,producer,now)
        payload=prepared['payload']; b=acquired.snapshot.observed_binding
        from .decision import MAX_SNAPSHOT_AGE
        effect_deadline=min(purpose.expires_at,producer.expires_at,acquired.authority.expires_at,
            _instant(payload['lease']['expires_at']),_instant(payload['proof']['expires_at']),
            _instant(payload['delegation']['expires_at']),_instant(payload['delegation']['receipt_expires_at']),
            _instant(payload['issue_grant_expires_at']),acquired.snapshot.observed_at+MAX_SNAPSHOT_AGE)
        require(before_effect is not None,'ATOMIC_PRE_EFFECT_AUTHORITY_FENCE_REQUIRED')
        before_effect()
        require(self.clock()<effect_deadline,'ATOMIC_PRE_EFFECT_AUTHORITY_EXPIRED')
        self.api.bind_effect_expiry(effect_deadline)
        check=self.api.post(f'/repos/{b.repository}/check-runs',dict(name=purpose.name,head_sha=b.source_sha,
            external_id=receipt_digest(payload),status='completed',conclusion='success',
            output=dict(title='Authenticated atomic inclusion',summary='Exact merged inclusion verified under an independent active issuance lease. No write admission conferred.')))
        check=self.api.get(f'/repos/{b.repository}/check-runs/{check["id"]}')
        require(type(check.get('id')) is int and check['id']>0 and check.get('app',{}).get('id')==purpose.app_id
                and check.get('name')==purpose.name and check.get('head_sha')==b.source_sha
                and check.get('external_id')==receipt_digest(payload) and check.get('status')=='completed'
                and check.get('conclusion')=='success', 'ATOMIC_ISSUER_CHECK_READBACK_FAILED')
        suite=self.api.get(f'/repos/{b.repository}/check-suites/{check["check_suite"]["id"]}')
        require(suite.get('id')==check['check_suite']['id'] and suite.get('app',{}).get('id')==purpose.app_id
                and suite.get('head_sha')==b.source_sha and suite.get('status')=='completed'
                and suite.get('conclusion')=='success', 'ATOMIC_ISSUER_SUITE_READBACK_FAILED')
        return check,observation_digest(payload['delegation']['context'],check,*facts)


class AtomicInclusionIssuer:
    def __init__(self,registry=None,github=None,ledger=None,policy_reader=None,producer_policy_reader=None,
                 snapshot_reader=None,*,host,clock=lambda:datetime.now(timezone.utc)):
        self.registry,self.github,self.ledger=registry,github,ledger
        self.policy_reader,self.producer_policy_reader,self.snapshot_reader=policy_reader,producer_policy_reader,snapshot_reader
        self.host,self.clock=host,clock

    def issue(self,delegation,request):
        require(all(v is not None for v in (self.registry,self.github,self.ledger,self.policy_reader,
            self.producer_policy_reader,self.snapshot_reader)), 'ATOMIC_ISSUER_UNCONFIGURED')
        from .publisher_acceptance import load_acceptance
        prepared=self.registry.prepare(delegation,request)
        acquired=self.snapshot_reader(prepared)
        require(type(acquired) is AtomicIssuerAcquisition and acquired.authority.host==self.host,
                'ATOMIC_ISSUER_PROTECTED_SNAPSHOT_REQUIRED')
        purpose=load_atomic_policy(self.policy_reader(),self.clock())
        producer=load_acceptance(self.producer_policy_reader(),self.clock())
        self.github.observe(prepared,acquired,purpose,producer,self.clock())
        key='atomic-inclusion:'+receipt_digest(prepared['payload'])
        require(self.ledger.reserve(key,str(prepared['payload']['lease']['epoch'])), 'ATOMIC_ISSUER_INTENT_ALREADY_CONSUMED')
        attempted=False; receipts=[]
        try:
            require(self.registry.prepare(delegation,request)==prepared and self.snapshot_reader(prepared)==acquired
                    and load_atomic_policy(self.policy_reader(),self.clock())==purpose
                    and load_acceptance(self.producer_policy_reader(),self.clock())==producer,
                    'ATOMIC_ISSUER_AUTHORITY_CHANGED')
            self.github.observe(prepared,acquired,purpose,producer,self.clock())
            attempted=True
            def fence():
                require(self.registry.prepare(delegation,request)==prepared and self.snapshot_reader(prepared)==acquired
                        and load_atomic_policy(self.policy_reader(),self.clock())==purpose
                        and load_acceptance(self.producer_policy_reader(),self.clock())==producer,
                        'ATOMIC_ISSUER_AUTHORITY_CHANGED')
            check,observation=self.github.emit(prepared,acquired,purpose,producer,self.clock(),before_effect=fence)
            # Fresh evidence and actual SQL active lease are both required after
            # the external effect. They are not one atomic network transaction.
            self.github.observe(prepared,acquired,purpose,producer,self.clock())
            require(self.snapshot_reader(prepared)==acquired
                    and load_atomic_policy(self.policy_reader(),self.clock())==purpose
                    and load_acceptance(self.producer_policy_reader(),self.clock())==producer,
                    'ATOMIC_ISSUER_AUTHORITY_CHANGED')
            receipts.append(self.registry.seal(prepared,check,observation))
        except BaseException as exc:
            state='UNCERTAIN' if attempted else 'REJECTED'; self.ledger.record(key,state,receipts)
            if not isinstance(exc,Exception): raise
            return PublicationResult(state,tuple(receipts))
        self.ledger.record(key,'COMPLETE',receipts)
        return PublicationResult('COMPLETE',tuple(receipts))


def build_atomic_issuer_service(connection,jwt_provider,ledger_path,policy_reader,
                               producer_policy_reader,snapshot_reader,*,host,clock=lambda:datetime.now(timezone.utc)):
    from .certifier_adapter import CertifierGitHubClient
    from .publisher_effect import IntentLedger
    return AtomicInclusionIssuer(RestrictedAtomicIssuerRegistry(connection),
        AtomicIssuerGitHubVerifier(CertifierGitHubClient(jwt_provider,clock=clock),clock=clock),IntentLedger(ledger_path),
        policy_reader,producer_policy_reader,snapshot_reader,host=host,clock=clock)
