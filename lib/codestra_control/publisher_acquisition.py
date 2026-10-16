"""Concrete restricted PostgreSQL reader and online GitHub receipt verifier.

Authority read-model rows are operator-maintained, never runtime-writable.
GitHub is independently queried on every preflight; stored PASS values are unused.
"""
from dataclasses import fields,replace
from datetime import datetime
import uuid
from urllib.parse import quote
from . import evidence as e
from .policy import ProductMapping,ScopeEdge
from .publisher_startup import protected_read
from .publisher_ownership import PublisherUnavailable
from .publisher_adapter import Acquired,Authority,CertificateIssuer,CONTEXTS,verify_issuer,require,binding_digest


def decode_snapshot(raw):
    require(type(raw) is dict and set(raw)=={f.name for f in fields(e.TrustedSnapshot)},'SNAPSHOT_SCHEMA_MISMATCH')
    value=dict(raw)
    def binding(v):return e.PromotionRequest(**v)
    mapping=dict(value['mapping']);mapping['scope_edges']=tuple(ScopeEdge(**v) for v in mapping['scope_edges'])
    value['mapping']=ProductMapping(**mapping)
    value['observed_binding']=binding(value['observed_binding'])
    for name in ('observed_at','evaluated_at'):value[name]=datetime.fromisoformat(value[name])
    value['required_checks']=tuple(e.RequiredCheck(**v) for v in value['required_checks'])
    for name,kind in (('checks',e.CheckEvidence),('reviews',e.ReviewEvidence)):
        value[name]=tuple(kind(**dict(v,binding=binding(v['binding']))) for v in value[name])
    for name,kind in (('certificate',e.ScopeCertificate),('lease',e.LeaseEvidence)):
        item=value[name]
        if item is not None:
            item=dict(item,binding=binding(item['binding']))
            if name=='lease':item['expires_at']=datetime.fromisoformat(item['expires_at'])
            value[name]=kind(**item)
    return e.TrustedSnapshot(**value)

class RestrictedRegistry:
    def __init__(self,connection):self.connection=connection
    def _session(self):
        params=self.connection.get_dsn_parameters()
        require(params.get('sslmode')=='verify-full' and bool(params.get('host'))
                and not params['host'].startswith('/') and bool(params.get('sslrootcert')),'VERIFIED_DATABASE_TLS_REQUIRED')
        try:protected_read(params['sslrootcert'],allow_public=True)
        except PublisherUnavailable:
            require(False,'UNTRUSTED_DATABASE_CA')
        self.connection.set_session(readonly=True,autocommit=False)
    @staticmethod
    def _roles(cur):
        cur.execute("""SELECT session_user=current_user AND system_user IS NOT NULL,
         NOT (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls)
         AND NOT pg_has_role(session_user,n.nspowner,'MEMBER')
         AND NOT has_schema_privilege(session_user,'publisher_authority','CREATE')
         AND NOT has_table_privilege(session_user,'publisher_authority.bindings','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
         AND EXISTS (SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)
         FROM pg_roles r CROSS JOIN pg_namespace n
         WHERE r.rolname=session_user AND n.nspname='publisher_authority'""")
        row=cur.fetchone()
        require(row is not None and tuple(row)==(True,True),'RESTRICTED_AUTHENTICATED_SESSION_REQUIRED')
    def acquire(self,binding):
        self._session()
        with self.connection:
            with self.connection.cursor() as cur:
                self._roles(cur)
                cur.execute("""SELECT authority,snapshot,repository_id,pr_number,certificate_check_id,issuer
                 FROM publisher_authority.bindings WHERE binding_hash=%s AND principal=session_user
                 AND role_oid=(SELECT oid FROM pg_roles WHERE rolname=session_user)
                 AND active AND expires_at>clock_timestamp()""",(binding_digest(binding),))
                rows=cur.fetchall();require(len(rows)==1,'ACTIVE_AUTHORITY_BINDING_REQUIRED')
                raw,snapshot,repo_id,pr,certificate,issuer=rows[0]
                issuer=dict(issuer);issuer['expires_at']=datetime.fromisoformat(issuer['expires_at'])
                raw=dict(raw);raw['expires_at']=datetime.fromisoformat(raw['expires_at']);raw['repositories']=tuple(raw['repositories'])
                snapshot=decode_snapshot(snapshot)
                lease=snapshot.lease
                require(type(lease) is e.LeaseEvidence,'AUTHENTICATED_LEASE_REQUIRED')
                try:assignment=str(uuid.UUID(lease.assignment_id))
                except (ValueError,TypeError,AttributeError):require(False,'AUTHENTICATED_ASSIGNMENT_REQUIRED')
                # This publisher handles registered scope/environment edges.
                # Atomic candidate leases have a different, narrower authority
                # and cannot authenticate these bindings.
                cur.execute('SELECT scope_assignment_leases.inspect_binding(%s)',(assignment,))
                row=cur.fetchone()
                require(row is not None and type(row[0]) is dict,'ONLINE_LEASE_UNAVAILABLE')
                receipt=row[0];actual=receipt.get('binding',{})
                require(receipt.get('authority')=='ONLINE_DATABASE_RECEIPT' and receipt.get('binding_id')==assignment
                        and receipt.get('state')=='ACTIVE' and receipt.get('principal')==lease.owner==lease.expected_owner
                        and actual.get('principal')==lease.owner,'ONLINE_LEASE_OWNER_OR_STATE_MISMATCH')
                expected={'repository':binding.repository,'repository_id':repo_id,'product':binding.product,
                          'source_ref':binding.source_ref,'target_ref':binding.target_ref,
                          'head_sha':binding.source_sha,'base_sha':binding.target_base_sha}
                require(all(actual.get(k)==v for k,v in expected.items()),'ONLINE_LEASE_BINDING_MISMATCH')
                try:
                    lease_id=str(uuid.UUID(receipt['lease_id']))
                    expiry=datetime.fromisoformat(receipt['expires_at'])
                except (KeyError,ValueError,TypeError,AttributeError):require(False,'ONLINE_LEASE_RECEIPT_INVALID')
                require(type(receipt.get('epoch')) is int and receipt['epoch']>0 and expiry.tzinfo is not None,'ONLINE_LEASE_RECEIPT_INVALID')
                snapshot=replace(snapshot,lease=replace(lease,state='ACTIVE',expires_at=expiry))
                return Acquired(Authority(**raw),snapshot,repo_id,pr,certificate,CertificateIssuer(**issuer),lease_id,receipt['epoch'])


    def bindings(self):
        self._session()
        with self.connection:
            with self.connection.cursor() as cur:
                self._roles(cur)
                cur.execute("""SELECT snapshot->'observed_binding' FROM publisher_authority.bindings
                 WHERE principal=session_user AND role_oid=(SELECT oid FROM pg_roles WHERE rolname=session_user)
                 AND active AND expires_at>clock_timestamp() ORDER BY binding_hash LIMIT 1001""")
                rows=cur.fetchall()
                require(len(rows)<=1000,'AUTHORITY_INVENTORY_LIMIT')
                return tuple(e.PromotionRequest(**row[0]) for row in rows)

class GitHubVerifier:
    def __init__(self,api,*,certificate_name,certificate_app_id=None,provenance_verifier=None):
        self.api=api;self.certificate_name=certificate_name;self.certificate_app_id=certificate_app_id
        self.provenance_verifier=provenance_verifier
        self._last_provenance=None
    @staticmethod
    def _producer(check):return 'github-actions:'+str(check['app']['id'])
    def _checks(self,repo,sha,requirements):
        checks=self.api.pages(f'/repos/{repo}/commits/{sha}/check-runs?filter=latest','check_runs')
        for requirement in requirements:
            matches=[v for v in checks if v['name']==requirement.name and self._producer(v)==requirement.producer]
            require(len(matches)==1,'ONLINE_REQUIRED_CHECK_AMBIGUOUS')
            check=matches[0]
            require(check['head_sha']==sha and check['status']=='completed' and check['conclusion']=='success','ONLINE_CHECK_NOT_SUCCESS')
        return checks
    def verify(self,acquired,now):
        from .publisher_provenance import verify_contract
        from .effective_protection import observe_protection,validate_protection
        self._last_provenance=None
        verify_issuer(acquired,now)
        provenance=verify_contract(self.provenance_verifier,acquired,now)
        require(acquired.issuer.app_id==self.certificate_app_id and acquired.issuer.name==self.certificate_name,'CERTIFIER_CONFIG_CAPABILITY_MISMATCH')
        s=acquired.snapshot;b=s.observed_binding;a=acquired.authority;repo=b.repository
        self.api.assert_identity(a,acquired.repository_id,now)
        pr=self.api.get(f'/repos/{repo}/pulls/{acquired.pr_number}')
        require(pr['state']=='open' and pr['draft'] is False,'PR_NOT_READY')
        require(pr['user']['login'].casefold()==s.author.casefold(),'ONLINE_AUTHOR_MISMATCH')
        require(self.api.review_approved(repo,acquired.pr_number),'ONLINE_REVIEW_DECISION_UNAPPROVED')
        for name,ref,sha in (('head',b.source_ref,b.source_sha),('base',b.target_ref,b.target_base_sha)):
            part=pr[name]
            require(part['sha']==sha and part['ref']==ref and part['repo']['id']==acquired.repository_id,'PR_REF_BINDING_MISMATCH')
        require(pr['mergeable'] is True and type(pr['merge_commit_sha']) is str and len(pr['merge_commit_sha'])==40,'MERGE_RESULT_UNAVAILABLE')
        branch=self.api.get(f'/repos/{repo}/branches/{quote(b.target_ref,safe="")}')
        require(branch['protected'] is True and branch['commit']['sha']==b.target_base_sha,'TARGET_NOT_PROTECTED_OR_MOVED')
        protection=observe_protection(self.api,repo,b.target_ref)
        require(s.require_codeowner is True,'CODEOWNER_POLICY_REQUIRED')
        validate_protection(protection,s.required_approvals,
                            {(v.name,v.producer) for v in s.required_checks},a.app_id,
                            provenance.controller_contexts)
        # Require the same approved producer checks on head and current test merge.
        online=self._checks(repo,b.source_sha,s.required_checks)
        self._checks(repo,pr['merge_commit_sha'],s.required_checks)
        for stored in s.checks:
            require(any(stored.evidence_id=='run:'+str(v['id']) and stored.name==v['name'] and stored.producer==self._producer(v) for v in online),'STORED_CHECK_RECEIPT_MISMATCH')
        receipt=self.api.get(f'/repos/{repo}/check-runs/{acquired.certificate_check_id}')
        require(type(self.certificate_app_id) is int and self.certificate_app_id>0,'CERTIFICATE_ISSUER_UNCONFIGURED')
        require(s.certificate.receipt_id=='check:'+str(receipt['id']) and receipt['id']==acquired.certificate_check_id
                and receipt['head_sha']==b.source_sha and receipt['app']['id']==self.certificate_app_id
                and receipt['name']==self.certificate_name and receipt['external_id']==binding_digest(b)
                and receipt['status']=='completed' and receipt['conclusion']=='success','ONLINE_CERTIFICATE_INVALID')
        live=self.api.pages(f'/repos/{repo}/pulls/{acquired.pr_number}/reviews')
        latest={}
        for review in live:
            if review['state'] not in ('PENDING','COMMENTED'):
                login=review['user']['login'].casefold()
                if login not in latest or review['id']>latest[login]['id']:latest[login]=review
        require(not any(v['state']=='CHANGES_REQUESTED' for v in latest.values()),'ONLINE_CHANGES_REQUESTED')
        for review in s.reviews:
            current=latest.get(review.reviewer.casefold())
            require(current is not None and current['state']==review.state and current['commit_id']==b.source_sha
                    and review.evidence_id=='review:'+str(current['id']),'ONLINE_REVIEW_MISMATCH')
            require(self.api.eligible_reviewer(repo,review.reviewer),'ONLINE_REVIEWER_INELIGIBLE')
        require(self.api.threads_resolved(repo,acquired.pr_number),'ONLINE_THREADS_UNRESOLVED')
        final_pr=self.api.get(f'/repos/{repo}/pulls/{acquired.pr_number}')
        final_branch=self.api.get(f'/repos/{repo}/branches/{quote(b.target_ref,safe="")}')
        require(final_pr==pr and final_branch==branch,'REF_OR_PR_MOVED_DURING_VERIFICATION')
        require(observe_protection(self.api,repo,b.target_ref)==protection,'PROTECTION_CHANGED_DURING_VERIFICATION')
        require(verify_contract(self.provenance_verifier,acquired,now)==provenance,'PUBLISHER_PROVENANCE_CHANGED')
        self._last_provenance=provenance
    def revalidate(self,acquired,now):
        from .publisher_provenance import verify_contract
        require(verify_contract(self.provenance_verifier,acquired,now)==self._last_provenance,'PUBLISHER_PROVENANCE_CHANGED')
    def post(self,acquired,context,state):
        from .publisher_adapter import CONTEXTS
        require(context in CONTEXTS and state=='success','INVALID_PUBLICATION_CONTEXT')
        b=acquired.snapshot.observed_binding
        result=self.api.post(f'/repos/{b.repository}/statuses/{b.source_sha}',
                             {'state':state,'context':context,'description':'Authenticated exact-binding promotion evidence',
                              'target_url':f'https://github.com/{b.repository}/pull/{acquired.pr_number}'})
        require(type(result['id']) is int and result['id']>0,'INVALID_STATUS_RECEIPT')
        return result['id']
    def readback(self,acquired,context,receipt):
        b=acquired.snapshot.observed_binding
        values=self.api.pages(f'/repos/{b.repository}/commits/{b.source_sha}/statuses')
        latest=next((v for v in values if v['context']==context),None)
        return latest is not None and latest['id']==receipt and latest['state']=='success'
