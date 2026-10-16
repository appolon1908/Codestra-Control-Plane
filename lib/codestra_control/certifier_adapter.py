"""Transport independently authenticated, EXISTING scope certifications only.

No first-certification decision, ScopeCertificate constructor, public CLI, issuer
bootstrap, production factory or credential installation lives here. Privileged
registry and accepted-contract ports are mandatory and unset by default. Their
return types are contracts, never authentication by themselves. An operator must
independently authenticate an existing certification before registering it in
any source read model. CI, promotion decisions and legacy PASS rows cannot do so.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import re
from urllib.parse import quote

from .evidence import PromotionRequest, TrustedSnapshot, LeaseEvidence
from .publisher_adapter import Authority, PublicationResult, require, binding_digest, CONTEXTS
from .publisher_github import GitHubAppClient


@dataclass(frozen=True)
class ExistingScopeReceipt:
    binding: PromotionRequest
    receipt_ref: str
    scope_type: str
    scope_name: str
    certified_sha: str
    expires_at: datetime
    assignment_id: str
    lease_id: str
    lease_epoch: int
    principal: str
    purpose: str


@dataclass(frozen=True)
class AcquiredCertification:
    authority: Authority
    snapshot: TrustedSnapshot
    repository_id: int
    pr_number: int
    receipt: ExistingScopeReceipt


@dataclass(frozen=True)
class AcceptedCertificationContract:
    binding_hash: str
    repository_id: int
    pr_number: int
    certifier_app_id: int
    publisher_app_id: int
    certificate_name: str
    controller_contexts: tuple[str, ...]
    receipt_ref: str
    expires_at: datetime
    purpose: str


def _future(value, now):
    return type(value) is datetime and value.tzinfo is not None and value > now


def _text(value):
    return type(value) is str and bool(value.strip())


def _validate(acquired, binding, now, host):
    from .decision import MAX_SNAPSHOT_AGE, CONTROL_PLANE_CONTEXTS
    from .policy import resolve_edge, PolicyError, valid_ref
    require(type(binding) is PromotionRequest, 'INVALID_CERTIFICATION_BINDING')
    require(all(_text(v) for v in (binding.product, binding.repository))
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*', binding.repository)
            and valid_ref(binding.source_ref) and valid_ref(binding.target_ref)
            and all(type(v) is str and re.fullmatch('[0-9a-f]{40}', v)
                    for v in (binding.source_sha, binding.target_base_sha)), 'INVALID_CERTIFICATION_BINDING')
    require(type(acquired) is AcquiredCertification, 'AUTHENTICATED_EXISTING_CERTIFICATION_REQUIRED')
    a, s, receipt = acquired.authority, acquired.snapshot, acquired.receipt
    require(type(a) is Authority and type(s) is TrustedSnapshot, 'CERTIFIER_AUTHORITY_UNAVAILABLE')
    require(a.authority_name == 'Ralph L. Appolon' and a.host == host and _text(a.custody_receipt)
            and _future(a.expires_at, now), 'CERTIFIER_AUTHORITY_INVALID')
    require(all(type(v) is int and v > 0 for v in
                (a.app_id, a.installation_id, a.epoch, acquired.repository_id, acquired.pr_number)), 'INVALID_CERTIFIER_IDENTITIES')
    from .publisher_scope import APPROVED_REPOSITORIES
    require(binding.repository in a.repositories and binding.repository in APPROVED_REPOSITORIES,
            'CERTIFIER_REPOSITORY_NOT_GRANTED')
    require(s.observed_binding == binding and s.mapping.repository == binding.repository
            and s.mapping.product == binding.product, 'CERTIFIER_SNAPSHOT_BINDING_MISMATCH')
    try:
        source_level, _ = resolve_edge(s.mapping, binding.source_ref, binding.target_ref)
    except PolicyError:
        require(False, 'UNREGISTERED_CERTIFICATION_SCOPE')
    require(type(s.observed_at) is datetime and s.observed_at.tzinfo is not None
            and now - MAX_SNAPSHOT_AGE <= s.observed_at <= now, 'STALE_CERTIFICATION_SNAPSHOT')
    require(all(value is False for value in (s.production_go, s.live_capabilities_enabled,
                                            s.external_effects_enabled)), 'CERTIFIER_POLICY_NOT_SAFE')
    require(s.dependencies_complete is True and s.dependencies_certified is True,
            'CERTIFIER_DEPENDENCIES_UNVERIFIED')
    require(type(receipt) is ExistingScopeReceipt and receipt.binding == binding
            and receipt.purpose == 'SCOPE_CERTIFICATION' and _text(receipt.receipt_ref)
            and receipt.scope_type == source_level.upper() and receipt.scope_name == binding.source_ref
            and receipt.certified_sha == binding.source_sha and _future(receipt.expires_at, now),
            'AUTHENTICATED_EXISTING_CERTIFICATION_REQUIRED')
    lease = s.lease
    require(type(lease) is LeaseEvidence and lease.binding == binding and lease.state == 'ACTIVE'
            and _future(lease.expires_at, now) and _text(lease.owner)
            and lease.owner == lease.expected_owner == receipt.principal
            and lease.assignment_id == receipt.assignment_id and _text(receipt.assignment_id)
            and _text(receipt.lease_id) and type(receipt.lease_epoch) is int and receipt.lease_epoch > 0,
            'CERTIFIER_LEASE_UNVERIFIED')
    require(s.check_inventory_complete is True and s.review_inventory_complete is True
            and s.unresolved_threads == 0 and s.require_codeowner is True
            and type(s.required_approvals) is int and s.required_approvals > 0,
            'CERTIFIER_REVIEW_OR_CHECK_INVENTORY_UNVERIFIED')
    require(type(s.required_checks) is tuple and bool(s.required_checks)
            and len({v.name for v in s.required_checks}) == len(s.required_checks), 'CERTIFIER_REQUIRED_CHECKS_UNAVAILABLE')
    for check in s.required_checks:
        require(_text(check.name) and check.name not in CONTROL_PLANE_CONTEXTS
                and type(check.producer) is str and re.fullmatch(r'github-actions:[1-9][0-9]*', check.producer),
                'CERTIFIER_REQUIRED_CHECK_PRODUCER_UNVERIFIED')
    require(_text(s.author) and _text(s.last_pusher) and type(s.reviews) is tuple,
            'CERTIFIER_REVIEW_INVENTORY_UNVERIFIED')
    reviewers = set(); owners = set()
    for review in s.reviews:
        require(review.binding == binding and _text(review.reviewer) and _text(review.evidence_id),
                'CERTIFIER_REVIEW_BINDING_MISMATCH')
        login = review.reviewer.casefold()
        require(login not in reviewers and review.state == 'APPROVED' and review.eligible is True
                and login not in (s.author.casefold(), s.last_pusher.casefold()), 'CERTIFIER_INDEPENDENT_REVIEW_REQUIRED')
        reviewers.add(login)
        if review.codeowner is True: owners.add(login)
    require(len(reviewers) >= s.required_approvals and bool(owners), 'CERTIFIER_INDEPENDENT_CODEOWNER_REQUIRED')


def _contract(verifier, acquired, now):
    from .decision import CONTROL_PLANE_CONTEXTS
    require(verifier is not None, 'CERTIFIER_ACCEPTED_CONTRACT_UNCONFIGURED')
    value = verifier.verify(acquired, now)
    require(type(value) is AcceptedCertificationContract, 'CERTIFIER_ACCEPTED_CONTRACT_UNVERIFIED')
    require(all(type(v) is int and v > 0 for v in
                (value.repository_id, value.pr_number, value.certifier_app_id, value.publisher_app_id)),
            'CERTIFIER_CONTRACT_IDENTITIES_INVALID')
    s = acquired.snapshot
    require(value.binding_hash == binding_digest(s.observed_binding)
            and value.repository_id == acquired.repository_id and value.pr_number == acquired.pr_number
            and value.certifier_app_id == acquired.authority.app_id
            and value.certifier_app_id not in (value.publisher_app_id, 15368)
            and all(v.producer not in ('github-actions:' + str(value.certifier_app_id),
                                      'github-actions:' + str(value.publisher_app_id)) for v in s.required_checks),
            'CERTIFIER_DISTINCT_ACCEPTED_APP_REQUIRED')
    require(_text(value.certificate_name) and value.certificate_name not in CONTROL_PLANE_CONTEXTS
            and value.certificate_name not in {v.name for v in s.required_checks}, 'CI_ALIAS_IS_NOT_CERTIFICATION')
    require(type(value.controller_contexts) is tuple and bool(value.controller_contexts)
            and len(set(value.controller_contexts)) == len(value.controller_contexts)
            and set(value.controller_contexts) <= set(CONTEXTS), 'CERTIFIER_CONTROLLER_CONTRACT_INVALID')
    require(value.purpose == 'SCOPE_CERTIFICATION' and _text(value.receipt_ref)
            and _future(value.expires_at, now)
            and value.expires_at <= min(acquired.authority.expires_at, acquired.receipt.expires_at),
            'CERTIFIER_ACCEPTED_CONTRACT_INVALID')
    return value


class AuthenticatedCertifier:
    """Privileged orchestration. Python dependencies are not author inputs."""
    def __init__(self, registry=None, github=None, ledger=None, *, contract_verifier=None,
                 host, clock=lambda: datetime.now(timezone.utc)):
        self.registry, self.github, self.ledger = registry, github, ledger
        self.contract_verifier, self.host, self.clock = contract_verifier, host, clock

    def _acquire(self, binding):
        require(all(v is not None for v in (self.registry, self.github, self.ledger)),
                'CERTIFIER_PRIVILEGED_DEPENDENCIES_UNCONFIGURED')
        require(self.contract_verifier is not None, 'CERTIFIER_ACCEPTED_CONTRACT_UNCONFIGURED')
        now = self.clock()
        acquired = self.registry.acquire(binding, now)
        _validate(acquired, binding, now, self.host)
        contract = _contract(self.contract_verifier, acquired, now)
        self.github.verify(acquired, contract, now)
        fresh = self.clock()
        require(self.registry.acquire(binding, fresh) == acquired, 'CERTIFICATION_REVOKED_OR_CHANGED')
        _validate(acquired, binding, fresh, self.host)
        require(_contract(self.contract_verifier, acquired, fresh) == contract, 'CERTIFIER_CONTRACT_CHANGED')
        return acquired, contract

    def publish(self, binding):
        acquired, contract = self._acquire(binding)
        key = 'certifier:' + binding_digest(binding)
        require(self.ledger.reserve(key, str(acquired.authority.epoch)), 'CERTIFIER_INTENT_ALREADY_CONSUMED')
        attempted = False
        receipts = []
        try:
            fresh, fresh_contract = self._acquire(binding)
            require(fresh == acquired and fresh_contract == contract, 'CERTIFICATION_REVOKED_OR_CHANGED')
            attempted = True
            check_id = self.github.emit(fresh, contract)
            require(self.github.readback(fresh, contract, check_id), 'CERTIFIER_READBACK_MISMATCH')
            receipts.append({'check_id': check_id, 'registry_receipt': fresh.receipt.receipt_ref})
        except BaseException as exc:
            state = 'UNCERTAIN' if attempted else 'REJECTED'
            self.ledger.record(key, state, receipts)
            if not isinstance(exc, Exception): raise
            return PublicationResult(state, tuple(receipts))
        self.ledger.record(key, 'COMPLETE', receipts)
        return PublicationResult('COMPLETE', tuple(receipts))


class CertifierGitHubClient(GitHubAppClient):
    # contents/pull_requests read exact refs, test merge, checks and reviews.
    # administration:read is necessary for classic enforced protection/bypasses;
    # it cannot alter protection. checks:write is the only write permission.
    PERMISSIONS = {'metadata': 'read', 'checks': 'write', 'contents': 'read',
                   'pull_requests': 'read', 'administration': 'read'}

    def assert_identity(self, authority, repository_id, now):
        self._token = self._expires = None
        jwt = self.jwt_provider()
        app = self.request('GET', '/app', jwt)
        require(type(app.get('id')) is int and app['id'] == authority.app_id, 'CERTIFIER_APP_IDENTITY_MISMATCH')
        installation = self.request('GET', f'/app/installations/{authority.installation_id}', jwt)
        require(installation.get('id') == authority.installation_id and installation.get('app_id') == authority.app_id
                and installation.get('suspended_at') is None, 'CERTIFIER_INSTALLATION_REVOKED_OR_MISMATCHED')
        require(installation.get('permissions') == self.PERMISSIONS, 'CERTIFIER_MINIMAL_INSTALLATION_REQUIRED')
        token = self.request('POST', f'/app/installations/{authority.installation_id}/access_tokens', jwt,
                             {'repository_ids': [repository_id], 'permissions': dict(self.PERMISSIONS)})
        require(token['permissions'] == self.PERMISSIONS and len(token['repositories']) == 1
                and token['repositories'][0]['id'] == repository_id, 'CERTIFIER_TOKEN_SCOPE_MISMATCH')
        expiry = datetime.fromisoformat(token['expires_at'].replace('Z', '+00:00'))
        require(_future(expiry, now) and _text(token['token']), 'CERTIFIER_TOKEN_UNAVAILABLE')
        self._token, self._expires = token['token'], min(expiry, authority.expires_at)

    def _call(self, method, path, body=None):
        require(method == 'GET' or (method == 'POST' and
                (path == '/graphql' or re.fullmatch(r'/repos/[^/]+/[^/]+/check-runs', path))),
                'CERTIFIER_API_EFFECT_REFUSED')
        return super()._call(method, path, body)


class CertifierGitHubVerifier:
    """Observe online source/base, merge checks, protection and independent reviews."""
    def __init__(self, api): self.api = api

    def _checks(self, repo, sha, requirements):
        values = self.api.pages(f'/repos/{repo}/commits/{sha}/check-runs?filter=latest', 'check_runs')
        for requirement in requirements:
            matches = [v for v in values if v['name'] == requirement.name
                       and 'github-actions:' + str(v['app']['id']) == requirement.producer]
            require(len(matches) == 1 and matches[0]['head_sha'] == sha
                    and matches[0]['status'] == 'completed' and matches[0]['conclusion'] == 'success',
                    'CERTIFIER_ONLINE_REQUIRED_CHECK_UNVERIFIED')
        return values

    def verify(self, acquired, contract, now):
        from .effective_protection import observe_protection, validate_protection
        s = acquired.snapshot; b = s.observed_binding; repo = b.repository
        self.api.assert_identity(acquired.authority, acquired.repository_id, now)
        pr = self.api.get(f'/repos/{repo}/pulls/{acquired.pr_number}')
        require(pr['state'] == 'open' and pr['draft'] is False
                and pr['user']['login'].casefold() == s.author.casefold(), 'CERTIFIER_PR_NOT_READY')
        for field, ref, sha in (('head', b.source_ref, b.source_sha), ('base', b.target_ref, b.target_base_sha)):
            part = pr[field]
            require(part['sha'] == sha and part['ref'] == ref and part['repo']['id'] == acquired.repository_id,
                    'CERTIFIER_PR_EXACT_BINDING_MISMATCH')
        merge = pr['merge_commit_sha']
        require(pr['mergeable'] is True and type(merge) is str and re.fullmatch('[0-9a-f]{40}', merge),
                'CERTIFIER_MERGE_RESULT_UNAVAILABLE')
        branch_path = f'/repos/{repo}/branches/{quote(b.target_ref, safe="")}'
        branch = self.api.get(branch_path)
        require(branch['protected'] is True and branch['commit']['sha'] == b.target_base_sha,
                'CERTIFIER_TARGET_NOT_PROTECTED_OR_MOVED')
        protection = observe_protection(self.api, repo, b.target_ref)
        validate_protection(protection, s.required_approvals, {(v.name, v.producer) for v in s.required_checks},
                            contract.publisher_app_id, contract.controller_contexts)
        self._checks(repo, b.source_sha, s.required_checks)
        self._checks(repo, merge, s.required_checks)
        require(self.api.review_approved(repo, acquired.pr_number), 'CERTIFIER_ONLINE_REVIEW_UNAPPROVED')
        latest = {}
        for value in self.api.pages(f'/repos/{repo}/pulls/{acquired.pr_number}/reviews'):
            if value['state'] in ('PENDING', 'COMMENTED'): continue
            login = value['user']['login'].casefold()
            if login not in latest or value['id'] > latest[login]['id']: latest[login] = value
        require(not any(v['state'] == 'CHANGES_REQUESTED' for v in latest.values()), 'CERTIFIER_CHANGES_REQUESTED')
        for stored in s.reviews:
            value = latest.get(stored.reviewer.casefold())
            require(value is not None and value['state'] == 'APPROVED' and value['commit_id'] == b.source_sha
                    and stored.evidence_id == 'review:' + str(value['id'])
                    and self.api.eligible_reviewer(repo, stored.reviewer), 'CERTIFIER_REVIEW_RECEIPT_MISMATCH')
        require(self.api.threads_resolved(repo, acquired.pr_number), 'CERTIFIER_THREADS_UNRESOLVED')
        self._checks(repo, b.source_sha, s.required_checks)
        self._checks(repo, merge, s.required_checks)
        require(self.api.get(f'/repos/{repo}/pulls/{acquired.pr_number}') == pr
                and self.api.get(branch_path) == branch, 'CERTIFIER_REF_MOVED_DURING_VERIFICATION')
        require(observe_protection(self.api, repo, b.target_ref) == protection,
                'CERTIFIER_PROTECTION_CHANGED_DURING_VERIFICATION')

    def emit(self, acquired, contract):
        b = acquired.snapshot.observed_binding
        value = self.api.post(f'/repos/{b.repository}/check-runs', {
            'name': contract.certificate_name, 'head_sha': b.source_sha,
            'external_id': binding_digest(b), 'status': 'completed', 'conclusion': 'success',
            'output': {'title': 'Existing authenticated scope certification',
                       'summary': 'Independent registry receipt verified for the exact source and target binding.'}})
        require(type(value.get('id')) is int and value['id'] > 0, 'CERTIFIER_CHECK_RECEIPT_UNAVAILABLE')
        return value['id']

    def readback(self, acquired, contract, check_id):
        b = acquired.snapshot.observed_binding
        value = self.api.get(f'/repos/{b.repository}/check-runs/{check_id}')
        return (type(value.get('id')) is int and value['id'] == check_id
                and value.get('app', {}).get('id') == contract.certifier_app_id
                and value.get('name') == contract.certificate_name and value.get('head_sha') == b.source_sha
                and value.get('external_id') == binding_digest(b) and value.get('status') == 'completed'
                and value.get('conclusion') == 'success')


class RestrictedCertificationRegistry:
    """Read-only source adapter for the EMPTY, separately accepted 011 model.

    This adapter cannot register or issue certifications. Only the operator can
    authenticate an existing independent receipt and populate this read model.
    Legacy scope metadata is cross-checked as a prerequisite, never as authority.
    No deployed schema or populated authoritative receipts are assumed to exist.
    """
    def __init__(self, connection): self.connection = connection

    def _session(self):
        from .publisher_startup import protected_read
        from .publisher_ownership import PublisherUnavailable
        params = self.connection.get_dsn_parameters()
        require(params.get('sslmode') == 'verify-full' and _text(params.get('host'))
                and not params['host'].startswith('/') and _text(params.get('sslrootcert')),
                'CERTIFIER_VERIFIED_DATABASE_TLS_REQUIRED')
        try:
            protected_read(params['sslrootcert'], allow_public=True)
        except PublisherUnavailable:
            require(False, 'CERTIFIER_UNTRUSTED_DATABASE_CA')
        self.connection.set_session(readonly=True, autocommit=False)

    @staticmethod
    def _roles(cur):
        cur.execute("""SELECT session_user=current_user
         AND system_user='scram-sha-256:'||session_user::text
         AND current_setting('role')='none',
         r.rolcanlogin AND NOT (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls)
         AND EXISTS(SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)
         AND NOT EXISTS(SELECT 1 FROM pg_roles bad WHERE
          (bad.rolsuper OR bad.rolcreaterole OR bad.rolcreatedb OR bad.rolreplication OR bad.rolbypassrls)
          AND pg_has_role(session_user,bad.oid,'MEMBER'))
         AND NOT EXISTS(SELECT 1 FROM pg_namespace n WHERE
          n.nspname IN ('certifier_authority','publisher_authority','assignment_leases','scoped_registration',
                        'atomic_inspection','controller_coordinator','frozen_recovery','scoped_admission')
          AND (pg_has_role(session_user,n.nspowner,'MEMBER') OR has_schema_privilege(session_user,n.oid,'CREATE')))
         AND NOT EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
          WHERE t.relkind IN ('r','p','v','m','f')
          AND (n.nspname IN ('certifier_authority','publisher_authority','assignment_leases','scoped_registration',
                            'atomic_inspection','controller_coordinator','frozen_recovery','scoped_admission')
               OR n.nspname='public')
          AND (pg_has_role(session_user,t.relowner,'MEMBER')
               OR has_table_privilege(session_user,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')))
         AND NOT EXISTS(SELECT 1 FROM pg_proc f JOIN pg_namespace n ON n.oid=f.pronamespace
          WHERE n.nspname IN ('certifier_authority','publisher_authority','assignment_leases','scoped_registration',
                             'atomic_inspection','controller_coordinator','frozen_recovery','scoped_admission')
          AND f.oid<>'assignment_leases.inspect_binding(uuid)'::regprocedure
          AND has_function_privilege(session_user,f.oid,'EXECUTE'))
         FROM pg_roles r WHERE r.rolname=session_user""")
        row = cur.fetchone()
        require(row is not None and tuple(row) == (True, True), 'CERTIFIER_RESTRICTED_AUTHENTICATED_SESSION_REQUIRED')

    def acquire(self, binding, now):
        import uuid
        from .publisher_acquisition import decode_snapshot
        require(type(binding) is PromotionRequest, 'INVALID_CERTIFICATION_BINDING')
        self._session()
        with self.connection:
            with self.connection.cursor() as cur:
                self._roles(cur)
                cur.execute("""SELECT c.authority,c.snapshot,c.receipt,c.repository_id,c.pr_number,
                 c.assignment_id,c.lease_id,c.lease_epoch,c.existing_receipt_ref,c.scope_type,c.scope_name,
                 c.accepted_by,c.acceptance_ref
                 FROM certifier_authority.existing_receipts c
                 JOIN certifier_authority.product_grants g ON g.principal=c.principal AND g.product=c.product
                 JOIN pg_roles r ON r.rolname=c.principal AND r.oid=c.role_oid AND r.oid=g.role_oid
                 JOIN public.products p ON p.product=c.product AND p.repository=c.repository
                 WHERE c.binding_hash=%s AND c.principal=session_user AND c.product=%s AND c.repository=%s
                 AND g.repository=c.repository AND g.repository_id=c.repository_id
                 AND c.active AND g.active AND c.expires_at>clock_timestamp() AND g.expires_at>clock_timestamp()
                 AND c.purpose='SCOPE_CERTIFICATION' AND c.origin='INDEPENDENTLY_AUTHENTICATED_EXISTING_RECEIPT'
                 AND NOT p.production_go AND NOT p.live_capabilities_enabled AND NOT p.external_effects_enabled
                 LIMIT 2""", (binding_digest(binding), binding.product, binding.repository))
                rows = cur.fetchall()
                require(len(rows) == 1, 'CERTIFIER_ACTIVE_EXISTING_RECEIPT_AND_PRODUCT_GRANT_REQUIRED')
                (raw_authority, raw_snapshot, raw_receipt, repo_id, pr, assignment, lease_id, epoch,
                 receipt_ref, scope_type, scope_name, accepted_by, acceptance_ref) = rows[0]
                raw_authority = dict(raw_authority)
                raw_authority['expires_at'] = datetime.fromisoformat(raw_authority['expires_at'])
                raw_authority['repositories'] = tuple(raw_authority['repositories'])
                authority = Authority(**raw_authority)
                raw_receipt = dict(raw_receipt)
                raw_receipt['binding'] = PromotionRequest(**raw_receipt['binding'])
                raw_receipt['expires_at'] = datetime.fromisoformat(raw_receipt['expires_at'])
                receipt = ExistingScopeReceipt(**raw_receipt)
                snapshot = decode_snapshot(raw_snapshot)
                require(accepted_by == 'Ralph L. Appolon' and _text(acceptance_ref)
                        and receipt.binding == binding and receipt.receipt_ref == receipt_ref
                        and receipt.scope_type == scope_type and receipt.scope_name == scope_name
                        and receipt.assignment_id == str(assignment) and receipt.lease_id == str(lease_id)
                        and receipt.lease_epoch == epoch and receipt.purpose == 'SCOPE_CERTIFICATION'
                        and _future(receipt.expires_at, now), 'CERTIFIER_REGISTERED_RECEIPT_MISMATCH')
                # Read model acceptance provides independent provenance; this
                # legacy record is only an additional exact scope prerequisite.
                cur.execute("""SELECT EXISTS(SELECT 1 FROM public.scope_certifications s
                 WHERE s.product=%s AND s.scope_type=%s AND s.scope_name=%s
                 AND s.sha=%s AND s.status='CERTIFIED')""",
                            (binding.product, scope_type, scope_name, binding.source_sha))
                require(cur.fetchone() == (True,), 'CERTIFIER_EXISTING_SCOPE_REGISTRATION_REQUIRED')
                assignment_id = str(uuid.UUID(str(assignment)))
                cur.execute('SELECT assignment_leases.inspect_binding(%s)', (assignment_id,))
                row = cur.fetchone()
                require(row is not None and type(row[0]) is dict, 'CERTIFIER_ONLINE_LEASE_UNAVAILABLE')
                live = row[0]
                require(live.get('authority') == 'ONLINE_DATABASE_RECEIPT' and live.get('state') == 'ACTIVE'
                        and live.get('binding_id') == assignment_id and live.get('lease_id') == str(lease_id)
                        and type(live.get('epoch')) is int and live['epoch'] == epoch
                        and live.get('principal') == receipt.principal, 'CERTIFIER_ONLINE_LEASE_REVOKED_OR_CHANGED')
                expected = dict(repository=binding.repository, repository_id=repo_id, product=binding.product,
                                source_ref=binding.source_ref, target_ref=binding.target_ref,
                                head_sha=binding.source_sha, base_sha=binding.target_base_sha, principal=receipt.principal)
                actual = live.get('binding', {})
                require(all(actual.get(k) == v for k, v in expected.items()), 'CERTIFIER_ONLINE_LEASE_BINDING_MISMATCH')
                expiry = datetime.fromisoformat(live['expires_at'])
                require(_future(expiry, now) and snapshot.lease is not None
                        and snapshot.lease.expires_at == expiry, 'CERTIFIER_ONLINE_LEASE_EXPIRED_OR_CHANGED')
                acquired = AcquiredCertification(authority, snapshot, repo_id, pr, receipt)
                _validate(acquired, binding, now, authority.host)
                return acquired


class AcceptedCertifierContractVerifier:
    """Read the shared protected acceptance policy; never infer issuer authority.

    protected_policy_reader is a privileged zero-argument reader installed by the
    operator integration, never a publication/author field. The separate certifier
    GitHub client authenticates this accepted App online before any check-run.
    """
    def __init__(self, protected_policy_reader):
        self.protected_policy_reader = protected_policy_reader

    def verify(self, acquired, now):
        from .publisher_adapter import PublicationDenied
        try:
            from .publisher_acceptance import load_acceptance
            policy = load_acceptance(self.protected_policy_reader(), now)
        except PublicationDenied:
            raise
        except Exception:
            raise PublicationDenied('CERTIFIER_ACCEPTANCE_UNAVAILABLE') from None
        a = acquired.authority; b = acquired.snapshot.observed_binding
        require(policy.certificate_app_id == a.app_id
                and policy.certificate_installation_id == a.installation_id
                and policy.publisher_app_id != a.app_id
                and policy.certifier_custody_receipt == a.custody_receipt
                and (b.repository, acquired.repository_id) in policy.repositories,
                'CERTIFIER_ACCEPTANCE_IDENTITY_OR_REPOSITORY_MISMATCH')
        require(_text(policy.certifier_capability_receipt), 'CERTIFIER_ACCEPTED_CAPABILITY_UNAVAILABLE')
        return AcceptedCertificationContract(
            binding_digest(b), acquired.repository_id, acquired.pr_number,
            policy.certificate_app_id, policy.publisher_app_id, policy.certificate_name,
            policy.controller_contexts, policy.acceptance_ref + '#' + policy.revision,
            min(policy.expires_at, a.expires_at, acquired.receipt.expires_at), 'SCOPE_CERTIFICATION')
