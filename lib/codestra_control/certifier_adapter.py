"""Independent scope certification SOURCE, default-deny and never author input.

Existing-receipt transport and separate scoped first issuance have distinct
privileged registry and accepted-contract ports. First issuance requires an
operator-authenticated exact-scope pending delegation, no historical certificate,
and fresh independent online checks/reviews/protection/dependencies/scope lease.
No public CLI, production factory, trust bootstrap or credential installation is
provided. Promotion.allowed, ordinary CI and legacy PASS do not confer authority.
Python types never authenticate themselves; all registry acquisition is privileged.
"""
from dataclasses import dataclass, replace
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


def _validate_snapshot_data(acquired, binding, now, host):
    from .decision import MAX_SNAPSHOT_AGE, CONTROL_PLANE_CONTEXTS
    from .policy import valid_ref
    require(type(binding) is PromotionRequest, 'INVALID_CERTIFICATION_BINDING')
    require(all(_text(v) for v in (binding.product, binding.repository))
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*', binding.repository)
            and valid_ref(binding.source_ref) and valid_ref(binding.target_ref)
            and all(type(v) is str and re.fullmatch('[0-9a-f]{40}', v)
                    for v in (binding.source_sha, binding.target_base_sha)), 'INVALID_CERTIFICATION_BINDING')
    a, s = acquired.authority, acquired.snapshot
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
    require(type(s.observed_at) is datetime and s.observed_at.tzinfo is not None
            and now - MAX_SNAPSHOT_AGE <= s.observed_at <= now, 'STALE_CERTIFICATION_SNAPSHOT')
    require(all(value is False for value in (s.production_go, s.live_capabilities_enabled,
                                            s.external_effects_enabled)), 'CERTIFIER_POLICY_NOT_SAFE')
    require(s.dependencies_complete is True and s.dependencies_certified is True,
            'CERTIFIER_DEPENDENCIES_UNVERIFIED')
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


def _validate_snapshot(acquired, binding, now, host):
    from .policy import resolve_edge, PolicyError
    _validate_snapshot_data(acquired,binding,now,host)
    try: return resolve_edge(acquired.snapshot.mapping,binding.source_ref,binding.target_ref)[0]
    except PolicyError: require(False,'UNREGISTERED_CERTIFICATION_SCOPE')


def _validate(acquired, binding, now, host):
    require(type(acquired) is AcquiredCertification, 'AUTHENTICATED_EXISTING_CERTIFICATION_REQUIRED')
    source_level = _validate_snapshot(acquired, binding, now, host)
    receipt = acquired.receipt; s = acquired.snapshot
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


def _contract(verifier, acquired, now):
    require(verifier is not None, 'CERTIFIER_ACCEPTED_CONTRACT_UNCONFIGURED')
    return _validate_contract(verifier.verify(acquired, now), acquired, now)


def _validate_contract(value, acquired, now):
    from .decision import CONTROL_PLANE_CONTEXTS
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
            and value.expires_at <= min(acquired.authority.expires_at, acquired.receipt.expires_at, acquired.snapshot.lease.expires_at),
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
        require(_contract(self.contract_verifier, acquired, self.clock()) == contract, 'CERTIFIER_CONTRACT_CHANGED')
        final = self.clock()
        _validate(acquired, binding, final, self.host)
        _validate_contract(contract, acquired, final)
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
            effect_time = self.clock()
            _validate(fresh, binding, effect_time, self.host)
            _validate_contract(contract, fresh, effect_time)
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
        require(installation.get('repository_selection') == 'selected'
                and installation.get('account', {}).get('login') == 'appolon1908'
                and type(installation['account'].get('id')) is int and installation['account']['id'] > 0,
                'CERTIFIER_SELECTED_INSTALLATION_OWNER_REQUIRED')
        token = self.request('POST', f'/app/installations/{authority.installation_id}/access_tokens', jwt,
                             {'repository_ids': [repository_id], 'permissions': dict(self.PERMISSIONS)})
        require(token['permissions'] == self.PERMISSIONS and len(token['repositories']) == 1
                and token['repositories'][0]['id'] == repository_id, 'CERTIFIER_TOKEN_SCOPE_MISMATCH')
        expiry = datetime.fromisoformat(token['expires_at'].replace('Z', '+00:00'))
        require(_future(expiry, now) and _text(token['token']), 'CERTIFIER_TOKEN_UNAVAILABLE')
        self._token, self._expires = token['token'], min(expiry, authority.expires_at)
        repository = self.get(f'/repositories/{repository_id}')
        require(type(repository.get('id')) is int and repository['id'] == repository_id
                and repository.get('full_name') in authority.repositories
                and repository.get('owner', {}).get('login') == installation['account']['login']
                and type(repository['owner'].get('id')) is int
                and repository['owner']['id'] == installation['account']['id'], 'CERTIFIER_REPOSITORY_OWNER_OR_ID_MISMATCH')
        coverage = self.request('GET', f'/repos/{repository["full_name"]}/installation', jwt)
        require(all(coverage.get(k) == installation.get(k) for k in
                    ('id', 'app_id', 'suspended_at', 'repository_selection', 'permissions'))
                and coverage.get('account', {}).get('id') == installation['account']['id']
                and coverage.get('account', {}).get('login') == installation['account']['login'],
                'CERTIFIER_INSTALLATION_REPOSITORY_COVERAGE_MISMATCH')

    def bind_effect_expiry(self, expires_at):
        require(self._token is not None and _future(expires_at, self.clock()), 'CERTIFIER_EFFECT_AUTHORITY_EXPIRED')
        self._expires = min(self._expires, expires_at)

    def _call(self, method, path, body=None):
        require(method == 'GET' or (method == 'POST' and
                (path == '/graphql' or re.fullmatch(r'/repos/[^/]+/[^/]+/check-runs', path))),
                'CERTIFIER_API_EFFECT_REFUSED')
        return super()._call(method, path, body)


class CertifierGitHubVerifier:
    """Observe online source/base, merge checks, protection and independent reviews."""
    def __init__(self, api, *, atomic_policy_reader=None):
        self.api, self.atomic_policy_reader = api, atomic_policy_reader

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
        self.api.bind_effect_expiry(min(contract.expires_at, acquired.authority.expires_at,
            acquired.receipt.expires_at, acquired.snapshot.lease.expires_at))
        b = acquired.snapshot.observed_binding
        value = self.api.post(f'/repos/{b.repository}/check-runs', {
            'name': contract.certificate_name, 'head_sha': b.source_sha,
            'external_id': binding_digest(b), 'status': 'completed', 'conclusion': 'success',
            'output': {'title': 'Existing authenticated scope certification',
                       'summary': 'Independent registry receipt verified for the exact source and target binding.'}})
        require(type(value.get('id')) is int and value['id'] > 0, 'CERTIFIER_CHECK_RECEIPT_UNAVAILABLE')
        return value['id']

    def emit_first(self, acquired, contract):
        self.api.bind_effect_expiry(min(contract.expires_at, acquired.authority.expires_at,
            acquired.expires_at, acquired.snapshot.lease.expires_at))
        b = acquired.snapshot.observed_binding
        value = self.api.post(f'/repos/{b.repository}/check-runs', {
            'name': contract.certificate_name, 'head_sha': b.source_sha,
            'external_id': binding_digest(b), 'status': 'completed', 'conclusion': 'success',
            'output': {'title': 'First scope certification',
                       'summary': 'Authenticated operator scope delegation and independent current evidence verified.'}})
        require(type(value.get('id')) is int and value['id'] > 0, 'FIRST_CERTIFICATION_CHECK_RECEIPT_UNAVAILABLE')
        return value['id']

    def verify_dependencies(self, acquired, contract, now):
        from datetime import timedelta
        deadline = contract.expires_at
        if getattr(acquired,'atomic_inventory',None) is not None:
            from .atomic_receipts import verify_inclusions
            deadline = min(deadline, verify_inclusions(self.api,self.atomic_policy_reader,
                acquired,contract,acquired.atomic_inventory,now))
        if acquired.dependencies:
            self.api.assert_identity(acquired.authority, acquired.repository_id, now)
        for dependency in acquired.dependencies:
            require(dependency.issuer_app_id == contract.certifier_app_id
                    and dependency.name == contract.certificate_name and _future(dependency.expires_at, now),
                    'FIRST_CERTIFICATION_DEPENDENCY_ISSUER_UNACCEPTED')
            b = dependency.binding
            for ref, sha in ((b.source_ref, b.source_sha), (b.target_ref, b.target_base_sha)):
                value = self.api.get(f'/repos/{b.repository}/branches/{quote(ref, safe="")}')
                require(value['commit']['sha'] == sha, 'FIRST_CERTIFICATION_DEPENDENCY_REF_MOVED')
            value = self.api.get(f'/repos/{b.repository}/check-runs/{dependency.check_id}')
            require(value['id'] == dependency.check_id and value['app']['id'] == dependency.issuer_app_id
                    and value['name'] == dependency.name and value['head_sha'] == b.source_sha
                    and value['external_id'] == binding_digest(b)
                    and value['status'] == 'completed' and value['conclusion'] == 'success',
                    'FIRST_CERTIFICATION_DEPENDENCY_RECEIPT_UNVERIFIED')
            completed_raw = value.get('completed_at')
            require(type(completed_raw) is str, 'FIRST_CERTIFICATION_DEPENDENCY_TIME_UNAVAILABLE')
            try:
                completed = datetime.fromisoformat(completed_raw.replace('Z', '+00:00'))
            except (ValueError, TypeError):
                require(False, 'FIRST_CERTIFICATION_DEPENDENCY_TIME_INVALID')
            require(completed.tzinfo is not None and completed.utcoffset() == timedelta(0),
                    'FIRST_CERTIFICATION_DEPENDENCY_TIME_INVALID')
            fresh_until = completed + timedelta(seconds=contract.max_receipt_age_seconds)
            require(completed <= now < fresh_until, 'FIRST_CERTIFICATION_DEPENDENCY_RECEIPT_STALE_OR_FUTURE')
            suite_ref = value.get('check_suite')
            require(type(suite_ref) is dict and type(suite_ref.get('id')) is int and suite_ref['id'] > 0,
                    'FIRST_CERTIFICATION_DEPENDENCY_SUITE_UNAVAILABLE')
            suite = self.api.get(f'/repos/{b.repository}/check-suites/{suite_ref["id"]}')
            require(type(suite.get('id')) is int and suite['id'] == suite_ref['id']
                    and suite.get('app', {}).get('id') == contract.certifier_app_id
                    and suite.get('head_sha') == b.source_sha and suite.get('status') == 'completed'
                    and suite.get('conclusion') == 'success', 'FIRST_CERTIFICATION_DEPENDENCY_SUITE_UNVERIFIED')
            deadline = min(deadline, dependency.expires_at, fresh_until)
            for ref, sha in ((b.source_ref, b.source_sha), (b.target_ref, b.target_base_sha)):
                value = self.api.get(f'/repos/{b.repository}/branches/{quote(ref, safe="")}')
                require(value['commit']['sha'] == sha, 'FIRST_CERTIFICATION_DEPENDENCY_REF_MOVED')
        return deadline

    def readback(self, acquired, contract, check_id):
        b = acquired.snapshot.observed_binding
        value = self.api.get(f'/repos/{b.repository}/check-runs/{check_id}')
        return (type(value.get('id')) is int and value['id'] == check_id
                and value.get('app', {}).get('id') == contract.certifier_app_id
                and value.get('name') == contract.certificate_name and value.get('head_sha') == b.source_sha
                and value.get('external_id') == binding_digest(b) and value.get('status') == 'completed'
                and value.get('conclusion') == 'success')


class RestrictedCertificationRegistry:
    """Read-only source adapter for the EMPTY, separately accepted 011 model and 012 scope lease API.

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
        self.connection.set_session(readonly=True, autocommit=False, isolation_level='READ COMMITTED')

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
                        'atomic_inspection','controller_coordinator','frozen_recovery','scoped_admission','scope_assignment_leases','atomic_receipts')
          AND (pg_has_role(session_user,n.nspowner,'MEMBER') OR has_schema_privilege(session_user,n.oid,'CREATE')))
         AND NOT EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
          WHERE t.relkind IN ('r','p','v','m','f')
          AND (n.nspname IN ('certifier_authority','publisher_authority','assignment_leases','scoped_registration',
                            'atomic_inspection','controller_coordinator','frozen_recovery','scoped_admission','scope_assignment_leases','atomic_receipts')
               OR n.nspname='public')
          AND (pg_has_role(session_user,t.relowner,'MEMBER')
               OR has_table_privilege(session_user,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')))
         AND NOT EXISTS(SELECT 1 FROM pg_proc f JOIN pg_namespace n ON n.oid=f.pronamespace
          WHERE n.nspname IN ('certifier_authority','publisher_authority','assignment_leases','scoped_registration',
                             'atomic_inspection','controller_coordinator','frozen_recovery','scoped_admission','scope_assignment_leases','atomic_receipts')
          AND f.oid IS DISTINCT FROM to_regprocedure('assignment_leases.inspect_binding(uuid)')
          AND f.oid IS DISTINCT FROM to_regprocedure('scope_assignment_leases.inspect_binding(uuid)')
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
                cur.execute('SELECT scope_assignment_leases.inspect_binding(%s)', (assignment_id,))
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
            min(policy.expires_at, a.expires_at, acquired.receipt.expires_at, acquired.snapshot.lease.expires_at), 'SCOPE_CERTIFICATION')


@dataclass(frozen=True)
class CertificationDependency:
    binding: PromotionRequest
    repository_id: int
    check_id: int
    issuer_app_id: int
    name: str
    expires_at: datetime


@dataclass(frozen=True)
class PendingCertification:
    authority: Authority
    snapshot: TrustedSnapshot
    repository_id: int
    pr_number: int
    scope_type: str
    scope_name: str
    assignment_id: str
    lease_id: str
    lease_epoch: int
    principal: str
    delegation_ref: str
    capability_receipt: str
    issued_at: datetime
    expires_at: datetime
    dependencies: tuple[CertificationDependency, ...]
    atomic_inventory: object = None  # Authenticated014 read port; never caller policy.


@dataclass(frozen=True)
class AcceptedFirstCertificationContract:
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
    scope_type: str
    scope_name: str
    delegation_ref: str
    capability_receipt: str
    max_receipt_age_seconds: int


def _validate_pending(acquired, binding, now, host):
    from datetime import timedelta
    require(type(acquired) is PendingCertification, 'AUTHENTICATED_PENDING_SCOPE_DELEGATION_REQUIRED')
    source_level = _validate_snapshot(acquired, binding, now, host)
    s = acquired.snapshot; lease = s.lease
    require(s.certificate is None, 'FIRST_CERTIFICATION_CANNOT_USE_HISTORICAL_CERTIFICATE')
    require(acquired.scope_type == source_level.upper() and acquired.scope_name == binding.source_ref
            and _text(acquired.delegation_ref) and _text(acquired.capability_receipt),
            'FIRST_CERTIFICATION_EXACT_SCOPE_DELEGATION_REQUIRED')
    require(type(acquired.issued_at) is datetime and acquired.issued_at.tzinfo is not None
            and acquired.issued_at <= now < acquired.expires_at <= acquired.issued_at + timedelta(minutes=5)
            and acquired.expires_at <= acquired.authority.expires_at, 'FIRST_CERTIFICATION_DELEGATION_EXPIRED_OR_UNBOUNDED')
    require(type(lease) is LeaseEvidence and lease.binding == binding and lease.state == 'ACTIVE'
            and _future(lease.expires_at, now) and acquired.expires_at <= lease.expires_at
            and _text(lease.owner) and lease.owner == lease.expected_owner == acquired.principal
            and lease.assignment_id == acquired.assignment_id and _text(acquired.assignment_id)
            and _text(acquired.lease_id) and type(acquired.lease_epoch) is int and acquired.lease_epoch > 0,
            'FIRST_CERTIFICATION_CURRENT_SCOPE_LEASE_REQUIRED')
    require(type(acquired.dependencies) is tuple and len(acquired.dependencies) <= 100,
            'FIRST_CERTIFICATION_DEPENDENCY_POLICY_UNAVAILABLE')
    if acquired.atomic_inventory is not None:
        from .atomic_receipts import AtomicInventory
        require(acquired.scope_type == 'SUBSECTION' and type(acquired.atomic_inventory) is AtomicInventory
                and bool(acquired.atomic_inventory.receipts), 'FIRST_CERTIFICATION_ATOMIC_INVENTORY_INVALID')
    seen = set()
    from .policy import resolve_edge, PolicyError
    for value in acquired.dependencies:
        require(type(value) is CertificationDependency and type(value.binding) is PromotionRequest
                and value.binding != binding and value.binding.repository == binding.repository
                and value.binding.product == binding.product and value.repository_id == acquired.repository_id
                and all(type(v) is int and v > 0 for v in (value.repository_id, value.check_id, value.issuer_app_id))
                and _text(value.name) and _future(value.expires_at, now), 'FIRST_CERTIFICATION_DEPENDENCY_INVALID')
        try:
            resolve_edge(s.mapping, value.binding.source_ref, value.binding.target_ref)
        except PolicyError:
            require(False, 'FIRST_CERTIFICATION_DEPENDENCY_SCOPE_UNREGISTERED')
        key = binding_digest(value.binding)
        require(key not in seen, 'FIRST_CERTIFICATION_DEPENDENCY_AMBIGUOUS')
        seen.add(key)


def _first_contract(verifier, acquired, now):
    require(verifier is not None, 'FIRST_CERTIFICATION_ACCEPTANCE_UNCONFIGURED')
    return _validate_first_contract(verifier.verify(acquired, now), acquired, now)


def _validate_first_contract(value, acquired, now):
    from .decision import CONTROL_PLANE_CONTEXTS
    require(type(value) is AcceptedFirstCertificationContract, 'FIRST_CERTIFICATION_ACCEPTANCE_UNVERIFIED')
    require(all(type(v) is int and v > 0 for v in (value.repository_id, value.pr_number,
            value.certifier_app_id, value.publisher_app_id)), 'FIRST_CERTIFICATION_ACCEPTANCE_IDENTITIES_INVALID')
    require(value.binding_hash == binding_digest(acquired.snapshot.observed_binding)
            and value.repository_id == acquired.repository_id and value.pr_number == acquired.pr_number
            and value.certifier_app_id == acquired.authority.app_id
            and value.certifier_app_id not in (15368, value.publisher_app_id)
            and value.scope_type == acquired.scope_type and value.scope_name == acquired.scope_name
            and value.delegation_ref == acquired.delegation_ref and value.capability_receipt == acquired.capability_receipt,
            'FIRST_CERTIFICATION_ACCEPTANCE_SCOPE_OR_IDENTITY_MISMATCH')
    require(_text(value.certificate_name) and value.certificate_name not in CONTROL_PLANE_CONTEXTS
            and value.certificate_name not in {v.name for v in acquired.snapshot.required_checks}
            and all(v.producer not in ('github-actions:' + str(value.certifier_app_id),
                                      'github-actions:' + str(value.publisher_app_id))
                    for v in acquired.snapshot.required_checks), 'FIRST_CERTIFICATION_DISTINCT_ISSUER_REQUIRED')
    require(type(value.max_receipt_age_seconds) is int and 1 <= value.max_receipt_age_seconds <= 300,
            'FIRST_CERTIFICATION_DEPENDENCY_FRESHNESS_POLICY_REQUIRED')
    require(type(value.controller_contexts) is tuple and bool(value.controller_contexts)
            and len(set(value.controller_contexts)) == len(value.controller_contexts)
            and set(value.controller_contexts) <= set(CONTEXTS)
            and value.purpose == 'FIRST_SCOPE_CERTIFICATION' and _text(value.receipt_ref)
            and _future(value.expires_at, now) and value.expires_at <= acquired.expires_at,
            'FIRST_CERTIFICATION_ACCEPTANCE_INVALID')
    return value


class AcceptedFirstCertificationContractVerifier:
    """Scoped first issuance is delegated by operator row AND protected policy."""
    def __init__(self, protected_policy_reader): self.protected_policy_reader = protected_policy_reader

    def verify(self, acquired, now):
        from .publisher_adapter import PublicationDenied
        try:
            from .publisher_acceptance import load_acceptance
            policy = load_acceptance(self.protected_policy_reader(), now)
        except PublicationDenied:
            raise
        except Exception:
            raise PublicationDenied('FIRST_CERTIFICATION_ACCEPTANCE_UNAVAILABLE') from None
        a = acquired.authority; b = acquired.snapshot.observed_binding
        require(policy.certificate_app_id == a.app_id and policy.certificate_installation_id == a.installation_id
                and policy.publisher_app_id != a.app_id and policy.certifier_custody_receipt == a.custody_receipt
                and policy.certifier_capability_receipt == acquired.capability_receipt
                and (b.repository, acquired.repository_id) in policy.repositories,
                'FIRST_CERTIFICATION_ACCEPTANCE_PINS_MISMATCH')
        return AcceptedFirstCertificationContract(binding_digest(b), acquired.repository_id, acquired.pr_number,
            a.app_id, policy.publisher_app_id, policy.certificate_name, policy.controller_contexts,
            policy.acceptance_ref + '#' + policy.revision, min(policy.expires_at, acquired.expires_at),
            'FIRST_SCOPE_CERTIFICATION', acquired.scope_type, acquired.scope_name,
            acquired.delegation_ref, acquired.capability_receipt, policy.max_receipt_age_seconds)


class AuthenticatedFirstCertifier(AuthenticatedCertifier):
    """First issuance from authenticated scoped delegation, never promotion.allowed."""
    def _acquire(self, binding):
        require(all(v is not None for v in (self.registry, self.github, self.ledger)),
                'FIRST_CERTIFICATION_PRIVILEGED_DEPENDENCIES_UNCONFIGURED')
        require(self.contract_verifier is not None, 'FIRST_CERTIFICATION_ACCEPTANCE_UNCONFIGURED')
        now = self.clock()
        acquired = self.registry.acquire(binding, now)
        _validate_pending(acquired, binding, now, self.host)
        contract = _first_contract(self.contract_verifier, acquired, now)
        dependency_deadline = self.github.verify_dependencies(acquired, contract, now)
        self.github.verify(acquired, contract, now)
        fresh = self.clock()
        require(self.registry.acquire(binding, fresh) == acquired, 'FIRST_CERTIFICATION_DELEGATION_REVOKED_OR_CHANGED')
        require(_first_contract(self.contract_verifier, acquired, self.clock()) == contract, 'FIRST_CERTIFICATION_CONTRACT_CHANGED')
        final = self.clock()
        _validate_pending(acquired, binding, final, self.host)
        effect_contract = replace(contract, expires_at=min(contract.expires_at, dependency_deadline))
        _validate_first_contract(effect_contract, acquired, final)
        return acquired, effect_contract

    def publish(self, binding):
        acquired, contract = self._acquire(binding)
        # Shared key with existing-receipt transport prevents two effects for the
        # same exact binding even when one ledger serves both operations.
        key = 'certifier:' + binding_digest(binding)
        require(self.ledger.reserve(key, str(acquired.authority.epoch)), 'CERTIFIER_INTENT_ALREADY_CONSUMED')
        attempted = False; receipts = []
        try:
            fresh, fresh_contract = self._acquire(binding)
            require(fresh == acquired and fresh_contract == contract, 'FIRST_CERTIFICATION_DELEGATION_REVOKED_OR_CHANGED')
            effect_time = self.clock()
            _validate_pending(fresh, binding, effect_time, self.host)
            _validate_first_contract(contract, fresh, effect_time)
            attempted = True
            check_id = self.github.emit_first(fresh, contract)
            require(self.github.readback(fresh, contract, check_id), 'FIRST_CERTIFICATION_READBACK_MISMATCH')
            receipts.append({'check_id': check_id, 'delegation_ref': fresh.delegation_ref})
        except BaseException as exc:
            state = 'UNCERTAIN' if attempted else 'REJECTED'
            self.ledger.record(key, state, receipts)
            if not isinstance(exc, Exception): raise
            return PublicationResult(state, tuple(receipts))
        self.ledger.record(key, 'COMPLETE', receipts)
        return PublicationResult('COMPLETE', tuple(receipts))


class RestrictedFirstCertificationRegistry(RestrictedCertificationRegistry):
    """Read-only scoped delegation + genuine scope-level lease API (012/013).

    Missing operator read model, product grant or scope lease API denies. There is
    no fallback to legacy metadata or the incompatible atomic assignment API.
    """
    @staticmethod
    def _registered_dependencies(cur, acquired, now=None):
        """Reconcile the entire current registered hierarchy, never snapshot claims."""
        from .policy import ScopeEdge
        b = acquired.snapshot.observed_binding; mapping = acquired.snapshot.mapping
        cur.execute("""SELECT p.repository,p.test_branch,p.promotion_chain,r.payload,
         s.repository_id,s.development_ref,s.testing_ref,s.staging_ref,s.production_ref,s.release_ref,
         NOT EXISTS(SELECT 1 FROM scoped_registration.workstations rw
          LEFT JOIN public.workstations w ON w.workstation_id=rw.workstation_id AND w.product=rw.product
          WHERE rw.product=p.product AND w.workstation_id IS NULL)
         AND NOT EXISTS(SELECT 1 FROM scoped_registration.lanes l
          LEFT JOIN public.workstations w ON w.workstation_id=l.identity AND w.product=l.product
          WHERE l.product=p.product AND l.kind='workstation' AND w.workstation_id IS NULL)
         FROM public.products p JOIN scoped_registration.products r USING(product)
         JOIN scope_assignment_leases.products s USING(product)
         WHERE p.product=%s AND s.repository=p.repository AND s.active AND s.expires_at>clock_timestamp()
         AND NOT p.production_go AND NOT p.live_capabilities_enabled AND NOT p.external_effects_enabled""", (b.product,))
        product = cur.fetchone()
        require(product is not None, 'FIRST_CERTIFICATION_CURRENT_PRODUCT_REGISTRY_REQUIRED')
        repository, testing, chain, registered, repo_id, development, test_ref, staging, production, release, complete = product
        require(repository == b.repository and repo_id == acquired.repository_id and complete is True
                and registered == dict(product=b.product, repository=repository, test_branch=testing, promotion_chain=chain)
                and chain == [development, test_ref, staging, production] and testing == test_ref
                and (mapping.development_ref, mapping.testing_ref, mapping.staging_ref,
                     mapping.production_ref, mapping.release_ref) == (development, test_ref, staging, production, release),
                'FIRST_CERTIFICATION_PRODUCT_REGISTRY_DRIFT')
        cur.execute("""SELECT section_id,section_key,branch,depends_on FROM public.sections
         WHERE product=%s ORDER BY branch LIMIT 1001""", (b.product,))
        sections = cur.fetchall()
        require(len(sections) <= 1000 and all(all(_text(value) for value in row[:3]) for row in sections)
                and all(len({row[index] for row in sections}) == len(sections) for index in (0, 1, 2)),
                'FIRST_CERTIFICATION_SECTION_INVENTORY_INVALID')
        section_refs = {key: ref for _, key, ref, _ in sections}
        section_ids = {ref: identity for identity, _, ref, _ in sections}
        section_branches = {identity: ref for identity, _, ref, _ in sections}
        aliases = {}
        for identity, key, _, _ in sections:
            for alias in (identity, key): aliases.setdefault(alias, set()).add(identity)
        prerequisites = {}; dependents = {identity: set() for identity in section_branches}
        for identity, _, _, declared in sections:
            require(type(declared) is list and len(declared) <= 1000
                    and all(_text(value) for value in declared) and len(set(declared)) == len(declared),
                    'FIRST_CERTIFICATION_SECTION_DEPENDENCY_SHAPE_INVALID')
            resolved = set()
            for alias in declared:
                matches = aliases.get(alias, set())
                require(len(matches) == 1 and identity not in matches,
                        'FIRST_CERTIFICATION_SECTION_DEPENDENCY_REFERENCE_INVALID')
                dependency = next(iter(matches))
                require(dependency not in resolved, 'FIRST_CERTIFICATION_SECTION_DEPENDENCY_REFERENCE_INVALID')
                resolved.add(dependency); dependents[dependency].add(identity)
            prerequisites[identity] = resolved
        # Validate the bounded graph iteratively without recursion depth limits.
        outstanding = {identity: len(values) for identity, values in prerequisites.items()}
        ready = [identity for identity, count in outstanding.items() if count == 0]
        visited = 0
        while ready:
            identity = ready.pop(); visited += 1
            for dependent in dependents[identity]:
                outstanding[dependent] -= 1
                if outstanding[dependent] == 0: ready.append(dependent)
        require(visited == len(sections), 'FIRST_CERTIFICATION_SECTION_DEPENDENCY_CYCLE')
        cur.execute("""SELECT w.workstation_id,w.section,w.subsection,w.branch,w.parent_branch,
         w.worktree,w.order_index,w.depends_on,r.branch,r.worktree,r.payload,l.worktree,l.branch,l.identity
         FROM public.workstations w
         LEFT JOIN scoped_registration.workstations r ON r.workstation_id=w.workstation_id AND r.product=w.product
         LEFT JOIN scoped_registration.lanes l ON l.identity=w.workstation_id AND l.product=w.product AND l.kind='workstation'
         WHERE w.product=%s ORDER BY w.branch LIMIT 1001""", (b.product,))
        workstations = cur.fetchall()
        require(len(workstations) <= 1000, 'FIRST_CERTIFICATION_SUBSECTION_INVENTORY_LIMIT')
        edges = {ScopeEdge('section', ref, 'development', development) for _, _, ref, _ in sections}
        scopes = {}; identities = {}
        for row in workstations:
            wid, section, subsection, ref, parent, worktree, order, depends, registered_ref, registered_tree, payload, lane_tree, lane_ref, lane_id = row
            expected = dict(product=b.product, workstation_id=wid, section=section, subsection=subsection,
                            branch=ref, parent_branch=parent, worktree=worktree, order_index=order)
            require(section_refs.get(section) == parent and payload == expected
                    and registered_ref == ref == lane_ref and registered_tree == worktree == lane_tree
                    and lane_id == wid and wid not in identities and ref not in scopes,
                    'FIRST_CERTIFICATION_SUBSECTION_REGISTRY_DRIFT')
            require(type(depends) is list and len(depends) <= 1000 and all(_text(v) for v in depends)
                    and len(set(depends)) == len(depends), 'FIRST_CERTIFICATION_SUBSECTION_DEPENDENCY_DRIFT')
            scopes[ref] = (parent, wid, tuple(depends)); identities[wid] = (ref, parent)
            edges.add(ScopeEdge('subsection', ref, 'section', parent))
        # depends_on uses canonical workstation IDs only. Do not guess aliases
        # from subsection names or branch refs; identity uniqueness is checked above.
        subsection_dependents = {identity: set() for identity in identities}
        subsection_outstanding = {}
        for _, identity, dependencies in scopes.values():
            require(all(value in identities and value != identity for value in dependencies),
                    'FIRST_CERTIFICATION_SUBSECTION_DEPENDENCY_REFERENCE_INVALID')
            subsection_outstanding[identity] = len(dependencies)
            for dependency in dependencies: subsection_dependents[dependency].add(identity)
        subsection_ready = [identity for identity, count in subsection_outstanding.items() if count == 0]
        subsection_visited = 0
        while subsection_ready:
            identity = subsection_ready.pop(); subsection_visited += 1
            for dependent in subsection_dependents[identity]:
                subsection_outstanding[dependent] -= 1
                if subsection_outstanding[dependent] == 0: subsection_ready.append(dependent)
        require(subsection_visited == len(identities), 'FIRST_CERTIFICATION_SUBSECTION_DEPENDENCY_CYCLE')
        require(len(mapping.scope_edges) == len(edges) and set(mapping.scope_edges) == edges,
                'FIRST_CERTIFICATION_SCOPE_MAPPING_HIDES_CURRENT_REGISTRY')
        scope = acquired.scope_type
        if scope == 'SECTION':
            require(b.source_ref in section_ids, 'FIRST_CERTIFICATION_SECTION_REGISTRY_REQUIRED')
            required = {(ref, parent) for ref, (parent, _, _) in scopes.items() if parent == b.source_ref}
            required.update((section_branches[value], development)
                            for value in prerequisites[section_ids[b.source_ref]])
        elif scope == 'DEVELOPMENT':
            required = {(ref, development) for _, _, ref, _ in sections}
        elif scope in ('TESTING', 'STAGING', 'PRODUCTION'):
            required = {dict(TESTING=(development, test_ref), STAGING=(test_ref, staging), PRODUCTION=(staging, production))[scope]}
        elif scope == 'SUBSECTION':
            require(b.source_ref in scopes, 'FIRST_CERTIFICATION_SUBSECTION_REGISTRY_REQUIRED')
            parent, workstation, depends = scopes[b.source_ref]
            from .atomic_receipts import read_inventory
            atomic_inventory = read_inventory(cur,acquired,workstation,now or datetime.now(timezone.utc))
            require(all(value in identities and value != workstation for value in depends),
                    'FIRST_CERTIFICATION_SUBSECTION_PREREQUISITE_UNREGISTERED')
            required = {identities[value] for value in depends}
        else:
            require(False, 'FIRST_CERTIFICATION_SCOPE_UNSUPPORTED')
        declared = [(value.binding.source_ref, value.binding.target_ref) for value in acquired.dependencies]
        require(len(declared) == len(required) and set(declared) == required,
                'FIRST_CERTIFICATION_CURRENT_DEPENDENCY_INVENTORY_MISMATCH')
        return atomic_inventory if scope == 'SUBSECTION' else None

    def acquire(self, binding, now):
        import uuid
        from .publisher_acquisition import decode_snapshot
        from .policy import resolve_edge
        require(type(binding) is PromotionRequest, 'INVALID_CERTIFICATION_BINDING')
        self._session()
        with self.connection:
            with self.connection.cursor() as cur:
                self._roles(cur)
                cur.execute("""SELECT c.authority,c.snapshot,c.repository_id,c.pr_number,
                 c.scope_type,c.scope_name,c.assignment_id,c.lease_id,c.lease_epoch,c.lease_principal,
                 c.delegation_ref,c.capability_receipt,c.issued_at,c.expires_at,c.dependency_policy,c.accepted_by
                 FROM certifier_authority.pending_bindings c
                 JOIN certifier_authority.product_grants g ON g.principal=c.principal AND g.product=c.product
                 JOIN pg_roles r ON r.rolname=c.principal AND r.oid=c.role_oid AND r.oid=g.role_oid
                 JOIN public.products p ON p.product=c.product AND p.repository=c.repository
                 WHERE c.binding_hash=%s AND c.principal=session_user AND c.product=%s AND c.repository=%s
                 AND g.repository=c.repository AND g.repository_id=c.repository_id
                 AND c.active AND g.active AND c.issued_at<=clock_timestamp()
                 AND c.expires_at>clock_timestamp() AND g.expires_at>clock_timestamp()
                 AND c.purpose='FIRST_SCOPE_CERTIFICATION' AND c.accepted_by='Ralph L. Appolon'
                 AND NOT p.production_go AND NOT p.live_capabilities_enabled AND NOT p.external_effects_enabled
                 LIMIT 2""", (binding_digest(binding), binding.product, binding.repository))
                rows = cur.fetchall()
                require(len(rows) == 1, 'FIRST_CERTIFICATION_ACTIVE_PENDING_PRODUCT_GRANT_REQUIRED')
                (raw_authority, raw_snapshot, repo_id, pr, scope_type, scope_name, assignment, lease_id, epoch,
                 principal, delegation_ref, capability, issued_at, expires_at, raw_dependencies, accepted_by) = rows[0]
                raw_authority = dict(raw_authority)
                raw_authority['expires_at'] = datetime.fromisoformat(raw_authority['expires_at'])
                raw_authority['repositories'] = tuple(raw_authority['repositories'])
                authority = Authority(**raw_authority)
                snapshot = decode_snapshot(raw_snapshot)
                require(type(raw_dependencies) is list and len(raw_dependencies) <= 100
                        and accepted_by == 'Ralph L. Appolon', 'FIRST_CERTIFICATION_OPERATOR_DEPENDENCY_POLICY_REQUIRED')
                dependencies = []
                for raw in raw_dependencies:
                    raw = dict(raw)
                    raw['binding'] = PromotionRequest(**raw['binding'])
                    raw['expires_at'] = datetime.fromisoformat(raw['expires_at'])
                    dependencies.append(CertificationDependency(**raw))
                assignment_id = str(uuid.UUID(str(assignment)))
                acquired = PendingCertification(authority, snapshot, repo_id, pr, scope_type, scope_name,
                    assignment_id, str(lease_id), epoch, principal, delegation_ref, capability,
                    issued_at, expires_at, tuple(dependencies))
                _validate_pending(acquired, binding, now, authority.host)
                acquired = replace(acquired, atomic_inventory=self._registered_dependencies(cur, acquired, now))
                cur.execute('SELECT scope_assignment_leases.inspect_binding(%s)', (assignment_id,))
                row = cur.fetchone()
                require(row is not None and type(row[0]) is dict, 'FIRST_CERTIFICATION_ONLINE_SCOPE_LEASE_UNAVAILABLE')
                live = row[0]
                require(live.get('authority') == 'ONLINE_DATABASE_RECEIPT' and live.get('state') == 'ACTIVE'
                        and live.get('binding_id') == assignment_id and live.get('lease_id') == str(lease_id)
                        and type(live.get('epoch')) is int and live['epoch'] == epoch
                        and live.get('principal') == principal, 'FIRST_CERTIFICATION_ONLINE_SCOPE_LEASE_REVOKED_OR_CHANGED')
                source_level, target_level = resolve_edge(snapshot.mapping, binding.source_ref, binding.target_ref)
                expected = dict(repository=binding.repository, repository_id=repo_id, product=binding.product,
                    source_ref=binding.source_ref, target_ref=binding.target_ref, head_sha=binding.source_sha,
                    base_sha=binding.target_base_sha, principal=principal,
                    source_level=source_level, target_level=target_level)
                actual = live.get('binding', {})
                require(all(actual.get(k) == v for k, v in expected.items()), 'FIRST_CERTIFICATION_ONLINE_SCOPE_BINDING_MISMATCH')
                expiry = datetime.fromisoformat(live['expires_at'])
                require(_future(expiry, now) and snapshot.lease.expires_at == expiry,
                        'FIRST_CERTIFICATION_ONLINE_SCOPE_LEASE_EXPIRED_OR_CHANGED')
                return acquired


def build_first_certifier_service(connection, jwt_provider, ledger_path, policy_reader,
                                  *, host, clock=lambda: datetime.now(timezone.utc), atomic_policy_reader=None):
    """Compose administered source dependencies; no credential/config provisioning.

    Call only from an operator-controlled integration. connection must authenticate
    the independent restricted reader, jwt_provider the dedicated certifier key
    custodian, and policy_reader the protected accepted policy. No author JSON,
    issuer guessing, environment enabling, public CLI or installed caller exists.
    Construction creates only the caller-provisioned private durable intent ledger.
    """
    from .publisher_effect import IntentLedger
    api = CertifierGitHubClient(jwt_provider, clock=clock)
    return AuthenticatedFirstCertifier(RestrictedFirstCertificationRegistry(connection),
        CertifierGitHubVerifier(api,atomic_policy_reader=atomic_policy_reader), IntentLedger(ledger_path),
        contract_verifier=AcceptedFirstCertificationContractVerifier(policy_reader),
        host=host, clock=clock)
