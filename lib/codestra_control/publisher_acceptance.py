"""Privileged operator acceptance and independently authenticated producer reads.

The protected reader authenticates operator origin outside this module. JSON and
receipt strings alone never authorize publication. The independent certifier API
port must be administered separately: it can forward the three identity GETs to
a credential custodian without exposing the certifier signer to the publisher.
No identities, credentials, grants or acceptance records are provisioned here.
"""
from dataclasses import dataclass, fields
from datetime import datetime, timedelta
import hashlib
import json
import re

from .publisher_adapter import (Acquired, Authority, CONTEXTS, PublicationDenied,
                                binding_digest, require, verify_issuer)
from .publisher_provenance import VerifiedProducerContract
from .publisher_github import GitHubAppClient


CERTIFIER_INSTALLATION_PERMISSIONS = {
    'checks': 'write', 'contents': 'read', 'pull_requests': 'read',
    'administration': 'read', 'metadata': 'read',
}


@dataclass(frozen=True)
class AcceptedProducerPolicy:
    schema: str
    state: str
    accepted_by: str
    acceptance_ref: str
    publisher_app_id: int
    publisher_installation_id: int
    certificate_app_id: int
    certificate_installation_id: int
    certificate_name: str
    controller_contexts: tuple[str, ...]
    repositories: tuple[tuple[str, int], ...]
    custody_receipt: str
    certifier_custody_receipt: str
    certifier_capability_receipt: str
    accepted_at: datetime
    expires_at: datetime
    max_receipt_age_seconds: int
    revision: str


def _positive(value):
    return type(value) is int and value > 0


def _text(value):
    return type(value) is str and bool(value.strip())


def _utc(value):
    require(type(value) is str, 'PRODUCER_ACCEPTANCE_TIME_INVALID')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        raise PublicationDenied('PRODUCER_ACCEPTANCE_TIME_INVALID') from None
    require(parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0),
            'PRODUCER_ACCEPTANCE_TIME_INVALID')
    return parsed


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'PRODUCER_ACCEPTANCE_DUPLICATE_KEY')
        result[key] = value
    return result


def load_acceptance(raw: bytes, now: datetime) -> AcceptedProducerPolicy:
    """Decode a bounded, current, exact-schema protected operator acceptance."""
    require(type(raw) is bytes and 0 < len(raw) <= 65536,
            'PRODUCER_ACCEPTANCE_BYTES_REQUIRED')
    require(type(now) is datetime and now.tzinfo is not None
            and now.utcoffset() == timedelta(0), 'PRODUCER_ACCEPTANCE_TIME_INVALID')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise PublicationDenied('PRODUCER_ACCEPTANCE_JSON_INVALID') from None
    keys = {field.name for field in fields(AcceptedProducerPolicy)} - {'revision'}
    require(type(value) is dict and set(value) == keys, 'PRODUCER_ACCEPTANCE_SCHEMA_INVALID')
    require(value['schema'] == 'codestra.producer-acceptance.v1'
            and value['state'] == 'ACCEPTED' and value['accepted_by'] == 'Ralph L. Appolon',
            'PRODUCER_ACCEPTANCE_NOT_ACCEPTED')
    for name in ('publisher_app_id', 'publisher_installation_id', 'certificate_app_id',
                 'certificate_installation_id'):
        require(_positive(value[name]), 'PRODUCER_ACCEPTANCE_IDENTITY_INVALID')
    require(value['publisher_app_id'] != value['certificate_app_id']
            and 15368 not in (value['publisher_app_id'], value['certificate_app_id'])
            and value['publisher_installation_id'] != value['certificate_installation_id'],
            'PRODUCER_ACCEPTANCE_INDEPENDENT_APPS_REQUIRED')
    for name in ('acceptance_ref', 'custody_receipt', 'certifier_custody_receipt',
                 'certifier_capability_receipt', 'certificate_name'):
        require(_text(value[name]), 'PRODUCER_ACCEPTANCE_PIN_INVALID')
    require(value['custody_receipt'] != value['certifier_custody_receipt'],
            'PRODUCER_ACCEPTANCE_INDEPENDENT_CUSTODY_REQUIRED')
    require(value['certificate_name'] not in CONTEXTS, 'PRODUCER_ACCEPTANCE_CERTIFICATE_ALIAS')
    require(type(value['controller_contexts']) is list
            and value['controller_contexts'] == list(CONTEXTS),
            'PRODUCER_ACCEPTANCE_CONTEXTS_INVALID')
    require(type(value['repositories']) is list and bool(value['repositories']),
            'PRODUCER_ACCEPTANCE_REPOSITORIES_INVALID')
    repositories = []
    for item in value['repositories']:
        require(type(item) is dict and set(item) == {'repository', 'repository_id'}
                and type(item['repository']) is str
                and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+', item['repository'])
                and item['repository'].split('/')[1] not in ('.', '..')
                and _positive(item['repository_id']), 'PRODUCER_ACCEPTANCE_REPOSITORY_INVALID')
        repositories.append((item['repository'], item['repository_id']))
    require(len({name.casefold() for name, _ in repositories}) == len(repositories)
            and len({repo_id for _, repo_id in repositories}) == len(repositories),
            'PRODUCER_ACCEPTANCE_REPOSITORY_AMBIGUOUS')
    accepted_at, expires_at = _utc(value['accepted_at']), _utc(value['expires_at'])
    require(accepted_at <= now < expires_at <= accepted_at + timedelta(hours=24),
            'PRODUCER_ACCEPTANCE_EXPIRED_OR_UNBOUNDED')
    age = value['max_receipt_age_seconds']
    require(type(age) is int and 1 <= age <= 300, 'PRODUCER_ACCEPTANCE_RECEIPT_AGE_INVALID')
    return AcceptedProducerPolicy(**dict(value, controller_contexts=tuple(CONTEXTS),
        repositories=tuple(repositories), accepted_at=accepted_at, expires_at=expires_at,
        revision=hashlib.sha256(raw).hexdigest()))


class AcceptedProducerVerifier:
    """Verify protected pins and live producer identities before status intent.

    api is the dedicated publisher GitHubAppClient. certifier_api is an independent
    identity-only port with jwt_provider() and request(method,path,opaque_handle).
    It must authenticate as the accepted certifier App; a publisher JWT cannot
    establish another App's installation. Missing this port always denies.

    These per-repository reads prove current target coverage, not the complete
    selected-repository inventory. Operators must independently accept that full
    installation inventory. Repository-scoped publisher tokens and protected
    policy pins prevent a publication target from expanding automatically.
    """
    def __init__(self, policy_reader, api, *, certifier_api=None):
        self.policy_reader, self.api, self.certifier_api = policy_reader, api, certifier_api

    def _policy(self, now):
        try:
            raw = self.policy_reader()
        except Exception:
            raise PublicationDenied('PRODUCER_ACCEPTANCE_UNAVAILABLE') from None
        return load_acceptance(raw, now)

    @staticmethod
    def _installation(value, installation_id, app_id, owner):
        require(type(value) is dict and type(value.get('id')) is int
                and value['id'] == installation_id and type(value.get('app_id')) is int
                and value['app_id'] == app_id and 'suspended_at' in value
                and value['suspended_at'] is None and value.get('account', {}).get('login') == owner['login']
                and type(value['account'].get('id')) is int and value['account']['id'] == owner['id']
                and value.get('repository_selection') == 'selected',
                'PRODUCER_INSTALLATION_IDENTITY_MISMATCH')

    def verify(self, acquired, now) -> VerifiedProducerContract:
        try:
            return self._verify(acquired, now)
        except PublicationDenied:
            raise
        except Exception:
            # Never expose remote errors, response bodies or credential handles.
            raise PublicationDenied('PRODUCER_ONLINE_VERIFICATION_UNAVAILABLE') from None

    def _verify(self, acquired, now):
        policy = self._policy(now)
        require(self.certifier_api is not None, 'CERTIFIER_IDENTITY_UNCONFIGURED')
        require(type(acquired) is Acquired and type(acquired.authority) is Authority,
                'PRODUCER_AUTHORITY_UNAVAILABLE')
        verify_issuer(acquired, now)
        authority, issuer = acquired.authority, acquired.issuer
        binding = acquired.snapshot.observed_binding
        repo = binding.repository
        require(_positive(authority.app_id) and _positive(authority.installation_id),
                'PRODUCER_AUTHORITY_IDENTITY_INVALID')
        require(authority.authority_name == policy.accepted_by
                and authority.app_id == policy.publisher_app_id
                and authority.installation_id == policy.publisher_installation_id
                and issuer.app_id == policy.certificate_app_id
                and issuer.name == policy.certificate_name
                and authority.custody_receipt == policy.custody_receipt
                and issuer.capability_receipt == policy.certifier_capability_receipt,
                'PRODUCER_ACCEPTANCE_PIN_MISMATCH')
        require(type(acquired.repository_id) is int and (repo, acquired.repository_id) in policy.repositories
                and repo in authority.repositories, 'PRODUCER_ACCEPTANCE_REPOSITORY_MISMATCH')
        require(type(authority.expires_at) is datetime and authority.expires_at.tzinfo is not None
                and authority.expires_at > now, 'PRODUCER_AUTHORITY_EXPIRED')
        require(_positive(acquired.pr_number) and _positive(acquired.certificate_check_id),
                'PRODUCER_RECEIPT_ID_INVALID')

        self.api.assert_identity(authority, acquired.repository_id, now)
        repository = self.api.get(f'/repos/{repo}')
        owner = repository['owner']
        require(type(repository['id']) is int and repository['id'] == acquired.repository_id
                and repository['full_name'] == repo and owner['login'] == repo.split('/')[0]
                and _positive(owner['id']), 'PRODUCER_REPOSITORY_IDENTITY_MISMATCH')
        publisher_installation = self.api.request('GET',
            f'/app/installations/{policy.publisher_installation_id}', self.api.jwt_provider())
        self._installation(publisher_installation, policy.publisher_installation_id,
                           policy.publisher_app_id, owner)
        require(publisher_installation.get('permissions') == GitHubAppClient.PERMISSIONS,
                'PUBLISHER_INSTALLED_PERMISSIONS_MISMATCH')
        # A separate signer/custodian is essential: publisher App JWTs cannot
        # authenticate the installation of a different App.
        handle = self.certifier_api.jwt_provider()
        certifier_app = self.certifier_api.request('GET', '/app', handle)
        require(type(certifier_app.get('id')) is int and certifier_app['id'] == policy.certificate_app_id,
                'CERTIFIER_APP_IDENTITY_MISMATCH')
        installation = self.certifier_api.request('GET',
            f'/app/installations/{policy.certificate_installation_id}', handle)
        self._installation(installation, policy.certificate_installation_id, policy.certificate_app_id, owner)
        coverage = self.certifier_api.request('GET', f'/repos/{repo}/installation', handle)
        self._installation(coverage, policy.certificate_installation_id, policy.certificate_app_id, owner)
        require(installation.get('permissions') == CERTIFIER_INSTALLATION_PERMISSIONS
                and coverage.get('permissions') == CERTIFIER_INSTALLATION_PERMISSIONS,
                'CERTIFIER_INSTALLED_PERMISSIONS_MISMATCH')

        check = self.api.get(f'/repos/{repo}/check-runs/{acquired.certificate_check_id}')
        require(type(check['id']) is int and check['id'] == acquired.certificate_check_id
                and acquired.snapshot.certificate.receipt_id == 'check:' + str(check['id'])
                and type(check['app']['id']) is int and check['app']['id'] == policy.certificate_app_id
                and check['name'] == policy.certificate_name and check['head_sha'] == binding.source_sha
                and check['external_id'] == binding_digest(binding)
                and check['status'] == 'completed' and check['conclusion'] == 'success',
                'PRODUCER_ONLINE_CERTIFICATE_INVALID')
        completed = _utc(check['completed_at'])
        receipt_expiry = completed + timedelta(seconds=policy.max_receipt_age_seconds)
        require(completed <= now < receipt_expiry, 'PRODUCER_ONLINE_CERTIFICATE_STALE_OR_FUTURE')
        suite_id = check['check_suite']['id']
        require(_positive(suite_id), 'PRODUCER_CERTIFICATE_SUITE_INVALID')
        suite = self.api.get(f'/repos/{repo}/check-suites/{suite_id}')
        require(type(suite['id']) is int and suite['id'] == suite_id
                and type(suite['app']['id']) is int and suite['app']['id'] == policy.certificate_app_id
                and suite['head_sha'] == binding.source_sha, 'PRODUCER_CERTIFICATE_SUITE_MISMATCH')
        require(self._policy(now) == policy, 'PRODUCER_ACCEPTANCE_CHANGED')
        return VerifiedProducerContract(binding_digest(binding), acquired.repository_id, acquired.pr_number,
            policy.publisher_app_id, policy.certificate_app_id, policy.certificate_name,
            policy.controller_contexts, policy.acceptance_ref + ':' + policy.revision,
            min(policy.expires_at, authority.expires_at, issuer.expires_at, receipt_expiry), 'STATUS_PUBLICATION')
