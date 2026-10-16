"""Synthetic protected policies and HTTP responses; no selected live identities."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import test_decision as fixture
from test_authenticated_publisher import Store
from codestra_control.publisher_adapter import PublicationDenied, binding_digest
from codestra_control.publisher_github import GitHubAppClient
from codestra_control.publisher_provenance import verify_contract
from codestra_control import publisher_acceptance as acceptance


def policy():
    return {'schema': 'codestra.producer-acceptance.v1', 'state': 'ACCEPTED',
            'accepted_by': 'Ralph L. Appolon', 'acceptance_ref': 'synthetic:acceptance:1',
            'publisher_app_id': 7, 'publisher_installation_id': 8,
            'certificate_app_id': 99, 'certificate_installation_id': 100,
            'certificate_name': 'scope-certification',
            'controller_contexts': ['codestra-control-plane', 'codestra/control-plane'],
            'repositories': [{'repository': 'appolon1908/Breero.com', 'repository_id': 123}],
            'custody_receipt': 'custody:1',
            'certifier_custody_receipt': 'synthetic-certifier-custody:1',
            'certifier_capability_receipt': 'synthetic-issuer-capability',
            'accepted_at': (fixture.NOW-timedelta(minutes=1)).isoformat(),
            'expires_at': (fixture.NOW+timedelta(minutes=4)).isoformat(),
            'max_receipt_age_seconds': 60}


def raw(value):
    return json.dumps(value).encode()


class Transport:
    """Route strict real GitHubAppClient calls to a synthetic online inventory."""
    def __init__(self):
        owner = {'id': 456, 'login': 'appolon1908'}
        self.publisher = {'id': 8, 'app_id': 7, 'suspended_at': None,
                          'account': owner, 'repository_selection': 'selected'}
        self.certifier = {'id': 100, 'app_id': 99, 'suspended_at': None,
                          'account': owner, 'repository_selection': 'selected',
                          'permissions': {'checks': 'write', 'metadata': 'read'}}
        self.repository = {'id': 123, 'full_name': fixture.REQUEST.repository, 'owner': owner}
        self.check = {'id': 10, 'app': {'id': 99}, 'name': 'scope-certification',
                      'head_sha': 'a'*40, 'external_id': binding_digest(fixture.REQUEST),
                      'status': 'completed', 'conclusion': 'success',
                      'completed_at': (fixture.NOW-timedelta(seconds=10)).isoformat(),
                      'check_suite': {'id': 101}}
        self.suite = {'id': 101, 'app': {'id': 99}, 'head_sha': 'a'*40}
        self.certifier_repository_installation = self.certifier
        self.calls = []
        self.error = None

    def __call__(self, method, path, token, body=None):
        self.calls.append((method, path, token, body))
        if self.error:
            raise self.error
        if token == 'synthetic-publisher-jwt':
            if (method, path) == ('GET', '/app'):
                return {'id': 7}
            if (method, path) == ('GET', '/app/installations/8'):
                return deepcopy(self.publisher)
            if (method, path) == ('POST', '/app/installations/8/access_tokens'):
                if body != {'repository_ids': [123], 'permissions': GitHubAppClient.PERMISSIONS}:
                    raise AssertionError('wrong publisher token scope')
                return {'permissions': dict(GitHubAppClient.PERMISSIONS),
                        'repositories': [deepcopy(self.repository)],
                        'expires_at': (fixture.NOW+timedelta(minutes=5)).isoformat(),
                        'token': 'synthetic-installation-token'}
        if token == 'synthetic-certifier-jwt' and method == 'GET':
            if path == '/app':
                return {'id': 99}
            if path == '/app/installations/100':
                return deepcopy(self.certifier)
            if path == '/repos/appolon1908/Breero.com/installation':
                return deepcopy(self.certifier_repository_installation)
        if token == 'synthetic-installation-token' and method == 'GET':
            if path == '/repos/appolon1908/Breero.com':
                return deepcopy(self.repository)
            if path == '/repos/appolon1908/Breero.com/check-runs/10':
                return deepcopy(self.check)
            if path == '/repos/appolon1908/Breero.com/check-suites/101':
                return deepcopy(self.suite)
        raise AssertionError((method, path, token, body))


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.value = policy()
        self.acquired = Store().acquire(fixture.REQUEST)
        self.acquired = replace(self.acquired, snapshot=replace(self.acquired.snapshot,
            certificate=replace(self.acquired.snapshot.certificate, receipt_id='check:10')))
        self.transport = Transport()
        self.api = GitHubAppClient(lambda: 'synthetic-publisher-jwt',
            request=self.transport, clock=lambda: fixture.NOW)
        self.certifier = GitHubAppClient(lambda: 'synthetic-certifier-jwt',
            request=self.transport, clock=lambda: fixture.NOW)
        self.verifier = acceptance.AcceptedProducerVerifier(lambda: raw(self.value), self.api,
            certifier_api=self.certifier)

    def verify(self, acquired=None, now=fixture.NOW):
        return verify_contract(self.verifier, acquired or self.acquired, now)

    def test_accepted_policy_is_deeply_immutable(self):
        accepted = acceptance.load_acceptance(raw(self.value), fixture.NOW)
        self.value['repositories'][0]['repository_id'] = 999
        self.assertEqual(accepted.repositories, (('appolon1908/Breero.com', 123),))
        with self.assertRaises(FrozenInstanceError):
            accepted.publisher_app_id = 999

    def test_missing_independent_certifier_custody_cannot_be_accepted(self):
        item = policy()
        item.pop('certifier_custody_receipt', None)
        with self.assertRaises(PublicationDenied):
            acceptance.load_acceptance(raw(item), fixture.NOW)

    def test_equal_publisher_and_certifier_custody_receipts_cannot_be_accepted(self):
        item = policy()
        item['certifier_custody_receipt'] = item['custody_receipt']
        with self.assertRaises(PublicationDenied):
            acceptance.load_acceptance(raw(item), fixture.NOW)

    def test_exact_policy_schema_rejects_authored_stage_and_unknown_fields(self):
        mutations = [('schema', 'other'), ('state', 'PROPOSED'), ('state', 'REVOKED'),
                     ('accepted_by', 'someone else'), ('acceptance_ref', ''),
                     ('unknown', 'value')]
        for key, value in mutations:
            item = dict(policy(), **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(PublicationDenied):
                acceptance.load_acceptance(raw(item), fixture.NOW)
        for key in policy():
            item = policy(); del item[key]
            with self.subTest(missing=key), self.assertRaises(PublicationDenied):
                acceptance.load_acceptance(raw(item), fixture.NOW)

    def test_duplicate_keys_malformed_json_and_nonbytes_cannot_authenticate(self):
        for item in (b'{}', b'[]', b'null', b'not json', b'\xff', raw(policy()).decode(),
                     b'{"state":"ACCEPTED","state":"REVOKED"}', b'x'*65537):
            with self.subTest(value=repr(item)[:50]), self.assertRaises(PublicationDenied):
                acceptance.load_acceptance(item, fixture.NOW)

    def test_all_identity_and_pin_fields_require_strict_types_and_values(self):
        for key in ('publisher_app_id', 'publisher_installation_id', 'certificate_app_id',
                    'certificate_installation_id'):
            for value in (True, 0, -1, '7', None):
                with self.subTest(key=key, value=value), self.assertRaises(PublicationDenied):
                    acceptance.load_acceptance(raw(dict(policy(), **{key: value})), fixture.NOW)
        for key in ('acceptance_ref', 'custody_receipt', 'certifier_custody_receipt',
                    'certifier_capability_receipt', 'certificate_name'):
            for value in ('', ' ', True, None):
                with self.subTest(key=key, value=value), self.assertRaises(PublicationDenied):
                    acceptance.load_acceptance(raw(dict(policy(), **{key: value})), fixture.NOW)
        for key, value in [('certificate_app_id', 7), ('certificate_app_id', 15368),
                           ('publisher_app_id', 15368), ('certificate_installation_id', 8),
                           ('certificate_name', 'codestra-control-plane')]:
            with self.subTest(key=key, value=value), self.assertRaises(PublicationDenied):
                acceptance.load_acceptance(raw(dict(policy(), **{key: value})), fixture.NOW)

    def test_controller_contexts_and_repository_pins_cannot_be_broadened_or_ambiguous(self):
        for contexts in ([], ['codestra-control-plane'], ['quality'],
                         ['codestra/control-plane', 'codestra-control-plane'],
                         ['codestra-control-plane', 'codestra/control-plane', 'other']):
            with self.subTest(contexts=contexts), self.assertRaises(PublicationDenied):
                acceptance.load_acceptance(raw(dict(policy(), controller_contexts=contexts)), fixture.NOW)
        for repos in ([], ['owner/name'], [{'repository': '../oops', 'repository_id': 123}],
                      [{'repository': 'appolon1908/Breero.com', 'repository_id': True}],
                      policy()['repositories']*2,
                      policy()['repositories']+[{'repository': 'appolon1908/Other', 'repository_id': 123}],
                      [{'repository': 'appolon1908/Breero.com', 'repository_id': 123, 'extra': True}]):
            with self.subTest(repositories=repos), self.assertRaises(PublicationDenied):
                acceptance.load_acceptance(raw(dict(policy(), repositories=repos)), fixture.NOW)

    def test_acceptance_is_current_utc_and_expires_within_24_hours(self):
        for key, value in [('accepted_at', (fixture.NOW+timedelta(seconds=1)).isoformat()),
                           ('accepted_at', fixture.NOW.replace(tzinfo=None).isoformat()),
                           ('accepted_at', '2026-10-07T15:30:00+01:00'),
                           ('expires_at', fixture.NOW.isoformat()),
                           ('expires_at', (fixture.NOW+timedelta(days=1)).isoformat()),
                           ('expires_at', None)]:
            with self.subTest(key=key, value=value), self.assertRaises(PublicationDenied):
                acceptance.load_acceptance(raw(dict(policy(), **{key: value})), fixture.NOW)
        with self.assertRaises(PublicationDenied):
            acceptance.load_acceptance(raw(policy()), fixture.NOW.replace(tzinfo=None))
        for age in (0, 301, True, '60', None):
            with self.subTest(age=age), self.assertRaises(PublicationDenied):
                acceptance.load_acceptance(raw(dict(policy(), max_receipt_age_seconds=age)), fixture.NOW)

    def test_online_accepted_exact_binding_returns_bounded_status_contract(self):
        result = self.verify()
        self.assertEqual(result.repository_id, 123)
        self.assertEqual(result.certificate_app_id, 99)
        self.assertEqual(result.controller_contexts, ('codestra-control-plane', 'codestra/control-plane'))
        self.assertEqual(result.purpose, 'STATUS_PUBLICATION')
        self.assertEqual(result.expires_at, fixture.NOW+timedelta(seconds=50))
        self.assertIn('synthetic:acceptance:1', result.receipt_ref)
        self.assertFalse(any(method != 'GET' and token == 'synthetic-certifier-jwt'
                             for method, _, token, _ in self.transport.calls))

    def test_each_protected_pin_is_bound_to_registry_authority_and_issuer(self):
        for field, value in [('publisher_app_id', 70), ('publisher_installation_id', 80),
                             ('certificate_app_id', 90), ('certificate_name', 'other-certificate'),
                             ('custody_receipt', 'different'), ('certifier_capability_receipt', 'different')]:
            self.value = dict(policy(), **{field: value})
            with self.subTest(field=field), self.assertRaises(PublicationDenied):
                self.verify()
        self.value = policy()
        for item in (replace(self.acquired, repository_id=999),
                     replace(self.acquired, authority=replace(self.acquired.authority, repositories=())),
                     replace(self.acquired, issuer=replace(self.acquired.issuer, binding_hash='0'*64)),
                     replace(self.acquired, authority=replace(self.acquired.authority, expires_at=fixture.NOW)),
                     replace(self.acquired, issuer=replace(self.acquired.issuer, expires_at=fixture.NOW))):
            with self.subTest(acquired=item), self.assertRaises(PublicationDenied):
                self.verify(item)

    def test_missing_certifier_identity_credential_fails_closed_without_using_publisher_jwt(self):
        self.verifier = acceptance.AcceptedProducerVerifier(lambda: raw(self.value), self.api)
        with self.assertRaisesRegex(PublicationDenied, 'CERTIFIER_IDENTITY_UNCONFIGURED'):
            self.verify()
        self.assertEqual(self.transport.calls, [])

    def test_boolean_authority_identity_is_rejected_before_credential_use(self):
        self.value.update(publisher_app_id=1, publisher_installation_id=2)
        acquired = replace(self.acquired,
            authority=replace(self.acquired.authority, app_id=True, installation_id=2))
        with self.assertRaises(PublicationDenied):
            self.verify(acquired)
        self.assertEqual(self.transport.calls, [])

    def test_certifier_observer_uses_an_opaque_handle_with_only_identity_gets(self):
        transport = self.transport
        class Observer:
            def __init__(self):
                self.handle = object()
            def jwt_provider(self):
                return self.handle
            def request(self, method, path, handle):
                if handle is not self.handle or method != 'GET' or path not in (
                        '/app', '/app/installations/100', '/repos/appolon1908/Breero.com/installation'):
                    raise AssertionError('observer port exceeded')
                return transport(method, path, 'synthetic-certifier-jwt')
        self.verifier = acceptance.AcceptedProducerVerifier(lambda: raw(self.value), self.api,
            certifier_api=Observer())
        self.assertEqual(self.verify().certificate_app_id, 99)

    def test_contract_expiry_is_bounded_by_policy_authority_issuer_and_receipt(self):
        self.value['expires_at'] = (fixture.NOW+timedelta(seconds=20)).isoformat()
        self.assertEqual(self.verify().expires_at, fixture.NOW+timedelta(seconds=20))
        self.value = policy()
        authority = replace(self.acquired.authority, expires_at=fixture.NOW+timedelta(seconds=30))
        self.assertEqual(self.verify(replace(self.acquired, authority=authority)).expires_at,
                         fixture.NOW+timedelta(seconds=30))
        issuer = replace(self.acquired.issuer, expires_at=fixture.NOW+timedelta(seconds=40))
        self.assertEqual(self.verify(replace(self.acquired, issuer=issuer)).expires_at,
                         fixture.NOW+timedelta(seconds=40))

    def test_independent_app_installation_owner_and_repository_are_online_authoritative(self):
        changes = [('publisher', 'app_id', 70), ('publisher', 'suspended_at', 'revoked'),
                   ('publisher', 'account', {'id': 999, 'login': 'appolon1908'}),
                   ('certifier', 'id', 101), ('certifier', 'app_id', 7),
                   ('certifier', 'suspended_at', 'revoked'),
                   ('certifier', 'permissions', {'checks': 'read', 'metadata': 'read'}),
                   ('certifier', 'account', {'id': 456, 'login': 'someone-else'}),
                   ('certifier', 'account', {'id': 999, 'login': 'appolon1908'}),
                   ('repository', 'id', 999), ('repository', 'full_name', 'other/repo')]
        for target, key, value in changes:
            self.transport = Transport(); self.api.request = self.transport; self.certifier.request = self.transport
            getattr(self.transport, target)[key] = value
            with self.subTest(target=target, key=key), self.assertRaises(PublicationDenied):
                self.verify()
        self.transport = Transport(); self.api.request = self.transport; self.certifier.request = self.transport
        self.transport.certifier_repository_installation = dict(self.transport.certifier, id=101)
        with self.assertRaises(PublicationDenied):
            self.verify()

    def test_certificate_receipt_matches_online_id_app_name_sha_binding_and_completed_success(self):
        for key, value in [('id', 11), ('app', {'id': 7}), ('name', 'quality'),
                           ('head_sha', 'b'*40), ('external_id', 'wrong-binding'),
                           ('status', 'in_progress'), ('conclusion', 'failure'),
                           ('check_suite', {'id': True})]:
            self.transport.check = dict(Transport().check, **{key: value})
            with self.subTest(key=key), self.assertRaises(PublicationDenied):
                self.verify()
        self.transport.check = Transport().check
        item = replace(self.acquired, snapshot=replace(self.acquired.snapshot,
            certificate=replace(self.acquired.snapshot.certificate, receipt_id='check:999')))
        with self.assertRaises(PublicationDenied):
            self.verify(item)

    def test_check_suite_authenticates_linked_app_and_exact_head(self):
        for key, value in [('id', 999), ('app', {'id': 7}), ('head_sha', 'b'*40)]:
            self.transport.suite = dict(Transport().suite, **{key: value})
            with self.subTest(key=key), self.assertRaises(PublicationDenied):
                self.verify()

    def test_certificate_completion_cannot_be_stale_future_missing_naive_or_malformed(self):
        for value in ((fixture.NOW-timedelta(seconds=61)).isoformat(),
                      (fixture.NOW+timedelta(seconds=1)).isoformat(), None,
                      fixture.NOW.replace(tzinfo=None).isoformat(), 'garbage'):
            self.transport.check['completed_at'] = value
            with self.subTest(completed_at=value), self.assertRaises(PublicationDenied):
                self.verify()

    def test_revised_policy_changes_contract_and_revocation_is_observed_every_call(self):
        first = self.verify()
        self.value['acceptance_ref'] = 'synthetic:acceptance:2'
        second = self.verify()
        self.assertNotEqual(first, second)
        self.value['state'] = 'REVOKED'
        with self.assertRaises(PublicationDenied):
            self.verify()

    def test_policy_revoked_during_online_acquisition_does_not_return_contract(self):
        original = self.api.get
        def revoke(path):
            value = original(path)
            self.value['state'] = 'REVOKED'
            return value
        self.api.get = revoke
        with self.assertRaises(PublicationDenied):
            self.verify()

    def test_policy_reader_and_online_transport_failures_never_authenticate(self):
        def unavailable():
            raise OSError('protected path unavailable')
        self.verifier = acceptance.AcceptedProducerVerifier(unavailable, self.api, certifier_api=self.certifier)
        with self.assertRaises(PublicationDenied):
            self.verify()
        self.verifier = acceptance.AcceptedProducerVerifier(lambda: raw(self.value), self.api, certifier_api=self.certifier)
        self.transport.error = OSError('network unavailable')
        with self.assertRaises(PublicationDenied):
            self.verify()

    def test_expired_proposed_and_revoked_acceptance_never_reserve_intent_or_post_status(self):
        from codestra_control.publisher_adapter import AuthenticatedPublisher
        from codestra_control.publisher_effect import IntentLedger
        verifier = self.verifier
        class Gate:
            def __init__(self):
                self.posts = []
            def verify(self, acquired, now):
                verify_contract(verifier, acquired, now)
            revalidate = verify
            def post(self, acquired, context, state):
                self.posts.append((context, state))
                return 42
            def readback(self, *args):
                return True
        gate = Gate()
        store = Store(); store.snapshot = self.acquired.snapshot
        with tempfile.TemporaryDirectory() as directory:
            ledger = IntentLedger(Path(directory)/'intents.sqlite')
            publisher = AuthenticatedPublisher(store, gate, ledger, host='dev-desktop', clock=lambda: fixture.NOW)
            for changes in ({'state': 'PROPOSED'}, {'state': 'REVOKED'},
                            {'expires_at': fixture.NOW.isoformat()}):
                self.value = dict(policy(), **changes)
                with self.subTest(changes=changes), self.assertRaises(PublicationDenied):
                    publisher.publish(fixture.REQUEST)
            with sqlite3.connect(ledger.path) as database:
                self.assertEqual(database.execute('SELECT COUNT(*) FROM intents').fetchone()[0], 0)
            self.assertEqual(gate.posts, [])


if __name__ == '__main__':
    unittest.main()
