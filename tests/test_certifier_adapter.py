"""Synthetic privileged dependencies only; never contacts GitHub or a database."""
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_decision as fixture
from test_authenticated_publisher import Store
from test_publisher_acquisition import API
from codestra_control.publisher_adapter import PublicationDenied, binding_digest
from codestra_control.publisher_effect import IntentLedger
from codestra_control.certifier_adapter import (
    AcceptedCertificationContract, AcquiredCertification, AuthenticatedCertifier,
    CertifierGitHubClient, CertifierGitHubVerifier, ExistingScopeReceipt,
)


class Registry:
    """This fake substitutes for an independently authenticated online registry."""
    def __init__(self):
        authority = replace(Store().authority, app_id=99, installation_id=100)
        self.receipt = ExistingScopeReceipt(
            fixture.REQUEST, 'database:existing-scope:34', 'STAGING', 'staging',
            fixture.REQUEST.source_sha, fixture.NOW + timedelta(minutes=2),
            'assignment:1', 'lease:1', 1, 'owner', 'SCOPE_CERTIFICATION')
        self.value = AcquiredCertification(
            authority, replace(fixture.ready(), certificate=None), 123, 9, self.receipt)
        self.calls = 0
    def acquire(self, binding, now):
        self.calls += 1
        return self.value


class ContractVerifier:
    def __init__(self): self.revoked = False
    def verify(self, acquired, now):
        if self.revoked: raise PublicationDenied('CONTRACT_REVOKED')
        return AcceptedCertificationContract(
            binding_digest(fixture.REQUEST), 123, 9, 99, 7, 'scope-certification',
            ('codestra-control-plane', 'codestra/control-plane'),
            'accepted:synthetic-contract', fixture.NOW + timedelta(minutes=2),
            'SCOPE_CERTIFICATION')


class CertifierAPI(API):
    def __init__(self):
        super().__init__(); self.effects = []; self.identity = None; self.result = None
    def assert_identity(self, authority, repository_id, now):
        self.identity = authority.app_id
    def post(self, path, body):
        self.effects.append((path, body))
        self.result = dict(body, id=77, app={'id': self.identity})
        return self.result
    def get(self, path):
        if path.endswith('/check-runs/77'): return self.result
        return super().get(path)


class CertifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'certifier.sqlite'
        self.ledger = IntentLedger(self.path)
        self.registry = Registry(); self.contract = ContractVerifier(); self.api = CertifierAPI()
        self.github = CertifierGitHubVerifier(self.api)
        self.certifier = AuthenticatedCertifier(
            self.registry, self.github, self.ledger, contract_verifier=self.contract,
            host='dev-desktop', clock=lambda: fixture.NOW)

    def test_existing_authenticated_receipt_can_be_transported_without_scope_certificate(self):
        # A decision cannot synthesize authority: no ScopeCertificate is supplied.
        with patch('codestra_control.decision.evaluate_promotion', side_effect=AssertionError('not a certifier')):
            result = self.certifier.publish(fixture.REQUEST)
        self.assertEqual(result.state, 'COMPLETE')
        self.assertEqual(result.receipts, ({'check_id': 77, 'registry_receipt': self.registry.receipt.receipt_ref},))
        self.assertEqual(len(self.api.effects), 1)
        path, body = self.api.effects[0]
        self.assertEqual(path, '/repos/appolon1908/Breero.com/check-runs')
        self.assertEqual(body['external_id'], binding_digest(fixture.REQUEST))
        self.assertEqual(body['head_sha'], fixture.REQUEST.source_sha)
        self.assertEqual(body['name'], 'scope-certification')
        self.assertEqual(body['conclusion'], 'success')
        self.assertEqual(self.api.identity, 99)
        self.assertGreaterEqual(self.registry.calls, 4)
        self.assertFalse(any('/statuses/' in p or '/git/' in p for p, _ in self.api.effects))

    def test_default_unconfigured_dependencies_deny_before_effect(self):
        for dependency in ('registry', 'contract_verifier', 'github', 'ledger'):
            original = getattr(self.certifier, dependency)
            setattr(self.certifier, dependency, None)
            with self.subTest(dependency=dependency), self.assertRaises(PublicationDenied):
                self.certifier.publish(fixture.REQUEST)
            setattr(self.certifier, dependency, original)
        self.assertEqual(self.api.effects, [])

    def test_caller_objects_legacy_pass_and_missing_receipt_cannot_certify(self):
        for value in (None, {'allowed': True}, fixture.ready(), replace(self.registry.value, receipt=None)):
            self.registry.value = value
            with self.subTest(value=value), self.assertRaises(PublicationDenied):
                self.certifier.publish(fixture.REQUEST)
        self.assertEqual(self.api.effects, [])

    def test_expired_revoked_or_wrong_binding_receipt_denies(self):
        original = self.registry.value
        for change in ({'expires_at': fixture.NOW}, {'purpose': 'CI'},
                       {'binding': replace(fixture.REQUEST, target_base_sha='d' * 40)},
                       {'certified_sha': 'd' * 40}, {'scope_type': 'PRODUCTION'},
                       {'assignment_id': 'other'}, {'lease_epoch': 0}, {'principal': 'other'}):
            self.registry.value = replace(original, receipt=replace(original.receipt, **change))
            with self.subTest(change=change), self.assertRaises(PublicationDenied):
                self.certifier.publish(fixture.REQUEST)
        self.contract.revoked = True
        self.registry.value = original
        with self.assertRaises(PublicationDenied): self.certifier.publish(fixture.REQUEST)
        self.assertEqual(self.api.effects, [])

    def test_dedicated_app_cannot_be_publisher_or_ordinary_ci(self):
        original = self.contract.verify
        for app_id in (7, 15368):
            self.registry.value = replace(self.registry.value, authority=replace(self.registry.value.authority, app_id=app_id))
            self.contract.verify = lambda acquired, now: replace(original(acquired, now), certifier_app_id=app_id)
            with self.subTest(app_id=app_id), self.assertRaises(PublicationDenied):
                self.certifier.publish(fixture.REQUEST)
        self.assertEqual(self.api.effects, [])

    def test_changed_source_or_base_sha_and_unprotected_target_deny(self):
        original = self.api.get
        for kind in ('head', 'base', 'protection'):
            def changed(path):
                value = original(path)
                if path.endswith('/pulls/9') and kind != 'protection': value[kind]['sha'] = 'd' * 40
                if '/branches/' in path and not path.endswith('/protection') and kind == 'protection': value['protected'] = False
                return value
            self.api.get = changed
            with self.subTest(kind=kind), self.assertRaises(PublicationDenied):
                self.certifier.publish(fixture.REQUEST)
        self.assertEqual(self.api.effects, [])

    def test_current_merge_check_failure_denies(self):
        original = self.api.pages
        def failed(path, key=None):
            values = original(path, key)
            if '/commits/' + 'c' * 40 in path: values[0]['conclusion'] = 'failure'
            return values
        self.api.pages = failed
        with self.assertRaises(PublicationDenied): self.certifier.publish(fixture.REQUEST)
        self.assertEqual(self.api.effects, [])

    def test_authority_or_receipt_revoked_after_intent_denies_without_effect(self):
        original = self.registry.acquire
        def revoked(binding, now):
            if self.registry.calls >= 2: raise PublicationDenied('REGISTRY_RECEIPT_REVOKED')
            return original(binding, now)
        self.registry.acquire = revoked
        result = self.certifier.publish(fixture.REQUEST)
        self.assertEqual(result.state, 'REJECTED')
        self.assertEqual(self.api.effects, [])
        self.registry.acquire = original
        with self.assertRaises(PublicationDenied): self.certifier.publish(fixture.REQUEST)

    def test_one_use_intent_survives_reopen(self):
        self.assertEqual(self.certifier.publish(fixture.REQUEST).state, 'COMPLETE')
        self.certifier.ledger = IntentLedger(self.path)
        with self.assertRaises(PublicationDenied): self.certifier.publish(fixture.REQUEST)
        self.assertEqual(len(self.api.effects), 1)

    def test_wrong_app_name_sha_or_binding_readback_is_uncertain_and_cannot_retry(self):
        original = self.api.get
        for field, value in (('app', {'id': 7}), ('name', 'quality'), ('head_sha', 'd' * 40), ('external_id', 'wrong')):
            with self.subTest(field=field):
                self.certifier.ledger = IntentLedger(Path(self.temp.name) / (field + '.sqlite'))
                self.api.get = lambda path: dict(original(path), **{field: value}) if path.endswith('/check-runs/77') else original(path)
                self.assertEqual(self.certifier.publish(fixture.REQUEST).state, 'UNCERTAIN')
                with self.assertRaises(PublicationDenied): self.certifier.publish(fixture.REQUEST)
        self.assertEqual(len(self.api.effects), 4)

    def test_ambiguous_transport_never_retries(self):
        def failed(path, body):
            self.api.effects.append((path, body)); raise OSError('ambiguous response')
        self.api.post = failed
        self.assertEqual(self.certifier.publish(fixture.REQUEST).state, 'UNCERTAIN')
        with self.assertRaises(PublicationDenied): self.certifier.publish(fixture.REQUEST)
        self.assertEqual(len(self.api.effects), 1)


class CertifierTransportTests(unittest.TestCase):
    def test_scoped_token_has_only_certifier_permissions(self):
        calls = []
        def request(method, path, token, body=None):
            calls.append((method, path, body))
            if path == '/app': return {'id': 99}
            if path == '/app/installations/100':
                return {'id': 100, 'app_id': 99, 'suspended_at': None, 'permissions': dict(CertifierGitHubClient.PERMISSIONS)}
            if path.endswith('/access_tokens'):
                return {'token': 'synthetic', 'expires_at': (fixture.NOW + timedelta(minutes=1)).isoformat(),
                        'permissions': dict(CertifierGitHubClient.PERMISSIONS), 'repositories': [{'id': 123}]}
            raise AssertionError(path)
        client = CertifierGitHubClient(lambda: 'synthetic-jwt', request=request, clock=lambda: fixture.NOW)
        client.assert_identity(Registry().value.authority, 123, fixture.NOW)
        self.assertEqual(calls[-1][2]['repository_ids'], [123])
        permissions = calls[-1][2]['permissions']
        self.assertEqual(permissions['checks'], 'write')
        self.assertEqual({key for key, value in permissions.items() if value == 'write'}, {'checks'})
        self.assertNotIn('statuses', permissions)
        self.assertNotIn('workflows', permissions)
        self.assertNotIn('issues', permissions)

    def test_extra_installation_permission_is_refused_before_token(self):
        calls = []
        def request(method, path, token, body=None):
            calls.append(path)
            if path == '/app': return {'id': 99}
            return {'id': 100, 'app_id': 99, 'suspended_at': None,
                    'permissions': dict(CertifierGitHubClient.PERMISSIONS, contents='write')}
        client = CertifierGitHubClient(lambda: 'synthetic-jwt', request=request, clock=lambda: fixture.NOW)
        with self.assertRaises(PublicationDenied):
            client.assert_identity(Registry().value.authority, 123, fixture.NOW)
        self.assertFalse(any(path.endswith('/access_tokens') for path in calls))


class RestrictedCertificationRegistryTests(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        import json
        from dataclasses import asdict
        self.mock = mock
        self.connection = mock.MagicMock()
        self.connection.get_dsn_parameters.return_value = {
            'sslmode': 'verify-full', 'host': 'registry.example', 'sslrootcert': '/fixture/ca.pem'}
        self.cursor = self.connection.cursor.return_value.__enter__.return_value
        self.value = Registry().value
        assignment = '11111111-1111-4111-8111-111111111111'
        lease_id = '22222222-2222-4222-8222-222222222222'
        self.value = replace(self.value, receipt=replace(self.value.receipt, assignment_id=assignment, lease_id=lease_id),
                             snapshot=replace(self.value.snapshot, lease=replace(self.value.snapshot.lease, assignment_id=assignment)))
        encode = lambda v: json.loads(json.dumps(asdict(v), default=lambda dt: dt.isoformat()))
        self.row = (encode(self.value.authority), encode(self.value.snapshot), encode(self.value.receipt),
                    123, 9, assignment, lease_id, 1, self.value.receipt.receipt_ref,
                    'STAGING', 'staging', 'Ralph L. Appolon', 'operator:accepted-existing:34')
        self.lease = {'authority': 'ONLINE_DATABASE_RECEIPT', 'binding_id': assignment, 'lease_id': lease_id,
                      'epoch': 1, 'state': 'ACTIVE', 'principal': 'owner',
                      'expires_at': self.value.snapshot.lease.expires_at.isoformat(),
                      'binding': {'repository': fixture.REQUEST.repository, 'repository_id': 123,
                                  'product': fixture.REQUEST.product, 'source_ref': fixture.REQUEST.source_ref,
                                  'target_ref': fixture.REQUEST.target_ref, 'head_sha': fixture.REQUEST.source_sha,
                                  'base_sha': fixture.REQUEST.target_base_sha, 'principal': 'owner'}}
        self.cursor.fetchall.return_value = [self.row]
        self.cursor.fetchone.side_effect = [(True, True), (True,), (self.lease,)]
        patcher = mock.patch('codestra_control.publisher_startup.protected_read', return_value=b'synthetic-ca')
        patcher.start(); self.addCleanup(patcher.stop)

    def test_authenticated_source_reader_checks_grant_scope_existing_certification_and_online_lease(self):
        from codestra_control.certifier_adapter import RestrictedCertificationRegistry
        value = RestrictedCertificationRegistry(self.connection).acquire(fixture.REQUEST, fixture.NOW)
        self.assertEqual(value, self.value)
        self.connection.set_session.assert_called_once_with(readonly=True, autocommit=False)
        statements = [call.args[0] for call in self.cursor.execute.call_args_list]
        self.assertEqual(len(statements), 4)
        self.assertTrue(all(statement.lstrip().startswith('SELECT') for statement in statements))
        self.assertIn('certifier_authority.product_grants', statements[1])
        self.assertIn('role_oid', statements[1])
        self.assertIn('scope_certifications', statements[2])
        self.assertEqual(self.cursor.execute.call_args.args, ('SELECT assignment_leases.inspect_binding(%s)', (self.value.receipt.assignment_id,)))

    def test_role_switch_trust_authentication_or_mutating_privileges_are_refused(self):
        from codestra_control.certifier_adapter import RestrictedCertificationRegistry
        for result in ((False, True), (True, False), None):
            self.cursor.fetchone.side_effect = [result]
            with self.subTest(result=result), self.assertRaises(PublicationDenied):
                RestrictedCertificationRegistry(self.connection).acquire(fixture.REQUEST, fixture.NOW)

    def test_grant_or_existing_scope_registration_missing_denies(self):
        from codestra_control.certifier_adapter import RestrictedCertificationRegistry
        self.cursor.fetchall.return_value = []
        with self.assertRaises(PublicationDenied):
            RestrictedCertificationRegistry(self.connection).acquire(fixture.REQUEST, fixture.NOW)
        self.cursor.fetchall.return_value = [self.row]
        self.cursor.fetchone.side_effect = [(True, True), (False,)]
        with self.assertRaises(PublicationDenied):
            RestrictedCertificationRegistry(self.connection).acquire(fixture.REQUEST, fixture.NOW)

    def test_wrong_lease_current_binding_or_revocation_denies(self):
        from codestra_control.certifier_adapter import RestrictedCertificationRegistry
        for change in ({'state': 'REVOKED'}, {'epoch': 2}, {'principal': 'other'},
                       {'expires_at': fixture.NOW.isoformat()},
                       {'binding': dict(self.lease['binding'], base_sha='d' * 40)}):
            self.cursor.fetchone.side_effect = [(True, True), (True,), (dict(self.lease, **change),)]
            with self.subTest(change=change), self.assertRaises(PublicationDenied):
                RestrictedCertificationRegistry(self.connection).acquire(fixture.REQUEST, fixture.NOW)

    def test_unverified_tls_and_untrusted_ca_deny_before_query(self):
        from codestra_control.certifier_adapter import RestrictedCertificationRegistry
        from codestra_control.publisher_ownership import PublisherUnavailable
        for mode in ('require', 'prefer', 'verify-ca'):
            self.connection.get_dsn_parameters.return_value['sslmode'] = mode
            with self.subTest(mode=mode), self.assertRaises(PublicationDenied):
                RestrictedCertificationRegistry(self.connection).acquire(fixture.REQUEST, fixture.NOW)
        self.connection.get_dsn_parameters.return_value['sslmode'] = 'verify-full'
        with self.mock.patch('codestra_control.publisher_startup.protected_read', side_effect=PublisherUnavailable('unsafe-ca')):
            with self.assertRaises(PublicationDenied):
                RestrictedCertificationRegistry(self.connection).acquire(fixture.REQUEST, fixture.NOW)
        self.assertEqual(self.cursor.execute.call_count, 0)


class AcceptedCertifierContractTests(unittest.TestCase):
    def setUp(self):
        import types
        from unittest import mock
        self.policy = types.SimpleNamespace(
            publisher_app_id=7, publisher_installation_id=8,
            certificate_app_id=99, certificate_installation_id=100,
            certificate_name='scope-certification',
            controller_contexts=('codestra-control-plane', 'codestra/control-plane'),
            repositories=((fixture.REQUEST.repository, 123),),
            custody_receipt='publisher-custody:1', certifier_custody_receipt='custody:1',
            certifier_capability_receipt='accepted:scope-capability',
            acceptance_ref='accepted:operator:1', revision='e' * 64,
            expires_at=fixture.NOW + timedelta(minutes=3))
        self.loader = mock.Mock(return_value=self.policy)
        # The shared publisher acceptance parser is maintained independently.
        # This synthetic port isolates certifier wiring; integration uses its
        # actual parser after the parallel sections are assembled by the lead.
        patcher = mock.patch.dict('sys.modules', {'codestra_control.publisher_acceptance':
            types.SimpleNamespace(load_acceptance=self.loader)})
        patcher.start(); self.addCleanup(patcher.stop)

    def test_protected_accepted_policy_binds_distinct_certifier_and_exact_repository(self):
        from codestra_control.certifier_adapter import AcceptedCertifierContractVerifier
        verifier = AcceptedCertifierContractVerifier(lambda: b'protected-synthetic-policy')
        acquired = Registry().value
        value = verifier.verify(acquired, fixture.NOW)
        self.loader.assert_called_once_with(b'protected-synthetic-policy', fixture.NOW)
        self.assertEqual(value.certifier_app_id, 99)
        self.assertEqual(value.publisher_app_id, 7)
        self.assertEqual(value.binding_hash, binding_digest(fixture.REQUEST))
        self.assertEqual(value.purpose, 'SCOPE_CERTIFICATION')
        self.assertIn(self.policy.revision, value.receipt_ref)
        self.assertLessEqual(value.expires_at, acquired.receipt.expires_at)

    def test_policy_wrong_app_installation_custody_or_repository_denies(self):
        from codestra_control.certifier_adapter import AcceptedCertifierContractVerifier
        verifier = AcceptedCertifierContractVerifier(lambda: b'protected-synthetic-policy')
        for field, value in (('certificate_app_id', 7), ('certificate_installation_id', 999),
                             ('certifier_custody_receipt', 'other'), ('repositories', ((fixture.REQUEST.repository, 999),))):
            original = getattr(self.policy, field)
            setattr(self.policy, field, value)
            with self.subTest(field=field), self.assertRaises(PublicationDenied):
                verifier.verify(Registry().value, fixture.NOW)
            setattr(self.policy, field, original)

    def test_missing_protected_policy_and_parser_refusal_deny(self):
        from codestra_control.certifier_adapter import AcceptedCertifierContractVerifier
        def unreadable(): raise OSError('private secret diagnostic')
        with self.assertRaises(PublicationDenied) as caught:
            AcceptedCertifierContractVerifier(unreadable).verify(Registry().value, fixture.NOW)
        self.assertNotIn('secret', str(caught.exception))
        self.loader.side_effect = PublicationDenied('POLICY_NOT_ACCEPTED')
        with self.assertRaises(PublicationDenied):
            AcceptedCertifierContractVerifier(lambda: b'invalid').verify(Registry().value, fixture.NOW)


@unittest.skipUnless(Path('/usr/lib/postgresql/16/bin/initdb').exists(), 'Disposable PostgreSQL16 binaries required')
class CertifierSourceSQLTests(unittest.TestCase):
    """Only a new temporary socket-only cluster; no runtime DSN or live database."""
    @classmethod
    def setUpClass(cls):
        import subprocess
        import psycopg2
        cls.tmp = tempfile.TemporaryDirectory(prefix='cp-certifier-source-test-')
        cls.path = Path(cls.tmp.name); cls.pg = Path('/usr/lib/postgresql/16/bin'); cls.started = False
        try:
            subprocess.run([str(cls.pg / 'initdb'), '-D', str(cls.path / 'data'), '-A', 'trust', '-U', 'fixture_admin', '--no-locale'],
                           check=True, capture_output=True)
            subprocess.run([str(cls.pg / 'pg_ctl'), '-D', str(cls.path / 'data'), '-l', str(cls.path / 'postgres.log'),
                            '-o', f"-k {cls.path} -p 6543 -c listen_addresses=''", '-w', 'start'], check=True, capture_output=True)
            cls.started = True
            cls.connection = psycopg2.connect(host=str(cls.path), port=6543, dbname='postgres', user='fixture_admin')
            cls.connection.autocommit = True
            with cls.connection.cursor() as cur:
                cur.execute('CREATE TABLE public.products(product text PRIMARY KEY)')
                cur.execute("INSERT INTO public.products VALUES('Breero')")
                cur.execute('CREATE SCHEMA assignment_leases')
                cur.execute("CREATE FUNCTION assignment_leases.inspect_binding(uuid) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$")
                cur.execute((Path(__file__).resolve().parents[1] / '011-certifier-authority.sql').read_text())
        except BaseException:
            cls.tearDownClass(); raise

    @classmethod
    def tearDownClass(cls):
        import subprocess
        if hasattr(cls, 'connection'): cls.connection.close()
        if cls.started:
            subprocess.run([str(cls.pg / 'pg_ctl'), '-D', str(cls.path / 'data'), '-m', 'immediate', '-w', 'stop'], check=True, capture_output=True)
        cls.tmp.cleanup()

    def test_schema_is_empty_without_public_grants_or_runtime_certification_writer(self):
        with self.connection.cursor() as cur:
            cur.execute('SELECT (SELECT count(*) FROM certifier_authority.product_grants), (SELECT count(*) FROM certifier_authority.existing_receipts)')
            self.assertEqual(cur.fetchone(), (0, 0))
            cur.execute("SELECT count(*) FROM pg_proc f JOIN pg_namespace n ON n.oid=f.pronamespace WHERE n.nspname='certifier_authority'")
            self.assertEqual(cur.fetchone(), (0,))
            cur.execute("SELECT count(*) FROM information_schema.role_table_grants WHERE table_schema='certifier_authority' AND grantee='PUBLIC'")
            self.assertEqual(cur.fetchone(), (0,))

    def test_actual_reader_predicate_rejects_trust_authenticated_privileged_session(self):
        from codestra_control.certifier_adapter import RestrictedCertificationRegistry
        with self.connection.cursor() as cur, self.assertRaises(PublicationDenied):
            RestrictedCertificationRegistry._roles(cur)

    def test_source_readmodel_cannot_label_ci_or_legacy_pass_as_an_accepted_receipt(self):
        import psycopg2
        with self.connection.cursor() as cur:
            cur.execute("INSERT INTO certifier_authority.product_grants(principal,role_oid,product,repository,repository_id,expires_at) SELECT session_user,oid,'Breero','appolon1908/Breero.com',123,clock_timestamp()+interval '1 minute' FROM pg_roles WHERE rolname=session_user")
            for purpose, origin, actor in (('CI', 'INDEPENDENTLY_AUTHENTICATED_EXISTING_RECEIPT', 'Ralph L. Appolon'),
                                           ('SCOPE_CERTIFICATION', 'LEGACY_PASS', 'Ralph L. Appolon'),
                                           ('SCOPE_CERTIFICATION', 'INDEPENDENTLY_AUTHENTICATED_EXISTING_RECEIPT', 'caller')):
                with self.subTest(purpose=purpose, origin=origin, actor=actor), self.assertRaises(psycopg2.errors.CheckViolation):
                    cur.execute("""INSERT INTO certifier_authority.existing_receipts VALUES(
                     %s,session_user,(SELECT oid FROM pg_roles WHERE rolname=session_user),'Breero',
                     'appolon1908/Breero.com',123,9,'{}','{}','{}',%s,%s,1,'existing:34',
                     'STAGING','staging',%s,'acceptance:34',%s,%s,false,clock_timestamp()+interval '1 minute')""",
                                ('d' * 64, '11111111-1111-4111-8111-111111111111',
                                 '22222222-2222-4222-8222-222222222222', actor, purpose, origin))
            cur.execute('DELETE FROM certifier_authority.product_grants')
