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
    def bind_effect_expiry(self, expires_at): self.expiry_cap = expires_at
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
            if path in ('/app/installations/100', '/repos/appolon1908/Breero.com/installation'):
                return {'id': 100, 'app_id': 99, 'suspended_at': None, 'permissions': dict(CertifierGitHubClient.PERMISSIONS),
                        'repository_selection': 'selected', 'account': {'login': 'appolon1908', 'id': 42}}
            if path == '/repositories/123':
                return {'id': 123, 'full_name': fixture.REQUEST.repository, 'owner': {'login': 'appolon1908', 'id': 42}}
            if path.endswith('/access_tokens'):
                return {'token': 'synthetic', 'expires_at': (fixture.NOW + timedelta(minutes=1)).isoformat(),
                        'permissions': dict(CertifierGitHubClient.PERMISSIONS), 'repositories': [{'id': 123}]}
            raise AssertionError(path)
        client = CertifierGitHubClient(lambda: 'synthetic-jwt', request=request, clock=lambda: fixture.NOW)
        client.assert_identity(Registry().value.authority, 123, fixture.NOW)
        minted = next(body for method, path, body in calls if path.endswith('/access_tokens'))
        self.assertEqual(minted['repository_ids'], [123])
        permissions = minted['permissions']
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
        self.connection.set_session.assert_called_once_with(readonly=True, autocommit=False, isolation_level='READ COMMITTED')
        statements = [call.args[0] for call in self.cursor.execute.call_args_list]
        self.assertEqual(len(statements), 4)
        self.assertTrue(all(statement.lstrip().startswith('SELECT') for statement in statements))
        self.assertIn('certifier_authority.product_grants', statements[1])
        self.assertIn('role_oid', statements[1])
        self.assertIn('scope_certifications', statements[2])
        self.assertEqual(self.cursor.execute.call_args.args, ('SELECT scope_assignment_leases.inspect_binding(%s)', (self.value.receipt.assignment_id,)))

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
            expires_at=fixture.NOW + timedelta(minutes=3), max_receipt_age_seconds=300)
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
                cur.execute((Path(__file__).resolve().parents[1] / '013-first-certification-pending.sql').read_text())
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


    def test_pending_schema_rejects_historical_certificate_unbounded_delegation_and_wrong_purpose(self):
        import psycopg2
        import json
        with self.connection.cursor() as cur:
            cur.execute("INSERT INTO certifier_authority.product_grants(principal,role_oid,product,repository,repository_id,expires_at) SELECT session_user,oid,'Breero','appolon1908/Breero.com',123,clock_timestamp()+interval '1 minute' FROM pg_roles WHERE rolname=session_user")
            for snapshot, minutes, purpose in (({}, 2, 'FIRST_SCOPE_CERTIFICATION'),
                    ({'certificate': {'status': 'CERTIFIED'}}, 2, 'FIRST_SCOPE_CERTIFICATION'),
                    ({'certificate': None}, 10, 'FIRST_SCOPE_CERTIFICATION'),
                    ({'certificate': None}, 2, 'CI')):
                with self.subTest(snapshot=snapshot, minutes=minutes, purpose=purpose), self.assertRaises(psycopg2.errors.CheckViolation):
                    cur.execute("""INSERT INTO certifier_authority.pending_bindings(
                     binding_hash,principal,role_oid,product,repository,repository_id,pr_number,authority,snapshot,
                     scope_type,scope_name,assignment_id,lease_id,lease_epoch,lease_principal,delegation_ref,
                     capability_receipt,dependency_policy,accepted_by,purpose,issued_at,expires_at)
                     SELECT %s,session_user,oid,'Breero','appolon1908/Breero.com',123,9,'{}',%s::jsonb,
                     'STAGING','staging',%s,%s,1,'owner','delegation:1','capability:1','[]','Ralph L. Appolon',
                     %s,clock_timestamp(),clock_timestamp()+make_interval(mins=>%s)
                     FROM pg_roles WHERE rolname=session_user""", ('f' * 64, json.dumps(snapshot),
                        '11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222', purpose, minutes))
            cur.execute('SELECT count(*) FROM certifier_authority.pending_bindings')
            self.assertEqual(cur.fetchone(), (0,))
            cur.execute('DELETE FROM certifier_authority.product_grants')


class PendingRegistry:
    def __init__(self):
        from codestra_control.certifier_adapter import PendingCertification
        base = Registry().value
        self.value = PendingCertification(base.authority, base.snapshot, 123, 9,
            'STAGING', 'staging', 'assignment:1', 'lease:1', 1, 'owner',
            'operator:exact-scope-delegation', 'accepted:scope-capability',
            fixture.NOW, fixture.NOW + timedelta(minutes=2), ())
        self.calls = 0
    def acquire(self, binding, now):
        self.calls += 1
        return self.value


class FirstContractVerifier:
    def verify(self, acquired, now):
        from codestra_control.certifier_adapter import AcceptedFirstCertificationContract
        return AcceptedFirstCertificationContract(binding_digest(fixture.REQUEST), 123, 9, 99, 7,
            'scope-certification', ('codestra-control-plane', 'codestra/control-plane'),
            'operator:accepted-first-scope-delegation', fixture.NOW + timedelta(minutes=2),
            'FIRST_SCOPE_CERTIFICATION', acquired.scope_type, acquired.scope_name,
            acquired.delegation_ref, acquired.capability_receipt, 300)


class FirstCertifierTests(unittest.TestCase):
    def setUp(self):
        from codestra_control.certifier_adapter import AuthenticatedFirstCertifier
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.registry = PendingRegistry(); self.api = CertifierAPI(); self.github = CertifierGitHubVerifier(self.api)
        self.path = Path(self.temp.name) / 'first.sqlite'
        self.certifier = AuthenticatedFirstCertifier(self.registry, self.github, IntentLedger(self.path),
            contract_verifier=FirstContractVerifier(), host='dev-desktop', clock=lambda: fixture.NOW)

    def test_first_check_absent_can_be_issued_from_authenticated_scoped_delegation_only(self):
        self.assertIsNone(self.registry.value.snapshot.certificate)
        with patch('codestra_control.decision.evaluate_promotion', side_effect=AssertionError('not a certifier')):
            result = self.certifier.publish(fixture.REQUEST)
        self.assertEqual(result.state, 'COMPLETE')
        self.assertEqual(len(self.api.effects), 1)
        self.assertFalse(any('/check-runs/10' in path for path in self.api.paths))
        self.assertEqual(self.api.effects[0][1]['external_id'], binding_digest(fixture.REQUEST))
        self.assertIn('First scope certification', self.api.effects[0][1]['output']['title'])
        self.assertEqual(result.receipts, ({'check_id': 77, 'delegation_ref': self.registry.value.delegation_ref},))

    def test_missing_delegation_dependency_lease_review_and_historical_certificate_deny(self):
        original = self.registry.value
        snapshots = (replace(original.snapshot, dependencies_complete=False),
                     replace(original.snapshot, dependencies_certified=False),
                     replace(original.snapshot, lease=None), replace(original.snapshot, reviews=()),
                     replace(original.snapshot, certificate=fixture.ready().certificate))
        for value in (replace(original, delegation_ref=''), replace(original, capability_receipt=''),
                      replace(original, expires_at=fixture.NOW),
                      *(replace(original, snapshot=snapshot) for snapshot in snapshots)):
            self.registry.value = value
            with self.subTest(value=value), self.assertRaises(PublicationDenied):
                self.certifier.publish(fixture.REQUEST)
        self.assertEqual(self.api.effects, [])

    def test_supported_scope_does_not_include_atomic_or_hotfix_exceptions(self):
        for ref in ('atomic/sec--sub--task', 'hotfix/fix'):
            binding = replace(fixture.REQUEST, source_ref=ref)
            self.registry.value = replace(self.registry.value,
                snapshot=replace(self.registry.value.snapshot, observed_binding=binding))
            with self.subTest(ref=ref), self.assertRaises(PublicationDenied): self.certifier.publish(binding)
        self.assertEqual(self.api.effects, [])

    def test_source_base_drift_and_failed_merge_check_deny_before_first_effect(self):
        original_get = self.api.get; original_pages = self.api.pages
        for field in ('head', 'base'):
            def moved(path):
                value = original_get(path)
                if path.endswith('/pulls/9'): value[field]['sha'] = 'd' * 40
                return value
            self.api.get = moved
            with self.subTest(field=field), self.assertRaises(PublicationDenied): self.certifier.publish(fixture.REQUEST)
        self.api.get = original_get
        def failed(path, key=None):
            value = original_pages(path, key)
            if '/commits/' + 'c' * 40 in path: value[0]['conclusion'] = 'failure'
            return value
        self.api.pages = failed
        with self.assertRaises(PublicationDenied): self.certifier.publish(fixture.REQUEST)
        self.assertEqual(self.api.effects, [])

    def test_revoked_pending_grant_after_intent_stops_and_consumes_intent(self):
        original = self.registry.acquire
        def revoked(binding, now):
            if self.registry.calls >= 2: raise PublicationDenied('PENDING_GRANT_REVOKED')
            return original(binding, now)
        self.registry.acquire = revoked
        self.assertEqual(self.certifier.publish(fixture.REQUEST).state, 'REJECTED')
        self.assertEqual(self.api.effects, [])
        self.registry.acquire = original
        with self.assertRaises(PublicationDenied): self.certifier.publish(fixture.REQUEST)

    def test_first_readback_wrong_app_is_uncertain_and_reopen_cannot_retry(self):
        original = self.api.get
        self.api.get = lambda path: dict(original(path), app={'id': 7}) if path.endswith('/check-runs/77') else original(path)
        self.assertEqual(self.certifier.publish(fixture.REQUEST).state, 'UNCERTAIN')
        self.certifier.ledger = IntentLedger(self.path)
        with self.assertRaises(PublicationDenied): self.certifier.publish(fixture.REQUEST)
        self.assertEqual(len(self.api.effects), 1)

    def test_no_privileged_registry_or_accepted_contract_defaults_to_denial(self):
        self.certifier.registry = None
        with self.assertRaises(PublicationDenied): self.certifier.publish(fixture.REQUEST)
        self.certifier.registry = self.registry; self.certifier.contract_verifier = None
        with self.assertRaises(PublicationDenied): self.certifier.publish(fixture.REQUEST)
        self.assertEqual(self.api.effects, [])


    def test_complete_dependency_policy_requires_exact_live_accepted_scope_check(self):
        from codestra_control.certifier_adapter import CertificationDependency
        dependency_binding = replace(fixture.REQUEST, source_ref='testing', target_ref='staging',
                                     source_sha='e' * 40, target_base_sha=fixture.REQUEST.source_sha)
        dependency = CertificationDependency(dependency_binding, 123, 88, 99,
                                            'scope-certification', fixture.NOW + timedelta(minutes=2))
        self.registry.value = replace(self.registry.value, dependencies=(dependency,))
        original = self.api.get
        def dependency_api(path):
            self.assertEqual(self.api.identity, 99, 'dependency reads require accepted App authentication')
            if path.endswith('/branches/testing'): return {'commit': {'sha': 'e' * 40}}
            if path.endswith('/branches/staging'): return {'commit': {'sha': fixture.REQUEST.source_sha}}
            if path.endswith('/check-runs/88'):
                return {'id': 88, 'app': {'id': 99}, 'name': 'scope-certification', 'head_sha': 'e' * 40,
                        'external_id': binding_digest(dependency_binding), 'status': 'completed', 'conclusion': 'success',
                        'completed_at': fixture.NOW.isoformat(), 'check_suite': {'id': 188}}
            if path.endswith('/check-suites/188'):
                return {'id': 188, 'app': {'id': 99}, 'head_sha': 'e' * 40, 'status': 'completed', 'conclusion': 'success'}
            return original(path)
        self.api.get = dependency_api
        self.assertEqual(self.certifier.publish(fixture.REQUEST).state, 'COMPLETE')

    def test_revoked_wrong_issuer_or_missing_dependency_receipt_denies_without_effect(self):
        from codestra_control.certifier_adapter import CertificationDependency
        dependency_binding = replace(fixture.REQUEST, source_ref='testing', target_ref='staging',
                                     source_sha='e' * 40, target_base_sha=fixture.REQUEST.source_sha)
        original = self.api.get
        for issuer, conclusion in ((7, 'success'), (99, 'failure')):
            self.registry.value = replace(self.registry.value, dependencies=(CertificationDependency(
                dependency_binding, 123, 88, issuer, 'scope-certification', fixture.NOW + timedelta(minutes=2)),))
            def dependency_api(path):
                if path.endswith('/branches/testing'): return {'commit': {'sha': 'e' * 40}}
                if path.endswith('/branches/staging'): return {'commit': {'sha': fixture.REQUEST.source_sha}}
                if path.endswith('/check-runs/88'):
                    return {'id': 88, 'app': {'id': issuer}, 'name': 'scope-certification', 'head_sha': 'e' * 40,
                            'external_id': binding_digest(dependency_binding), 'status': 'completed', 'conclusion': conclusion}
                return original(path)
            self.api.get = dependency_api
            with self.subTest(issuer=issuer, conclusion=conclusion), self.assertRaises(PublicationDenied):
                self.certifier.publish(fixture.REQUEST)
        self.assertEqual(self.api.effects, [])


class RestrictedFirstCertificationRegistryTests(RestrictedCertificationRegistryTests):
    """Exercise first-issuance acquisition separately from existing receipt reads."""
    def setUp(self):
        super().setUp()
        from dataclasses import asdict
        import json
        pending = PendingRegistry().value
        self.pending = replace(pending, assignment_id=self.value.receipt.assignment_id,
            lease_id=self.value.receipt.lease_id, snapshot=self.value.snapshot)
        encode = lambda value: json.loads(json.dumps(asdict(value), default=lambda dt: dt.isoformat()))
        self.pending_row = (encode(self.pending.authority), encode(self.pending.snapshot), 123, 9,
            self.pending.scope_type, self.pending.scope_name, self.pending.assignment_id,
            self.pending.lease_id, 1, 'owner', self.pending.delegation_ref,
            self.pending.capability_receipt, self.pending.issued_at, self.pending.expires_at, [], 'Ralph L. Appolon')
        self.lease['binding'].update(source_level='staging', target_level='production')
        from codestra_control.certifier_adapter import CertificationDependency
        dependency = CertificationDependency(replace(fixture.REQUEST, source_ref='testing', target_ref='staging',
            source_sha='e' * 40, target_base_sha=fixture.REQUEST.source_sha), 123, 88, 99,
            'scope-certification', fixture.NOW + timedelta(minutes=2))
        self.pending = replace(self.pending, dependencies=(dependency,))
        raw_dependency = encode(dependency)
        self.pending_row = self.pending_row[:14] + ([raw_dependency],) + self.pending_row[15:]
        mapping = self.pending.snapshot.mapping
        chain = [mapping.development_ref,mapping.testing_ref,mapping.staging_ref,mapping.production_ref]
        self.product_row = (fixture.REQUEST.repository,mapping.testing_ref,chain,
            dict(product=fixture.REQUEST.product,repository=fixture.REQUEST.repository,
                 test_branch=mapping.testing_ref,promotion_chain=chain),123,*chain,mapping.release_ref,True)
        self.cursor.fetchall.side_effect = [[self.pending_row], [], []]
        self.cursor.fetchone.side_effect = [(True, True), self.product_row, (self.lease,)]

    def test_authenticated_source_reader_checks_grant_scope_existing_certification_and_online_lease(self):
        from codestra_control.certifier_adapter import RestrictedFirstCertificationRegistry
        value = RestrictedFirstCertificationRegistry(self.connection).acquire(fixture.REQUEST, fixture.NOW)
        self.assertEqual(value, self.pending)
        statements = [call.args[0] for call in self.cursor.execute.call_args_list]
        self.assertEqual(len(statements), 6)
        self.assertIn('certifier_authority.pending_bindings', statements[1])
        self.assertIn('certifier_authority.product_grants', statements[1])
        self.assertEqual(self.cursor.execute.call_args.args,
            ('SELECT scope_assignment_leases.inspect_binding(%s)', (self.pending.assignment_id,)))
        self.assertFalse(any('scope_certifications' in statement or 'SELECT assignment_leases.inspect_binding' in statement for statement in statements))

    def test_grant_or_existing_scope_registration_missing_denies(self):
        from codestra_control.certifier_adapter import RestrictedFirstCertificationRegistry
        self.cursor.fetchall.side_effect = [[]]
        with self.assertRaises(PublicationDenied):
            RestrictedFirstCertificationRegistry(self.connection).acquire(fixture.REQUEST, fixture.NOW)

    def test_role_switch_trust_authentication_or_mutating_privileges_are_refused(self):
        from codestra_control.certifier_adapter import RestrictedFirstCertificationRegistry
        for result in ((False, True), (True, False), None):
            self.cursor.fetchone.side_effect = [result]
            with self.subTest(result=result), self.assertRaises(PublicationDenied):
                RestrictedFirstCertificationRegistry(self.connection).acquire(fixture.REQUEST, fixture.NOW)

    def test_wrong_lease_current_binding_or_revocation_denies(self):
        from codestra_control.certifier_adapter import RestrictedFirstCertificationRegistry
        for change in ({'state': 'REVOKED'}, {'epoch': 2}, {'principal': 'other'},
                       {'expires_at': fixture.NOW.isoformat()},
                       {'binding': dict(self.lease['binding'], base_sha='d' * 40)},
                       {'binding': dict(self.lease['binding'], source_level='atomic_task')}):
            self.cursor.fetchall.side_effect = [[self.pending_row], [], []]
            self.cursor.fetchone.side_effect = [(True, True), self.product_row, (dict(self.lease, **change),)]
            with self.subTest(change=change), self.assertRaises(PublicationDenied):
                RestrictedFirstCertificationRegistry(self.connection).acquire(fixture.REQUEST, fixture.NOW)

    def test_unverified_tls_and_untrusted_ca_deny_before_query(self):
        from codestra_control.certifier_adapter import RestrictedFirstCertificationRegistry
        self.connection.get_dsn_parameters.return_value['sslmode'] = 'require'
        with self.assertRaises(PublicationDenied):
            RestrictedFirstCertificationRegistry(self.connection).acquire(fixture.REQUEST, fixture.NOW)
        self.assertEqual(self.cursor.execute.call_count, 0)


class AcceptedFirstCertificationContractTests(AcceptedCertifierContractTests):
    def test_protected_accepted_policy_binds_distinct_certifier_and_exact_repository(self):
        from codestra_control.certifier_adapter import AcceptedFirstCertificationContractVerifier
        acquired = PendingRegistry().value
        value = AcceptedFirstCertificationContractVerifier(lambda: b'protected-synthetic-policy').verify(acquired, fixture.NOW)
        self.assertEqual(value.purpose, 'FIRST_SCOPE_CERTIFICATION')
        self.assertEqual(value.scope_type, 'STAGING')
        self.assertEqual(value.scope_name, fixture.REQUEST.source_ref)
        self.assertEqual(value.delegation_ref, acquired.delegation_ref)
        self.assertEqual(value.capability_receipt, acquired.capability_receipt)
        self.assertFalse(hasattr(value, 'existing_receipt_ref'))

    def test_policy_wrong_app_installation_custody_or_repository_denies(self):
        from codestra_control.certifier_adapter import AcceptedFirstCertificationContractVerifier
        verifier = AcceptedFirstCertificationContractVerifier(lambda: b'protected-synthetic-policy')
        for field, value in (('certificate_app_id', 7), ('certificate_installation_id', 999),
                            ('certifier_custody_receipt', 'other'), ('certifier_capability_receipt', 'other'),
                            ('repositories', ((fixture.REQUEST.repository, 999),))):
            original = getattr(self.policy, field); setattr(self.policy, field, value)
            with self.subTest(field=field), self.assertRaises(PublicationDenied):
                verifier.verify(PendingRegistry().value, fixture.NOW)
            setattr(self.policy, field, original)

    def test_missing_protected_policy_and_parser_refusal_deny(self):
        from codestra_control.certifier_adapter import AcceptedFirstCertificationContractVerifier
        def unreadable(): raise OSError('private secret diagnostic')
        with self.assertRaises(PublicationDenied) as caught:
            AcceptedFirstCertificationContractVerifier(unreadable).verify(PendingRegistry().value, fixture.NOW)
        self.assertNotIn('secret', str(caught.exception))


class CertifierExpirationFenceTests(unittest.TestCase):
    def test_existing_and_first_preflight_final_registry_read_exhausting_expiry_never_reserves_or_posts(self):
        from codestra_control.certifier_adapter import AuthenticatedFirstCertifier
        from unittest import mock
        for first in (False, True):
            registry = PendingRegistry() if first else Registry()
            api = CertifierAPI(); now = [fixture.NOW]
            original = registry.acquire
            calls = [0]
            def slow(binding, observed_at):
                calls[0] += 1
                if calls[0] == 2: now[0] += timedelta(minutes=3)
                return original(binding, observed_at)
            registry.acquire = slow
            ledger = mock.Mock()
            cls = AuthenticatedFirstCertifier if first else AuthenticatedCertifier
            certifier = cls(registry, CertifierGitHubVerifier(api), ledger,
                contract_verifier=FirstContractVerifier() if first else ContractVerifier(),
                host='dev-desktop', clock=lambda: now[0])
            with self.subTest(first=first), self.assertRaises(PublicationDenied): certifier.publish(fixture.REQUEST)
            self.assertEqual(api.effects, [])
            ledger.reserve.assert_not_called()

    def test_existing_and_first_contract_read_exhausting_expiry_after_intent_rejects_without_post(self):
        from codestra_control.certifier_adapter import AuthenticatedFirstCertifier
        for first in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                registry = PendingRegistry() if first else Registry()
                verifier = FirstContractVerifier() if first else ContractVerifier()
                original = verifier.verify; calls = [0]; now = [fixture.NOW]
                def slow(acquired, observed_at):
                    calls[0] += 1
                    result = original(acquired, observed_at)
                    if calls[0] == 4: now[0] += timedelta(minutes=3)
                    return result
                verifier.verify = slow
                api = CertifierAPI(); cls = AuthenticatedFirstCertifier if first else AuthenticatedCertifier
                certifier = cls(registry, CertifierGitHubVerifier(api), IntentLedger(Path(directory) / 'intent.sqlite'),
                    contract_verifier=verifier, host='dev-desktop', clock=lambda: now[0])
                with self.subTest(first=first): self.assertEqual(certifier.publish(fixture.REQUEST).state, 'REJECTED')
                self.assertEqual(api.effects, [])

    def test_certifier_token_expiry_is_capped_before_check_effect(self):
        client = CertifierGitHubClient(lambda: 'unused', clock=lambda: fixture.NOW)
        client._token = 'synthetic'; client._expires = fixture.NOW + timedelta(hours=1)
        expiry = fixture.NOW + timedelta(seconds=1)
        client.bind_effect_expiry(expiry)
        client.clock = lambda: expiry
        with self.assertRaises(PublicationDenied): client.post('/repos/appolon1908/Breero.com/check-runs', {})


class CertifierInstallationFenceTests(unittest.TestCase):
    def test_all_repository_installation_wrong_owner_or_repository_identity_denies(self):
        for kind in ('selection', 'owner', 'repository', 'coverage'):
            def request(method, path, token, body=None):
                installation = {'id': 100, 'app_id': 99, 'suspended_at': None,
                    'permissions': dict(CertifierGitHubClient.PERMISSIONS), 'repository_selection': 'selected',
                    'account': {'login': 'appolon1908', 'id': 42}}
                if path == '/app': return {'id': 99}
                if path == '/app/installations/100':
                    if kind == 'selection': installation['repository_selection'] = 'all'
                    if kind == 'owner': installation['account']['id'] = 43
                    return installation
                if path.endswith('/access_tokens'):
                    return {'token': 'synthetic', 'expires_at': (fixture.NOW + timedelta(minutes=1)).isoformat(),
                            'permissions': dict(CertifierGitHubClient.PERMISSIONS), 'repositories': [{'id': 123}]}
                if path == '/repositories/123':
                    return {'id': 999 if kind == 'repository' else 123, 'full_name': fixture.REQUEST.repository,
                            'owner': {'login': 'appolon1908', 'id': 42}}
                if path.endswith('/installation'):
                    if kind == 'coverage': installation['id'] = 101
                    return installation
                raise AssertionError(path)
            client = CertifierGitHubClient(lambda: 'synthetic', request=request, clock=lambda: fixture.NOW)
            with self.subTest(kind=kind), self.assertRaises(PublicationDenied):
                client.assert_identity(Registry().value.authority, 123, fixture.NOW)


class FirstCertifierFactoryTests(unittest.TestCase):
    def test_privileged_factory_wires_real_ports_without_reading_credentials_or_posting(self):
        from unittest import mock
        from codestra_control.certifier_adapter import build_first_certifier_service, AuthenticatedFirstCertifier, RestrictedFirstCertificationRegistry
        with tempfile.TemporaryDirectory() as directory:
            signer = mock.Mock(side_effect=AssertionError('construction cannot read credentials'))
            policy_reader = mock.Mock(side_effect=AssertionError('construction cannot read policy'))
            connection = mock.Mock()
            service = build_first_certifier_service(connection, signer, Path(directory) / 'ledger.sqlite',
                policy_reader, host='dev-desktop', clock=lambda: fixture.NOW)
            self.assertIsInstance(service, AuthenticatedFirstCertifier)
            self.assertIsInstance(service.registry, RestrictedFirstCertificationRegistry)
            self.assertIsInstance(service.github.api, CertifierGitHubClient)
            self.assertIs(service.registry.connection, connection)
            signer.assert_not_called(); policy_reader.assert_not_called()


class DependencyFreshnessTests(unittest.TestCase):
    def test_stale_missing_future_time_or_wrong_independent_suite_denies_first_effect(self):
        from codestra_control.certifier_adapter import CertificationDependency
        original_registry = PendingRegistry()
        binding = replace(fixture.REQUEST, source_ref='testing', target_ref='staging', source_sha='e' * 40,
                          target_base_sha=fixture.REQUEST.source_sha)
        dependency = CertificationDependency(binding, 123, 88, 99, 'scope-certification', fixture.NOW + timedelta(minutes=2))
        for kind in ('stale', 'missing', 'future', 'suite-app', 'suite-sha', 'suite-missing'):
            registry = PendingRegistry(); registry.value = replace(original_registry.value, dependencies=(dependency,))
            api = CertifierAPI(); original = api.get
            def get(path):
                if path.endswith('/branches/testing'): return {'commit': {'sha': 'e' * 40}}
                if path.endswith('/branches/staging'): return {'commit': {'sha': fixture.REQUEST.source_sha}}
                if path.endswith('/check-runs/88'):
                    value = {'id': 88, 'app': {'id': 99}, 'name': 'scope-certification', 'head_sha': 'e' * 40,
                        'external_id': binding_digest(binding), 'status': 'completed', 'conclusion': 'success',
                        'completed_at': fixture.NOW.isoformat(), 'check_suite': {'id': 188}}
                    if kind == 'missing': value.pop('completed_at')
                    if kind == 'suite-missing': value.pop('check_suite')
                    if kind == 'stale': value['completed_at'] = (fixture.NOW - timedelta(minutes=6)).isoformat()
                    if kind == 'future': value['completed_at'] = (fixture.NOW + timedelta(seconds=1)).isoformat()
                    return value
                if path.endswith('/check-suites/188'):
                    return {'id': 188, 'app': {'id': 7 if kind == 'suite-app' else 99},
                        'head_sha': 'd' * 40 if kind == 'suite-sha' else 'e' * 40,
                        'status': 'completed', 'conclusion': 'success'}
                return original(path)
            api.get = get
            with tempfile.TemporaryDirectory() as directory:
                from codestra_control.certifier_adapter import AuthenticatedFirstCertifier
                issuer = AuthenticatedFirstCertifier(registry, CertifierGitHubVerifier(api),
                    IntentLedger(Path(directory) / 'intent.sqlite'), contract_verifier=FirstContractVerifier(),
                    host='dev-desktop', clock=lambda: fixture.NOW)
                with self.subTest(kind=kind), self.assertRaises(PublicationDenied): issuer.publish(fixture.REQUEST)
                self.assertEqual(api.effects, [])

    def test_final_registry_read_exhausting_github_dependency_freshness_denies_before_intent(self):
        from codestra_control.certifier_adapter import AuthenticatedFirstCertifier, CertificationDependency
        from unittest import mock
        registry = PendingRegistry(); now = [fixture.NOW]
        binding = replace(fixture.REQUEST, source_ref='testing', target_ref='staging', source_sha='e' * 40,
                          target_base_sha=fixture.REQUEST.source_sha)
        registry.value = replace(registry.value, dependencies=(CertificationDependency(binding, 123, 88, 99,
            'scope-certification', fixture.NOW + timedelta(minutes=2)),))
        api = CertifierAPI(); original_get = api.get
        def get(path):
            if path.endswith('/branches/testing'): return {'commit': {'sha': 'e' * 40}}
            if path.endswith('/branches/staging'): return {'commit': {'sha': fixture.REQUEST.source_sha}}
            if path.endswith('/check-runs/88'):
                return {'id': 88, 'app': {'id': 99}, 'name': 'scope-certification', 'head_sha': 'e' * 40,
                    'external_id': binding_digest(binding), 'status': 'completed', 'conclusion': 'success',
                    'completed_at': (fixture.NOW - timedelta(seconds=299)).isoformat(), 'check_suite': {'id': 188}}
            if path.endswith('/check-suites/188'):
                return {'id': 188, 'app': {'id': 99}, 'head_sha': 'e' * 40, 'status': 'completed', 'conclusion': 'success'}
            return original_get(path)
        api.get = get
        original_acquire = registry.acquire
        def slow(binding, observed_at):
            result = original_acquire(binding, observed_at)
            if registry.calls == 2: now[0] += timedelta(seconds=2)
            return result
        registry.acquire = slow
        ledger = mock.Mock()
        issuer = AuthenticatedFirstCertifier(registry, CertifierGitHubVerifier(api), ledger,
            contract_verifier=FirstContractVerifier(), host='dev-desktop', clock=lambda: now[0])
        with self.assertRaises(PublicationDenied): issuer.publish(fixture.REQUEST)
        self.assertEqual(api.effects, []); ledger.reserve.assert_not_called()


class ConfiguredDependencyInventoryTests(unittest.TestCase):
    def test_every_environment_scope_requires_its_actual_registered_predecessor_inventory(self):
        from unittest import mock
        from codestra_control.certifier_adapter import CertificationDependency, RestrictedFirstCertificationRegistry
        from codestra_control.policy import ScopeEdge
        pending = PendingRegistry().value
        mapping = replace(pending.snapshot.mapping, scope_edges=(
            ScopeEdge('section', 'section/sec', 'development', 'development'),))
        chain = [mapping.development_ref,mapping.testing_ref,mapping.staging_ref,mapping.production_ref]
        product = (fixture.REQUEST.repository,mapping.testing_ref,chain,
            dict(product=fixture.REQUEST.product,repository=fixture.REQUEST.repository,test_branch=mapping.testing_ref,promotion_chain=chain),
            123,*chain,mapping.release_ref,True)
        for scope, current, expected in (
            ('DEVELOPMENT', ('development','testing'), ('section/sec','development')),
            ('TESTING', ('testing','staging'), ('development','testing')),
            ('STAGING', ('staging','production/environment'), ('testing','staging')),
            ('PRODUCTION', ('production/environment','main'), ('staging','production/environment'))):
            binding = replace(fixture.REQUEST, source_ref=current[0], target_ref=current[1])
            dependency = CertificationDependency(replace(fixture.REQUEST, source_ref=expected[0], target_ref=expected[1]),
                123,88,99,'scope-certification',fixture.NOW+timedelta(minutes=2))
            acquired = replace(pending, scope_type=scope, scope_name=binding.source_ref,
                snapshot=replace(pending.snapshot, mapping=mapping, observed_binding=binding), dependencies=())
            cursor = mock.Mock(); cursor.fetchone.return_value = product; cursor.fetchall.side_effect = [[('section-id','sec','section/sec',[])],[]]
            with self.subTest(scope=scope), self.assertRaisesRegex(PublicationDenied, 'CURRENT_DEPENDENCY_INVENTORY_MISMATCH'):
                RestrictedFirstCertificationRegistry._registered_dependencies(cursor, acquired)
            cursor.fetchall.side_effect = [[('section-id','sec','section/sec',[])],[]]
            RestrictedFirstCertificationRegistry._registered_dependencies(cursor, replace(acquired, dependencies=(dependency,)))
