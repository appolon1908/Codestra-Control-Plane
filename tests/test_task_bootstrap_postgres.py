"""Authenticated bootstrap in a disposable PostgreSQL16 TLS/SCRAM fixture only."""
import concurrent.futures
import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest
from unittest import mock
import uuid

import psycopg2
from psycopg2.extras import Json

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import test_coordinator_integration as integration
import test_scoped_registration as registration

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / '016-authenticated-task-bootstrap.sql'


@unittest.skipUnless((registration.PG / 'initdb').exists(), 'PostgreSQL16 required')
class TaskBootstrapPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        integration.CoordinatorIntegrationTests.setUpClass.__func__(cls)
        try:
            with cls.connect('fixture_admin') as connection, connection.cursor() as cursor:
                cursor.execute((ROOT / '010-scoped-operation-admission.sql').read_text())
                cursor.execute('GRANT USAGE ON SCHEMA scoped_admission TO alice,bob,verifier,operator')
                cursor.execute('GRANT EXECUTE ON FUNCTION scoped_admission.request(uuid,uuid,bigint,jsonb,text),scoped_admission.consume(uuid,uuid),scoped_admission.inspect(uuid) TO alice,bob')
                cursor.execute('GRANT EXECUTE ON FUNCTION scoped_admission.describe(uuid),scoped_admission.attest(uuid,jsonb) TO verifier')
                if MIGRATION.exists():
                    cursor.execute(MIGRATION.read_text())
                    cursor.execute('GRANT USAGE ON SCHEMA task_bootstrap TO alice,bob,verifier,operator')
                    cursor.execute('GRANT EXECUTE ON FUNCTION task_bootstrap.request(jsonb,text),task_bootstrap.issue(uuid,uuid),task_bootstrap.inspect(uuid),task_bootstrap.revoke(uuid) TO operator')
                    cursor.execute('GRANT EXECUTE ON FUNCTION task_bootstrap.describe(uuid),task_bootstrap.attest(uuid,jsonb) TO verifier')
                    cursor.execute('GRANT EXECUTE ON FUNCTION task_bootstrap.lease_description(uuid),task_bootstrap.lease_attest(uuid,jsonb),task_bootstrap.stage_description(uuid),task_bootstrap.stage_attest(uuid,jsonb) TO verifier')
                    cursor.execute('GRANT EXECUTE ON FUNCTION task_bootstrap.acknowledge(uuid) TO alice,bob')
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        integration.CoordinatorIntegrationTests.tearDownClass.__func__(cls)

    password = staticmethod(integration.CoordinatorIntegrationTests.password)
    connect = classmethod(integration.CoordinatorIntegrationTests.connect.__func__)
    admin = integration.CoordinatorIntegrationTests.admin

    def setUp(self):
        if MIGRATION.exists():
            self.admin('SET LOCAL session_replication_role=replica; TRUNCATE task_bootstrap.audit,task_bootstrap.issued,task_bootstrap.proofs,task_bootstrap.acknowledgements,task_bootstrap.requests,task_bootstrap.sessions,task_bootstrap.profiles CASCADE')
        self.fixture = integration.CoordinatorIntegrationTests('test_a_subsection_prepare_independent_proof_admit_and_atomic_inspect')
        def fixture_connection(user='alice', sslmode='verify-full'):
            connection = self.connect(user, sslmode)
            if user == 'fixture_admin':
                # Only synthetic fixture reset bypasses immutable-history triggers.
                # Every API, authority update and adversarial test below uses normal
                # trigger execution on a fresh, explicitly closed connection.
                with connection.cursor() as cursor:
                    cursor.execute('SET session_replication_role=replica')
                connection.commit()
            return connection
        self.fixture.connect = fixture_connection
        self.fixture.setUp()
        self.fixture.connect = self.connect
        self.profile = str(uuid.uuid4())
        self.session = str(uuid.uuid4())
        self.oids = dict(self.admin("SELECT rolname,oid::bigint FROM pg_roles WHERE rolname IN ('alice','bob','operator','verifier')"))
        self.payload = {
            'schema': 'codestra.task-bootstrap-request.v1', 'profile_id': self.profile,
            'session_id': self.session, 'binding': {
                'product': 'A', 'workstation_id': 'A-ws', 'task_id': 'A-new-task',
                'principal': 'alice', 'principal_oid': self.oids['alice'],
                'repository': 'appolon1908/A', 'repository_id': 123,
                'source_ref': 'atomic/sec--sub--new-task', 'target_ref': 'subsection/sec--sub',
                'head_sha': 'a' * 40, 'base_sha': 'b' * 40,
                'worktree': '/fixture/A/new-atomic', 'host': 'fixture-host',
                'root_path': '/fixture/A', 'git_common_dir': '/fixture/A/repo.git',
                'worktree_uid': 1000, 'valid_until': (datetime.now(timezone.utc) + timedelta(minutes=4)).isoformat(),
            }, 'title': 'Synthetic bootstrap task', 'prerequisites': [], 'dependencies': [],
            'paths': ['src/one.py'], 'permitted_remote': 'https://github.com/appolon1908/A.git',
            'route': {'source_level': 'atomic', 'target_level': 'subsection'},
            'custody_sha256': 'c' * 64, 'expected_predecessor': None,
        }
        if MIGRATION.exists():
            self.admin("INSERT INTO assignment_leases.permissions VALUES('verifier','A','read',true)")
            self.admin('INSERT INTO task_bootstrap.profiles(profile_id,operator,operator_oid,verifier,verifier_oid,product,repository,repository_id,target_ref,permitted_remote,host,root_path,paths,custody_sha256,valid_until,active) VALUES(%s,\'operator\',%s,\'verifier\',%s,\'A\',\'appolon1908/A\',123,\'subsection/sec--sub\',\'https://github.com/appolon1908/A.git\',\'fixture-host\',\'/fixture/A\',%s,%s,clock_timestamp()+interval \'10 minutes\',true)',
                       (self.profile, self.oids['operator'], self.oids['verifier'], Json(['src/one.py', 'src/two.py']), 'c' * 64))
            self.admin('INSERT INTO task_bootstrap.sessions(session_id,profile_id,principal,principal_oid,custody_sha256,valid_until,active) VALUES(%s,%s,\'alice\',%s,%s,clock_timestamp()+interval \'10 minutes\',true)',
                       (self.session, self.profile, self.oids['alice'], 'c' * 64))

    def call(self, name, values, user='operator', role=None, session_authorization=None, commit=True):
        with self.connect(user) as connection, connection.cursor() as cursor:
            if role:
                cursor.execute('SET ROLE ' + role)
            if session_authorization:
                cursor.execute('SET SESSION AUTHORIZATION ' + session_authorization)
            try:
                cursor.execute('SELECT task_bootstrap.' + name + '(' + ','.join(['%s'] * len(values)) + ')', values)
            except (psycopg2.errors.InvalidSchemaName, psycopg2.errors.UndefinedFunction):
                self.fail('Authenticated initial task-bootstrap API is missing')
            result = cursor.fetchone()[0]
            if commit:
                connection.commit()
            else:
                connection.rollback()
            return result

    def request(self, payload=None, nonce='bootstrap-1'):
        return self.call('request', (Json(self.payload if payload is None else payload), nonce))

    def proof(self, request, changes=None, materialization_changes=None):
        description = self.call('describe', (request['request_id'],), user='verifier')
        binding = description['binding']
        materialization = {key: binding[key] for key in ('repository', 'repository_id', 'source_ref', 'target_ref', 'head_sha', 'base_sha', 'worktree', 'host', 'git_common_dir', 'worktree_uid')}
        materialization.update(directory_device=1, directory_inode=2, observed_at=datetime.now(timezone.utc).isoformat(),
                               dependencies={row['dependency_key']: row for row in description['dependencies']},
                               permitted_remote=description['permitted_remote'])
        materialization.update(materialization_changes or {})
        observed = {'request_digest': description['request_digest'], 'materialization': materialization}
        observed.update(changes or {})
        return self.call('attest', (request['request_id'], Json(observed)), user='verifier')

    def issue(self, request=None):
        request = request or self.request()
        self.call('acknowledge', (request['request_id'],), user='alice')
        proof = self.proof(request)
        return self.call('issue', (request['request_id'], proof['proof_id']))

    def test_initial_issue_requires_authenticated_receiving_ack_and_independent_proof(self):
        request = self.request()
        self.assertEqual(request['state'], 'PENDING')
        proof = self.proof(request)
        with self.assertRaisesRegex(psycopg2.Error, 'BOOTSTRAP_ACK_REQUIRED'):
            self.call('issue', (request['request_id'], proof['proof_id']))
        with self.assertRaises(psycopg2.Error):
            self.call('acknowledge', (request['request_id'],), user='bob')
        self.call('acknowledge', (request['request_id'],), user='alice')
        issued = self.call('issue', (request['request_id'], proof['proof_id']))
        self.assertEqual(issued['state'], 'ISSUED')
        self.assertFalse(issued['usable'])
        self.assertFalse(issued['source_authorized'])
        self.assertEqual(self.admin('SELECT count(*) FROM assignment_leases.bindings WHERE binding_id=%s', (issued['binding_id'],)), [(1,)])
        self.assertEqual(self.admin('SELECT count(*) FROM scoped_admission.grants WHERE binding_id=%s AND active', (issued['binding_id'],)), [(2,)])

    def test_legacy_claim_without_issued_bootstrap_is_rejected(self):
        self.fixture.coordinate()
        with self.assertRaisesRegex(psycopg2.Error, 'BOOTSTRAP_AUTHORITY_REQUIRED'):
            self.fixture.coordinate('admit', proof=str(uuid.uuid4()))

    def test_operator_identity_profile_session_route_and_custody_are_independent(self):
        for kwargs in ({'user': 'alice'}, {'user': 'fixture_admin', 'session_authorization': 'operator'}, {'role': 'alice'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(psycopg2.Error):
                self.call('request', (Json(self.payload), 'forged'), **kwargs)
        for key, value in [('session_id', str(uuid.uuid4())), ('custody_sha256', 'd' * 64), ('route', {'source_level': 'atomic', 'target_level': 'section'})]:
            payload = copy.deepcopy(self.payload)
            payload[key] = value
            with self.subTest(key=key), self.assertRaises(psycopg2.Error):
                self.request(payload)

    def test_request_idempotence_binds_all_bytes_and_readback_never_reissues(self):
        request = self.request()
        self.assertEqual(self.request(), request)
        changed = copy.deepcopy(self.payload)
        changed['title'] = 'Changed task'
        with self.assertRaisesRegex(psycopg2.Error, 'BOOTSTRAP_REQUEST_CONFLICT'):
            self.request(changed)
        issued = self.issue(request)
        self.assertEqual(self.call('inspect', (request['request_id'],))['binding_id'], issued['binding_id'])
        self.assertEqual(self.call('issue', (request['request_id'], self.proof(request)['proof_id']))['binding_id'], issued['binding_id'])

    def test_profile_reenable_cannot_revive_old_request_or_proof(self):
        request = self.request()
        self.call('acknowledge', (request['request_id'],), user='alice')
        proof = self.proof(request)
        self.admin('UPDATE task_bootstrap.profiles SET active=false WHERE profile_id=%s', (self.profile,))
        self.admin('UPDATE task_bootstrap.profiles SET active=true WHERE profile_id=%s', (self.profile,))
        with self.assertRaises(psycopg2.Error):
            self.call('issue', (request['request_id'], proof['proof_id']))

    def test_changed_materialization_or_full_request_digest_cannot_be_attested(self):
        request = self.request()
        with self.assertRaises(psycopg2.Error):
            self.proof(request, {'request_digest': 'f' * 64})

    def test_runtime_cannot_create_profiles_sessions_or_authority_records(self):
        for table in ('profiles', 'sessions', 'requests', 'proofs', 'issued', 'acknowledgements', 'audit'):
            with self.subTest(table=table), self.connect('alice') as connection, connection.cursor() as cursor:
                with self.assertRaises(psycopg2.Error):
                    cursor.execute('DELETE FROM task_bootstrap.' + table)

    def test_pending_revocation_is_durable_and_cannot_be_issued_later(self):
        request = self.request()
        proof = self.proof(request)
        self.call('acknowledge', (request['request_id'],), user='alice')
        self.assertEqual(self.call('revoke', (request['request_id'],))['state'], 'REVOKED')
        with self.assertRaisesRegex(psycopg2.Error, 'BOOTSTRAP_REVOKED'):
            self.call('issue', (request['request_id'], proof['proof_id']))
        self.assertEqual(self.call('inspect', (request['request_id'],))['state'], 'REVOKED')

    def test_verifier_capability_revocation_after_proof_prevents_issue(self):
        request = self.request()
        self.call('acknowledge', (request['request_id'],), user='alice')
        proof = self.proof(request)
        self.admin("UPDATE assignment_leases.permissions SET active=false WHERE principal='verifier' AND capability='read'")
        with self.assertRaises(psycopg2.Error):
            self.call('issue', (request['request_id'], proof['proof_id']))

    def test_historical_readback_survives_profile_revocation_without_authority(self):
        request = self.request()
        issued = self.issue(request)
        self.admin('UPDATE task_bootstrap.profiles SET active=false WHERE profile_id=%s', (self.profile,))
        historical = self.call('inspect', (request['request_id'],))
        self.assertEqual(historical['binding_id'], issued['binding_id'])
        self.assertTrue(historical['historical'])
        self.assertFalse(historical['usable'])
        self.assertFalse(historical['ready_for_admission'])
        self.assertEqual(historical['authority'], 'NONE')

    def test_column_writer_and_noninherited_writer_cannot_be_bound(self):
        self.admin('GRANT UPDATE(active) ON task_bootstrap.profiles TO alice')
        with self.assertRaises(psycopg2.Error):
            self.request()
        self.admin('REVOKE UPDATE(active) ON task_bootstrap.profiles FROM alice')
        self.admin('CREATE ROLE bootstrap_column_holder NOINHERIT; GRANT UPDATE(active) ON task_bootstrap.sessions TO bootstrap_column_holder; GRANT bootstrap_column_holder TO alice')
        try:
            with self.assertRaises(psycopg2.Error):
                self.request()
        finally:
            self.admin('REVOKE bootstrap_column_holder FROM alice; DROP OWNED BY bootstrap_column_holder; DROP ROLE bootstrap_column_holder')

    def test_real_client_composes_request_ack_verify_issue_and_safe_readback(self):
        from codestra_control import task_bootstrap as client
        from test_lease_materialization import MaterializationTests
        fixture = MaterializationTests('test_real_checkout_identity_and_remote_binding_are_observed')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.payload['binding'].update(fixture.binding)
        self.payload['paths'] = ['source.txt']
        self.admin('UPDATE task_bootstrap.profiles SET root_path=%s,paths=%s WHERE profile_id=%s', (str(fixture.root),Json(['source.txt']),self.profile))
        with self.connect('operator') as connection:
            request = client.operate(connection, 'request', {'payload': self.payload, 'request_id': 'real-client'}, apply=True)['result']
        with self.connect('alice') as connection:
            client.operate(connection, 'acknowledge', {'operation_id': request['request_id']}, apply=True)
        materializer = client.BootstrapMaterializer
        with mock.patch.object(client, 'BootstrapMaterializer', side_effect=lambda observer: materializer(observer,host=lambda:'fixture-host',filesystem_anchor=fixture.root)):
            with self.connect('verifier') as connection:
                proof = client.operate(connection, 'verify', {'operation_id': request['request_id']}, observer=fixture.observer, apply=True)['result']
        with self.connect('operator') as connection:
            issued = client.operate(connection, 'issue', {'operation_id': request['request_id'], 'proof_id': proof['proof_id']}, apply=True)['result']
        self.assertEqual(issued['state'], 'ISSUED')
        self.assertFalse(issued['usable'])

    def successor(self, issued, task=None, paths=None):
        session = str(uuid.uuid4())
        self.admin('INSERT INTO task_bootstrap.sessions(session_id,profile_id,principal,principal_oid,custody_sha256,valid_until,active) VALUES(%s,%s,\'bob\',%s,%s,clock_timestamp()+interval \'10 minutes\',true)',
                   (session, self.profile, self.oids['bob'], 'c' * 64))
        payload = copy.deepcopy(self.payload)
        payload['session_id'] = session
        payload['binding'].update(principal='bob', principal_oid=self.oids['bob'])
        if task:
            payload['binding'].update(task_id=task, source_ref='atomic/sec--sub--' + task.lower(), worktree='/fixture/A/' + task.lower())
        if paths:
            payload['paths'] = paths
        payload['expected_predecessor'] = {key: issued[key] for key in ('binding_id', 'revision', 'epoch', 'session_id')}
        return payload

    def test_same_task_cas_handoff_preserves_old_vector_and_invalidates_old_owner(self):
        old = self.issue()
        from codestra_control.controller_coordinator import coordinate
        with self.connect('alice') as connection:
            coordinate(connection, 'prepare', 'A-new-task', 'appolon1908/A', 'old-prepare', apply=True)
        payload = self.successor(old)
        request = self.request(payload, 'handoff')
        self.call('acknowledge', (request['request_id'],), user='bob')
        proof = self.proof(request)
        new = self.call('issue', (request['request_id'], proof['proof_id']))
        self.assertNotEqual(old['binding_id'], new['binding_id'])
        self.assertEqual(new['revision'], old['revision'] + 1)
        self.assertGreater(new['epoch'], old['epoch'])
        self.assertEqual(self.admin('SELECT state,binding_snapshot->>\'principal\' FROM task_bootstrap.issued WHERE request_id=%s', (old['request_id'],)), [('REVOKED', 'alice')])
        self.assertEqual(self.admin('SELECT principal::text,active FROM scoped_registration.task_assignments WHERE task_id=\'A-new-task\' ORDER BY principal::text'), [('alice', False), ('bob', True)])
        with self.connect('bob') as connection:
            result = coordinate(connection, 'prepare', 'A-new-task', 'appolon1908/A', 'new-prepare', apply=True)
        self.assertEqual(result['state'], 'AWAITING_VERIFICATION')
        descriptor = self.call('lease_description',(new['binding_id'],),user='verifier')
        binding = descriptor['description']['binding']
        observation = {key: binding[key] for key in ('repository','repository_id','source_ref','target_ref','head_sha','base_sha','worktree','host','git_common_dir','worktree_uid')}
        observation.update(directory_device=1,directory_inode=2,observed_at=datetime.now(timezone.utc).isoformat(),dependencies={},permitted_remote=payload['permitted_remote'])
        lease_proof = self.call('lease_attest',(new['binding_id'],Json({'request_digest':descriptor['request_digest'],'materialization':observation})),user='verifier')
        with self.connect('bob') as connection:
            admitted = coordinate(connection,'admit','A-new-task','appolon1908/A','new-admit',proof_id=lease_proof['proof_id'],apply=True)
        lease = admitted['lease']
        self.assertEqual(self.legacy('assignment_leases','check_owned',(lease['lease_id'],lease['epoch']),user='bob')['principal'],'bob')
        with self.connect('alice') as connection, connection.cursor() as cursor:
            with self.assertRaises(psycopg2.Error):
                cursor.execute('SELECT assignment_leases.resolve_task(%s,%s)', ('A-new-task', 'appolon1908/A'))

    def test_different_worktrees_do_not_hide_overlapping_repository_paths(self):
        self.issue()
        payload = copy.deepcopy(self.payload)
        payload['binding'].update(task_id='A-second-task',source_ref='atomic/sec--sub--second-task',worktree='/fixture/A/second-atomic')
        request = self.request(payload, 'overlap')
        self.call('acknowledge', (request['request_id'],), user='alice')
        proof = self.proof(request)
        with self.assertRaisesRegex(psycopg2.Error, 'BOOTSTRAP_OVERLAP'):
            self.call('issue', (request['request_id'], proof['proof_id']))

    def legacy(self, schema, name, values, user='alice', session_authorization=None):
        with self.connect(user) as connection, connection.cursor() as cursor:
            if session_authorization:
                cursor.execute('SET SESSION AUTHORIZATION ' + session_authorization)
            cursor.execute('SELECT ' + schema + '.' + name + '(' + ','.join(['%s'] * len(values)) + ')', values)
            return cursor.fetchone()[0]

    def test_sealed_lease_and_operation_proofs_are_required_by_direct_legacy_apis(self):
        issued = self.issue()
        from codestra_control.controller_coordinator import coordinate
        with self.connect('alice') as connection:
            coordinate(connection, 'prepare', 'A-new-task', 'appolon1908/A', 'prepare', apply=True)
        description = self.call('lease_description', (issued['binding_id'],), user='verifier')
        binding = description['description']['binding']
        observed = {key: binding[key] for key in ('repository','repository_id','source_ref','target_ref','head_sha','base_sha','worktree','host','git_common_dir','worktree_uid')}
        observed.update(directory_device=1,directory_inode=2,observed_at=datetime.now(timezone.utc).isoformat(),dependencies={})
        raw_proof = self.legacy('assignment_leases','attest',(issued['binding_id'],Json(observed)),user='verifier')
        with self.assertRaisesRegex(psycopg2.Error, 'BOOTSTRAP_AUTHORITY_REQUIRED'):
            self.legacy('assignment_leases','claim',(issued['binding_id'],raw_proof['proof_id'],'raw-proof'))
        sealed = self.call('lease_attest',(issued['binding_id'],Json({'request_digest':description['request_digest'],'materialization':dict(observed,permitted_remote=self.payload['permitted_remote'])})),user='verifier')
        with self.assertRaisesRegex(psycopg2.Error, 'BOOTSTRAP_AUTHENTICATION_REQUIRED'):
            self.legacy('assignment_leases','claim',(issued['binding_id'],sealed['proof_id'],'impersonation'),user='fixture_admin',session_authorization='alice')
        lease = self.legacy('assignment_leases','claim',(issued['binding_id'],sealed['proof_id'],'sealed-proof'))
        self.assertEqual(lease['state'],'ACTIVE')
        intent = self.legacy('scoped_admission','request',(issued['l1_grant_id'],lease['lease_id'],lease['epoch'],Json({'paths':['src/one.py'],'mutation_sha256':'e'*64}),'source-op'))
        stage = self.call('stage_description',(intent['intent_id'],),user='verifier')
        stage_observation = {'intent_id':intent['intent_id'],'request_digest':stage['request_digest'],'operation':'L1','lease_id':lease['lease_id'],'epoch':lease['epoch'],
            'head_sha':'a'*40,'tree_sha':'d'*40,'changed_paths':['src/one.py'],'directory_device':1,'directory_inode':2,'dependencies':{},'observed_at':datetime.now(timezone.utc).isoformat()}
        raw_stage = self.legacy('scoped_admission','attest',(intent['intent_id'],Json(stage_observation)),user='verifier')
        with self.assertRaisesRegex(psycopg2.Error,'BOOTSTRAP_AUTHORITY_REQUIRED'):
            self.legacy('scoped_admission','consume',(intent['intent_id'],raw_stage['proof_id']))
        for remote in ('git@github.com:appolon1908/A.git', 'https://github.com/other/A.git'):
            with self.subTest(remote=remote),self.assertRaisesRegex(psycopg2.Error,'BOOTSTRAP_OBSERVATION_MISMATCH'):
                self.call('stage_attest',(intent['intent_id'],Json({'request_digest':stage['request_digest'],'materialization':dict(stage_observation,permitted_remote=remote)})),user='verifier')
        sealed_stage = self.call('stage_attest',(intent['intent_id'],Json({'request_digest':stage['request_digest'],'materialization':dict(stage_observation,permitted_remote=self.payload['permitted_remote'])})),user='verifier')
        receipt = self.legacy('scoped_admission','consume',(intent['intent_id'],sealed_stage['proof_id']))
        self.assertEqual(receipt['authority'],'ONLINE_SCOPED_OPERATION_RECEIPT')
        self.assertTrue(receipt['usable'])

    def test_disjoint_paths_with_distinct_materializations_can_be_reserved(self):
        self.issue()
        payload = copy.deepcopy(self.payload)
        payload['paths'] = ['src/two.py']
        payload['binding'].update(task_id='A-disjoint-task',source_ref='atomic/sec--sub--disjoint-task',worktree='/fixture/A/disjoint-atomic')
        request = self.request(payload,'disjoint')
        self.call('acknowledge',(request['request_id'],),user='alice')
        proof = self.proof(request,materialization_changes={'directory_inode':3})
        issued = self.call('issue',(request['request_id'],proof['proof_id']))
        self.assertEqual(issued['state'],'ISSUED')
        self.assertEqual(self.admin("SELECT count(*) FROM task_bootstrap.issued WHERE state='ISSUED'"),[(2,)])

    def test_two_cas_successors_have_exactly_one_winner(self):
        old = self.issue()
        payload = self.successor(old)
        requests = []
        for index in range(2):
            proposed = copy.deepcopy(payload)
            proposed['title'] += str(index)
            request = self.request(proposed,'cas-'+str(index))
            self.call('acknowledge',(request['request_id'],),user='bob')
            requests.append((request,self.proof(request)))
        def attempt(pair):
            request,proof = pair
            try:
                return self.call('issue',(request['request_id'],proof['proof_id']))
            except psycopg2.Error as error:
                return error.diag.message_primary
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(attempt,requests))
        self.assertEqual(sum(isinstance(outcome,dict) for outcome in outcomes),1,repr(outcomes))
        self.assertIn('BOOTSTRAP_CAS_MISMATCH',outcomes)
        self.assertEqual(self.admin("SELECT count(*) FROM task_bootstrap.issued WHERE state='ISSUED'"),[(1,)])

    def test_pure_windows_executor_and_mixed_path_have_distinct_denials(self):
        for path,reason in [('C:\\Codestra\\atomic','BOOTSTRAP_EXECUTOR_UNSUPPORTED'),('/srv/apps/C:\\Codestra\\atomic','BOOTSTRAP_EXECUTOR_MALFORMED')]:
            payload = copy.deepcopy(self.payload)
            payload['binding']['worktree'] = path
            with self.subTest(path=path),self.assertRaisesRegex(psycopg2.Error,reason):
                self.request(payload)

    def test_cas_tokens_must_be_nonnull_positive_integer_values(self):
        payload = self.successor(self.issue())
        for field in ('revision','epoch'):
            for value in (None, '1', 0, -1, True):
                changed = copy.deepcopy(payload)
                changed['expected_predecessor'][field] = value
                with self.subTest(field=field,value=value),self.assertRaisesRegex(psycopg2.Error,'BOOTSTRAP_CAS_MISMATCH'):
                    self.request(changed, 'bad-'+field+'-'+str(value))

    def test_function_owner_cannot_be_accepted_as_builder(self):
        self.admin('CREATE FUNCTION public.bootstrap_owned() RETURNS integer LANGUAGE sql AS \'SELECT 1\'; ALTER FUNCTION public.bootstrap_owned() OWNER TO alice')
        try:
            with self.assertRaises(psycopg2.Error):
                self.request()
        finally:
            self.admin('DROP FUNCTION public.bootstrap_owned()')

    def test_immutable_bootstrap_history_rejects_update_delete_and_truncate(self):
        request = self.request()
        self.issue(request)
        for statement in ('UPDATE task_bootstrap.requests SET client_request_id=\'changed\'',
                          'DELETE FROM task_bootstrap.issued', 'TRUNCATE task_bootstrap.audit'):
            with self.subTest(statement=statement),self.assertRaisesRegex(psycopg2.Error,'BOOTSTRAP_HISTORY_IMMUTABLE'):
                self.admin(statement)


@unittest.skipUnless((registration.PG / 'initdb').exists(), 'PostgreSQL16 required')
class TaskBootstrapCachedPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        integration.CoordinatorIntegrationTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        integration.CoordinatorIntegrationTests.tearDownClass.__func__(cls)

    password = staticmethod(integration.CoordinatorIntegrationTests.password)
    connect = classmethod(integration.CoordinatorIntegrationTests.connect.__func__)

    def test_existing_connection_and_cached_function_oid_cannot_bypass_forward_guard(self):
        fixture = integration.CoordinatorIntegrationTests('test_a_subsection_prepare_independent_proof_admit_and_atomic_inspect')
        fixture.connect = self.connect
        fixture.setUp()
        fixture.coordinate()
        lease = fixture.coordinate('admit',proof=fixture.proof())['lease']
        with self.connect('alice') as connection,connection.cursor() as cursor:
            cursor.execute("SELECT 'assignment_leases._binding(uuid,boolean)'::regprocedure::oid")
            before_oid = cursor.fetchone()[0]
            cursor.execute('PREPARE cached_owned(uuid,bigint) AS SELECT assignment_leases.check_owned($1,$2)')
            cursor.execute('EXECUTE cached_owned(%s,%s)',(lease['lease_id'],lease['epoch']))
            self.assertEqual(cursor.fetchone()[0]['state'],'ACTIVE')
            connection.commit()
            with self.connect('fixture_admin') as owner,owner.cursor() as administrator:
                administrator.execute((ROOT/'010-scoped-operation-admission.sql').read_text())
                administrator.execute(MIGRATION.read_text())
            cursor.execute("SELECT 'assignment_leases._binding(uuid,boolean)'::regprocedure::oid")
            self.assertEqual(cursor.fetchone()[0],before_oid)
            with self.assertRaisesRegex(psycopg2.Error,'BOOTSTRAP_AUTHORITY_REQUIRED'):
                cursor.execute('EXECUTE cached_owned(%s,%s)',(lease['lease_id'],lease['epoch']))
