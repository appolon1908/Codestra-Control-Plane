"""Scope leases in real disposable PostgreSQL16/TLS/SCRAM, never installed DB."""
import concurrent.futures
from datetime import datetime
from pathlib import Path
import unittest
import uuid

import psycopg2
from psycopg2 import sql

import test_frozen_recovery_executor as harness
import test_scoped_registration as registration


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / '012-scope-assignment-leases.sql'


@unittest.skipUnless((registration.PG / 'initdb').exists(), 'PostgreSQL16 disposable binaries required')
class ScopeAssignmentLeaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        migration = MIGRATION.read_text()
        harness.FrozenRecoveryExecutorTests.setUpClass()
        cls.path = harness.FrozenRecoveryExecutorTests.path
        cls.port = harness.FrozenRecoveryExecutorTests.port
        try:
            with cls.connect('fixture_admin') as connection, connection.cursor() as cursor:
                cursor.execute(migration)
                cursor.execute('GRANT USAGE ON SCHEMA scope_assignment_leases TO alice,bob,verifier,trust_operator')
                cursor.execute('GRANT EXECUTE ON FUNCTION scope_assignment_leases.claim(uuid,uuid) TO alice,bob,verifier,trust_operator')
                cursor.execute('GRANT EXECUTE ON FUNCTION scope_assignment_leases.inspect_binding(uuid) TO alice,bob,verifier,trust_operator')
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        harness.FrozenRecoveryExecutorTests.tearDownClass()

    @classmethod
    def connect(cls, user='alice', sslmode='verify-full'):
        return psycopg2.connect(host='127.0.0.1', port=cls.port, dbname='postgres', user=user,
            password=harness.FrozenRecoveryExecutorTests.password(user), sslmode=sslmode,
            sslrootcert=str(cls.path / 'fixture.crt'), connect_timeout=5,
            options='-c statement_timeout=30000 -c lock_timeout=10000')

    def admin(self, query, args=()):
        if getattr(self,'_seed_connection',None) is not None:
            with self._seed_connection.cursor() as cursor:
                cursor.execute(query,args)
                return cursor.fetchall() if cursor.description else None
        with self.connect('fixture_admin') as connection, connection.cursor() as cursor:
            cursor.execute(query, args)
            return cursor.fetchall() if cursor.description else None

    def setUp(self):
        with self.connect('fixture_admin') as connection:
            self._seed_connection=connection
            try:
                self.prepare()
            finally:
                self._seed_connection=None

    def prepare(self):
        self.admin('REVOKE alice FROM bob')
        self.admin('TRUNCATE scope_assignment_leases.audit,scope_assignment_leases.leases,'
                   'scope_assignment_leases.assignments,scope_assignment_leases.grants,'
                   'scope_assignment_leases.principals,scope_assignment_leases.products CASCADE')
        self.admin("DELETE FROM scoped_registration.workstations WHERE product='ScopeFixture'; "
                   "DELETE FROM scoped_registration.lanes WHERE product='ScopeFixture'; "
                   "DELETE FROM public.workstations WHERE product='ScopeFixture'; "
                   "DELETE FROM scoped_registration.products WHERE product='ScopeFixture'; "
                   "DELETE FROM public.products WHERE product='ScopeFixture'")
        self.admin("INSERT INTO public.products(product,repository,test_branch,promotion_chain) "
                   "VALUES('ScopeFixture','appolon1908/ScopeFixture','testing',"
                   "'[\"development\",\"testing\",\"staging\",\"production\"]')")
        self.admin("INSERT INTO scoped_registration.products VALUES('ScopeFixture',"
                   "'{\"product\":\"ScopeFixture\",\"repository\":\"appolon1908/ScopeFixture\","
                   "\"test_branch\":\"testing\",\"promotion_chain\":[\"development\",\"testing\",\"staging\",\"production\"]}')")
        self.admin("INSERT INTO public.sections(section_id,product,section_key,branch,order_index) "
                   "VALUES('scope-fixture-section','ScopeFixture','sec','section/sec',1)")
        self.admin("INSERT INTO public.workstations(workstation_id,product,section,subsection,branch,parent_branch,worktree,order_index) "
                   "VALUES('scope-fixture-ws','ScopeFixture','sec','sub','subsection/sec--sub','section/sec','/fixture/scope/subsection',1)")
        self.admin("INSERT INTO scoped_registration.workstations SELECT 'ScopeFixture',workstation_id,branch,worktree,"
                   "jsonb_build_object('product',product,'workstation_id',workstation_id,'section',section,'subsection',subsection,"
                   "'branch',branch,'parent_branch',parent_branch,'worktree',worktree,'order_index',order_index) "
                   "FROM public.workstations WHERE workstation_id='scope-fixture-ws'")
        self.admin("INSERT INTO scoped_registration.lanes VALUES('/fixture/scope/subsection','ScopeFixture','workstation','scope-fixture-ws','subsection/sec--sub')")
        self.admin("INSERT INTO scope_assignment_leases.products(product,repository,repository_id,account_owner,"
                   "development_ref,testing_ref,staging_ref,production_ref,release_ref,expires_at,active) "
                   "VALUES('ScopeFixture','appolon1908/ScopeFixture',123,'appolon1908','development','testing','staging','production','main',"
                   "clock_timestamp()+interval '10 minutes',true)")
        self.admin("INSERT INTO scope_assignment_leases.principals(principal,role_oid,account_owner,expires_at,active) "
                   "SELECT rolname,oid,'appolon1908',clock_timestamp()+interval '10 minutes',true FROM pg_roles "
                   "WHERE rolname IN ('alice','bob','verifier','trust_operator')")
        self.admin("INSERT INTO scope_assignment_leases.grants(principal,role_oid,product,capability,expires_at,active) "
                   "SELECT rolname,oid,'ScopeFixture',CASE WHEN rolname='verifier' THEN 'read' ELSE 'claim' END,"
                   "clock_timestamp()+interval '10 minutes',true FROM pg_roles WHERE rolname IN ('alice','bob','verifier','trust_operator')")
        self.assignment = self.assign()

    def assign(self, source_level='section', target_level='development', source_ref='section/sec',
               target_ref='development', principal='alice', expires_seconds=600):
        assignment = str(uuid.uuid4())
        self.admin("INSERT INTO scope_assignment_leases.assignments(assignment_id,task_id,product,principal,principal_oid,"
                   "repository,repository_id,source_level,target_level,source_ref,target_ref,head_sha,base_sha,expires_at,active) "
                   "SELECT %s,%s,'ScopeFixture',rolname,oid,'appolon1908/ScopeFixture',123,%s,%s,%s,%s,%s,%s,"
                   "clock_timestamp()+make_interval(secs=>%s),true FROM pg_roles WHERE rolname=%s",
                   (assignment, 'task-'+assignment, source_level,target_level,source_ref,target_ref,'a'*40,'b'*40,expires_seconds,principal))
        return assignment

    def call(self, operation, args, user='alice', role=None, sslmode='verify-full', readonly=False):
        with self.connect(user, sslmode) as connection:
            if readonly:
                connection.set_session(readonly=True)
            with connection.cursor() as cursor:
                if role:
                    cursor.execute(sql.SQL('SET ROLE {}').format(sql.Identifier(role)))
                cursor.execute(sql.SQL('SELECT scope_assignment_leases.{}({})').format(
                    sql.Identifier(operation),sql.SQL(',').join(sql.Placeholder() for _ in args)),args)
                return cursor.fetchone()[0]

    def claim(self, assignment=None, request=None, **kwargs):
        return self.call('claim',(assignment or self.assignment,request or str(uuid.uuid4())),**kwargs)

    def test_authenticated_claim_and_readonly_verifier_receipt_match_exact_binding(self):
        lease = self.claim()
        receipt = self.call('inspect_binding',(self.assignment,),user='verifier',readonly=True)
        self.assertEqual(receipt,lease)
        self.assertEqual(receipt['authority'],'ONLINE_DATABASE_RECEIPT')
        self.assertEqual(receipt['binding_id'],self.assignment)
        self.assertEqual(receipt['principal'],'alice')
        self.assertEqual(receipt['state'],'ACTIVE')
        self.assertGreater(receipt['epoch'],0)
        self.assertEqual(str(uuid.UUID(receipt['lease_id'])),receipt['lease_id'])
        self.assertEqual(receipt['binding'],{'repository':'appolon1908/ScopeFixture','repository_id':123,
            'product':'ScopeFixture','source_level':'section','target_level':'development',
            'source_ref':'section/sec','target_ref':'development','head_sha':'a'*40,'base_sha':'b'*40,'principal':'alice'})
        self.assertLessEqual((datetime.fromisoformat(receipt['expires_at'])-datetime.fromisoformat(receipt['started_at'])).total_seconds(),300)

    def test_missing_trust_plaintext_superuser_and_role_impersonation_deny(self):
        for user,sslmode in (('trust_operator','verify-full'),('alice','disable'),('fixture_admin','verify-full'),('bob','verify-full')):
            with self.subTest(user=user,sslmode=sslmode),self.assertRaisesRegex(psycopg2.Error,'SCOPE_'):
                self.claim(user=user,sslmode=sslmode)
        self.admin('GRANT alice TO bob')
        with self.assertRaisesRegex(psycopg2.Error,'SCOPE_'):
            self.claim(user='bob',role='alice')
        with self.assertRaisesRegex(psycopg2.Error,'SCOPE_'):
            self.claim(role='alice')

    def test_changed_role_oid_account_mapping_and_missing_product_grant_deny(self):
        mutations=("UPDATE scope_assignment_leases.principals SET role_oid=0 WHERE principal='alice'",
                   "UPDATE scope_assignment_leases.assignments SET principal_oid=0",
                   "UPDATE scope_assignment_leases.grants SET role_oid=0 WHERE principal='alice'",
                   "UPDATE scope_assignment_leases.principals SET account_owner='other' WHERE principal='alice'",
                   "UPDATE scope_assignment_leases.grants SET active=false WHERE principal='alice'")
        for query in mutations:
            with self.subTest(query=query):
                self.setUp();self.admin(query)
                with self.assertRaisesRegex(psycopg2.Error,'SCOPE_'):
                    self.claim()

    def test_concurrent_claims_have_exactly_one_winner_and_nonce_cannot_replay(self):
        requests=[str(uuid.uuid4()),str(uuid.uuid4())]
        def attempt(index):
            try:return self.claim(request=requests[index])
            except psycopg2.Error:return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(attempt,range(2)))
        self.assertEqual(sum(result is not None for result in results),1)
        request=requests[next(index for index,result in enumerate(results) if result is not None)]
        with self.assertRaisesRegex(psycopg2.Error,'SCOPE_'):
            self.claim(request=request)
        with self.assertRaisesRegex(psycopg2.Error,'SCOPE_'):
            self.claim(request=str(uuid.uuid4()))
        another=self.assign()
        with self.assertRaisesRegex(psycopg2.Error,'SCOPE_'):
            self.claim(assignment=another,request=request)

    def test_every_allowed_scope_edge_uses_actual_registered_refs(self):
        for source,target,source_ref,target_ref in (
            ('subsection','section','subsection/sec--sub','section/sec'),
            ('section','development','section/sec','development'),
            ('development','testing','development','testing'),
            ('testing','staging','testing','staging'),
            ('staging','production','staging','production'),
            ('production','main','production','main')):
            with self.subTest(source=source,target=target):
                assignment=self.assign(source,target,source_ref,target_ref)
                self.assertEqual(self.claim(assignment=assignment)['binding']['source_level'],source)
        for source,target in (('atomic_task','subsection'),('atomic','subsection'),('development','production'),('hotfix','production')):
            with self.subTest(source=source,target=target),self.assertRaises(psycopg2.Error):
                self.assign(source,target,'hotfix/bypass','production')

    def test_hotfix_or_wrong_registered_refs_and_registry_drift_deny(self):
        for column,value in (('source_ref','hotfix/fix'),('target_ref','main'),('repository','appolon1908/Other'),('testing_ref','other')):
            with self.subTest(column=column):
                self.setUp()
                table='assignments' if column.endswith('_ref') and column in ('source_ref','target_ref') else 'products'
                self.admin(sql.SQL('UPDATE scope_assignment_leases.{} SET {}=%s').format(sql.Identifier(table),sql.Identifier(column)),(value,))
                with self.assertRaisesRegex(psycopg2.Error,'SCOPE_'):
                    self.claim()
        self.setUp()
        subsection=self.assign('subsection','section','subsection/sec--sub','section/sec')
        self.admin("UPDATE scoped_registration.workstations SET branch='subsection/other'")
        with self.assertRaisesRegex(psycopg2.Error,'SCOPE_'):
            self.claim(assignment=subsection)

    def test_revoked_and_expired_states_are_current_without_renewal(self):
        for query,state in (("UPDATE scope_assignment_leases.assignments SET active=false",'REVOKED'),
                            ("UPDATE scope_assignment_leases.assignments SET expires_at=clock_timestamp()-interval '1 second'",'EXPIRED'),
                            ("UPDATE scope_assignment_leases.leases SET started_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 second'",'EXPIRED'),
                            ("UPDATE scope_assignment_leases.grants SET active=false WHERE principal='alice'",'REVOKED')):
            with self.subTest(state=state,query=query):
                self.setUp();self.claim();self.admin(query)
                receipt=self.call('inspect_binding',(self.assignment,),user='verifier',readonly=True)
                self.assertEqual(receipt['state'],state)
                with self.assertRaisesRegex(psycopg2.Error,'SCOPE_'):
                    self.claim()

    def test_assignment_expiry_bounds_lease_and_binding_edits_cannot_reseal(self):
        assignment=self.assign(expires_seconds=20)
        lease=self.claim(assignment=assignment)
        self.assertLessEqual((datetime.fromisoformat(lease['expires_at'])-datetime.fromisoformat(lease['started_at'])).total_seconds(),20)
        self.admin('UPDATE scope_assignment_leases.assignments SET head_sha=%s WHERE assignment_id=%s',('c'*40,assignment))
        with self.assertRaisesRegex(psycopg2.Error,'SCOPE_BINDING_CHANGED'):
            self.call('inspect_binding',(assignment,),user='verifier',readonly=True)

    def test_wrong_product_read_grant_and_recreated_verifier_identity_deny(self):
        self.claim()
        with self.assertRaisesRegex(psycopg2.Error,'SCOPE_'):
            self.call('inspect_binding',(self.assignment,),user='bob',readonly=True)
        self.admin("INSERT INTO scope_assignment_leases.products SELECT 'legacy','appolon1908/legacy',456,account_owner,"
                   "development_ref,testing_ref,staging_ref,production_ref,release_ref,expires_at,active "
                   "FROM scope_assignment_leases.products WHERE product='ScopeFixture'")
        self.admin("UPDATE scope_assignment_leases.grants SET product='legacy' WHERE principal='verifier'")
        with self.assertRaisesRegex(psycopg2.Error,'SCOPE_'):
            self.call('inspect_binding',(self.assignment,),user='verifier',readonly=True)
        self.admin("UPDATE scope_assignment_leases.principals SET role_oid=0 WHERE principal='verifier'")
        with self.assertRaisesRegex(psycopg2.Error,'SCOPE_'):
            self.call('inspect_binding',(self.assignment,),user='verifier',readonly=True)

    def test_runtime_cannot_write_authority_or_invoke_internal_functions(self):
        for table in ('principals','products','grants','assignments','leases','audit'):
            with self.subTest(table=table),self.connect() as connection,connection.cursor() as cursor:
                with self.assertRaisesRegex(psycopg2.Error,'permission denied'):
                    cursor.execute(sql.SQL('DELETE FROM scope_assignment_leases.{}').format(sql.Identifier(table)))
        with self.assertRaises(psycopg2.Error):
            self.call('_actor',())

    def test_repeatable_snapshot_cannot_cache_revocation_authority(self):
        self.claim()
        with self.connect('verifier') as connection:
            connection.set_session(readonly=True,isolation_level='REPEATABLE READ')
            with connection.cursor() as cursor:
                with self.assertRaisesRegex(psycopg2.Error,'SCOPE_AUTHENTICATION_REQUIRED'):
                    cursor.execute('SELECT scope_assignment_leases.inspect_binding(%s)',(self.assignment,))

    def test_actual_recreated_login_does_not_inherit_original_role_oid(self):
        assignment=self.assign(principal='bob')
        self.admin('DROP OWNED BY bob; DROP ROLE bob; CREATE ROLE bob LOGIN')
        self.admin(sql.SQL('ALTER ROLE bob PASSWORD {}').format(sql.Literal(harness.FrozenRecoveryExecutorTests.password('bob'))))
        self.admin('GRANT USAGE ON SCHEMA scope_assignment_leases TO bob; '
                   'GRANT EXECUTE ON FUNCTION scope_assignment_leases.claim(uuid,uuid),'
                   'scope_assignment_leases.inspect_binding(uuid) TO bob')
        with self.assertRaisesRegex(psycopg2.Error,'SCOPE_LEASE_DENIED'):
            self.claim(assignment=assignment,user='bob')

    def test_noninherited_writer_membership_denies_claim_and_inspection(self):
        self.claim()
        self.admin('CREATE ROLE scope_fixture_writer NOLOGIN NOINHERIT')
        try:
            self.admin('GRANT UPDATE ON scope_assignment_leases.assignments TO scope_fixture_writer')
            self.admin('GRANT scope_fixture_writer TO alice,verifier WITH INHERIT FALSE')
            for user,operation,args in (('alice','claim',(self.assignment,str(uuid.uuid4()))),
                                        ('verifier','inspect_binding',(self.assignment,))):
                with self.subTest(user=user),self.assertRaisesRegex(psycopg2.Error,'SCOPE_'):
                    self.call(operation,args,user=user)
        finally:
            self.admin('REVOKE scope_fixture_writer FROM alice,verifier')
            self.admin('DROP OWNED BY scope_fixture_writer; DROP ROLE scope_fixture_writer')

    def test_pending_certifier_authority_owner_is_not_independent_lease_reader(self):
        self.claim()
        self.admin('CREATE ROLE scope_fixture_pending_owner NOLOGIN NOINHERIT')
        try:
            self.admin('CREATE SCHEMA certifier_authority AUTHORIZATION scope_fixture_pending_owner')
            self.admin('GRANT scope_fixture_pending_owner TO verifier WITH INHERIT FALSE')
            with self.assertRaisesRegex(psycopg2.Error,'SCOPE_LEASE_DENIED'):
                self.call('inspect_binding',(self.assignment,),user='verifier',readonly=True)
        finally:
            self.admin('REVOKE scope_fixture_pending_owner FROM verifier')
            self.admin('DROP SCHEMA certifier_authority; DROP ROLE scope_fixture_pending_owner')
