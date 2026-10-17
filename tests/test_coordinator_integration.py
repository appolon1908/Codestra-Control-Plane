"""Combined coordinator migrations in disposable PostgreSQL16/TLS/SCRAM.

Every authority row, role credential and materialization observation is synthetic.
No installed DSN, live database or GitHub endpoint is used by this fixture.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import unittest

import psycopg2
from psycopg2 import sql
from psycopg2.extras import Json

import test_assignment_leases as issuer
import test_atomic_inspection_sql as atomic
import test_scoped_registration as registration

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / '010-controller-coordinator-integration.sql'


class FixtureConnection(psycopg2.extensions.connection):
    """Close even when unittest retains an exception traceback and its locals."""
    def __exit__(self, *error):
        try:
            return super().__exit__(*error)
        finally:
            self.close()


@unittest.skipUnless((registration.PG / 'initdb').exists(), 'PostgreSQL16 required')
class CoordinatorIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        atomic.AtomicInspectionSQLTests.setUpClass()
        cls.path = atomic.AtomicInspectionSQLTests.path
        cls.port = atomic.AtomicInspectionSQLTests.port
        try:
            with cls.connect('fixture_admin') as connection, connection.cursor() as cursor:
                cursor.execute((ROOT / '009-controller-coordinator.sql').read_text())
                cursor.execute('GRANT EXECUTE ON FUNCTION assignment_leases.resolve_task(text,text),'
                               'assignment_leases.lookup_task(text,text,text),'
                               'assignment_leases.admit_task(text,text,text,uuid) TO alice,bob')
                cursor.execute("SELECT p.oid::regprocedure::text,p.oid,p.proacl::text FROM pg_proc p "
                               "JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='assignment_leases' "
                               "AND p.proname IN ('_authenticate_proof','resolve_task','_coordinator_receipt','lookup_task','admit_task') "
                               "ORDER BY p.proname")
                cls.original_functions = cursor.fetchall()
                # Before010 exists these tests reproduce the merged009 defects.
                # All subsequent runs install the actual forward migration.
                if MIGRATION.exists():
                    cursor.execute(MIGRATION.read_text())
        except BaseException:
            atomic.AtomicInspectionSQLTests.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        atomic.AtomicInspectionSQLTests.tearDownClass()

    password = staticmethod(atomic.AtomicInspectionSQLTests.password)
    @classmethod
    def connect(cls, user='alice', sslmode='verify-full'):
        # Crash durability is outside this test: real transactions, constraints,
        # identity and rollback remain enabled; only disposable WAL waits differ.
        return psycopg2.connect(host='127.0.0.1', port=cls.port, dbname='postgres',
                                user=user, password=cls.password(user), sslmode=sslmode,
                                sslrootcert=str(cls.path / 'fixture.crt'), connect_timeout=5,
                                options='-c statement_timeout=30000 -c lock_timeout=10000 -c synchronous_commit=off',
                                connection_factory=FixtureConnection)
    inspect = atomic.AtomicInspectionSQLTests.inspect
    proof = atomic.AtomicInspectionSQLTests.proof
    durable_state = atomic.AtomicInspectionSQLTests.durable_state

    def admin(self, statement, parameters=()):
        with self.connect('fixture_admin') as connection, connection.cursor() as cursor:
            cursor.execute("SET TIME ZONE 'UTC'")
            cursor.execute(statement, parameters)
            return cursor.fetchall() if cursor.description else None

    def call(self, name, args, user='alice', role=None, sslmode='verify-full', timezone=None,
             session_authorization=None):
        with self.connect(user, sslmode) as connection, connection.cursor() as cursor:
            if timezone:
                cursor.execute('SET TIME ZONE %s', (timezone,))
            if role:
                cursor.execute(sql.SQL('SET ROLE {}').format(sql.Identifier(role)))
            if session_authorization:
                cursor.execute(sql.SQL('SET SESSION AUTHORIZATION {}').format(sql.Identifier(session_authorization)))
            cursor.execute(sql.SQL('SELECT assignment_leases.{}({})').format(
                sql.Identifier(name), sql.SQL(',').join(sql.Placeholder() for _ in args)), args)
            return cursor.fetchone()[0]

    def setUp(self):
        self.admin('TRUNCATE frozen_recovery.audit,frozen_recovery.proofs,frozen_recovery.reviews,'
                   'frozen_recovery.grants,frozen_recovery.incidents,frozen_recovery.permissions,'
                   'frozen_recovery.policies CASCADE')
        issuer.AssignmentLeaseTests.setUp(self)
        self.admin("DELETE FROM scoped_registration.candidates;"
                   "DELETE FROM scoped_registration.lanes WHERE kind='candidate';"
                   "DELETE FROM public.atomic_tasks; DELETE FROM scoped_registration.audit WHERE kind='candidate'")
        self.admin("INSERT INTO scoped_registration.principals SELECT rolname,oid,true FROM pg_roles WHERE rolname='reviewer'")
        self.admin("INSERT INTO assignment_leases.permissions VALUES('reviewer','A','read',true)")
        self.admin("UPDATE assignment_leases.policies SET lease_seconds=600,renewal_seconds=600,"
                   "max_lifetime_seconds=3600,attestation_seconds=600")
        self.admin('INSERT INTO assignment_leases.coordinator_tasks VALUES(%s,%s,%s,true)',
                   (self.binding, 'fixture task', Json([])))
        # Establish a valid pre-registration mapping before every negative case.
        self.assertEqual(self.resolve()['candidate'], self.fixture.candidate())

    def resolve(self, **options):
        return self.call('resolve_task', ('A-task', 'appolon1908/A'), timezone=options.pop('timezone', 'UTC'), **options)

    def coordinate(self, operation='prepare', *, proof=None, request='integration-request', timezone='UTC'):
        from codestra_control.controller_coordinator import coordinate
        with self.connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute('SET TIME ZONE %s', (timezone,))
            connection.commit()
            return coordinate(connection, operation, 'A-task', 'appolon1908/A', request,
                              proof_id=proof, apply=True)

    def add_dependency(self):
        self.dependency = dict(self.fixture.workstation(), workstation_id='A-dep', subsection='dep',
                               branch='subsection/sec--dep', worktree='/fixture/A/dependency', order_index=2)
        self.fixture.register('workstation', self.dependency, 'registered-dependency')
        self.admin("UPDATE public.workstations SET status='CERTIFIED',remote_sha=%s,exact_sha_certified=%s "
                   "WHERE workstation_id='A-dep'", ('d' * 40, 'd' * 40))
        self.admin("UPDATE public.workstations SET depends_on='[\"A-dep\"]' WHERE workstation_id='A-ws'")
        self.prerequisite = dict(product='A', scope_type='SUBSECTION', scope_name=self.dependency['branch'], sha='d' * 40)
        binding = dict(repository='appolon1908/A', product='A', source_ref=self.dependency['branch'],
                       target_ref='section/sec', source_sha='d' * 40, target_base_sha='e' * 40)
        self.add_receipt('subsection:dep', self.prerequisite, binding)
        self.admin('UPDATE assignment_leases.coordinator_tasks SET prerequisites=%s', (Json([self.prerequisite]),))
        self.admin("INSERT INTO public.scope_certifications VALUES('A','SUBSECTION',%s,%s,'CERTIFIED')",
                   (self.dependency['branch'], 'd' * 40))

    def add_receipt(self, key, prerequisite, binding):
        digest = hashlib.sha256(json.dumps(dict(schema='codestra.lease-dependency.v1', promotion=binding,
                                                scope_type=prerequisite['scope_type'], scope_name=prerequisite['scope_name']),
                                           sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.admin("INSERT INTO assignment_leases.dependencies VALUES(%s,%s,%s,'appolon1908/A',123,%s,%s,99,"
                   "'scope-certification','synthetic-capability','Ralph L. Appolon','SCOPE_CERTIFICATION',10,"
                   "clock_timestamp()+interval '5 minutes',true)",
                   (self.binding, key, Json(prerequisite), Json(binding), digest))

    def observations(self):
        description = self.call('describe', (self.binding,), user='verifier', timezone='UTC')
        binding = description['binding']
        observed = {key: binding[key] for key in ('repository', 'repository_id', 'source_ref', 'target_ref',
                                                  'head_sha', 'base_sha', 'worktree', 'host',
                                                  'git_common_dir', 'worktree_uid')}
        observed.update(directory_device=1, directory_inode=2, observed_at=datetime.now(timezone.utc).isoformat(),
                        dependencies={entry['dependency_key']: entry for entry in description['dependencies']})
        return observed

    def test_a_subsection_prepare_independent_proof_admit_and_atomic_inspect(self):
        self.add_dependency()
        result = self.coordinate(timezone='America/New_York')
        self.assertEqual(result['state'], 'AWAITING_VERIFICATION')
        self.assertFalse(result['usable'])
        proof = self.proof(timezone='Pacific/Auckland')
        result = self.coordinate('admit', proof=proof, timezone='America/New_York')
        self.assertTrue(result['usable'])
        self.assertFalse(result['certified'])
        self.assertFalse(result['promotion_authorized'])
        inspection = self.inspect(timezone='Pacific/Auckland')
        self.assertEqual(inspection['lease'], result['lease'])
        self.assertEqual(inspection['required_workstations'], [dict(workstation_id='A-dep', product='A',
                          branch='subsection/sec--dep', remote_sha='d' * 40, exact_sha_certified='d' * 40, status='CERTIFIED')])
        self.assertEqual(self.coordinate('recover', timezone='Pacific/Auckland')['lease'], result['lease'])

    def test_non_utc_builder_mapping_and_hardened_issuer_receipt_agree(self):
        self.coordinate(timezone='America/New_York')
        result = self.coordinate('admit', proof=self.proof(timezone='Pacific/Auckland'), timezone='America/New_York')
        self.assertTrue(result['usable'])
        self.assertTrue(result['lease']['binding']['valid_until'].endswith('+00:00'))
        self.assertEqual(self.coordinate('recover', timezone='Pacific/Auckland')['lease'], result['lease'])

    def test_authenticated_admin_cannot_impersonate_builder(self):
        with self.assertRaisesRegex(psycopg2.Error, 'COORDINATOR_DENIED'):
            self.resolve(user='fixture_admin', session_authorization='alice')

    def test_set_role_builder_is_not_an_unswitched_authenticated_session(self):
        with self.assertRaisesRegex(psycopg2.Error, 'COORDINATOR_DENIED'):
            self.resolve(role='alice')

    def test_authenticated_admin_cannot_impersonate_verifier(self):
        self.coordinate()
        with self.assertRaisesRegex(psycopg2.Error, 'CREDENTIAL_AUTHENTICATION_REQUIRED'):
            self.call('attest', (self.binding, Json(self.observations())), user='fixture_admin',
                      session_authorization='verifier', timezone='UTC')

    def test_set_role_verifier_cannot_create_provenance(self):
        self.coordinate()
        with self.assertRaisesRegex(psycopg2.Error, 'CREDENTIAL_AUTHENTICATION_REQUIRED'):
            self.call('attest', (self.binding, Json(self.observations())), user='verifier', role='verifier', timezone='UTC')

    def test_wrong_historical_provenance_cannot_admit_or_consume_proof(self):
        self.coordinate()
        proof = self.proof(timezone='UTC')
        self.admin("UPDATE assignment_leases.proofs SET verifier_authentication='scram-sha-256:another-user' WHERE proof_id=%s", (proof,))
        with self.assertRaisesRegex(psycopg2.Error, 'CREDENTIAL_AUTHENTICATION_REQUIRED|ADMISSION_RECEIPT_MISMATCH'):
            self.coordinate('admit', proof=proof)
        self.assertEqual(self.admin('SELECT consumed FROM assignment_leases.proofs WHERE proof_id=%s', (proof,)), [(False,)])
        self.assertEqual(self.admin('SELECT count(*) FROM assignment_leases.leases'), [(0,)])

    def test_wrong_provenance_revokes_recovery_without_rewriting_history(self):
        self.coordinate()
        proof = self.proof(timezone='UTC')
        self.coordinate('admit', proof=proof)
        self.admin("UPDATE assignment_leases.proofs SET verifier_authentication='password:verifier' WHERE proof_id=%s", (proof,))
        before = self.admin('SELECT to_jsonb(p) FROM assignment_leases.proofs p WHERE proof_id=%s', (proof,))
        with self.assertRaisesRegex(psycopg2.Error, 'ADMISSION_RECEIPT_MISMATCH'):
            self.coordinate('recover')
        self.assertEqual(self.admin('SELECT to_jsonb(p) FROM assignment_leases.proofs p WHERE proof_id=%s', (proof,)), before)

    def test_empty_approved_inventory_cannot_omit_configured_workstation(self):
        self.add_dependency()
        self.admin('DELETE FROM assignment_leases.dependencies')
        self.admin("UPDATE assignment_leases.coordinator_tasks SET prerequisites='[]'")
        with self.assertRaisesRegex(psycopg2.Error, 'COORDINATOR_DEPENDENCY_UNAVAILABLE'):
            self.coordinate()
        self.assertEqual(self.admin('SELECT count(*) FROM scoped_registration.candidates'), [(0,)])

    def test_malformed_duplicate_self_or_missing_configured_graph_denies(self):
        for graph in ({}, ['A-ws'], ['A-missing'], ['A-missing', 'A-missing'], [None], ['']):
            self.admin('UPDATE public.workstations SET depends_on=%s WHERE workstation_id=\'A-ws\'', (Json(graph),))
            with self.subTest(graph=graph), self.assertRaisesRegex(psycopg2.Error, 'COORDINATOR_DEPENDENCY_'):
                self.resolve()

    def test_configured_dependency_requires_current_exact_certification(self):
        self.add_dependency()
        self.resolve()
        for mutation, restore in (
            ("status='NOT_STARTED'", "status='CERTIFIED'"),
            ('exact_sha_certified=NULL', "exact_sha_certified=repeat('d',40)"),
            ("remote_sha=repeat('f',40)", "remote_sha=repeat('d',40)"),
        ):
            self.admin("UPDATE public.workstations SET " + mutation + " WHERE workstation_id='A-dep'")
            try:
                with self.subTest(mutation=mutation), self.assertRaisesRegex(psycopg2.Error, 'COORDINATOR_DEPENDENCY_UNAVAILABLE'):
                    self.resolve()
            finally:
                self.admin("UPDATE public.workstations SET " + restore + " WHERE workstation_id='A-dep'")

    def test_configured_dependency_mapping_parent_section_and_lane_cannot_drift(self):
        self.add_dependency()
        self.resolve()
        for mutation, restore in (
            ("UPDATE scoped_registration.workstations SET payload=jsonb_set(payload,'{order_index}','99') WHERE workstation_id='A-dep'", "UPDATE scoped_registration.workstations SET payload=jsonb_set(payload,'{order_index}','2') WHERE workstation_id='A-dep'"),
            ("UPDATE scoped_registration.lanes SET identity='wrong' WHERE identity='A-dep'", "UPDATE scoped_registration.lanes SET identity='A-dep' WHERE identity='wrong'"),
            ("UPDATE public.sections SET branch='section/other'", "UPDATE public.sections SET branch='section/sec'"),
        ):
            self.admin(mutation)
            try:
                with self.subTest(mutation=mutation), self.assertRaises(psycopg2.Error):
                    self.resolve()
            finally:
                self.admin(restore)

    def test_extra_subsection_cannot_substitute_for_configured_graph(self):
        self.add_dependency()
        extra = dict(self.prerequisite, scope_name='subsection/sec--extra')
        self.admin('UPDATE assignment_leases.coordinator_tasks SET prerequisites=%s', (Json([self.prerequisite, extra]),))
        self.add_receipt('subsection:extra', extra, dict(repository='appolon1908/A', product='A',
                         source_ref=extra['scope_name'], target_ref='section/sec', source_sha='d' * 40, target_base_sha='e' * 40))
        with self.assertRaisesRegex(psycopg2.Error, 'COORDINATOR_DEPENDENCY_UNAVAILABLE'):
            self.resolve()

    def test_explicit_legacy_section_extra_remains_supported_for_admission(self):
        self.add_dependency()
        extra = dict(product='A', scope_type='SECTION', scope_name='sec', sha='f' * 40)
        self.admin('UPDATE assignment_leases.coordinator_tasks SET prerequisites=%s', (Json([self.prerequisite, extra]),))
        self.admin("INSERT INTO public.scope_certifications VALUES('A','SECTION','sec',%s,'CERTIFIED')", ('f' * 40,))
        self.add_receipt('section:sec', extra, dict(repository='appolon1908/A', product='A', source_ref='section/sec',
                         target_ref='development', source_sha='f' * 40, target_base_sha='e' * 40))
        self.coordinate()
        self.assertTrue(self.coordinate('admit', proof=self.proof(timezone='UTC'))['usable'])
        # Inspection retains its deliberately narrower configured-workstation contract.
        with self.assertRaisesRegex(psycopg2.Error, 'ATOMIC_DEPENDENCY_INVENTORY_MISMATCH'):
            self.inspect()

    def test_required_receipt_revocation_expiry_or_binding_substitution_denies(self):
        self.add_dependency()
        self.resolve()
        original = self.admin('SELECT to_jsonb(d) FROM assignment_leases.dependencies d')[0][0]
        for mutation, parameters in (("active=false", ()),
                                     ("valid_until=clock_timestamp()-interval '1 second'", ()),
                                     ("binding=jsonb_set(binding,'{source_ref}','\"subsection/sec--other\"')", ())):
            self.admin('UPDATE assignment_leases.dependencies SET ' + mutation, parameters)
            try:
                with self.subTest(mutation=mutation), self.assertRaises(psycopg2.Error):
                    self.resolve()
            finally:
                self.admin('UPDATE assignment_leases.dependencies SET active=true,valid_until=%s,binding=%s',
                           (original['valid_until'], Json(original['binding'])))

    def test_dependency_revoked_after_claim_rolls_back_every_issued_effect(self):
        self.add_dependency()
        self.coordinate()
        proof = self.proof(timezone='UTC')
        self.resolve()
        tables = ('public.workstations', 'public.atomic_tasks', 'assignment_leases.leases',
                  'assignment_leases.proofs', 'assignment_leases.audit', 'assignment_leases.slots')
        def state():
            return {table: self.admin('SELECT to_jsonb(t) FROM ' + table + ' t ORDER BY to_jsonb(t)::text')
                    for table in tables}
        before = state()
        self.admin("CREATE SEQUENCE public.fixture_child_revocation_hit; "
                   "CREATE FUNCTION public.fixture_revoke_child() RETURNS trigger LANGUAGE plpgsql AS $$ "
                   "BEGIN PERFORM nextval('public.fixture_child_revocation_hit'); "
                   "UPDATE public.workstations SET status='NOT_STARTED' WHERE workstation_id='A-dep'; "
                   "RETURN NEW; END $$; "
                   "CREATE TRIGGER fixture_revoke_child AFTER INSERT ON assignment_leases.leases "
                   "FOR EACH ROW EXECUTE FUNCTION public.fixture_revoke_child()")
        try:
            with self.assertRaisesRegex(psycopg2.Error, 'COORDINATOR_DEPENDENCY_UNAVAILABLE'):
                self.coordinate('admit', proof=proof)
            self.assertEqual(self.admin('SELECT last_value,is_called FROM public.fixture_child_revocation_hit'), [(1, True)])
            self.assertEqual(state(), before)
        finally:
            self.admin('DROP TRIGGER fixture_revoke_child ON assignment_leases.leases; '
                       'DROP FUNCTION public.fixture_revoke_child(); DROP SEQUENCE public.fixture_child_revocation_hit')

    def test_forward_replacement_preserves_function_identity_and_execute_permissions(self):
        current = self.admin("SELECT p.oid::regprocedure::text,p.oid,p.proacl::text FROM pg_proc p "
                             "JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='assignment_leases' "
                             "AND p.proname IN ('_authenticate_proof','resolve_task','_coordinator_receipt','lookup_task','admit_task') "
                             "ORDER BY p.proname")
        self.assertEqual(current, self.original_functions)

    def test_stale_transaction_snapshots_cannot_admit_after_committed_child_revocation(self):
        self.add_dependency()
        self.coordinate()
        proof = self.proof(timezone='UTC')
        # Read-only table access is granted only inside this disposable case to
        # demonstrate the stale snapshot independently of the resolver itself.
        self.admin('GRANT SELECT ON public.workstations TO alice')
        try:
            for isolation in ('REPEATABLE READ', 'SERIALIZABLE'):
                with self.subTest(isolation=isolation):
                    self.admin("UPDATE public.workstations SET status='CERTIFIED' WHERE workstation_id='A-dep'")
                    connection = self.connect()
                    try:
                        connection.set_session(isolation_level=isolation)
                        with connection.cursor() as cursor:
                            cursor.execute("SELECT status FROM public.workstations WHERE workstation_id='A-dep'")
                            self.assertEqual(cursor.fetchone(), ('CERTIFIED',))
                            # A distinct authenticated transaction commits the
                            # revocation after the builder snapshot was established.
                            self.admin("UPDATE public.workstations SET status='NOT_STARTED' WHERE workstation_id='A-dep'")
                            cursor.execute("SELECT status FROM public.workstations WHERE workstation_id='A-dep'")
                            self.assertEqual(cursor.fetchone(), ('CERTIFIED',))
                            before = self.durable_state()
                            with self.assertRaisesRegex(psycopg2.Error, 'COORDINATOR_ISOLATION_REQUIRED'):
                                cursor.execute('SELECT assignment_leases.admit_task(%s,%s,%s,%s)',
                                               ('A-task', 'appolon1908/A', 'stale-snapshot-admission', proof))
                    finally:
                        connection.rollback()
                        connection.close()
                    self.assertEqual(self.durable_state(), before)
        finally:
            self.admin('REVOKE SELECT ON public.workstations FROM alice')


if __name__ == '__main__':
    unittest.main()
