"""Real atomic read-boundary tests using disposable PostgreSQL/TLS/SCRAM only."""
from datetime import datetime, timezone as utc_timezone
import hashlib
import json
from pathlib import Path
import unittest
import uuid

import psycopg2
from psycopg2 import sql
from psycopg2.extras import Json

import test_assignment_leases as issuer
import test_frozen_recovery_executor as recovery
import test_scoped_registration as registration


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / '009-atomic-inspection.sql'
ISSUER_FUNCTIONS = (
    '_restricted(name,oid)', '_actor()', '_permission(text,text,boolean)',
    '_lock(assignment_leases.bindings)', '_binding(uuid,boolean)', '_dependencies(uuid)',
    'describe(uuid)', 'attest(uuid,jsonb)', '_proof(assignment_leases.bindings,uuid)',
    '_receipt(assignment_leases.leases)', '_audit(uuid,uuid,text,text,jsonb)',
    'claim(uuid,uuid,text)', '_owned(uuid,bigint)', 'check_owned(uuid,bigint)',
    'renew(uuid,bigint,uuid,text)', 'release(uuid,bigint,text)', 'revoke(uuid,text,text)',
    'inspect_binding(uuid)', 'lookup(text)',
)


class ForwardRegistrationDefinitionTests(unittest.TestCase):
    def test_reviewed_definition_changes_only_supported_scope_enum(self):
        reviewed = (ROOT / '005-scoped-registration.sql').read_text()
        self.assertEqual(hashlib.sha256(reviewed.encode()).hexdigest(),
                         '266300e66f26d7c70ccb31435dcc00ae57c018d5dba29f18d932e345da0e3362')
        start = 'CREATE OR REPLACE FUNCTION scoped_registration.register('
        end = '$function$;'
        original = reviewed[reviewed.index(start):reviewed.index(end, reviewed.index(start)) + len(end)]
        forward = MIGRATION.read_text()
        replacement = forward[forward.index(start):forward.index(end, forward.index(start)) + len(end)]
        old_enum = "('SECTION','DEVELOPMENT','TESTING','STAGING','PRODUCTION')"
        self.assertEqual(original.count(old_enum), 1)
        self.assertEqual(replacement, original.replace(
            old_enum, "('SUBSECTION','SECTION','DEVELOPMENT','TESTING','STAGING','PRODUCTION')"))


@unittest.skipUnless((registration.PG / 'initdb').exists(), 'PostgreSQL16 disposable binaries required')
class AtomicInspectionSQLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        migration = MIGRATION.read_text()
        recovery.FrozenRecoveryExecutorTests.setUpClass()
        cls.path = recovery.FrozenRecoveryExecutorTests.path
        cls.port = recovery.FrozenRecoveryExecutorTests.port
        try:
            with cls.connect('fixture_admin') as connection, connection.cursor() as cursor:
                cursor.execute(migration)
                cursor.execute('GRANT USAGE ON SCHEMA atomic_inspection TO alice,bob,reviewer,verifier,trust_operator')
                cursor.execute('GRANT EXECUTE ON FUNCTION atomic_inspection.inspect(uuid) TO alice,bob,reviewer,verifier,trust_operator')
        except BaseException:
            recovery.FrozenRecoveryExecutorTests.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        recovery.FrozenRecoveryExecutorTests.tearDownClass()

    password = staticmethod(recovery.FrozenRecoveryExecutorTests.password)

    @classmethod
    def connect(cls, user='alice', sslmode='verify-full'):
        return psycopg2.connect(host='127.0.0.1', port=cls.port, dbname='postgres',
                                user=user, password=cls.password(user), sslmode=sslmode,
                                sslrootcert=str(cls.path / 'fixture.crt'), connect_timeout=5,
                                options='-c statement_timeout=30000 -c lock_timeout=10000')

    def admin(self, query, parameters=()):
        with self.connect('fixture_admin') as connection, connection.cursor() as cursor:
            cursor.execute("SET TIME ZONE 'UTC'")
            cursor.execute(query, parameters)
            return cursor.fetchall() if cursor.description else None

    def call(self, name, args, user='alice', role=None, sslmode='verify-full', timezone=None):
        with self.connect(user, sslmode) as connection, connection.cursor() as cursor:
            if role:
                cursor.execute(sql.SQL('SET ROLE {}').format(sql.Identifier(role)))
            if timezone:
                cursor.execute('SET TIME ZONE %s', (timezone,))
            cursor.execute(sql.SQL('SELECT assignment_leases.{}({})').format(
                sql.Identifier(name), sql.SQL(',').join(sql.Placeholder() for _ in args)), args)
            return cursor.fetchone()[0]

    def proof(self, changes=None, timezone=None):
        description = self.call('describe', (self.binding,), user='verifier', timezone=timezone)
        binding = description['binding']
        observed = {key: binding[key] for key in ('repository', 'repository_id', 'source_ref', 'target_ref',
                                                 'head_sha', 'base_sha', 'worktree', 'host',
                                                 'git_common_dir', 'worktree_uid')}
        observed.update(directory_device=1, directory_inode=2,
                        observed_at=datetime.now(utc_timezone.utc).isoformat(),
                        dependencies={entry['dependency_key']: entry for entry in description['dependencies']})
        observed.update(changes or {})
        return self.call('attest', (self.binding, Json(observed)), user='verifier', timezone=timezone)['proof_id']

    def setUp(self):
        self.admin('TRUNCATE frozen_recovery.audit,frozen_recovery.proofs,frozen_recovery.reviews,'
                   'frozen_recovery.grants,frozen_recovery.incidents,frozen_recovery.permissions,'
                   'frozen_recovery.policies CASCADE')
        issuer.AssignmentLeaseTests.setUp(self)
        self.admin("INSERT INTO scoped_registration.principals(principal,role_oid,active) "
                   "SELECT rolname,oid,true FROM pg_roles WHERE rolname IN ('reviewer','trust_operator')")
        self.admin("INSERT INTO assignment_leases.permissions VALUES('reviewer','A','read',true),"
                   "('trust_operator','A','read',true),('alice','A','read',true)")
        self.admin("UPDATE assignment_leases.policies SET lease_seconds=600,renewal_seconds=600,"
                   "max_lifetime_seconds=3600,attestation_seconds=600 WHERE product='A'")
        self.dependency = dict(self.fixture.workstation(), workstation_id='A-dep', subsection='dep',
                               branch='subsection/sec--dep', worktree='/fixture/A/dependency', order_index=2)
        self.fixture.register('workstation', self.dependency, 'dependency-workstation')
        self.admin("UPDATE workstations SET status='CERTIFIED',remote_sha=%s,exact_sha_certified=%s "
                   "WHERE workstation_id='A-dep'", ('d'*40, 'd'*40))
        self.admin("UPDATE workstations SET depends_on='[\"A-dep\"]'::jsonb,"
                   "required_gates='[\"unit\",\"security\",\"review\",\"clean_tree\",\"remote_sha_match\"]'::jsonb "
                   "WHERE workstation_id='A-ws'")
        self.prerequisite = dict(product='A', scope_type='SUBSECTION',
                                 scope_name=self.dependency['branch'], sha='d'*40)
        self.dependency_binding = dict(repository='appolon1908/A', product='A',
                                       source_ref=self.dependency['branch'], target_ref='section/sec',
                                       source_sha='d'*40, target_base_sha='e'*40)
        digest = hashlib.sha256(json.dumps(dict(schema='codestra.lease-dependency.v1',
                                                promotion=self.dependency_binding, scope_type='SUBSECTION',
                                                scope_name=self.dependency['branch']),
                                           sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.admin("UPDATE scoped_registration.candidates SET payload=jsonb_set(payload,'{prerequisites}',%s) "
                   "WHERE task_id='A-task'", (Json([self.prerequisite]),))
        self.admin("INSERT INTO assignment_leases.dependencies VALUES(%s,'subsection:dep',%s,'appolon1908/A',123,"
                   "%s,%s,99,'scope-certification','synthetic-accepted-capability','Ralph L. Appolon',"
                   "'SCOPE_CERTIFICATION',10,clock_timestamp()+interval '5 minutes',true)",
                   (self.binding, Json(self.prerequisite), Json(self.dependency_binding), digest))
        self.admin("INSERT INTO scope_certifications VALUES('A','SUBSECTION',%s,%s,'CERTIFIED')",
                   (self.dependency['branch'], 'd'*40))
        description = self.call('describe', (self.binding,), user='verifier')
        dependencies = {entry['dependency_key']: entry for entry in description['dependencies']}
        proof = self.proof({'dependencies': dependencies})
        self.lease = self.call('claim', (self.binding, proof, 'fixture-claim'))
        # Every denial test starts from a genuinely inspectable admission. This
        # prevents a generic baseline failure from making negative tests pass.
        self.assertEqual(self.inspect()['lease'], self.lease)

    def inspect(self, user='reviewer', *, role=None, session_authorization=None, sslmode='verify-full', timezone=None):
        connection = self.connect(user, sslmode)
        try:
            connection.set_session(readonly=True, isolation_level='REPEATABLE READ')
            with connection.cursor() as cursor:
                if role:
                    cursor.execute(sql.SQL('SET ROLE {}').format(sql.Identifier(role)))
                if session_authorization:
                    cursor.execute(sql.SQL('SET SESSION AUTHORIZATION {}').format(sql.Identifier(session_authorization)))
                if timezone:
                    cursor.execute('SET TIME ZONE %s', (timezone,))
                cursor.execute('SELECT atomic_inspection.inspect(%s)', (self.binding,))
                return cursor.fetchone()[0]
        finally:
            connection.rollback()
            connection.close()

    def durable_state(self):
        tables = ('public.workstations', 'public.atomic_tasks', 'public.events',
                  'public.scope_certifications', 'scoped_registration.audit',
                  'assignment_leases.leases', 'assignment_leases.proofs',
                  'assignment_leases.audit', 'assignment_leases.slots')
        return {table: self.admin('SELECT to_jsonb(t) FROM ' + table + ' t ORDER BY to_jsonb(t)::text') for table in tables}

    def test_a_real_readonly_receipt_mapping_dependencies_and_materialization(self):
        before = self.durable_state()
        result = self.inspect()
        self.assertEqual(set(result), {'schema', 'lease', 'product', 'section', 'workstation',
                                       'candidate', 'dependencies', 'required_workstations',
                                       'materialization', 'required_gates'})
        self.assertEqual(result['schema'], 'codestra.atomic-inspection.v1')
        self.assertEqual(result['lease'], self.lease)
        self.assertEqual(result['product'], self.fixture.product())
        self.assertEqual(result['section'], dict(section_key='sec', branch='section/sec'))
        self.assertEqual(result['workstation'], self.fixture.workstation())
        self.assertEqual(result['candidate'], dict(self.fixture.candidate(), prerequisites=[self.prerequisite]))
        self.assertEqual(result['materialization'], dict(host='fixture-host', directory_device=1, directory_inode=2))
        self.assertEqual(result['required_gates'], ['unit', 'security', 'review', 'clean_tree', 'remote_sha_match'])
        self.assertEqual(result['required_workstations'], [dict(workstation_id='A-dep', product='A',
                                                              branch='subsection/sec--dep', remote_sha='d'*40,
                                                              exact_sha_certified='d'*40, status='CERTIFIED')])
        self.assertEqual(result['dependencies'][0]['binding'], self.dependency_binding)
        self.assertEqual(result['dependencies'][0]['prerequisite'], self.prerequisite)
        self.assertEqual(self.durable_state(), before)

    def test_reader_requires_current_product_capability_and_independence(self):
        with self.assertRaises(psycopg2.Error):
            self.inspect('bob')
        with self.assertRaises(psycopg2.Error):
            self.inspect('alice')
        self.admin("UPDATE assignment_leases.permissions SET active=false WHERE principal='reviewer'")
        with self.assertRaises(psycopg2.Error):
            self.inspect()

    def test_scram_identity_cannot_be_spoofed_or_role_switched(self):
        for target in ('reviewer', 'alice'):
            with self.subTest(target=target), self.assertRaises(psycopg2.Error):
                self.inspect('fixture_admin', session_authorization=target)
        self.admin('GRANT reviewer TO bob')
        try:
            with self.assertRaises(psycopg2.Error):
                self.inspect('bob', role='reviewer')
        finally:
            self.admin('REVOKE reviewer FROM bob')

    def test_plaintext_and_trust_transport_are_not_identity(self):
        with self.assertRaises(psycopg2.Error):
            self.inspect(sslmode='disable')
        with self.assertRaises(psycopg2.Error):
            self.inspect('trust_operator')

    def test_recreated_reader_oid_cannot_reuse_authority(self):
        self.admin('DROP OWNED BY reviewer; DROP ROLE reviewer; CREATE ROLE reviewer LOGIN PASSWORD %s',
                   (self.password('reviewer'),))
        self.admin('GRANT USAGE ON SCHEMA atomic_inspection TO reviewer;'
                   'GRANT EXECUTE ON FUNCTION atomic_inspection.inspect(uuid) TO reviewer')
        with self.assertRaises(psycopg2.Error):
            self.inspect()

    def test_elevated_membership_schema_creation_and_evidence_dml_deny(self):
        for grant, revoke in (
            ('GRANT fixture_admin TO reviewer', 'REVOKE fixture_admin FROM reviewer'),
            ('GRANT CREATE ON SCHEMA atomic_inspection TO reviewer', 'REVOKE CREATE ON SCHEMA atomic_inspection FROM reviewer'),
            ('GRANT UPDATE ON public.scope_certifications TO reviewer', 'REVOKE UPDATE ON public.scope_certifications FROM reviewer'),
            ('GRANT UPDATE ON public.workstations TO reviewer', 'REVOKE UPDATE ON public.workstations FROM reviewer'),
        ):
            self.admin(grant)
            try:
                with self.subTest(grant=grant), self.assertRaises(psycopg2.Error):
                    self.inspect()
            finally:
                self.admin(revoke)

    def test_mapping_and_shared_lane_drift_deny(self):
        mutations = (
            ("UPDATE public.sections SET branch='section/other' WHERE product='A'", "UPDATE public.sections SET branch='section/sec' WHERE product='A'"),
            ("UPDATE scoped_registration.workstations SET payload=jsonb_set(payload,'{order_index}','99') WHERE workstation_id='A-ws'", "UPDATE scoped_registration.workstations SET payload=jsonb_set(payload,'{order_index}','1') WHERE workstation_id='A-ws'"),
            ("UPDATE scoped_registration.lanes SET branch='atomic/sec--sub--other' WHERE kind='candidate'", "UPDATE scoped_registration.lanes SET branch='atomic/sec--sub--task' WHERE kind='candidate'"),
            ("UPDATE scoped_registration.lanes SET identity='other' WHERE kind='workstation' AND identity='A-ws'", "UPDATE scoped_registration.lanes SET identity='A-ws' WHERE kind='workstation' AND identity='other'"),
            ("UPDATE public.products SET production_go=true WHERE product='A'", "UPDATE public.products SET production_go=false WHERE product='A'"),
        )
        for mutate, restore in mutations:
            self.admin(mutate)
            try:
                with self.subTest(mutation=mutate), self.assertRaises(psycopg2.Error):
                    self.inspect()
            finally:
                self.admin(restore)

    def test_frozen_lane_and_changed_assignment_or_slot_deny(self):
        for mutate, restore in (
            ("UPDATE workstations SET lease_state='FROZEN' WHERE workstation_id='A-ws'", "UPDATE workstations SET lease_state='ACTIVE' WHERE workstation_id='A-ws'"),
            ("UPDATE scoped_registration.task_assignments SET active=false WHERE task_id='A-task'", "UPDATE scoped_registration.task_assignments SET active=true WHERE task_id='A-task'"),
            ("UPDATE assignment_leases.slots SET epoch=epoch+1", "UPDATE assignment_leases.slots SET epoch=epoch-1"),
        ):
            self.admin(mutate)
            try:
                with self.subTest(mutation=mutate), self.assertRaises(psycopg2.Error):
                    self.inspect()
            finally:
                self.admin(restore)

    def test_expired_or_released_lease_cannot_inspect(self):
        self.admin("UPDATE assignment_leases.leases SET expires_at=clock_timestamp()-interval '1 second'")
        with self.assertRaises(psycopg2.Error):
            self.inspect()

    def test_corrupted_lease_workstation_cannot_reuse_another_matching_slot(self):
        # A-dep is a distinct, genuinely registered workstation created by this
        # fixture. Give it a matching fence while keeping the actual assignment,
        # original compatibility workstation and verifier evidence unchanged.
        before = self.admin("SELECT to_jsonb(w) FROM public.workstations w WHERE workstation_id='A-ws'")
        self.admin("INSERT INTO assignment_leases.slots(workstation_id,epoch) "
                   "SELECT 'A-dep',epoch FROM assignment_leases.slots WHERE workstation_id='A-ws'")
        self.admin("UPDATE assignment_leases.leases SET workstation_id='A-dep' WHERE lease_id=%s",
                   (self.lease['lease_id'],))
        self.assertEqual(self.admin("SELECT to_jsonb(w) FROM public.workstations w WHERE workstation_id='A-ws'"),
                         before)
        with self.assertRaisesRegex(psycopg2.Error, 'ATOMIC_MATERIALIZATION_UNAVAILABLE'):
            self.inspect()

    def test_omitted_configured_dependency_cannot_hide_behind_empty_candidate(self):
        self.admin('DELETE FROM assignment_leases.dependencies')
        self.admin("UPDATE scoped_registration.candidates SET payload=jsonb_set(payload,'{prerequisites}','[]') WHERE task_id='A-task'")
        # Keep the existing proof internally consistent; old issuer comparison
        # alone cannot catch omissions from configured workstation dependencies.
        self.admin("UPDATE assignment_leases.proofs SET observations=jsonb_set(observations,'{dependencies}','{}')")
        with self.assertRaises(psycopg2.Error):
            self.inspect()

    def test_duplicate_prerequisites_and_configured_dependencies_deny(self):
        self.admin("UPDATE scoped_registration.candidates SET payload=jsonb_set(payload,'{prerequisites}',%s) WHERE task_id='A-task'",
                   (Json([self.prerequisite, self.prerequisite]),))
        with self.assertRaises(psycopg2.Error):
            self.inspect()
        self.admin("UPDATE scoped_registration.candidates SET payload=jsonb_set(payload,'{prerequisites}',%s) WHERE task_id='A-task'",
                   (Json([self.prerequisite]),))
        self.admin("UPDATE workstations SET depends_on='[\"A-dep\",\"A-dep\"]' WHERE workstation_id='A-ws'")
        with self.assertRaises(psycopg2.Error):
            self.inspect()

    def test_dependency_requires_current_registered_exact_certification(self):
        for mutate, restore in (
            ("UPDATE workstations SET status='NOT_STARTED' WHERE workstation_id='A-dep'", "UPDATE workstations SET status='CERTIFIED' WHERE workstation_id='A-dep'"),
            ("UPDATE workstations SET exact_sha_certified=NULL WHERE workstation_id='A-dep'", "UPDATE workstations SET exact_sha_certified=remote_sha WHERE workstation_id='A-dep'"),
            ("UPDATE workstations SET remote_sha=repeat('f',40) WHERE workstation_id='A-dep'", "UPDATE workstations SET remote_sha=repeat('d',40) WHERE workstation_id='A-dep'"),
            ("UPDATE scoped_registration.lanes SET identity='wrong' WHERE identity='A-dep'", "UPDATE scoped_registration.lanes SET identity='A-dep' WHERE identity='wrong'"),
            ("UPDATE scoped_registration.workstations SET payload=jsonb_set(payload,'{parent_branch}','\"section/other\"') WHERE workstation_id='A-dep'", "UPDATE scoped_registration.workstations SET payload=jsonb_set(payload,'{parent_branch}','\"section/sec\"') WHERE workstation_id='A-dep'"),
        ):
            self.admin(mutate)
            try:
                with self.subTest(mutation=mutate), self.assertRaises(psycopg2.Error):
                    self.inspect()
            finally:
                self.admin(restore)

    def test_dependency_binding_scope_repository_and_independent_issuer_are_exact(self):
        for field, value in (
            ('source_ref', 'subsection/sec--other'), ('target_ref', 'section/other'),
            ('product', 'B'), ('repository', 'appolon1908/B'), ('source_sha', 'f'*40),
        ):
            self.admin('UPDATE assignment_leases.dependencies SET binding=%s', (Json(dict(self.dependency_binding, **{field: value})),))
            self.refresh_proof_dependencies()
            try:
                with self.subTest(field=field), self.assertRaisesRegex(
                        psycopg2.Error, 'ATOMIC_DEPENDENCY_BINDING_MISMATCH'):
                    self.inspect()
            finally:
                self.admin('UPDATE assignment_leases.dependencies SET binding=%s', (Json(self.dependency_binding),))
                self.refresh_proof_dependencies()

    def refresh_proof_dependencies(self):
        self.admin("UPDATE assignment_leases.proofs SET observations=jsonb_set(observations,'{dependencies}',"
                   "(SELECT jsonb_object_agg(dependency_key,to_jsonb(d)) FROM assignment_leases.dependencies d))")

    def test_dependency_producer_repository_id_and_digest_are_independently_checked(self):
        mutations = (
            ("issuer_name='codestra-control-plane'", "issuer_name='scope-certification'",
             'ATOMIC_DEPENDENCY_RECEIPT_INVALID'),
            ("capability_receipt='   '", "capability_receipt='synthetic-accepted-capability'",
             'ATOMIC_DEPENDENCY_RECEIPT_INVALID'),
            ('repository_id=999', 'repository_id=123', 'ATOMIC_DEPENDENCY_RECEIPT_INVALID'),
            ("binding_hash=repeat('f',64)", None, 'ATOMIC_DEPENDENCY_DIGEST_MISMATCH'),
        )
        original_digest = self.admin('SELECT binding_hash FROM assignment_leases.dependencies')[0][0]
        for mutation, restore, expected in mutations:
            self.admin('UPDATE assignment_leases.dependencies SET ' + mutation)
            self.refresh_proof_dependencies()
            try:
                with self.subTest(mutation=mutation), self.assertRaisesRegex(psycopg2.Error, expected):
                    self.inspect()
            finally:
                if restore:
                    self.admin('UPDATE assignment_leases.dependencies SET ' + restore)
                else:
                    self.admin('UPDATE assignment_leases.dependencies SET binding_hash=%s', (original_digest,))
                self.refresh_proof_dependencies()

    def test_expired_or_revoked_dependency_denies_fresh_acquisition(self):
        for mutate in ("UPDATE assignment_leases.dependencies SET active=false",
                       "UPDATE assignment_leases.dependencies SET valid_until=clock_timestamp()-interval '1 second'"):
            self.admin(mutate)
            with self.subTest(mutation=mutate), self.assertRaises(psycopg2.Error):
                self.inspect()

    def test_extra_section_evidence_is_not_a_configured_subsection(self):
        extra = dict(self.prerequisite, scope_type='SECTION', scope_name='sec')
        self.admin("UPDATE scoped_registration.candidates SET payload=jsonb_set(payload,'{prerequisites}',%s) WHERE task_id='A-task'", (Json([extra]),))
        self.admin('UPDATE assignment_leases.dependencies SET prerequisite=%s', (Json(extra),))
        self.refresh_proof_dependencies()
        with self.assertRaises(psycopg2.Error):
            self.inspect()

    def test_forward_registration_accepts_subsection_metadata_without_authority(self):
        self.admin("INSERT INTO scoped_registration.task_assignments VALUES('A','A-ws','A-task-next','alice',true)")
        candidate = dict(self.fixture.candidate(), task_id='A-task-next', branch='atomic/sec--sub--next',
                         worktree='/fixture/A/atomic-next', prerequisites=[self.prerequisite])
        result = self.fixture.register('candidate', candidate, 'subsection-candidate')
        self.assertFalse(result['authority'])
        self.assertFalse(result['ready'])
        invalid = dict(candidate, task_id='A-task-bad', branch='atomic/sec--sub--bad',
                       worktree='/fixture/A/atomic-bad', prerequisites=[dict(self.prerequisite, scope_type='UNSUPPORTED')])
        self.admin("INSERT INTO scoped_registration.task_assignments VALUES('A','A-ws','A-task-bad','alice',true)")
        with self.assertRaises(psycopg2.Error):
            self.fixture.register('candidate', invalid, 'invalid-scope')

    def test_readonly_repeatable_snapshot_canonicalizes_timezones(self):
        self.assertEqual(self.inspect(timezone='Pacific/Auckland'), self.inspect(timezone='America/New_York'))

    def test_non_utc_fresh_proof_and_claim_are_inspectable_across_timezones(self):
        self.call('release', (self.lease['lease_id'], self.lease['epoch'], 'release-for-timezone'))
        proof = self.proof(timezone='America/New_York')
        self.lease = self.call('claim', (self.binding, proof, 'non-utc-claim'), timezone='America/New_York')
        result = self.inspect(timezone='Pacific/Auckland')
        self.assertEqual(result['lease'], self.lease)
        self.assertEqual(result, self.inspect(timezone='America/New_York'))
        self.assertTrue(self.lease['binding']['valid_until'].endswith('+00:00'))

    def test_historical_non_utc_snapshot_remains_denied_and_unchanged(self):
        self.call('release', (self.lease['lease_id'], self.lease['epoch'], 'release-for-legacy'))
        # Reproduce the original007 function configuration in this disposable
        # server, issue an actual legacy proof/lease, then restore009 hardening.
        for signature in ISSUER_FUNCTIONS:
            self.admin('ALTER FUNCTION assignment_leases.' + signature + ' RESET timezone')
        try:
            proof = self.proof(timezone='America/New_York')
            self.lease = self.call('claim', (self.binding, proof, 'legacy-non-utc-claim'),
                                   timezone='America/New_York')
            self.assertNotEqual(datetime.fromisoformat(self.lease['binding']['valid_until']).utcoffset().total_seconds(), 0)
        finally:
            for signature in ISSUER_FUNCTIONS:
                self.admin('ALTER FUNCTION assignment_leases.' + signature + " SET timezone='UTC'")
        before = self.durable_state()
        with self.assertRaisesRegex(psycopg2.Error, 'LEASE_NOT_ACTIVE'):
            self.inspect()
        self.assertEqual(self.durable_state(), before)

    def test_public_execute_and_runtime_mutations_are_revoked(self):
        self.assertEqual(self.admin("SELECT has_function_privilege('mallory','atomic_inspection.inspect(uuid)','EXECUTE')"), [(False,)])
        for table in ('assignment_leases.dependencies', 'scoped_registration.candidates', 'public.workstations'):
            with self.subTest(table=table), self.connect('reviewer') as connection, connection.cursor() as cursor:
                with self.assertRaises(psycopg2.Error):
                    cursor.execute('DELETE FROM ' + table)


if __name__ == '__main__':
    unittest.main()
