"""Coordinator integration: disposable PostgreSQL/TLS, synthetic SCRAM identities.

The real resolver, registration, proof and issuer run here. Git/remote observation
has its own materializer suite; these tests submit fixture observations through
the independently authenticated verifier API, never builder-supplied PASS data.
"""
import concurrent.futures
import importlib
import os
import subprocess
import time
import unittest
from unittest import mock
import uuid
from datetime import datetime, timezone

import psycopg2
from psycopg2 import sql
from psycopg2.extras import Json
import test_assignment_leases as leases
import test_scoped_registration as registration


@unittest.skipUnless((registration.PG/'initdb').exists(), 'PostgreSQL 16 required')
class CoordinatorTests(unittest.TestCase):
    password_ready = False

    @classmethod
    def setUpClass(cls):
        leases.AssignmentLeaseTests.setUpClass.__func__(cls)
        try:
            with cls.connect('fixture_admin') as connection, connection.cursor() as cur:
                for actor in ('fixture_admin', 'alice', 'bob', 'verifier', 'operator'):
                    cur.execute(sql.SQL('ALTER ROLE {} PASSWORD %s').format(sql.Identifier(actor)), ('synthetic-coordinator-'+actor,))
                migration = leases.ROOT/'009-controller-coordinator.sql'
                if migration.exists():
                    cur.execute(migration.read_text())
                    cur.execute('GRANT EXECUTE ON FUNCTION assignment_leases.resolve_task(text,text),assignment_leases.lookup_task(text,text,text),assignment_leases.admit_task(text,text,text,uuid) TO alice,bob')
                cur.execute('GRANT EXECUTE ON FUNCTION assignment_leases.lookup(text) TO alice,bob')
            cls.hba = registration.ScopedRegistrationTests.data/'pg_hba.conf'
            cls.trust_hba = cls.hba.read_text()
            cls.hba.write_text('local all all trust\nhostssl all all 127.0.0.1/32 scram-sha-256\nhostnossl all all 127.0.0.1/32 reject\n')
            cls.reload_hba()
            cls.password_ready = True
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def reload_hba(cls):
        subprocess.run([str(registration.PG/'pg_ctl'), '-D', str(registration.ScopedRegistrationTests.data), 'reload'], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        leases.AssignmentLeaseTests.tearDownClass.__func__(cls)
        cls.password_ready = False

    @classmethod
    def connect(cls, user='alice', sslmode='verify-full'):
        return psycopg2.connect(host='127.0.0.1', port=cls.port, dbname='postgres', user=user,
            password='synthetic-coordinator-'+user if cls.password_ready else None,
            sslmode=sslmode, sslrootcert=str(cls.path/'fixture.crt'))

    call = leases.AssignmentLeaseTests.call
    proof = leases.AssignmentLeaseTests.proof

    def setUp(self):
        leases.AssignmentLeaseTests.setUp(self)
        with self.connect('fixture_admin') as connection, connection.cursor() as cur:
            cur.execute("DELETE FROM scoped_registration.candidates; DELETE FROM scoped_registration.lanes WHERE kind='candidate'; DELETE FROM atomic_tasks; DELETE FROM scoped_registration.audit WHERE kind='candidate'")
            cur.execute("SELECT to_regclass('assignment_leases.coordinator_tasks')")
            if cur.fetchone()[0]:
                cur.execute('INSERT INTO assignment_leases.coordinator_tasks VALUES(%s,%s,%s,true)', (self.binding, 'fixture task', Json([])))

    def resolve(self, task='A-task', repository='appolon1908/A', user='alice'):
        try:
            return self.call('resolve_task', (task, repository), user=user)
        except psycopg2.errors.UndefinedFunction:
            self.fail('Restricted pre-registration task resolver is missing')

    def coordinate(self, operation='prepare', request='coordinate-1', proof=None, apply=True, **kwargs):
        try:
            coordinator = importlib.import_module('codestra_control.controller_coordinator')
        except ImportError:
            self.fail('Controller coordinator cannot register or admit assigned tasks')
        with self.connect() as connection:
            return coordinator.coordinate(connection, operation, kwargs.get('task', 'A-task'),
                kwargs.get('repository', 'appolon1908/A'), request, proof_id=proof, apply=apply)

    def count(self, table):
        with self.connect('fixture_admin') as connection, connection.cursor() as cur:
            cur.execute('SELECT count(*) FROM '+table)
            return cur.fetchone()[0]

    def test_resolver_exposes_only_exact_approved_candidate_before_registration(self):
        result = self.resolve()
        self.assertEqual(result['binding']['binding_id'], self.binding)
        self.assertEqual(result['candidate'], self.fixture.candidate())
        self.assertEqual(self.count('scoped_registration.candidates'), 0)
        for task, repository, user in [('B-task','appolon1908/A','alice'), ('A-task','appolon1908/B','alice'), ('A-task','appolon1908/A','bob')]:
            with self.subTest(task=task, repository=repository, user=user), self.assertRaises(psycopg2.Error):
                self.resolve(task, repository, user)

    def test_prepare_registers_metadata_without_creating_admission(self):
        result = self.coordinate()
        self.assertEqual(result['state'], 'AWAITING_VERIFICATION')
        self.assertEqual(result['binding_id'], self.binding)
        self.assertFalse(result['usable'])
        self.assertEqual(self.count('scoped_registration.candidates'), 1)
        self.assertEqual(self.count('assignment_leases.leases'), 0)
        self.assertEqual(self.count('assignment_leases.proofs'), 0)

    def test_default_dry_run_rolls_back_registration_and_does_not_consume_proof(self):
        result = self.coordinate(apply=False)
        self.assertEqual(result['authority'], 'NONE_DRY_RUN')
        self.assertFalse(result['usable'])
        self.assertEqual(self.count('scoped_registration.candidates'), 0)
        self.coordinate()
        proof = self.proof()
        result = self.coordinate('admit', proof=proof, apply=False)
        self.assertFalse(result['usable'])
        self.assertEqual(self.count('assignment_leases.leases'), 0)
        with self.connect('fixture_admin') as connection, connection.cursor() as cur:
            cur.execute('SELECT consumed FROM assignment_leases.proofs WHERE proof_id=%s', (proof,))
            self.assertFalse(cur.fetchone()[0])

    def test_admission_requires_committed_independent_proof_and_returns_real_epoch(self):
        self.coordinate()
        with self.assertRaises((ValueError, psycopg2.Error)):
            self.coordinate('admit', proof=str(uuid.uuid4()))
        result = self.coordinate('admit', proof=self.proof())
        self.assertTrue(result['usable'])
        self.assertEqual(result['state'], 'ADMITTED')
        self.assertFalse(result['certified'])
        self.assertFalse(result['promotion_authorized'])
        receipt = result['lease']
        self.assertEqual(receipt['state'], 'ACTIVE')
        self.assertEqual(receipt['authority'], 'ONLINE_DATABASE_RECEIPT')
        self.assertEqual(receipt['epoch'], 1)
        self.assertEqual(self.call('check_owned', (receipt['lease_id'], 1))['lease_id'], receipt['lease_id'])

    def test_missing_or_revoked_operator_mapping_cannot_be_inferred(self):
        with self.connect('fixture_admin') as connection, connection.cursor() as cur:
            cur.execute('UPDATE assignment_leases.coordinator_tasks SET active=false')
        with self.assertRaises(psycopg2.Error): self.resolve()
        self.assertEqual(self.count('scoped_registration.candidates'), 0)

    def test_explicit_dependency_inventory_detects_missing_receipt_rows(self):
        prerequisite = {'product':'A','scope_type':'SECTION','scope_name':'sec','sha':'c'*40}
        with self.connect('fixture_admin') as connection, connection.cursor() as cur:
            cur.execute('UPDATE assignment_leases.coordinator_tasks SET prerequisites=%s', (Json([prerequisite]),))
            cur.execute("INSERT INTO scope_certifications VALUES('A','SECTION','sec',%s,'CERTIFIED')", ('c'*40,))
        with self.assertRaisesRegex(psycopg2.Error, 'DEPENDENCY_UNAVAILABLE'): self.resolve()

    def test_revocation_between_preparation_and_claim_denies_without_consuming_proof(self):
        self.coordinate()
        proof = self.proof()
        with self.connect('fixture_admin') as connection, connection.cursor() as cur:
            cur.execute('UPDATE assignment_leases.coordinator_tasks SET active=false')
        with self.assertRaises(psycopg2.Error): self.coordinate('admit', proof=proof)
        self.assertEqual(self.count('assignment_leases.leases'), 0)

    def test_recover_and_repeated_admit_reuse_same_committed_receipt(self):
        self.coordinate()
        first = self.coordinate('admit', proof=self.proof())
        recovered = self.coordinate('recover')
        self.assertEqual(recovered['lease']['lease_id'], first['lease']['lease_id'])
        repeated = self.coordinate('admit', proof=str(uuid.uuid4()))
        self.assertEqual(repeated['lease']['lease_id'], first['lease']['lease_id'])
        self.assertEqual(self.count('assignment_leases.leases'), 1)

    def test_recover_does_not_issue_and_request_cannot_cross_task_mapping(self):
        with self.assertRaises(psycopg2.Error): self.coordinate('recover')
        self.coordinate()
        self.coordinate('admit', proof=self.proof())
        with self.assertRaises((ValueError, psycopg2.Error)):
            self.coordinate('recover', repository='appolon1908/B')
        self.assertEqual(self.count('assignment_leases.leases'), 1)

    def test_concurrent_coordinators_cannot_create_multiple_active_leases(self):
        self.coordinate()
        proofs = [self.proof(), self.proof()]
        def attempt(index):
            try: return self.coordinate('admit', request='concurrent-'+str(index), proof=proofs[index])
            except psycopg2.Error: return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, range(2)))
        self.assertEqual(sum(value is not None for value in results), 1)
        self.assertEqual(self.count('assignment_leases.leases'), 1)

    def test_frozen_lane_and_registry_drift_are_preserved(self):
        with self.connect('fixture_admin') as connection, connection.cursor() as cur:
            cur.execute("UPDATE workstations SET lease_state='FROZEN',status='BLOCKED',blocker='STALE_DIRTY_WORKTREE'")
        with self.assertRaises(psycopg2.Error): self.coordinate()
        with self.connect('fixture_admin') as connection, connection.cursor() as cur:
            cur.execute('SELECT lease_state,status,blocker FROM workstations')
            self.assertEqual(cur.fetchone(), ('FROZEN','BLOCKED','STALE_DIRTY_WORKTREE'))

    def test_tls_without_credential_authentication_cannot_resolve_or_attest(self):
        self.coordinate()
        try:
            self.hba.write_text(self.trust_hba)
            self.reload_hba()
            with self.assertRaisesRegex(psycopg2.Error, 'COORDINATOR_DENIED'): self.resolve()
            with self.assertRaisesRegex(psycopg2.Error, 'CREDENTIAL_AUTHENTICATION_REQUIRED'): self.proof()
        finally:
            self.hba.write_text('local all all trust\nhostssl all all 127.0.0.1/32 scram-sha-256\nhostnossl all all 127.0.0.1/32 reject\n')
            self.reload_hba()

    def test_builder_cannot_write_mapping_or_self_attest(self):
        self.coordinate()
        with self.assertRaises(psycopg2.Error): self.call('attest', (self.binding, Json({})))
        with self.connect() as connection, connection.cursor() as cur:
            with self.assertRaises(psycopg2.Error): cur.execute('UPDATE assignment_leases.coordinator_tasks SET active=true')

    def test_recovery_revalidates_independent_verifier_authority(self):
        self.coordinate()
        self.coordinate('admit', proof=self.proof())
        with self.connect('fixture_admin') as connection, connection.cursor() as cur:
            cur.execute("UPDATE assignment_leases.permissions SET active=false WHERE principal='verifier'")
        with self.assertRaisesRegex(psycopg2.Error, 'VERIFIER_REVOKED'):
            self.coordinate('recover')

    def test_commit_response_loss_recovers_same_lease_without_second_claim(self):
        from codestra_control.controller_coordinator import coordinate, AdmissionOutcomeUnknown
        self.coordinate()
        proof = self.proof()
        class LostResponse:
            def __init__(self, real): self.real = real
            def __getattr__(self, name): return getattr(self.real, name)
            def commit(self):
                self.real.commit()
                raise psycopg2.OperationalError('synthetic lost response')
        with self.connect() as connection:
            with self.assertRaises(AdmissionOutcomeUnknown):
                coordinate(LostResponse(connection), 'admit', 'A-task', 'appolon1908/A', 'coordinate-1', proof_id=proof, apply=True)
        recovered = self.coordinate('recover')
        self.assertTrue(recovered['usable'])
        self.assertEqual(self.count('assignment_leases.leases'), 1)
        with self.connect('fixture_admin') as connection, connection.cursor() as cur:
            cur.execute("SELECT count(*) FROM assignment_leases.audit WHERE action='CLAIM'")
            self.assertEqual(cur.fetchone()[0], 1)

    def test_uncommitted_independent_proof_cannot_admit(self):
        self.coordinate()
        description = self.call('describe', (self.binding,), user='verifier')
        binding = description['binding']
        observed = {key:binding[key] for key in ('repository','repository_id','source_ref','target_ref','head_sha','base_sha','worktree','host','git_common_dir','worktree_uid')}
        observed.update(directory_device=1,directory_inode=2,observed_at=datetime.now(timezone.utc).isoformat(),dependencies={})
        with self.connect('verifier') as verifier, verifier.cursor() as cur:
            cur.execute('SELECT assignment_leases.attest(%s,%s)', (self.binding, Json(observed)))
            proof = cur.fetchone()[0]['proof_id']
            # The uncommitted verifier holds authority locks. The builder's
            # proof-existence check must deny without waiting or consuming it.
            with self.assertRaisesRegex(psycopg2.Error, 'CREDENTIAL_AUTHENTICATION_REQUIRED'):
                self.coordinate('admit', proof=proof)
            verifier.commit()
        self.assertTrue(self.coordinate('admit', proof=proof)['usable'])

    def test_missing_and_wrong_scram_credentials_are_rejected(self):
        for password in (None, 'incorrect-synthetic-password'):
            with self.subTest(password_present=password is not None), mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(psycopg2.OperationalError):
                psycopg2.connect(host='127.0.0.1', port=self.port, dbname='postgres', user='alice', password=password,
                    passfile=str(self.path/'absent-fixture-passfile'), sslmode='verify-full',
                    sslrootcert=str(self.path/'fixture.crt'), connect_timeout=2)

    def test_legacy_proof_without_credential_provenance_cannot_admit(self):
        self.coordinate()
        proof = self.proof()
        with self.connect('fixture_admin') as connection, connection.cursor() as cur:
            cur.execute('UPDATE assignment_leases.proofs SET verifier_authentication=NULL WHERE proof_id=%s', (proof,))
        with self.assertRaisesRegex(psycopg2.Error, 'CREDENTIAL_AUTHENTICATION_REQUIRED'):
            self.coordinate('admit', proof=proof)
        self.assertEqual(self.count('assignment_leases.leases'), 0)

    def test_nonempty_dependencies_are_pinned_through_recovery(self):
        from dataclasses import asdict
        from codestra_control.evidence import PromotionRequest
        from codestra_control.lease_materialization import dependency_digest
        prerequisite = {'product':'A','scope_type':'SECTION','scope_name':'sec','sha':'c'*40}
        binding = PromotionRequest('appolon1908/A','A','section/sec','development','c'*40,'d'*40)
        with self.connect('fixture_admin') as connection, connection.cursor() as cur:
            cur.execute('UPDATE assignment_leases.coordinator_tasks SET prerequisites=%s', (Json([prerequisite]),))
            cur.execute("INSERT INTO scope_certifications VALUES('A','SECTION','sec',%s,'CERTIFIED')", ('c'*40,))
            cur.execute("INSERT INTO assignment_leases.dependencies VALUES(%s,'section:sec',%s,'appolon1908/A',123,%s,%s,99,'scope-certification','synthetic-capability','Ralph L. Appolon','SCOPE_CERTIFICATION',10,clock_timestamp()+interval '5 minutes',true)",
                (self.binding, Json(prerequisite), Json(asdict(binding)), dependency_digest(binding,prerequisite)))
        self.coordinate()
        description = self.call('describe', (self.binding,), user='verifier')
        proof = self.proof({'dependencies':{row['dependency_key']:row for row in description['dependencies']}})
        self.assertTrue(self.coordinate('admit', proof=proof)['usable'])
        with self.connect('fixture_admin') as connection, connection.cursor() as cur:
            cur.execute('UPDATE assignment_leases.dependencies SET check_id=11')
        with self.assertRaisesRegex(psycopg2.Error, 'VERIFIER_REVOKED'):
            self.coordinate('recover')

    def test_revocation_lock_order_does_not_deadlock_resolver(self):
        self.coordinate()
        proof = self.proof()
        with self.connect('fixture_admin') as operator, operator.cursor() as cur:
            cur.execute('SELECT assignment_leases._lock(b) FROM assignment_leases.bindings b WHERE binding_id=%s', (self.binding,))
            def resolve_waiter():
                with self.connect() as connection, connection.cursor() as waiter:
                    waiter.execute("SET application_name='coordinator-lock-fixture'; SET statement_timeout='20s'")
                    try:
                        waiter.execute('SELECT assignment_leases.admit_task(%s,%s,%s,%s)', ('A-task','appolon1908/A','lock-order',proof))
                        return waiter.fetchone()[0]
                    except psycopg2.Error as error:
                        return error.diag.message_primary
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(resolve_waiter)
                deadline = time.monotonic()+15
                while time.monotonic() < deadline:
                    cur.execute('SELECT pg_stat_clear_snapshot()')
                    cur.execute("SELECT count(*) FROM pg_stat_activity WHERE application_name='coordinator-lock-fixture' AND wait_event='advisory'")
                    if cur.fetchone()[0]: break
                    if future.done():
                        operator.rollback()
                        self.fail('Admission finished before lock boundary: '+str(future.result()))
                    time.sleep(0.01)
                else:
                    operator.rollback()
                    self.fail('Resolver did not reach the controlled advisory-lock boundary')
                try:
                    cur.execute("SET LOCAL lock_timeout='1s'")
                    cur.execute('UPDATE assignment_leases.bindings SET active=false WHERE binding_id=%s', (self.binding,))
                    operator.commit()
                finally:
                    operator.rollback()
                self.assertEqual(future.result(timeout=10), 'TASK_MAPPING_UNAVAILABLE')
