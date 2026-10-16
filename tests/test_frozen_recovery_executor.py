"""Recovery API tests against disposable PostgreSQL16/TLS/SCRAM only.

No installed DSN, credential, lease or GitHub endpoint is accepted by this fixture.
Materialization observations are synthetic; real checkout inspection is tested at
the separate client boundary.
"""
import concurrent.futures
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import threading
import unittest
import uuid

import psycopg2
from psycopg2 import sql
from psycopg2.extras import Json

import test_assignment_leases as issuer
import test_scoped_registration as registration


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / '008-frozen-recovery.sql'
ROLES = ('alice', 'bob', 'operator', 'reviewer', 'verifier', 'trust_operator')


@unittest.skipUnless((registration.PG / 'initdb').exists(),
                     'PostgreSQL16 disposable binaries required')
class FrozenRecoveryExecutorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reproduce a missing implementation before allocating any test server.
        migration = MIGRATION.read_text()
        issuer.AssignmentLeaseTests.setUpClass()
        cls.path = issuer.AssignmentLeaseTests.path
        cls.port = issuer.AssignmentLeaseTests.port
        try:
            with issuer.AssignmentLeaseTests.connect('fixture_admin') as connection:
                with connection.cursor() as cursor:
                    cursor.execute('CREATE ROLE reviewer LOGIN; CREATE ROLE trust_operator LOGIN')
                    cursor.execute("SET password_encryption='scram-sha-256'")
                    for role in ('fixture_admin', *ROLES, 'mallory'):
                        cursor.execute(sql.SQL('ALTER ROLE {} PASSWORD {}').format(
                            sql.Identifier(role), sql.Literal(cls.password(role))))
            # Only this disposable cluster is changed. The sole trust login is a
            # deliberate negative case, not accepted authentication evidence.
            (registration.ScopedRegistrationTests.data / 'pg_hba.conf').write_text(
                'local all all trust\n'
                'host all trust_operator 127.0.0.1/32 trust\n'
                'host all all 127.0.0.1/32 scram-sha-256\n')
            subprocess.run([str(registration.PG / 'pg_ctl'), '-D',
                            str(registration.ScopedRegistrationTests.data), 'reload'],
                           check=True, capture_output=True)
            with cls.connect('fixture_admin') as connection, connection.cursor() as cursor:
                # Real upgrades encounter already-frozen legacy rows. Seed one
                # before installing008 with an intentionally non-UTC session.
                cursor.execute("INSERT INTO public.workstations("
                               "workstation_id,product,section,subsection,branch,parent_branch,worktree,order_index,"
                               "status,agent,current_atomic_task,blocker,lease_state,lease_started_at,heartbeat_at,lease_expires_at) "
                               "VALUES('fixture-migration-seed','legacy','seed','sub','subsection/seed--sub',"
                               "'section/seed','/fixture/legacy/subsection',1,'BLOCKED','legacy-previous',"
                               "'legacy-seed-task','STALE_DIRTY_WORKTREE','FROZEN',"
                               "clock_timestamp()-interval '2 hours',clock_timestamp()-interval '90 minutes',"
                               "clock_timestamp()-interval '1 hour')")
                cursor.execute("SET TIME ZONE 'America/New_York'")
                cursor.execute(migration)
                cursor.execute("SELECT snapshot FROM frozen_recovery.incidents "
                               "WHERE workstation_id='fixture-migration-seed'")
                cls.seeded_snapshot = cursor.fetchone()[0]
                cursor.execute("SET TIME ZONE 'UTC'")
                cursor.execute("SELECT to_jsonb(w) FROM public.workstations w "
                               "WHERE workstation_id='fixture-migration-seed'")
                cls.seeded_row_utc = cursor.fetchone()[0]
                cursor.execute('GRANT USAGE ON SCHEMA frozen_recovery TO ' + ','.join(ROLES))
                # Give fixture roles entrypoint execution so each test exercises
                # the server's capability/identity checks, not only SQL GRANTs.
                for name, arguments in (
                    ('authorize', 'text,jsonb,name,name,name,text'),
                    ('describe', 'uuid'), ('review', 'uuid,text'),
                    ('attest', 'uuid,text,jsonb'),
                    ('execute', 'uuid,uuid,text,text'), ('lookup', 'text'),
                    ('revoke', 'uuid,text,text,text'),
                ):
                    cursor.execute('GRANT EXECUTE ON FUNCTION frozen_recovery.'
                                   + name + '(' + arguments + ') TO ' + ','.join(ROLES))
            with cls.connect() as connection, connection.cursor() as cursor:
                cursor.execute('SELECT system_user,session_user,current_user')
                cls.authenticated_identity = cursor.fetchone()
                if cls.authenticated_identity != ('scram-sha-256:alice', 'alice', 'alice'):
                    raise AssertionError('fixture must use actual SCRAM session authentication')
        except BaseException:
            issuer.AssignmentLeaseTests.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        issuer.AssignmentLeaseTests.tearDownClass()

    @staticmethod
    def password(role):
        return 'disposable-recovery-fixture-' + role

    @classmethod
    def connect(cls, user='alice', sslmode='verify-full'):
        return psycopg2.connect(
            host='127.0.0.1', port=cls.port, dbname='postgres', user=user,
            password=cls.password(user), sslmode=sslmode,
            sslrootcert=str(cls.path / 'fixture.crt'), connect_timeout=5,
            options='-c statement_timeout=30000 -c lock_timeout=10000')

    def setUp(self):
        self.admin('TRUNCATE frozen_recovery.audit,frozen_recovery.proofs,'
                   'frozen_recovery.reviews,frozen_recovery.grants,'
                   'frozen_recovery.incidents,frozen_recovery.permissions,'
                   'frozen_recovery.policies CASCADE')
        issuer.AssignmentLeaseTests.setUp(self)
        self.admin("INSERT INTO scoped_registration.principals(principal,role_oid,active) "
                   "SELECT rolname,oid,true FROM pg_roles "
                   "WHERE rolname IN ('reviewer','trust_operator')")
        self.admin("INSERT INTO frozen_recovery.policies(product,grant_seconds,proof_seconds,active) "
                   "VALUES('A',3600,600,true)")
        self.admin("INSERT INTO frozen_recovery.permissions(principal,product,capability,active) "
                   "VALUES('operator','A','authorize',true),('reviewer','A','review',true),"
                   "('verifier','A','attest',true),('alice','A','execute',true),"
                   "('trust_operator','A','authorize',true)")
        self.admin("UPDATE workstations SET lease_state='FROZEN',status='BLOCKED',"
                   "blocker='STALE_DIRTY_WORKTREE',agent='legacy-previous',"
                   "current_atomic_task='legacy-frozen-task',base_sha=%s,local_sha=%s,"
                   "remote_sha=%s,parent_sha=%s,lease_started_at=clock_timestamp()-interval '2 hours',"
                   "heartbeat_at=clock_timestamp()-interval '90 minutes',"
                   "lease_expires_at=clock_timestamp()-interval '1 hour',"
                   "last_test_run=clock_timestamp()-interval '3 hours',ci_result='historical-ci',"
                   "review_result='historical-review',evidence=%s "
                   "WHERE workstation_id='A-ws'",
                   ('b'*40, 'a'*40, 'a'*40, 'b'*40,
                    Json({'preserve': {'repair': 'fixture'}, 'gates': {'unit': 'PASS'}})))
        self.admin("INSERT INTO scope_certifications VALUES('A','SECTION','sec',%s,'CERTIFIED')",
                   ('c'*40,))
        self.checkout = dict(
            repository='appolon1908/A', repository_id=123,
            source_ref='subsection/sec--sub', target_ref='section/sec',
            head_sha='a'*40, base_sha='b'*40,
            worktree='/fixture/A/subsection', root_path='/fixture/A',
            git_common_dir='/fixture/A/repo.git', host='fixture-host', worktree_uid=1000)

    def admin(self, query, parameters=()):
        with self.connect('fixture_admin') as connection, connection.cursor() as cursor:
            cursor.execute(query, parameters)
            return cursor.fetchall() if cursor.description else None

    def call(self, name, arguments=(), user='alice', role=None, sslmode='verify-full', timezone=None):
        connection = self.connect(user, sslmode)
        try:
            with connection.cursor() as cursor:
                if timezone is not None:
                    cursor.execute('SET TIME ZONE %s', (timezone,))
                if role:
                    cursor.execute(sql.SQL('SET ROLE {}').format(sql.Identifier(role)))
                cursor.execute('SELECT frozen_recovery.' + name + '(' +
                               ','.join(['%s'] * len(arguments)) + ')', arguments)
                value = cursor.fetchone()[0]
            connection.commit()
            return value
        finally:
            connection.close()

    def row(self):
        return self.admin("SELECT to_jsonb(w) FROM workstations w WHERE workstation_id='A-ws'")[0][0]

    def authorize(self, *, checkout=None, executor='alice', reviewer='reviewer',
                  verifier='verifier', user='operator', request='grant-1', workstation='A-ws'):
        return self.call('authorize', (workstation, Json(self.checkout if checkout is None else checkout),
                                     executor, reviewer, verifier, request), user=user)

    def observe(self, description):
        binding = description['binding']
        observed = {name: binding[name] for name in (
            'repository', 'repository_id', 'source_ref', 'target_ref', 'head_sha',
            'base_sha', 'worktree', 'host', 'git_common_dir', 'worktree_uid')}
        observed.update(directory_device=1, directory_inode=2,
                        observed_at=datetime.now(timezone.utc).isoformat(), dependencies={})
        return observed

    def ready(self, *, request='grant-1'):
        grant = self.authorize(request=request)
        grant_id, digest = grant['grant_id'], grant['request_digest']
        review = self.call('review', (grant_id, digest), user='reviewer')
        self.assertTrue(review['reviewed'])
        description = self.call('describe', (grant_id,), user='verifier')
        self.assertEqual(description['binding'], self.checkout)
        self.assertEqual(description['dependencies'], [])
        self.assertEqual(description['request_digest'], digest)
        proof = self.call('attest', (grant_id, digest, Json(self.observe(description))), user='verifier')
        return grant_id, proof['proof_id'], digest

    def execute(self, prepared=None, request='release-1', **kwargs):
        grant_id, proof_id, digest = prepared or self.ready()
        return self.call('execute', (grant_id, proof_id, digest, request), **kwargs)

    def assert_frozen(self):
        row = self.row()
        self.assertEqual((row['lease_state'], row['status'], row['blocker'], row['agent']),
                         ('FROZEN', 'BLOCKED', 'STALE_DIRTY_WORKTREE', 'legacy-previous'))

    def durable_state(self):
        return {
            'row': self.row(),
            **{table: self.admin('SELECT to_jsonb(t) FROM ' + table + ' t ORDER BY to_jsonb(t)::text')
               for table in ('frozen_recovery.grants', 'frozen_recovery.proofs',
                             'frozen_recovery.incidents', 'frozen_recovery.audit',
                             'assignment_leases.slots', 'public.events')},
        }

    def test_release_preserves_history_and_never_grants_lease_or_certifies(self):
        before = self.row()
        tasks = self.admin('SELECT to_jsonb(t) FROM atomic_tasks t ORDER BY task_id')
        certificates = self.admin('SELECT to_jsonb(c) FROM scope_certifications c')
        self.admin("INSERT INTO assignment_leases.slots VALUES('A-ws',7)")
        receipt = self.execute()
        self.assertTrue(receipt['released'])
        self.assertFalse(receipt['certified'])
        self.assertFalse(receipt['lease_granted'])
        self.assertEqual(receipt['epoch'], 8)
        after = self.row()
        self.assertEqual((after['lease_state'], after['status']), ('FREE', 'NOT_STARTED'))
        for name in ('agent', 'current_atomic_task', 'blocker', 'lease_started_at',
                     'heartbeat_at', 'lease_expires_at'):
            self.assertIsNone(after[name], name)
        for name in ('base_sha', 'local_sha', 'remote_sha', 'parent_sha', 'depends_on',
                     'required_gates', 'evidence', 'last_test_run', 'ci_result',
                     'review_result', 'completed_at', 'certified_at'):
            self.assertEqual(after[name], before[name], name)
        self.assertEqual(tasks, self.admin('SELECT to_jsonb(t) FROM atomic_tasks t ORDER BY task_id'))
        self.assertEqual(certificates, self.admin('SELECT to_jsonb(c) FROM scope_certifications c'))
        self.assertEqual(self.admin('SELECT count(*) FROM assignment_leases.leases'), [(0,)])
        self.assertEqual(self.admin('SELECT consumed FROM frozen_recovery.grants'), [(True,)])
        self.assertEqual(self.admin('SELECT consumed FROM frozen_recovery.proofs'), [(True,)])
        self.assertEqual(self.admin('SELECT count(*) FROM frozen_recovery.audit'), [(1,)])

    def test_runtime_callers_cannot_write_authority_or_evidence_tables(self):
        for table in ('policies', 'permissions', 'incidents', 'grants', 'reviews', 'proofs', 'audit'):
            with self.subTest(table=table), self.connect() as connection, connection.cursor() as cursor:
                with self.assertRaises(psycopg2.Error):
                    cursor.execute('DELETE FROM frozen_recovery.' + table)
        for table in ('workstations', 'events', 'atomic_tasks', 'scope_certifications'):
            with self.subTest(table=table), self.connect() as connection, connection.cursor() as cursor:
                with self.assertRaises(psycopg2.Error):
                    cursor.execute('DELETE FROM public.' + table)

    def test_operator_cannot_skip_distinct_review_and_observation(self):
        grant = self.authorize()
        for operation, arguments in (
            ('review', (grant['grant_id'], grant['request_digest'])),
            ('attest', (grant['grant_id'], grant['request_digest'], Json({}))),
            ('execute', (grant['grant_id'], str(uuid.uuid4()), grant['request_digest'], 'skip')),
        ):
            with self.subTest(operation=operation), self.assertRaises(psycopg2.Error):
                self.call(operation, arguments, user='operator')
        self.assert_frozen()

    def test_duplicate_role_or_previous_builder_cannot_be_independent(self):
        # Remove missing-capability as an alternative reason for rejecting role
        # aliasing: these synthetic principals deliberately hold every API cap.
        self.admin("INSERT INTO frozen_recovery.permissions(principal,product,capability,active) "
                   "SELECT p,'A',c,true FROM unnest(ARRAY['operator','reviewer','verifier','alice']) p "
                   "CROSS JOIN unnest(ARRAY['authorize','review','attest','execute']) c "
                   "ON CONFLICT DO NOTHING")
        combinations = (
            {'reviewer': 'operator'}, {'verifier': 'operator'}, {'executor': 'operator'},
            {'reviewer': 'alice'}, {'verifier': 'alice'}, {'verifier': 'reviewer'},
            {'executor': 'legacy-previous'}, {'reviewer': 'legacy-previous'},
        )
        for index, roles in enumerate(combinations):
            with self.subTest(roles=roles), self.assertRaises(psycopg2.Error):
                self.authorize(request='self-' + str(index), **roles)

    def test_frozen_eligibility_is_exact_and_never_downgrades_completion(self):
        changes = (
            "lease_state='STALE'", "status='IN_PROGRESS'", "blocker='OTHER_BLOCKER'",
            'agent=NULL', 'current_atomic_task=NULL',
            'completed_at=clock_timestamp()', 'certified_at=clock_timestamp()',
        )
        for change in changes:
            with self.subTest(change=change):
                before = self.row()
                self.admin("UPDATE workstations SET " + change + " WHERE workstation_id='A-ws'")
                try:
                    with self.assertRaises(psycopg2.Error):
                        self.authorize(request='bad-state')
                finally:
                    self.admin("UPDATE workstations SET lease_state=%s,status=%s,blocker=%s,agent=%s,"
                               "current_atomic_task=%s,completed_at=%s,certified_at=%s "
                               "WHERE workstation_id='A-ws'",
                               tuple(before[field] for field in ('lease_state', 'status', 'blocker',
                                                                 'agent', 'current_atomic_task',
                                                                 'completed_at', 'certified_at')))

    def test_repaired_checkout_cannot_change_registered_subsection_identity(self):
        for field, value in (
            ('repository', 'appolon1908/B'), ('source_ref', 'atomic/sec--sub--task'),
            ('target_ref', 'development'), ('worktree', '/fixture/A/atomic'),
            ('head_sha', '0'*40), ('base_sha', 'invalid'),
        ):
            with self.subTest(field=field), self.assertRaises(psycopg2.Error):
                self.authorize(checkout=dict(self.checkout, **{field: value}), request='wrong-' + field)
        for field in self.checkout:
            checkout = dict(self.checkout)
            del checkout[field]
            with self.subTest(missing=field), self.assertRaises(psycopg2.Error):
                self.authorize(checkout=checkout, request='missing-' + field)

    def test_frozen_row_drift_invalidates_grant_even_when_timestamp_restored(self):
        prepared = self.ready()
        timestamp = self.row()['updated_at']
        self.admin("UPDATE workstations SET evidence=evidence||'{\"new\":true}'::jsonb,updated_at=%s "
                   "WHERE workstation_id='A-ws'", (timestamp,))
        with self.assertRaises(psycopg2.Error):
            self.execute(prepared)
        self.assert_frozen()

    def test_identical_leave_refreeze_aba_rotates_incident_and_rejects_old_proof(self):
        prepared = self.ready()
        before = self.row()
        incident = self.admin("SELECT incident_id,revision FROM frozen_recovery.incidents WHERE workstation_id='A-ws'")[0]
        self.admin("UPDATE workstations SET lease_state='FREE' WHERE workstation_id='A-ws'")
        self.admin("UPDATE workstations SET lease_state='FROZEN',updated_at=%s WHERE workstation_id='A-ws'",
                   (before['updated_at'],))
        self.assertEqual(self.row(), before)
        replacement = self.admin("SELECT incident_id,revision FROM frozen_recovery.incidents WHERE workstation_id='A-ws'")[0]
        self.assertNotEqual(replacement[0], incident[0])
        self.assertGreater(replacement[1], incident[1])
        with self.assertRaises(psycopg2.Error):
            self.execute(prepared)

    def test_missing_authoritative_incident_cannot_release_or_consume_evidence(self):
        prepared = self.ready()
        self.admin("DELETE FROM frozen_recovery.incidents WHERE workstation_id='A-ws'")
        before = self.durable_state()
        with self.assertRaises(psycopg2.Error):
            self.execute(prepared)
        self.assertEqual(self.durable_state(), before)

    def test_scoped_registration_drift_denies_with_unchanged_frozen_row(self):
        prepared = self.ready()
        before = self.row()
        payload = self.fixture.workstation()
        for field, value in (('section', 'other'), ('subsection', 'other'),
                             ('parent_branch', 'section/other'), ('order_index', 99)):
            with self.subTest(field=field):
                self.admin("UPDATE scoped_registration.workstations SET payload=%s WHERE workstation_id='A-ws'",
                           (Json(dict(payload, **{field: value})),))
                try:
                    with self.assertRaises(psycopg2.Error):
                        self.execute(prepared)
                    self.assertEqual(self.row(), before)
                finally:
                    self.admin("UPDATE scoped_registration.workstations SET payload=%s WHERE workstation_id='A-ws'",
                               (Json(payload),))
        self.admin("DELETE FROM scoped_registration.lanes WHERE kind='workstation' AND identity='A-ws'")
        with self.assertRaises(psycopg2.Error):
            self.execute(prepared)
        self.assertEqual(self.row(), before)

    def test_missing_scoped_workstation_cannot_recover_unchanged_frozen_row(self):
        prepared = self.ready()
        before = self.row()
        self.admin("DELETE FROM assignment_leases.bindings WHERE workstation_id='A-ws';"
                   "DELETE FROM scoped_registration.candidates WHERE workstation_id='A-ws';"
                   "DELETE FROM scoped_registration.task_assignments WHERE workstation_id='A-ws';"
                   "DELETE FROM scoped_registration.workstations WHERE workstation_id='A-ws'")
        with self.assertRaises(psycopg2.Error):
            self.execute(prepared)
        self.assertEqual(self.row(), before)

    def test_equivalent_instants_survive_different_concurrent_client_timezones(self):
        grant = self.authorize()
        grant_id, digest = grant['grant_id'], grant['request_digest']
        def describe(zone):
            return self.call('describe', (grant_id,), user='verifier', timezone=zone)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            descriptions = list(pool.map(describe, ('Pacific/Auckland', 'America/New_York')))
        self.assertEqual(descriptions[0], descriptions[1])
        self.assertTrue(self.call('review', (grant_id, digest), user='reviewer', timezone='Asia/Tokyo')['reviewed'])
        observed = self.observe(descriptions[0])
        proof = self.call('attest', (grant_id, digest, Json(observed)), user='verifier', timezone='America/Los_Angeles')
        receipt = self.execute((grant_id, proof['proof_id'], digest), timezone='Pacific/Auckland')
        self.assertTrue(receipt['released'])

    def test_expired_grant_or_proof_cannot_release(self):
        # Let a genuine server-created grant expire without changing its digest
        # or policy; digest-mismatch denial cannot substitute for the TTL guard.
        self.admin("UPDATE frozen_recovery.policies SET grant_seconds=1,proof_seconds=1 WHERE product='A'")
        grant = self.authorize(request='short-lived-grant')
        self.admin('SELECT pg_sleep(1.05)')
        with self.assertRaises(psycopg2.Error):
            self.call('describe', (grant['grant_id'],), user='verifier')
        self.admin("UPDATE frozen_recovery.policies SET grant_seconds=3600,proof_seconds=600 WHERE product='A'")
        prepared = self.ready(request='proof-expiry-grant')
        self.admin("UPDATE frozen_recovery.proofs SET expires_at=clock_timestamp()-interval '1 second' "
                   "WHERE proof_id=%s", (prepared[1],))
        with self.assertRaises(psycopg2.Error):
            self.execute(prepared)
        self.assert_frozen()

    def test_existing_frozen_row_seed_survives_non_utc_installer(self):
        self.assertEqual(self.seeded_snapshot, self.seeded_row_utc)

    def test_permission_revocation_for_every_participant_invalidates_execution(self):
        prepared = self.ready()
        for principal in ('operator', 'reviewer', 'verifier', 'alice'):
            with self.subTest(principal=principal):
                self.admin('UPDATE frozen_recovery.permissions SET active=false WHERE principal=%s', (principal,))
                try:
                    with self.assertRaises(psycopg2.Error):
                        self.execute(prepared)
                finally:
                    self.admin('UPDATE frozen_recovery.permissions SET active=true WHERE principal=%s', (principal,))
        self.assert_frozen()

    def test_grant_revocation_is_durable_after_policy_disable_and_reenable(self):
        prepared = self.ready()
        self.admin("UPDATE frozen_recovery.policies SET active=false WHERE product='A'")
        revoked = self.call('revoke', (prepared[0], prepared[2], 'fixture revocation', 'revoke-1'),
                            user='operator')
        self.assertTrue(revoked['revoked'])
        self.admin("UPDATE frozen_recovery.policies SET active=true WHERE product='A'")
        with self.assertRaises(psycopg2.Error):
            self.execute(prepared)
        self.assertEqual(self.admin('SELECT revoked,consumed FROM frozen_recovery.grants'), [(True, False)])
        self.assertEqual(self.admin('SELECT consumed FROM frozen_recovery.proofs'), [(False,)])
        self.assert_frozen()

    def test_principal_revocation_and_policy_drift_invalidate_execution(self):
        prepared = self.ready()
        self.admin("UPDATE scoped_registration.principals SET active=false WHERE principal='reviewer'")
        with self.assertRaises(psycopg2.Error):
            self.execute(prepared)
        self.admin("UPDATE scoped_registration.principals SET active=true WHERE principal='reviewer'")
        self.admin("UPDATE frozen_recovery.policies SET proof_seconds=proof_seconds+1 WHERE product='A'")
        with self.assertRaises(psycopg2.Error):
            self.execute(prepared)
        self.assert_frozen()

    def test_wrong_or_missing_observation_fields_deny(self):
        grant = self.authorize()
        grant_id, digest = grant['grant_id'], grant['request_digest']
        self.call('review', (grant_id, digest), user='reviewer')
        description = self.call('describe', (grant_id,), user='verifier')
        observed = self.observe(description)
        for field, value in (
            ('head_sha', 'd'*40), ('repository_id', 999), ('worktree', '/other/path'),
            ('source_ref', 'atomic/sec--sub--task'), ('directory_inode', 0),
            ('observed_at', '2000-01-01T00:00:00+00:00'), ('dependencies', {'unapproved': True}),
        ):
            with self.subTest(field=field), self.assertRaises(psycopg2.Error):
                self.call('attest', (grant_id, digest, Json(dict(observed, **{field: value}))), user='verifier')
        for field in observed:
            malformed = dict(observed)
            del malformed[field]
            with self.subTest(missing=field), self.assertRaises(psycopg2.Error):
                self.call('attest', (grant_id, digest, Json(malformed)), user='verifier')
        with self.assertRaises(psycopg2.Error):
            self.call('attest', (grant_id, digest, Json(dict(observed, unexpected=True))), user='verifier')
        self.assertTrue(self.call('attest', (grant_id, digest, Json(observed)), user='verifier')['proof_id'])

    def test_wrong_digest_review_and_cross_grant_proof_cannot_release(self):
        prepared = self.ready()
        other = self.ready(request='grant-2')
        with self.assertRaises(psycopg2.Error):
            self.call('review', (prepared[0], 'f'*64), user='reviewer')
        with self.assertRaises(psycopg2.Error):
            self.execute((prepared[0], prepared[1], 'f'*64))
        with self.assertRaises(psycopg2.Error):
            self.execute((prepared[0], other[1], prepared[2]))
        self.assert_frozen()

    def test_success_is_one_use_and_lookup_is_only_historical(self):
        prepared = self.ready()
        receipt = self.execute(prepared)
        with self.assertRaises(psycopg2.Error):
            self.execute(prepared, request='replay-different-request')
        historical = self.call('lookup', ('release-1',))
        self.assertEqual(historical['authority'], 'HISTORICAL_RECOVERY_RECEIPT')
        self.assertFalse(historical['usable_as_lease'])
        self.assertEqual({key: historical[key] for key in receipt if key != 'authority'},
                         {key: value for key, value in receipt.items() if key != 'authority'})
        with self.assertRaises(psycopg2.Error):
            self.call('lookup', ('release-1',), user='bob')
        self.admin("UPDATE workstations SET lease_state='FROZEN',status='BLOCKED',"
                   "blocker='STALE_DIRTY_WORKTREE',agent='legacy-previous',"
                   "current_atomic_task='legacy-frozen-task' WHERE workstation_id='A-ws'")
        self.assertEqual(self.call('lookup', ('release-1',)), historical)
        self.assert_frozen()
        with self.assertRaises(psycopg2.Error):
            self.execute(prepared)

    def test_two_concurrent_executions_have_exactly_one_winner(self):
        prepared = self.ready()
        barrier = threading.Barrier(2)
        def attempt(index):
            barrier.wait(timeout=5)
            try:
                return self.execute(prepared, request='concurrent-' + str(index))
            except psycopg2.Error:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, range(2)))
        self.assertEqual(sum(value is not None for value in results), 1)
        self.assertEqual(self.admin('SELECT count(*) FROM frozen_recovery.audit'), [(1,)])
        self.assertEqual(self.admin("SELECT epoch FROM assignment_leases.slots WHERE workstation_id='A-ws'"), [(1,)])

    def test_audit_failure_rolls_back_row_epoch_proof_grant_and_incident(self):
        prepared = self.ready()
        self.admin("CREATE FUNCTION public.fixture_reject_recovery_audit() RETURNS trigger LANGUAGE plpgsql AS $$"
                   "BEGIN RAISE EXCEPTION 'SYNTHETIC_AUDIT_FAILURE'; END $$;"
                   "CREATE TRIGGER fixture_reject_recovery_audit BEFORE INSERT ON frozen_recovery.audit "
                   "FOR EACH ROW EXECUTE FUNCTION public.fixture_reject_recovery_audit()")
        before = self.durable_state()
        try:
            with self.assertRaisesRegex(psycopg2.Error, 'SYNTHETIC_AUDIT_FAILURE'):
                self.execute(prepared)
            self.assertEqual(self.durable_state(), before)
        finally:
            self.admin('DROP TRIGGER fixture_reject_recovery_audit ON frozen_recovery.audit;'
                       'DROP FUNCTION public.fixture_reject_recovery_audit()')
        self.assertTrue(self.execute(prepared)['released'])

    def test_expiration_during_slow_audit_rolls_back_complete_recovery(self):
        prepared = self.ready()
        self.admin("CREATE SEQUENCE public.fixture_recovery_audit_reached;"
                   "CREATE FUNCTION public.fixture_slow_recovery_audit() RETURNS trigger "
                   "LANGUAGE plpgsql AS $$ BEGIN "
                   "PERFORM nextval('public.fixture_recovery_audit_reached');"
                   "PERFORM pg_sleep(1); RETURN NEW; END $$;"
                   "CREATE TRIGGER fixture_slow_recovery_audit BEFORE INSERT ON frozen_recovery.audit "
                   "FOR EACH ROW EXECUTE FUNCTION public.fixture_slow_recovery_audit();"
                   "CREATE FUNCTION public.fixture_execute_near_expiry(g uuid,p uuid,d text,r text) "
                   "RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ "
                   "BEGIN UPDATE frozen_recovery.proofs SET expires_at=clock_timestamp()+interval '0.5 second' "
                   "WHERE proof_id=p; RETURN frozen_recovery.execute(g,p,d,r); END $$;"
                   "GRANT EXECUTE ON FUNCTION public.fixture_execute_near_expiry(uuid,uuid,text,text) TO alice")
        before = self.durable_state()
        try:
            connection = self.connect()
            try:
                with connection.cursor() as cursor:
                    with self.assertRaisesRegex(psycopg2.Error, 'EXPIRED'):
                        cursor.execute('SELECT public.fixture_execute_near_expiry(%s,%s,%s,%s)',
                                       (*prepared, 'slow-audit-expiry'))
            finally:
                connection.rollback()
                connection.close()
            # Sequence increments survive rollback: this proves execution
            # reached the sleeping audit trigger, not merely an early TTL guard.
            self.assertEqual(self.admin('SELECT last_value,is_called FROM public.fixture_recovery_audit_reached'), [(1, True)])
            self.assertEqual(self.durable_state(), before)
        finally:
            self.admin('DROP TRIGGER fixture_slow_recovery_audit ON frozen_recovery.audit;'
                       'DROP FUNCTION public.fixture_slow_recovery_audit();'
                       'DROP FUNCTION public.fixture_execute_near_expiry(uuid,uuid,text,text);'
                       'DROP SEQUENCE public.fixture_recovery_audit_reached')

    def test_recreated_executor_oid_does_not_inherit_grant(self):
        prepared = self.ready()
        self.admin('DROP OWNED BY alice; DROP ROLE alice; CREATE ROLE alice LOGIN PASSWORD %s',
                   (self.password('alice'),))
        self.admin('GRANT USAGE ON SCHEMA frozen_recovery TO alice;'
                   'GRANT EXECUTE ON FUNCTION frozen_recovery.execute(uuid,uuid,text,text) TO alice')
        try:
            with self.assertRaises(psycopg2.Error):
                self.execute(prepared)
        finally:
            self.admin('GRANT registration_runtime TO alice;'
                       'GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA frozen_recovery TO alice')
        self.assert_frozen()

    def test_set_role_privilege_membership_and_table_dml_deny(self):
        prepared = self.ready()
        self.admin('GRANT alice TO bob')
        try:
            with self.assertRaises(psycopg2.Error):
                self.execute(prepared, user='bob', role='alice')
        finally:
            self.admin('REVOKE alice FROM bob')
        for privilege, revoke in (
            ('GRANT fixture_admin TO alice', 'REVOKE fixture_admin FROM alice'),
            ('GRANT UPDATE ON public.workstations TO alice', 'REVOKE UPDATE ON public.workstations FROM alice'),
            ('GRANT CREATE ON SCHEMA frozen_recovery TO alice', 'REVOKE CREATE ON SCHEMA frozen_recovery FROM alice'),
        ):
            self.admin(privilege)
            try:
                with self.subTest(privilege=privilege), self.assertRaises(psycopg2.Error):
                    self.execute(prepared)
            finally:
                self.admin(revoke)
        self.assert_frozen()

    def test_plaintext_and_trust_over_tls_are_not_authenticated_recovery(self):
        with self.assertRaises(psycopg2.Error):
            self.call('authorize', ('A-ws', Json(self.checkout), 'alice', 'reviewer', 'verifier', 'plaintext'),
                      user='operator', sslmode='disable')
        with self.connect('trust_operator') as connection, connection.cursor() as cursor:
            cursor.execute('SELECT system_user IS NULL,(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())')
            self.assertEqual(cursor.fetchone(), (True, True))
        with self.assertRaises(psycopg2.Error):
            self.authorize(user='trust_operator', request='trust-is-not-authentication')
        self.assert_frozen()

    def test_authenticated_system_identity_cannot_switch_session_principal(self):
        prepared = self.ready()
        for principal, operation, arguments in (
            ('alice', 'execute', (*prepared, 'session-impersonation')),
            ('verifier', 'describe', (prepared[0],)),
            ('operator', 'authorize', ('A-ws', Json(self.checkout), 'alice', 'reviewer',
                                       'verifier', 'impersonated-operator')),
        ):
            with self.subTest(principal=principal), self.connect('fixture_admin') as connection:
                with connection.cursor() as cursor:
                    cursor.execute(sql.SQL('SET SESSION AUTHORIZATION {}').format(sql.Identifier(principal)))
                    cursor.execute('SELECT system_user,session_user,current_user')
                    self.assertEqual(cursor.fetchone(), ('scram-sha-256:fixture_admin', principal, principal))
                    with self.assertRaises(psycopg2.Error):
                        cursor.execute('SELECT frozen_recovery.' + operation + '(' +
                                       ','.join(['%s'] * len(arguments)) + ')', arguments)
        self.assert_frozen()

    def test_any_active_modern_lease_even_expired_blocks_recovery(self):
        prepared = self.ready()
        self.admin("INSERT INTO assignment_leases.proofs(binding_id,verifier,verifier_oid,binding_snapshot,observations,expires_at) "
                   "SELECT %s,'verifier',oid,'{}','{}',clock_timestamp()+interval '1 minute' "
                   "FROM pg_roles WHERE rolname='verifier' RETURNING proof_id", (self.binding,))
        proof_id = self.admin('SELECT proof_id FROM assignment_leases.proofs')[0][0]
        self.admin("INSERT INTO assignment_leases.leases(binding_id,workstation_id,principal,principal_oid,epoch,"
                   "host,directory_device,directory_inode,proof_id,binding_snapshot,state,started_at,expires_at,request_id) "
                   "SELECT %s,'A-ws','alice',oid,1,'fixture-host',1,2,%s,'{}','ACTIVE',"
                   "clock_timestamp()-interval '2 minutes',clock_timestamp()-interval '1 minute','legacy-active' "
                   "FROM pg_roles WHERE rolname='alice'", (self.binding, proof_id))
        with self.assertRaises(psycopg2.Error):
            self.execute(prepared)
        self.assert_frozen()


if __name__ == '__main__':
    unittest.main()
