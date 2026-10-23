"""Least-privilege installer and real lock behavior, disposable PG16/TLS/SCRAM only."""
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

import psycopg2
from psycopg2 import sql
import test_controller_coordinator as coordinator
from test_admission_installation import candidate_fixture
from test_admission_installation_postgres import fixture_authority

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
from codestra_control import admission_installation as module


class RestrictedInstallationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        coordinator.CoordinatorTests.setUpClass()
        with coordinator.CoordinatorTests.connect('fixture_admin') as c, c.cursor() as cur:
            for actor in ('narrow_installer', 'installation_reader'):
                cur.execute(sql.SQL('CREATE ROLE {} LOGIN PASSWORD %s').format(sql.Identifier(actor)),
                    ('synthetic-coordinator-' + actor,))
            cur.execute('CREATE ROLE installation_lock_owner NOLOGIN')
            cur.execute('GRANT narrow_installer,installation_reader TO installation_lock_owner WITH INHERIT TRUE, SET FALSE, ADMIN FALSE')

    @classmethod
    def tearDownClass(cls):
        coordinator.CoordinatorTests.tearDownClass()

    def connect(self, user='fixture_admin', sslmode='verify-full'):
        return psycopg2.connect(host='127.0.0.1', port=coordinator.CoordinatorTests.port,
            dbname=self.database, user=user, password='synthetic-coordinator-' + user,
            sslmode=sslmode, sslrootcert=str(coordinator.CoordinatorTests.path / 'fixture.crt'))

    def query(self, query, values=None, user='fixture_admin'):
        with closing(self.connect(user)) as c, c.cursor() as cur:
            cur.execute(query, values)
            result = cur.fetchall() if cur.description else None
            c.commit()
            return result

    def setUp(self):
        self.database = 'narrow_' + uuid.uuid4().hex
        with closing(coordinator.CoordinatorTests.connect('fixture_admin')) as c:
            c.autocommit = True
            with c.cursor() as cur:
                cur.execute(sql.SQL('CREATE DATABASE {} TEMPLATE template0').format(sql.Identifier(self.database)))
        with closing(self.connect()) as c, c.cursor() as cur:
            for name in ('schema.sql', '002-hierarchy-promotion.sql', '004-family-programs.sql'):
                cur.execute((ROOT / name).read_text())
            cur.execute('CREATE TABLE public.scope_certifications(product text,scope_type text,scope_name text,sha text,status text,PRIMARY KEY(product,scope_type,scope_name))')
            cur.execute("INSERT INTO public.products(product,repository) VALUES('preserved','fixture/preserved')")
            cur.execute(sql.SQL('GRANT CREATE ON DATABASE {} TO narrow_installer,installation_lock_owner').format(sql.Identifier(self.database)))
            cur.execute('GRANT USAGE ON SCHEMA public TO narrow_installer,installation_lock_owner')
            cur.execute('GRANT SELECT ON public.products,public.sections,public.workstations,public.atomic_tasks,public.scope_certifications TO narrow_installer')
            cur.execute('GRANT REFERENCES(product) ON public.products TO narrow_installer')
            cur.execute('GRANT REFERENCES(workstation_id) ON public.workstations TO narrow_installer')
            cur.execute('GRANT REFERENCES(task_id) ON public.atomic_tasks TO narrow_installer')
            # Separate existing runtime-owner rights; these column grants do NOT
            # confer the table-level privilege PostgreSQL requires for LOCK.
            cur.execute('GRANT INSERT(product,repository,test_branch,promotion_chain),UPDATE(product) ON public.products TO narrow_installer')
            cur.execute('GRANT INSERT(workstation_id,product,section,subsection,branch,parent_branch,worktree,order_index),UPDATE(agent,current_atomic_task,lease_state,lease_started_at,heartbeat_at,lease_expires_at) ON public.workstations TO narrow_installer')
            cur.execute('GRANT INSERT(task_id,workstation_id,title,owner),UPDATE(owner,title,status,updated_at) ON public.atomic_tasks TO narrow_installer')
            cur.execute('GRANT UPDATE ON ALL TABLES IN SCHEMA public TO installation_lock_owner')
            cur.execute('SET ROLE installation_lock_owner')
            cur.execute((ROOT / module.LOCK_SOURCE).read_text())
            cur.execute('RESET ROLE')
            cur.execute(sql.SQL('REVOKE CREATE ON DATABASE {} FROM installation_lock_owner').format(sql.Identifier(self.database)))
            cur.execute("""INSERT INTO admission_installation_lock.profile
              SELECT true,1,(pg_control_system()).system_identifier::text,d.oid,
              i.rolname,i.oid,v.rolname,v.oid,clock_timestamp()+interval '20 minutes',true,
              (SELECT jsonb_agg(jsonb_build_object('name',c.relname,'oid',c.oid::bigint,
                'namespace_oid',n.oid::bigint,'owner_oid',c.relowner::bigint,'kind',c.relkind) ORDER BY c.relname)
               FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r')
              FROM pg_database d,pg_roles i,pg_roles v WHERE d.datname=current_database()
              AND i.rolname='narrow_installer' AND v.rolname='installation_reader'""")
            cur.execute('GRANT USAGE ON SCHEMA admission_installation_lock TO narrow_installer,installation_reader')
            cur.execute('GRANT EXECUTE ON FUNCTION admission_installation_lock.describe() TO narrow_installer,installation_reader')
            cur.execute('GRANT EXECUTE ON FUNCTION admission_installation_lock.acquire(text) TO narrow_installer')
            cur.execute("SET timezone='UTC'")
            cur.execute("SELECT encode(sha256(convert_to(to_jsonb(p)::text,'UTF8')),'hex') FROM admission_installation_lock.profile p")
            self.selection = dict(profile_sha256=cur.fetchone()[0])
            c.commit()
        self.tmp = tempfile.TemporaryDirectory(prefix='cp-narrow-installer-')
        self.addCleanup(self.tmp.cleanup)
        path = Path(self.tmp.name)
        source = path / 'candidate'
        source.mkdir()
        self.candidate = module.SourceCandidate.load(source, candidate_fixture(source, administration=True))
        custody = path / 'custody'
        custody.mkdir(mode=0o700)
        self.store = module.FileCustody(custody, owner_uid=os.getuid())
        self.reader_connection = self.connect('installation_reader')
        self.addCleanup(self.reader_connection.close)
        self.reader = module.PostgresTarget(self.reader_connection, lock_selection=self.selection)
        self.connection = self.connect('narrow_installer')
        self.addCleanup(self.connection.close)
        self.backend = module.PostgresTarget(self.connection, lock_selection=self.selection, reader=self.reader)
        self.configuration = b'{"synthetic":"configuration"}\n'
        self.plan = self.make_plan()
        self.attempt = str(uuid.uuid4())
        self.authority = fixture_authority(module, self.plan, self.attempt)

    def make_plan(self):
        return module.build_plan(self.candidate, self.backend.restricted_observation(self.candidate),
            adopted_sources=['schema.sql', '002-hierarchy-promotion.sql'], filesystem_binding=self.store.binding,
            configuration_sha256=hashlib.sha256(self.configuration).hexdigest(), migration_profile=module.RESTRICTED_PROFILE)

    def install(self, **kwargs):
        return module.install(self.backend, self.candidate, self.plan, self.store,
            self.configuration, self.attempt, self.authority, **kwargs)

    def test_install_and_verify_without_blanket_writes_or_default_reads(self):
        self.assertEqual(self.query("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' AND has_table_privilege('narrow_installer',c.oid,'UPDATE,DELETE,TRUNCATE')"), [(0,)])
        for query in ('UPDATE public.events SET actor=actor', 'LOCK TABLE public.events IN ACCESS EXCLUSIVE MODE'):
            with self.assertRaises(psycopg2.errors.InsufficientPrivilege):
                self.query(query, user='narrow_installer')
        self.assertEqual(self.install()['state'], 'DATABASE_APPLIED_ARTIFACTS_STAGED')
        result = module.verify(self.reader, self.candidate, self.plan, self.store, self.attempt, self.authority)
        self.assertEqual(result['state'], 'INDEPENDENTLY_OBSERVED')
        self.assertFalse(result['usable'])
        self.assertEqual(self.query('SELECT product,repository FROM public.products'), [('preserved', 'fixture/preserved')])
        self.assertEqual(self.query('SELECT count(*) FROM pg_default_acl'), [(0,)])
        self.assertEqual(self.query("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='admission_installation' AND has_table_privilege('installation_reader',c.oid,'SELECT') ORDER BY 1"), [('attempts',), ('migrations',)])
        for query in ('SELECT * FROM admission_installation.events', 'SELECT * FROM public.products',
                      'SELECT * FROM scoped_registration.grants', 'SELECT * FROM task_bootstrap.profiles',
                      'SELECT task_bootstrap._actor()', 'UPDATE admission_installation.attempts SET stage=stage'):
            with self.assertRaises(psycopg2.errors.InsufficientPrivilege):
                self.query(query, user='installation_reader')
        self.query('CREATE TABLE public.future_private(value text)')
        with self.assertRaises(psycopg2.errors.InsufficientPrivilege):
            self.query('SELECT * FROM public.future_private', user='installation_reader')

    def test_broker_locks_persist_until_outer_commit_and_block_writer(self):
        with self.connection.cursor() as cur:
            cur.execute('SELECT admission_installation_lock.acquire(%s)', (self.selection['profile_sha256'],))
            cur.execute("SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation JOIN pg_namespace n ON n.oid=c.relnamespace WHERE l.pid=pg_backend_pid() AND l.mode='AccessExclusiveLock' AND l.granted AND n.nspname='public'")
            self.assertEqual(cur.fetchone()[0], 11)
        with closing(self.connect()) as writer:
            with writer.cursor() as cur:
                cur.execute("SET lock_timeout='150ms'")
                with self.assertRaises(psycopg2.errors.LockNotAvailable):
                    cur.execute('UPDATE public.products SET repository=repository')
            writer.rollback()
        self.connection.commit()
        self.query('UPDATE public.products SET repository=repository')

    def test_profile_row_drift_is_rejected_even_without_catalog_change(self):
        before = self.backend.describe()['catalog_sha256']
        self.query('UPDATE admission_installation_lock.profile SET revision=revision+1')
        self.assertEqual(self.backend.describe()['catalog_sha256'], before)
        with self.assertRaisesRegex(ValueError, 'LOCK_PROFILE_CHANGED'):
            self.install()
        self.assertEqual(self.query("SELECT to_regnamespace('admission_installation')"), [(None,)])

    def test_extra_legacy_table_is_denied_by_broker(self):
        self.query('CREATE TABLE public.unreviewed(value text)')
        with self.assertRaisesRegex(psycopg2.Error, 'LOCK_RELATION_VECTOR_CHANGED'):
            self.query('SELECT admission_installation_lock.acquire(%s)', (self.selection['profile_sha256'],), user='narrow_installer')

    def test_inherited_child_outside_public_is_denied(self):
        self.query('CREATE SCHEMA unreviewed; CREATE TABLE unreviewed.child() INHERITS(public.scope_certifications)')
        with self.assertRaisesRegex(psycopg2.Error, 'LOCK_RELATION_VECTOR_CHANGED'):
            self.query('SELECT admission_installation_lock.acquire(%s)', (self.selection['profile_sha256'],), user='narrow_installer')

    def test_trust_socket_and_explicit_set_role_are_denied(self):
        with closing(psycopg2.connect(host=str(coordinator.CoordinatorTests.path),
                port=coordinator.CoordinatorTests.port, dbname=self.database, user='narrow_installer')) as c, c.cursor() as cur:
            with self.assertRaisesRegex(psycopg2.Error, 'LOCK_AUTHENTICATION_REQUIRED'):
                cur.execute('SELECT admission_installation_lock.describe()')
        with self.assertRaisesRegex(psycopg2.Error, 'LOCK_AUTHENTICATION_REQUIRED'):
            self.query('SET ROLE narrow_installer; SELECT admission_installation_lock.describe()', user='narrow_installer')

    def test_changed_broker_code_is_rejected_before_execution(self):
        self.query("CREATE OR REPLACE FUNCTION admission_installation_lock.describe() RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$ BEGIN RAISE EXCEPTION 'UNACCEPTED_CODE_EXECUTED'; END $$")
        with self.assertRaisesRegex(ValueError, 'LOCK_BROKER_CONTRACT_CHANGED'):
            self.make_plan()

    def test_disabled_profile_guard_is_denied_before_initial_planning(self):
        self.query('ALTER TABLE admission_installation_lock.profile DISABLE TRIGGER profile_revision')
        with self.assertRaisesRegex(ValueError, 'LOCK_PROFILE_GUARDS_CHANGED'):
            self.make_plan()
        with self.assertRaisesRegex(psycopg2.Error, 'LOCK_AUTHENTICATION_REQUIRED'):
            self.query('SELECT admission_installation_lock.acquire(%s)', (self.selection['profile_sha256'],), user='narrow_installer')

    def test_immutable_broker_function_is_denied_before_execution(self):
        self.query('ALTER FUNCTION admission_installation_lock.describe() IMMUTABLE')
        with self.assertRaisesRegex(ValueError, 'LOCK_BROKER_CONTRACT_CHANGED'):
            self.make_plan()
        with self.assertRaisesRegex(psycopg2.Error, 'LOCK_AUTHENTICATION_REQUIRED'):
            self.query('SELECT admission_installation_lock.acquire(%s)', (self.selection['profile_sha256'],), user='narrow_installer')

    def test_direct_rpc_validates_before_reading_unaccepted_policy(self):
        self.query("""CREATE SCHEMA unreviewed;
          CREATE FUNCTION unreviewed.policy() RETURNS boolean LANGUAGE plpgsql AS $$
          BEGIN RAISE EXCEPTION 'UNREVIEWED_POLICY_EXECUTED'; END $$;
          GRANT USAGE ON SCHEMA unreviewed TO installation_lock_owner;
          ALTER TABLE admission_installation_lock.profile ENABLE ROW LEVEL SECURITY;
          ALTER TABLE admission_installation_lock.profile FORCE ROW LEVEL SECURITY;
          CREATE POLICY unaccepted ON admission_installation_lock.profile USING(unreviewed.policy())""")
        with self.assertRaisesRegex(psycopg2.Error, 'LOCK_AUTHENTICATION_REQUIRED'):
            self.query('SELECT admission_installation_lock.acquire(%s)', (self.selection['profile_sha256'],), user='narrow_installer')

    def test_direct_profile_locks_do_not_require_broker_profile_privileges(self):
        # Historical direct operators may still have their accepted legacy
        # table-lock grants. Coexisting broker custody does not expand those.
        self.query('GRANT UPDATE ON ALL TABLES IN SCHEMA public TO narrow_installer')
        with self.backend.transaction() as cur:
            module._lock_tables(cur)
            cur.execute("SELECT count(*) FROM pg_locks WHERE pid=pg_backend_pid() AND relation='admission_installation_lock.profile'::regclass AND mode='AccessExclusiveLock'")
            self.assertEqual(cur.fetchone()[0], 0)

    def test_same_name_replacement_is_denied(self):
        self.query('DROP TABLE public.scope_certifications; CREATE TABLE public.scope_certifications(LIKE public.products)')
        with self.assertRaisesRegex(psycopg2.Error, 'LOCK_RELATION_VECTOR_CHANGED'):
            self.query('SELECT admission_installation_lock.acquire(%s)', (self.selection['profile_sha256'],), user='narrow_installer')

    def test_verifier_cannot_acquire_or_read_profile(self):
        for query in ('SELECT admission_installation_lock.acquire(%s)', 'SELECT * FROM admission_installation_lock.profile WHERE %s IS NOT NULL'):
            with self.assertRaises(psycopg2.errors.InsufficientPrivilege):
                self.query(query, (self.selection['profile_sha256'],), user='installation_reader')

    def test_interrupted_intent_resumes_without_acl_churn(self):
        def stop(phase):
            if phase == 'after_intent_commit':
                raise RuntimeError('synthetic interruption')
        with self.assertRaisesRegex(RuntimeError, 'synthetic interruption'):
            self.install(progress=stop)
        before = self.backend.describe()['ledger_catalog_sha256']
        self.install()
        self.assertEqual(self.backend.describe()['ledger_catalog_sha256'], before)
        self.assertEqual(module.verify(self.reader, self.candidate, self.plan, self.store,
            self.attempt, self.authority)['state'], 'INDEPENDENTLY_OBSERVED')

    def test_precommit_failure_rolls_back_schema_and_reader_grants(self):
        def stop(phase):
            if phase == 'before_intent_commit':
                raise RuntimeError('synthetic interruption')
        with self.assertRaisesRegex(RuntimeError, 'synthetic interruption'):
            self.install(progress=stop)
        self.assertEqual(self.query("SELECT to_regnamespace('admission_installation')"), [(None,)])
        self.install()

    def test_broker_loss_does_not_prevent_issuer_revocation(self):
        self.install()
        self.query('DROP SCHEMA admission_installation_lock CASCADE')
        with self.assertRaises(module.InstallationRevokedRecordingFailed):
            module.rollback(self.backend, self.candidate, self.plan, self.store, self.attempt, self.authority)
        self.assertTrue(self.authority.revoked)

    def test_profile_column_write_is_denied_in_client_and_direct_rpc(self):
        self.query('GRANT UPDATE(valid_until) ON admission_installation_lock.profile TO narrow_installer')
        with self.assertRaisesRegex(ValueError, 'LOCK_BROKER_PROFILE_NOT_PROTECTED'):
            self.make_plan()
        with self.assertRaisesRegex(psycopg2.Error, 'LOCK_AUTHENTICATION_REQUIRED'):
            self.query('SELECT admission_installation_lock.acquire(%s)', (self.selection['profile_sha256'],), user='narrow_installer')

    def test_noninherited_profile_column_writer_is_denied(self):
        role = 'profile_writer_' + uuid.uuid4().hex
        self.query(sql.SQL('CREATE ROLE {}; GRANT UPDATE(active) ON admission_installation_lock.profile TO {}; GRANT {} TO narrow_installer WITH INHERIT FALSE').format(*[sql.Identifier(role)] * 3))
        self.addCleanup(self.query, sql.SQL('REVOKE {} FROM narrow_installer').format(sql.Identifier(role)))
        with self.assertRaisesRegex(ValueError, 'LOCK_BROKER_PROFILE_NOT_PROTECTED'):
            self.make_plan()

    def test_noninherited_legacy_blanket_writer_is_denied(self):
        role = 'legacy_writer_' + uuid.uuid4().hex
        self.query(sql.SQL('CREATE ROLE {}; GRANT UPDATE ON public.events TO {}; GRANT {} TO narrow_installer WITH INHERIT FALSE').format(*[sql.Identifier(role)] * 3))
        self.addCleanup(self.query, sql.SQL('REVOKE {} FROM narrow_installer').format(sql.Identifier(role)))
        with self.assertRaisesRegex(psycopg2.Error, 'LOCK_RELATION_VECTOR_CHANGED'):
            self.make_plan()

    def test_noninherited_reader_and_rpc_capabilities_are_denied(self):
        for privilege in ('SELECT ON public.products', 'EXECUTE ON FUNCTION admission_installation_lock.acquire(text)'):
            role = 'broad_reader_' + uuid.uuid4().hex
            self.query(sql.SQL('CREATE ROLE {}; GRANT ' + privilege + ' TO {}; GRANT {} TO installation_reader WITH INHERIT FALSE').format(*[sql.Identifier(role)] * 3))
            try:
                with self.assertRaisesRegex(ValueError, 'EXACT_INSTALLATION_READER_REQUIRED'):
                    self.make_plan()
            finally:
                self.query(sql.SQL('REVOKE {} FROM installation_reader').format(sql.Identifier(role)))

    def test_withdraw_and_reenable_never_restores_accepted_profile_hash(self):
        self.query('UPDATE admission_installation_lock.profile SET active=false; UPDATE admission_installation_lock.profile SET active=true')
        with self.assertRaisesRegex(ValueError, 'LOCK_PROFILE_CHANGED'):
            self.install()
        self.assertEqual(self.query('SELECT revision FROM admission_installation_lock.profile'), [(3,)])
        for statement in ('DELETE FROM admission_installation_lock.profile', 'TRUNCATE admission_installation_lock.profile'):
            with self.assertRaisesRegex(psycopg2.Error, 'LOCK_PROFILE_HISTORY_REQUIRED'):
                self.query(statement)
        with self.assertRaises(psycopg2.errors.CheckViolation):
            self.query("UPDATE admission_installation_lock.profile SET valid_until='infinity'")

    def test_reader_default_grant_is_rejected_before_intent(self):
        self.query('ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO installation_reader')
        with self.assertRaisesRegex(ValueError, 'EXACT_INSTALLATION_READER_REQUIRED'):
            self.make_plan()
        self.assertEqual(self.query("SELECT to_regnamespace('admission_installation')"), [(None,)])

    def test_reader_missing_broker_prerequisite_is_rejected_before_intent(self):
        for revoke, grant in (
            ('REVOKE USAGE ON SCHEMA admission_installation_lock FROM installation_reader',
             'GRANT USAGE ON SCHEMA admission_installation_lock TO installation_reader'),
            ('REVOKE EXECUTE ON FUNCTION admission_installation_lock.describe() FROM installation_reader',
             'GRANT EXECUTE ON FUNCTION admission_installation_lock.describe() TO installation_reader')):
            self.query(revoke)
            try:
                with self.assertRaises(psycopg2.errors.InsufficientPrivilege):
                    self.make_plan()
                self.assertEqual(self.query("SELECT to_regnamespace('admission_installation')"), [(None,)])
            finally:
                self.query(grant)

    def test_callers_cannot_attain_broker_owner(self):
        for actor in ('narrow_installer', 'installation_reader'):
            self.assertEqual(self.query("SELECT pg_has_role(session_user,'installation_lock_owner','MEMBER')", user=actor), [(False,)])
            with self.assertRaises(psycopg2.errors.InsufficientPrivilege):
                self.query('SET ROLE installation_lock_owner', user=actor)

    def test_reader_cannot_create_in_an_unrelated_schema(self):
        self.query('CREATE SCHEMA unreviewed; GRANT CREATE ON SCHEMA unreviewed TO installation_reader')
        with self.assertRaisesRegex(ValueError, 'INDEPENDENT_RESTRICTED_VERIFIER_REQUIRED'):
            self.make_plan()

    def test_verification_rechecks_profile_withdrawal_after_install(self):
        self.install()
        self.query('UPDATE admission_installation_lock.profile SET active=false')
        with self.assertRaisesRegex(psycopg2.Error, 'LOCK_PROFILE_DENIED'):
            module.verify(self.reader, self.candidate, self.plan, self.store, self.attempt, self.authority)

    def test_existing_ledger_requires_explicit_forward_adoption(self):
        self.install()
        with self.assertRaisesRegex(ValueError, 'EXISTING_LEDGER_REQUIRES_FORWARD_ADOPTION'):
            self.make_plan()

    def test_real_separate_issuer_rejects_wrong_verifier_before_intent(self):
        from test_installation_authority_postgres import ProductionIssuerFixture
        issuer = ProductionIssuerFixture(Path(self.tmp.name) / 'issuer',
            coordinator.CoordinatorTests.path / 'fixture.crt', coordinator.CoordinatorTests.path / 'fixture.key')
        self.addCleanup(issuer.close)
        binding = module._context(self.candidate, self.plan, self.store, self.attempt)[1]
        connection, selection, _ = issuer.create_grant(binding, self.plan.value['installation_reader']['role_oid'] + 1)
        authority = module.OnlinePostgresAuthority(connection, selection)
        with self.assertRaises((ValueError, psycopg2.Error)):
            module.install(self.backend, self.candidate, self.plan, self.store, self.configuration, self.attempt, authority)
        self.assertEqual(self.query("SELECT to_regnamespace('admission_installation')"), [(None,)])

    def test_real_separate_issuer_install_verify_and_revoke(self):
        from test_installation_authority_postgres import ProductionIssuerFixture
        issuer = ProductionIssuerFixture(Path(self.tmp.name) / 'issuer',
            coordinator.CoordinatorTests.path / 'fixture.crt', coordinator.CoordinatorTests.path / 'fixture.key')
        self.addCleanup(issuer.close)
        binding = module._context(self.candidate, self.plan, self.store, self.attempt)[1]
        connection, selection, _ = issuer.create_grant(binding, self.plan.value['installation_reader']['role_oid'])
        authority = module.OnlinePostgresAuthority(connection, selection)
        module.install(self.backend, self.candidate, self.plan, self.store, self.configuration, self.attempt, authority)
        self.assertEqual(module.verify(self.reader, self.candidate, self.plan, self.store, self.attempt, authority)['state'], 'INDEPENDENTLY_OBSERVED')
        self.assertEqual(module.rollback(self.backend, self.candidate, self.plan, self.store, self.attempt, authority)['state'], 'REVOKED')
