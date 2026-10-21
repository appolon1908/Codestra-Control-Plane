"""Installer upgrade/crash tests in an isolated PostgreSQL16/TLS/SCRAM fixture."""
from contextlib import closing, redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import socket
import subprocess
import unittest
from unittest.mock import patch
import uuid

import psycopg2
from psycopg2 import sql
from psycopg2.extras import Json

import test_assignment_leases as leases
import test_controller_coordinator as coordinator
import test_scoped_registration as registration
from test_admission_installation import candidate_fixture
import test_admission_installation as filesystem_tests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
LEGACY = ('schema.sql', '002-hierarchy-promotion.sql', '005-scoped-registration.sql',
          '007-assignment-leases.sql', '009-controller-coordinator.sql')


def fixture_authority(module, plan, attempt):
    """Trusted fixture service; a caller request cannot change its accepted record."""
    class FixtureAuthority(module.Authority):
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        revoked = False

        def authorize(self, operation, binding, phase):
            if (binding['plan_sha256'] != plan.digest or binding['attempt_id'] != attempt
                    or self.expires <= datetime.now(timezone.utc)
                    or self.revoked and operation != 'rollback'):
                raise ValueError('INSTALLATION_AUTHORITY_DENIED')

        def revoke(self, binding):
            self.authorize('rollback', binding, 'revoke')
            self.revoked = True

    return FixtureAuthority()


class InstallationPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = None
        cls.started = False
        try:
            cls.module = importlib.import_module('codestra_control.admission_installation')
        except ImportError:
            return
        coordinator.CoordinatorTests.setUpClass()
        cls.started = True

    @classmethod
    def tearDownClass(cls):
        if cls.started:
            coordinator.CoordinatorTests.tearDownClass()

    def connect(self, user='fixture_admin'):
        # Explicit isolated fixture endpoint; no installed or environment DSNs.
        return psycopg2.connect(host='127.0.0.1', port=coordinator.CoordinatorTests.port,
            dbname=self.database, user=user, password='synthetic-coordinator-' + user,
            sslmode='verify-full', sslrootcert=str(coordinator.CoordinatorTests.path / 'fixture.crt'))

    def setUp(self):
        if self.module is None:
            self.fail('Transactional admission installer is missing')
        self.database = 'installer_' + uuid.uuid4().hex
        with closing(coordinator.CoordinatorTests.connect('fixture_admin')) as c:
            c.autocommit = True
            with c.cursor() as cur:
                cur.execute(sql.SQL('CREATE DATABASE {} TEMPLATE template0').format(sql.Identifier(self.database)))
        with closing(self.connect()) as c, c.cursor() as cur:
            for name in LEGACY:
                cur.execute((ROOT / name).read_text())
            cur.execute('CREATE TABLE public.scope_certifications(product text,scope_type text,scope_name text,sha text,status text,PRIMARY KEY(product,scope_type,scope_name))')
            cur.execute('GRANT USAGE ON SCHEMA scoped_registration TO registration_runtime')
            cur.execute('GRANT EXECUTE ON FUNCTION scoped_registration.register(text,jsonb,text,text) TO registration_runtime')
            # Fixture-only, independently provisioned future read-only access.
            # The installer itself never creates roles or issues grants.
            cur.execute('ALTER DEFAULT PRIVILEGES GRANT USAGE ON SCHEMAS TO verifier')
            cur.execute('ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO verifier')
            c.commit()
        fixture = leases.AssignmentLeaseTests('test_real_authenticated_claim_and_online_owned_check')
        fixture.connect = self.connect
        fixture.setUp()
        self.legacy_binding = fixture.binding
        self.tmp = tempfile.TemporaryDirectory(prefix='cp-installer-postgres-')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        source = self.path / 'candidate'
        source.mkdir()
        self.candidate = self.module.SourceCandidate.load(source, candidate_fixture(source))
        custody = self.path / 'custody'
        custody.mkdir(mode=0o700)
        self.store = self.module.FileCustody(custody, owner_uid=os.getuid())
        self.connection = self.connect()
        self.addCleanup(self.connection.close)
        self.backend = self.module.PostgresTarget(self.connection)
        self.configuration = b'{"fixture_secret":"do-not-emit-this-fixture-value"}\n'
        self.plan = self.module.build_plan(self.candidate, self.backend.describe(),
            adopted_sources=LEGACY, filesystem_binding=self.store.binding,
            configuration_sha256=hashlib.sha256(self.configuration).hexdigest())
        self.attempt = str(uuid.uuid4())
        self.authority = fixture_authority(self.module, self.plan, self.attempt)

    def query(self, query, values=None):
        with closing(self.connect()) as c, c.cursor() as cur:
            cur.execute(query, values)
            result = cur.fetchall() if cur.description else None
            c.commit()
            return result

    def install(self, **kwargs):
        return self.module.install(self.backend, self.candidate, self.plan, self.store,
            self.configuration, self.attempt, self.authority, **kwargs)

    def preserved(self):
        tables = ('public.products', 'public.workstations', 'public.atomic_tasks',
                  'scoped_registration.audit', 'scoped_registration.grants',
                  'scoped_registration.task_assignments', 'assignment_leases.bindings',
                  'assignment_leases.permissions', 'assignment_leases.audit')
        return {name: self.query('SELECT row_to_json(t)::text FROM ' + name + ' t ORDER BY 1') for name in tables}

    def test_upgrade_preserves_existing_data_assignments_audit_and_grants(self):
        before = self.preserved()
        acl = self.query("SELECT proacl::text FROM pg_proc WHERE oid='scoped_registration.register(text,jsonb,text,text)'::regprocedure")
        receipt = self.install()
        self.assertEqual(self.preserved(), before)
        self.assertEqual(self.query("SELECT proacl::text FROM pg_proc WHERE oid='scoped_registration.register(text,jsonb,text,text)'::regprocedure"), acl)
        self.assertEqual(receipt['state'], 'DATABASE_APPLIED_ARTIFACTS_STAGED')
        self.assertFalse(receipt['usable'])
        self.assertFalse(receipt['certified'])
        self.assertNotIn('do-not-emit-this-fixture-value', json.dumps(receipt))
        self.assertEqual(self.query('SELECT disposition,count(*) FROM admission_installation.migrations GROUP BY disposition ORDER BY disposition'),
                         [('ADOPTED', 5), ('APPLIED', len(self.module.MIGRATIONS) - 5)])
        self.assertEqual(self.query("SELECT to_regnamespace('atomic_receipts'),to_regnamespace('certifier_authority'),to_regnamespace('frozen_recovery')"), [(None, None, None)])
        self.assertEqual(set(self.plan.value['sources']), set(self.module.MIGRATIONS))

    def test_explicit_task_bootstrap_profile_installs_no_authority_and_preserves_legacy_rows(self):
        before = self.preserved()
        self.assertNotIn('016-authenticated-task-bootstrap.sql', self.plan.value['sources'])
        self.plan = self.module.build_plan(self.candidate, self.backend.describe(),
            adopted_sources=LEGACY, filesystem_binding=self.store.binding,
            configuration_sha256=hashlib.sha256(self.configuration).hexdigest(),
            migration_profile='task-bootstrap-v1')
        self.authority = fixture_authority(self.module, self.plan, self.attempt)
        self.assertEqual(self.plan.value['migration_profile'], 'task-bootstrap-v1')
        self.assertIn('016-authenticated-task-bootstrap.sql', self.plan.value['pending_sources'])
        result = self.install()
        self.assertEqual(result['state'], 'DATABASE_APPLIED_ARTIFACTS_STAGED')
        self.assertFalse(result['usable'])
        self.assertEqual(self.preserved(), before)
        self.assertEqual(self.query('SELECT count(*) FROM task_bootstrap.profiles'), [(0,)])
        self.assertEqual(self.query('SELECT count(*) FROM task_bootstrap.sessions'), [(0,)])
        self.assertEqual(self.query('SELECT count(*) FROM task_bootstrap.issued'), [(0,)])
        self.assertEqual(self.install(), result)
        verifier = self.verifier()
        events = self.query('SELECT * FROM admission_installation.events ORDER BY event_id')
        observed = self.module.verify(verifier, self.candidate, self.plan, self.store,
                                      self.attempt, self.authority)
        self.assertEqual(observed['state'], 'INDEPENDENTLY_OBSERVED')
        self.assertFalse(observed['usable'])
        self.assertEqual(self.query('SELECT * FROM admission_installation.events ORDER BY event_id'), events)
        def interrupted(phase):
            if phase == 'after_revocation':
                raise RuntimeError('synthetic revoke-first interruption')
        with self.assertRaises(self.module.InstallationRevokedRecordingFailed):
            self.module.rollback(self.backend, self.candidate, self.plan, self.store,
                                 self.attempt, self.authority, progress=interrupted)
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(self.module.rollback(self.backend, self.candidate, self.plan, self.store,
            self.attempt, self.authority)['state'], 'REVOKED')
        self.assertEqual(self.preserved(), before)

    def test_task_bootstrap_trigger_drift_denies_retry_and_independent_verification(self):
        self.plan = self.module.build_plan(self.candidate, self.backend.describe(),
            adopted_sources=LEGACY, filesystem_binding=self.store.binding,
            configuration_sha256=hashlib.sha256(self.configuration).hexdigest(),
            migration_profile='task-bootstrap-v1')
        self.authority = fixture_authority(self.module, self.plan, self.attempt)
        self.install()
        verifier = self.verifier()
        self.assertEqual(self.module.verify(verifier, self.candidate, self.plan, self.store,
            self.attempt, self.authority)['state'], 'INDEPENDENTLY_OBSERVED')
        catalog_before = self.backend.describe()['catalog_sha256']
        guards = self.query("SELECT t.tgname FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid "
            "JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='task_bootstrap' "
            "AND t.tgrelid='assignment_leases.leases'::regclass AND NOT t.tgisinternal ORDER BY t.tgname")
        self.assertTrue(guards, 'No bootstrap guard protects legacy lease issuance')
        self.query(sql.SQL('ALTER TABLE assignment_leases.leases DISABLE TRIGGER {}').format(sql.Identifier(guards[0][0])))
        self.assertNotEqual(self.backend.describe()['catalog_sha256'], catalog_before)
        with self.assertRaisesRegex(ValueError, 'CATALOG'):
            self.install()
        with self.assertRaisesRegex(ValueError, '^INSTALLATION_NOT_INDEPENDENTLY_VERIFIABLE$'):
            self.module.verify(verifier, self.candidate, self.plan, self.store, self.attempt, self.authority)

    def test_untracked_task_bootstrap_schema_cannot_be_adopted_by_name_only(self):
        self.query('CREATE SCHEMA task_bootstrap')
        with self.assertRaisesRegex(ValueError, 'INVALID_LEGACY_ADOPTION'):
            self.module.build_plan(self.candidate, self.backend.describe(),
                adopted_sources=LEGACY + ('016-authenticated-task-bootstrap.sql',),
                filesystem_binding=self.store.binding, configuration_sha256='a' * 64,
                migration_profile='task-bootstrap-v1')
        self.assertEqual(self.query("SELECT to_regnamespace('admission_installation')"), [(None,)])

    def test_profile_substitution_cannot_expand_an_existing_plan(self):
        value = self.plan.value
        value['migration_profile'] = 'task-bootstrap-v1'
        self.plan = self.module.InstallationPlan(self.module.canonical(value))
        self.authority = fixture_authority(self.module, self.plan, self.attempt)
        with self.assertRaisesRegex(ValueError, 'BINDING_CONFLICT'):
            self.install()
        self.assertEqual(self.query("SELECT to_regnamespace('admission_installation'),to_regnamespace('task_bootstrap')"),
                         [(None, None)])

    def test_exact_retry_is_idempotent_and_does_not_replay_ddl(self):
        first = self.install()
        history = self.query('SELECT * FROM admission_installation.events ORDER BY event_id')
        self.assertEqual(self.install(), first)
        self.assertEqual(self.query('SELECT * FROM admission_installation.events ORDER BY event_id'), history)

    def test_missing_legacy_column_or_primary_key_fails_before_ledger_creation(self):
        self.query('ALTER TABLE public.scope_certifications DROP CONSTRAINT scope_certifications_pkey')
        with self.assertRaisesRegex(ValueError, 'LEGACY'):
            self.module.build_plan(self.candidate, self.backend.describe(), adopted_sources=LEGACY,
                filesystem_binding=self.store.binding, configuration_sha256='a' * 64)
        self.assertEqual(self.query("SELECT to_regnamespace('admission_installation')"), [(None,)])

    def test_untracked_existing_component_requires_explicit_accepted_adoption(self):
        self.query((ROOT / '009-atomic-inspection.sql').read_text())
        with self.assertRaisesRegex(ValueError, 'UNTRACKED'):
            self.module.build_plan(self.candidate, self.backend.describe(), adopted_sources=LEGACY,
                filesystem_binding=self.store.binding, configuration_sha256='a' * 64)

    def test_unrelated_existing_components_are_preserved_without_automatic_expansion(self):
        self.query((ROOT / '006-publisher-authority-read-model.sql').read_text())
        self.plan = self.module.build_plan(self.candidate, self.backend.describe(), adopted_sources=LEGACY,
            filesystem_binding=self.store.binding, configuration_sha256=hashlib.sha256(self.configuration).hexdigest())
        self.authority = fixture_authority(self.module, self.plan, self.attempt)
        self.query("INSERT INTO publisher_authority.bindings VALUES(repeat('a',64),'legacy',123,false,clock_timestamp()+interval '1 day','{}','{}','{}',1,1,1)")
        before = self.query("SELECT to_jsonb(p) FROM publisher_authority.bindings p")
        acl = self.query("SELECT relacl::text,relowner FROM pg_class WHERE oid='publisher_authority.bindings'::regclass")
        self.install()
        self.assertNotIn('006-publisher-authority-read-model.sql', self.plan.value['sources'])
        self.assertEqual(self.query("SELECT to_regnamespace('frozen_recovery'),to_regnamespace('certifier_authority')"), [(None, None)])
        after = self.query("SELECT to_jsonb(p) FROM publisher_authority.bindings p")
        self.assertEqual(after, before)
        self.assertEqual(self.query("SELECT relacl::text,relowner FROM pg_class WHERE oid='publisher_authority.bindings'::regclass"), acl)

    def test_changed_catalog_after_plan_cannot_be_installed(self):
        self.query('ALTER TABLE public.products ADD COLUMN unaccepted_drift text')
        with self.assertRaisesRegex(ValueError, 'CATALOG'):
            self.install()
        self.assertEqual(self.query("SELECT to_regnamespace('admission_installation')"), [(None,)])

    def test_expired_revoked_or_forged_authority_cannot_create_state(self):
        for mutation in ('expired', 'revoked', 'forged'):
            self.authority = fixture_authority(self.module, self.plan, self.attempt)
            if mutation == 'expired':
                self.authority.expires = datetime.now(timezone.utc) - timedelta(seconds=1)
            elif mutation == 'revoked':
                self.authority.revoked = True
            else:
                self.authority = {'approved': True, 'owner': 'fixture_admin'}
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.install()
            self.assertEqual(self.query("SELECT to_regnamespace('admission_installation')"), [(None,)])

    def test_preledger_fence_excludes_a_competing_connection(self):
        with self.backend.fence():
            with closing(self.connect()) as connection:
                competitor = self.module.PostgresTarget(connection)
                with self.assertRaisesRegex(ValueError, 'BUSY'):
                    with competitor.fence():
                        self.fail('competing installer acquired pre-ledger fence')
        self.assertEqual(self.query("SELECT to_regnamespace('admission_installation')"), [(None,)])

    def test_interruption_after_database_commit_resumes_without_schema_replay(self):
        def interrupted(phase):
            if phase == 'after_database_commit':
                raise RuntimeError('synthetic interruption')
        with self.assertRaises(RuntimeError):
            self.install(progress=interrupted)
        self.assertEqual(self.query('SELECT stage FROM admission_installation.attempts'), [('DATABASE_APPLIED',)])
        before = self.preserved()
        self.assertEqual(self.install()['state'], 'DATABASE_APPLIED_ARTIFACTS_STAGED')
        self.assertEqual(self.preserved(), before)

    def test_filesystem_and_config_boundaries_resume_exact_durable_artifacts(self):
        for wanted in ('after_files_install', 'after_configuration_install', 'after_receipt_install'):
            def interrupted(phase):
                if phase == wanted:
                    raise RuntimeError('synthetic interruption')
            # Stop a different future boundary on each exact retry.
            with self.subTest(boundary=wanted), self.assertRaises(RuntimeError):
                self.install(progress=interrupted)
        self.assertEqual(self.install()['state'], 'DATABASE_APPLIED_ARTIFACTS_STAGED')

    def test_transaction_failure_does_not_leave_partial_forward_schema(self):
        def interrupted(phase):
            if phase == 'before_database_commit':
                raise RuntimeError('synthetic interruption')
        with self.assertRaises(RuntimeError):
            self.install(progress=interrupted)
        self.assertEqual(self.query("SELECT to_regnamespace('scoped_admission')"), [(None,)])
        self.assertEqual(self.query('SELECT stage FROM admission_installation.attempts'), [('INTENT',)])
        self.assertEqual(self.install()['state'], 'DATABASE_APPLIED_ARTIFACTS_STAGED')

    def test_checksum_drift_blocks_idempotent_retry(self):
        self.install()
        with self.assertRaises(psycopg2.Error):
            self.query("UPDATE admission_installation.migrations SET sha256=repeat('f',64) WHERE source_path='005-scoped-registration.sql'")
        self.assertEqual(self.install()['state'], 'DATABASE_APPLIED_ARTIFACTS_STAGED')

    def test_disabled_ledger_enforcement_is_detected_on_retry_and_verification(self):
        self.install()
        verifier = self.verifier()
        self.query('ALTER TABLE admission_installation.migrations DISABLE TRIGGER immutable_versions')
        with self.assertRaisesRegex(ValueError, 'LEDGER_CATALOG'):
            self.install()
        with self.assertRaisesRegex(ValueError, 'VERIFIABLE'):
            self.module.verify(verifier, self.candidate, self.plan, self.store, self.attempt, self.authority)

    def test_immutable_history_cannot_be_truncated(self):
        self.install()
        before = self.query('SELECT * FROM admission_installation.events ORDER BY event_id')
        for table in ('events', 'migrations', 'attempts'):
            with self.subTest(table=table), self.assertRaises(psycopg2.Error):
                self.query('TRUNCATE admission_installation.' + table + ' CASCADE')
        self.assertEqual(self.query('SELECT * FROM admission_installation.events ORDER BY event_id'), before)

    def test_changed_existing_ledger_after_planning_cannot_start_another_attempt(self):
        self.install()
        self.module.rollback(self.backend, self.candidate, self.plan, self.store, self.attempt, self.authority)
        self.plan = self.module.build_plan(self.candidate, self.backend.describe(), adopted_sources=LEGACY,
            filesystem_binding=self.store.binding, configuration_sha256=hashlib.sha256(self.configuration).hexdigest())
        self.attempt = str(uuid.uuid4())
        self.authority = fixture_authority(self.module, self.plan, self.attempt)
        before = self.query('SELECT attempt_id,stage FROM admission_installation.attempts ORDER BY attempt_id')
        self.query('ALTER TABLE admission_installation.events DISABLE TRIGGER immutable_events')
        with self.assertRaisesRegex(ValueError, 'LEDGER|CATALOG'):
            self.install()
        self.assertEqual(self.query('SELECT attempt_id,stage FROM admission_installation.attempts ORDER BY attempt_id'), before)

    def test_independent_verification_is_readonly_and_cannot_reuse_installer_identity(self):
        self.install()
        before = self.query('SELECT stage,receipt FROM admission_installation.attempts')
        with self.assertRaisesRegex(ValueError, 'INDEPENDENT'):
            self.module.verify(self.backend, self.candidate, self.plan, self.store, self.attempt, self.authority)
        self.query('GRANT USAGE ON SCHEMA admission_installation TO verifier; GRANT SELECT ON ALL TABLES IN SCHEMA admission_installation TO verifier; GRANT EXECUTE ON FUNCTION pg_control_system() TO verifier')
        with closing(self.connect('verifier')) as connection:
            observation = self.module.verify(self.module.PostgresTarget(connection), self.candidate,
                self.plan, self.store, self.attempt, self.authority)
        self.assertEqual(observation['state'], 'INDEPENDENTLY_OBSERVED')
        self.assertFalse(observation['usable'])
        self.assertFalse(observation['certified'])
        self.assertEqual(self.query('SELECT stage,receipt FROM admission_installation.attempts'), before)

    def test_rollback_revokes_first_preserves_data_and_never_reactivates(self):
        self.install()
        before = self.preserved()
        def interrupted(phase):
            if phase == 'after_revocation':
                raise RuntimeError('synthetic interruption')
        with self.assertRaises(self.module.InstallationRevokedRecordingFailed):
            self.module.rollback(self.backend, self.candidate, self.plan, self.store,
                self.attempt, self.authority, progress=interrupted)
        with self.assertRaises(ValueError):
            self.install()
        result = self.module.rollback(self.backend, self.candidate, self.plan, self.store,
            self.attempt, self.authority)
        self.assertEqual(result['state'], 'REVOKED')
        self.assertEqual(self.preserved(), before)
        self.assertEqual(self.query('SELECT stage FROM admission_installation.attempts'), [('REVOKED',)])

    def verifier(self):
        self.query('GRANT USAGE ON SCHEMA admission_installation TO verifier; GRANT SELECT ON ALL TABLES IN SCHEMA admission_installation TO verifier; GRANT EXECUTE ON FUNCTION pg_control_system() TO verifier')
        connection = self.connect('verifier')
        self.addCleanup(connection.close)
        return self.module.PostgresTarget(connection)

    def test_security_catalog_changes_invalidate_exact_accepted_plan(self):
        self.query("CREATE FUNCTION public.installer_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$; CREATE TRIGGER installer_guard BEFORE UPDATE ON public.products FOR EACH ROW EXECUTE FUNCTION public.installer_guard(); CREATE VIEW public.installer_view AS SELECT product FROM public.products")
        for command in (
            'ALTER TABLE public.products DISABLE TRIGGER installer_guard',
            'ALTER TABLE public.products ENABLE ROW LEVEL SECURITY',
            'ALTER TABLE public.products FORCE ROW LEVEL SECURITY',
            'CREATE POLICY installer_deny ON public.products FOR SELECT USING(false)',
            'ALTER POLICY installer_deny ON public.products USING(true)',
            'CREATE OR REPLACE VIEW public.installer_view AS SELECT product FROM public.products WHERE false',
            'GRANT SELECT(repository) ON public.products TO verifier',
        ):
            observed = self.backend.describe()
            self.plan = self.module.build_plan(self.candidate, observed, adopted_sources=LEGACY,
                filesystem_binding=self.store.binding, configuration_sha256=hashlib.sha256(self.configuration).hexdigest())
            self.authority = fixture_authority(self.module, self.plan, self.attempt)
            self.query(command)
            with self.subTest(command=command):
                self.assertNotEqual(self.backend.describe()['catalog_sha256'], observed['catalog_sha256'])
                with self.assertRaisesRegex(ValueError, 'CATALOG'):
                    self.install()
        self.assertEqual(self.query("SELECT to_regnamespace('admission_installation')"), [(None,)])

    def test_recreated_same_named_acl_role_changes_the_catalog_identity(self):
        role = 'installer_reader_' + uuid.uuid4().hex
        self.query(sql.SQL('CREATE ROLE {}; GRANT SELECT(repository) ON public.products TO {}').format(sql.Identifier(role), sql.Identifier(role)))
        before = self.backend.describe()['catalog_sha256']
        self.query(sql.SQL('REVOKE ALL(repository) ON public.products FROM {}; DROP ROLE {}; CREATE ROLE {}; GRANT SELECT(repository) ON public.products TO {}').format(*[sql.Identifier(role)] * 4))
        self.assertNotEqual(self.backend.describe()['catalog_sha256'], before)

    def test_integration_functions_require_exact_explicit_version_adoption(self):
        additions = ('009-atomic-inspection.sql', '010-controller-coordinator-integration.sql')
        for name in additions:
            self.query((ROOT / name).read_text())
        observed = self.backend.describe()
        with self.assertRaisesRegex(ValueError, 'UNTRACKED'):
            self.module.build_plan(self.candidate, observed, adopted_sources=LEGACY,
                filesystem_binding=self.store.binding, configuration_sha256='a' * 64)
        accepted = self.module.build_plan(self.candidate, observed, adopted_sources=LEGACY + additions,
                filesystem_binding=self.store.binding, configuration_sha256='a' * 64)
        self.assertNotIn(additions[1], accepted.value['pending_sources'])
        self.query("ALTER FUNCTION assignment_leases._coordinator_receipt(jsonb,jsonb) RESET timezone")
        with self.assertRaisesRegex(ValueError, 'LEGACY_COORDINATOR'):
            self.module.build_plan(self.candidate, self.backend.describe(), adopted_sources=LEGACY + additions,
                filesystem_binding=self.store.binding, configuration_sha256='a' * 64)

    def test_receipt_must_be_durable_before_independent_observation(self):
        def interrupted(phase):
            if phase == 'after_configuration_commit':
                raise RuntimeError('synthetic interruption')
        with self.assertRaises(RuntimeError):
            self.install(progress=interrupted)
        verifier = self.verifier()
        with self.assertRaisesRegex(ValueError, 'VERIFIABLE|RECEIPT'):
            self.module.verify(verifier, self.candidate, self.plan, self.store, self.attempt, self.authority)
        self.install()
        receipt = self.store.root / 'receipts' / self.attempt / 'receipt.json'
        receipt.write_bytes(b'{"state":"forged"}\n')
        with self.assertRaises(ValueError):
            self.module.verify(verifier, self.candidate, self.plan, self.store, self.attempt, self.authority)

    def test_verifier_cannot_retain_noninherited_writer_membership(self):
        self.install()
        verifier = self.verifier()
        role = 'installer_writer_' + uuid.uuid4().hex
        self.query(sql.SQL('CREATE ROLE {} NOLOGIN; GRANT UPDATE(repository) ON public.products TO {}; GRANT {} TO verifier WITH INHERIT FALSE').format(sql.Identifier(role), sql.Identifier(role), sql.Identifier(role)))
        with self.assertRaisesRegex(ValueError, 'RESTRICTED_VERIFIER'):
            self.module.verify(verifier, self.candidate, self.plan, self.store, self.attempt, self.authority)

    def test_verifier_restrictions_are_fresh_at_return_boundary(self):
        self.install()
        verifier = self.verifier()
        authorize = self.authority.authorize
        for wanted in ('preflight', 'return'):
            changed = False
            def elevate(operation, binding, phase):
                nonlocal changed
                authorize(operation, binding, phase)
                if operation == 'verify' and phase == wanted:
                    self.query('ALTER ROLE verifier REPLICATION')
                    changed = True
            self.authority.authorize = elevate
            try:
                with self.subTest(phase=wanted), self.assertRaisesRegex(ValueError, 'RESTRICTED_VERIFIER'):
                    self.module.verify(verifier, self.candidate, self.plan, self.store, self.attempt, self.authority)
            finally:
                if changed:
                    self.query('ALTER ROLE verifier NOREPLICATION')

    def runtime_fixture(self):
        fixture = filesystem_tests.RuntimeTargetTests('test_fixed_targets_are_durable_and_fixture_cannot_claim_host_installation')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.candidate, self.store, self.configuration = fixture.candidate, fixture.store, fixture.bundle()
        return fixture

    def runtime_plan(self):
        self.plan = self.module.build_plan(self.candidate, self.backend.describe(), adopted_sources=LEGACY,
            filesystem_binding=self.store.binding, configuration_sha256=hashlib.sha256(self.configuration).hexdigest())
        self.authority = fixture_authority(self.module, self.plan, self.attempt)

    def test_request_dispatch_plans_readonly_then_installs_verifies_and_revokes(self):
        self.assertTrue(hasattr(self.module, 'dispatch_request'),
                        'The operational CLI has no engine dispatch')
        fixture = self.runtime_fixture()
        request = dict(schema='codestra.admission-installation-request.v1',
            candidate=str(self.candidate.root), manifest_sha256=self.candidate.manifest_sha256,
            runtime_selection=fixture.specification, adopted_sources=list(LEGACY),
            configuration_sha256=hashlib.sha256(self.configuration).hexdigest())
        before = self.preserved()
        def cli(operation, backend, configuration=None):
            request_file = self.path / 'request.json'
            raw = json.dumps(request).encode()
            request_file.write_bytes(raw)
            output = io.StringIO()
            # Replace only protected host composition: the real parser, digest
            # validation, dispatch, engine, files and PostgreSQL remain active.
            def configured(op, value):
                return self.module.dispatch_request(op, value, self.candidate, backend, self.store,
                    authority=self.authority, configuration=configuration)
            with patch.object(self.module, 'run_configured', configured), redirect_stdout(output):
                code = self.module.main([operation, '--request', str(request_file),
                    '--request-sha256', hashlib.sha256(raw).hexdigest()])
            self.assertEqual(code, 0, output.getvalue())
            return json.loads(output.getvalue())
        planned = cli('plan', self.backend)
        self.assertEqual(planned['state'], 'PLANNED_NOT_AUTHORIZED')
        self.assertFalse(planned['install_allowed'])
        self.assertEqual(self.preserved(), before)
        self.assertEqual(self.query("SELECT to_regnamespace('admission_installation')"), [(None,)])
        self.plan = self.module.InstallationPlan(self.module.canonical(planned['plan']))
        self.authority = fixture_authority(self.module, self.plan, self.attempt)
        request.update(plan=planned['plan'], plan_sha256=planned['plan_sha256'], attempt_id=self.attempt)
        receipt = cli('install', self.backend, self.configuration)
        self.assertEqual(receipt['state'], 'DATABASE_APPLIED_RUNTIME_FIXTURE_MATERIALIZED')
        observation = cli('verify', self.verifier())
        self.assertEqual(observation['state'], 'INDEPENDENTLY_OBSERVED')
        revoked = cli('rollback', self.backend)
        self.assertEqual(revoked['state'], 'REVOKED')
        self.assertEqual(self.query('SELECT stage FROM admission_installation.attempts'), [('REVOKED',)])
        self.assertEqual(self.preserved(), before)

    def test_request_dispatch_rejects_caller_approval_and_changed_plan(self):
        self.assertTrue(hasattr(self.module, 'dispatch_request'),
                        'The operational CLI has no request validation')
        fixture = self.runtime_fixture()
        request = dict(schema='codestra.admission-installation-request.v1',
            candidate=str(self.candidate.root), manifest_sha256=self.candidate.manifest_sha256,
            runtime_selection=fixture.specification, adopted_sources=list(LEGACY),
            configuration_sha256=hashlib.sha256(self.configuration).hexdigest())
        request['approved'] = True
        with self.assertRaisesRegex(ValueError, 'REQUEST'):
            self.module.dispatch_request('plan', request, self.candidate, self.backend, self.store)
        del request['approved']
        planned = self.module.dispatch_request('plan', request, self.candidate, self.backend, self.store)
        request.update(plan=planned['plan'], plan_sha256='0' * 64, attempt_id=self.attempt)
        with self.assertRaisesRegex(ValueError, 'PLAN'):
            self.module.dispatch_request('install', request, self.candidate, self.backend,
                self.store, authority=self.authority, configuration=self.configuration)
        self.assertEqual(self.query("SELECT to_regnamespace('admission_installation')"), [(None,)])

    def test_hostile_search_path_and_temporary_catalog_cannot_change_inspection(self):
        before = self.backend.describe()
        with self.connection, self.connection.cursor() as cur:
            cur.execute('CREATE TEMP TABLE pg_namespace AS SELECT * FROM pg_catalog.pg_namespace WHERE false')
            cur.execute('SET search_path=pg_temp,public,pg_catalog')
        after = self.backend.describe()
        self.assertEqual(after['identity'], before['identity'])
        self.assertEqual(after['catalog_sha256'], before['catalog_sha256'])
        self.assertIn('public.scope_certifications', after['tables'])

    def test_explicit_server_file_function_grants_disqualify_verifier(self):
        self.query('GRANT EXECUTE ON FUNCTION pg_control_system() TO verifier')
        connection = self.connect('verifier')
        self.addCleanup(connection.close)
        backend = self.module.PostgresTarget(connection)
        self.module._restricted_verifier(backend, self.plan.value['target'])
        for signature in ('lo_export(oid,text)', 'lo_import(text)', 'lo_import(text,oid)',
                'pg_read_file(text)', 'pg_read_binary_file(text)', 'pg_stat_file(text)', 'pg_ls_dir(text)',
                'pg_reload_conf()'):
            with self.subTest(signature=signature):
                self.query('GRANT EXECUTE ON FUNCTION pg_catalog.' + signature + ' TO verifier')
                try:
                    with self.assertRaisesRegex(ValueError, 'RESTRICTED_VERIFIER'):
                        self.module._restricted_verifier(backend, self.plan.value['target'])
                finally:
                    self.query('REVOKE EXECUTE ON FUNCTION pg_catalog.' + signature + ' FROM verifier')
        self.query('CREATE ROLE file_cap_holder NOLOGIN; GRANT file_cap_holder TO verifier WITH INHERIT FALSE, SET TRUE; GRANT EXECUTE ON FUNCTION pg_catalog.lo_export(oid,text) TO file_cap_holder')
        try:
            with self.assertRaisesRegex(ValueError, 'RESTRICTED_VERIFIER'):
                self.module._restricted_verifier(backend, self.plan.value['target'])
        finally:
            self.query('REVOKE file_cap_holder FROM verifier; DROP OWNED BY file_cap_holder; DROP ROLE file_cap_holder')
        self.query('GRANT EXECUTE ON FUNCTION pg_catalog.lo_export(oid,text) TO PUBLIC')
        try:
            with self.assertRaisesRegex(ValueError, 'RESTRICTED_VERIFIER'):
                self.module._restricted_verifier(backend, self.plan.value['target'])
        finally:
            self.query('REVOKE EXECUTE ON FUNCTION pg_catalog.lo_export(oid,text) FROM PUBLIC')
        # Dangerous functions were never invoked; only their grants were tested.

    def test_semantically_false_adoption_plan_is_rejected_before_new_intent(self):
        value = self.plan.value
        value['adopted_sources'] = sorted(set(self.module.MIGRATIONS) - {self.module.LEDGER_SOURCE})
        value['pending_sources'] = []
        self.plan = self.module.InstallationPlan(self.module.canonical(value))
        self.authority = fixture_authority(self.module, self.plan, self.attempt)
        with self.assertRaisesRegex(ValueError, 'LEGACY|PLAN'):
            self.install()
        self.assertEqual(self.query("SELECT to_regnamespace('admission_installation')"), [(None,)])
        self.assertFalse((self.store.root / 'releases').exists())

    def test_online_authority_uses_separate_scram_issuer_and_durable_revoke(self):
        self.assertTrue(hasattr(self.module, 'OnlinePostgresAuthority'),
                        'Independently authenticated operational authority is missing')
        # Independently administered fixture cluster: installation superuser
        # cannot change this issuer through its target connection.
        issuer_path = self.path / 'issuer'
        issuer_path.mkdir(mode=0o700)
        data = issuer_path / 'data'
        subprocess.run([str(registration.PG / 'initdb'), '-D', str(data), '-A', 'trust',
            '-U', 'issuer_owner', '--no-locale'], check=True, capture_output=True)
        (data / 'pg_hba.conf').write_text('local all all trust\nhostssl all all 127.0.0.1/32 scram-sha-256\nhostnossl all all 127.0.0.1/32 reject\n')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            issuer_port = listener.getsockname()[1]
        options = (f'-k {issuer_path} -p {issuer_port} -h 127.0.0.1 -c ssl=on '
            f'-c ssl_cert_file={coordinator.CoordinatorTests.path / "fixture.crt"} '
            f'-c ssl_key_file={coordinator.CoordinatorTests.path / "fixture.key"}')
        subprocess.run([str(registration.PG / 'pg_ctl'), '-D', str(data), '-l', str(issuer_path / 'postgres.log'),
            '-o', options, '-w', 'start'], check=True, capture_output=True)
        self.addCleanup(lambda: subprocess.run([str(registration.PG / 'pg_ctl'), '-D', str(data),
            '-m', 'immediate', '-w', 'stop'], check=True, capture_output=True))
        owner = psycopg2.connect(host=str(issuer_path), port=issuer_port, dbname='postgres', user='issuer_owner')
        self.addCleanup(owner.close)
        grant_id = str(uuid.uuid4())
        binding = self.module._context(self.candidate, self.plan, self.store, self.attempt)[1]
        verifier_oid = self.query("SELECT oid::bigint FROM pg_roles WHERE rolname='verifier'")[0][0]
        with owner, owner.cursor() as cur:
            cur.execute("CREATE ROLE issuer_client LOGIN PASSWORD 'synthetic-issuer-client'; CREATE SCHEMA admission_bootstrap; REVOKE ALL ON SCHEMA admission_bootstrap FROM PUBLIC")
            cur.execute("CREATE TABLE admission_bootstrap.grants(grant_id uuid PRIMARY KEY,principal oid NOT NULL,binding jsonb NOT NULL,verifier_oid oid NOT NULL,expires_at timestamptz NOT NULL,revoked_at timestamptz,corruption jsonb NOT NULL DEFAULT '{}')")
            cur.execute("""CREATE FUNCTION admission_bootstrap.describe(g uuid,op text,b jsonb,phase text,nonce uuid)
                RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,admission_bootstrap,pg_temp AS $$
                SELECT jsonb_build_object('schema','codestra.admission-authority-response.v1',
                    'grant_id',g,'operation',op,'binding',b,'phase',phase,'nonce',nonce,
                    'observed_at',clock_timestamp(),'not_before',clock_timestamp()-interval '1 minute',
                    'expires_at',x.expires_at,'revoked_at',x.revoked_at,
                    'decision',CASE WHEN x.principal=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=session_user)
                        AND CASE WHEN op='verify' THEN x.binding||jsonb_build_object('verifier_role_oid',x.verifier_oid::bigint)
                            ELSE x.binding END=b AND x.expires_at>clock_timestamp()
                        AND (op='rollback' OR x.revoked_at IS NULL)
                        AND op IN ('install','verify','rollback') THEN 'ALLOWED' ELSE 'DENIED' END) || x.corruption
                FROM admission_bootstrap.grants x WHERE x.grant_id=g $$""")
            cur.execute("""CREATE FUNCTION admission_bootstrap.revoke(g uuid,b jsonb,nonce uuid)
                RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,admission_bootstrap,pg_temp AS $$
                BEGIN
                    UPDATE admission_bootstrap.grants SET revoked_at=coalesce(revoked_at,clock_timestamp())
                    WHERE grant_id=g AND binding=b AND principal=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=session_user)
                        AND expires_at>clock_timestamp();
                    IF NOT FOUND THEN RAISE EXCEPTION 'DENIED'; END IF;
                    RETURN jsonb_build_object('grant_id',g,'binding',b,'nonce',nonce,'state','REVOKED');
                END $$""")
            cur.execute('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA admission_bootstrap FROM PUBLIC')
            cur.execute('GRANT USAGE ON SCHEMA admission_bootstrap TO issuer_client; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA admission_bootstrap TO issuer_client; GRANT EXECUTE ON FUNCTION pg_control_system() TO issuer_client')
            cur.execute("INSERT INTO admission_bootstrap.grants(grant_id,principal,binding,verifier_oid,expires_at,revoked_at) SELECT %s,oid,%s,%s,clock_timestamp()+interval '30 minutes',NULL FROM pg_roles WHERE rolname='issuer_client'", (grant_id, Json(binding), verifier_oid))
        connection = psycopg2.connect(host='127.0.0.1', port=issuer_port, dbname='postgres', user='issuer_client',
            password='synthetic-issuer-client', sslmode='verify-full', sslrootcert=str(coordinator.CoordinatorTests.path / 'fixture.crt'))
        self.addCleanup(connection.close)
        # A session can create temporary relations. They must never substitute
        # for the issuer's authenticated principal catalog, even in a definer.
        with owner, owner.cursor() as cur:
            cur.execute("SELECT oid FROM pg_catalog.pg_roles WHERE rolname='issuer_owner'")
            wrong_principal = cur.fetchone()[0]
            cur.execute('UPDATE admission_bootstrap.grants SET principal=%s', (wrong_principal,))
        with connection, connection.cursor() as cur:
            cur.execute('CREATE TEMP TABLE pg_roles(oid oid,rolname name)')
            cur.execute('INSERT INTO pg_temp.pg_roles VALUES(%s,session_user)', (wrong_principal,))
            cur.execute('SELECT admission_bootstrap.describe(%s,%s,%s,%s,%s)',
                (grant_id, 'install', Json(binding), 'preflight', str(uuid.uuid4())))
            self.assertEqual(cur.fetchone()[0]['decision'], 'DENIED')
        with self.assertRaises(psycopg2.Error), connection, connection.cursor() as cur:
            cur.execute('SELECT admission_bootstrap.revoke(%s,%s,%s)',
                (grant_id, Json(binding), str(uuid.uuid4())))
        with owner, owner.cursor() as cur:
            cur.execute('SELECT revoked_at FROM admission_bootstrap.grants')
            self.assertEqual(cur.fetchall(), [(None,)])
            cur.execute("UPDATE admission_bootstrap.grants SET principal=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='issuer_client')")
        with connection, connection.cursor() as cur:
            cur.execute('DROP TABLE pg_temp.pg_roles')
        backend = self.module.PostgresTarget(connection)
        with backend.readonly() as cur:
            identity = backend._identity(cur)
            catalog = backend._catalog(cur, ('admission_bootstrap', 'public'))[0]
        selection = dict(identity={k: identity[k] for k in ('system_identifier', 'database_oid', 'database_name', 'session_user', 'role_oid')},
            catalog_sha256=catalog, grant_id=grant_id)
        authority = self.module.OnlinePostgresAuthority(connection, selection)
        self.assertIsNone(authority.authorize('install', binding, 'preflight'))
        receipt = self.module.install(self.backend, self.candidate, self.plan, self.store,
            self.configuration, self.attempt, authority)
        self.assertEqual(receipt['state'], 'DATABASE_APPLIED_ARTIFACTS_STAGED')
        observed = self.module.verify(self.verifier(), self.candidate, self.plan, self.store, self.attempt, authority)
        self.assertEqual(observed['state'], 'INDEPENDENTLY_OBSERVED')
        self.assertEqual(observed['verifier_role_oid'], verifier_oid)
        with self.assertRaises(ValueError):
            authority.authorize('verify', dict(binding, verifier_role_oid=verifier_oid+1), 'preflight')
        same_cluster = json.loads(json.dumps(binding))
        same_cluster['target']['system_identifier'] = identity['system_identifier']
        same_cluster['target']['database_oid'] += 1
        with self.assertRaisesRegex(ValueError, 'INDEPENDENT_INSTALLATION_ISSUER_CLUSTER'):
            authority.authorize('install', same_cluster, 'preflight')
        wrong_identity = json.loads(json.dumps(selection))
        wrong_identity['identity']['role_oid'] += 1
        with self.assertRaisesRegex(ValueError, 'IDENTITY'):
            self.module.OnlinePostgresAuthority(connection, wrong_identity).authorize('install', binding, 'preflight')
        wrong = dict(binding, source_commit='b' * 40)
        with self.assertRaises(ValueError):
            authority.authorize('install', wrong, 'preflight')
        for corruption in ({'nonce': str(uuid.uuid4())}, {'phase': 'files'}, {'decision': True},
                {'binding': dict(binding, verifier_role_oid=987)}, {'extra': 'unaccepted'},
                {'observed_at': '2000-01-01T00:00:00+00:00'}, {'not_before': '2100-01-01T00:00:00+00:00'}):
            with self.subTest(corruption=corruption):
                with owner, owner.cursor() as cur:
                    cur.execute('UPDATE admission_bootstrap.grants SET corruption=%s', (Json(corruption),))
                with self.assertRaises(ValueError):
                    authority.authorize('install', binding, 'preflight')
        with owner, owner.cursor() as cur:
            cur.execute("UPDATE admission_bootstrap.grants SET corruption='{}'")
        with owner, owner.cursor() as cur:
            cur.execute("UPDATE admission_bootstrap.grants SET expires_at=clock_timestamp()-interval '1 second'")
        with self.assertRaises(ValueError):
            authority.authorize('install', binding, 'preflight')
        with owner, owner.cursor() as cur:
            cur.execute("UPDATE admission_bootstrap.grants SET expires_at=clock_timestamp()+interval '30 minutes'")
        class LostCommitResponse:
            failed = False
            def __getattr__(self, name):
                return getattr(connection, name)
            def commit(self):
                connection.commit()
                if not self.failed:
                    self.failed = True
                    raise ConnectionError('synthetic lost commit response')
        uncertain = self.module.OnlinePostgresAuthority(LostCommitResponse(), selection)
        with self.assertRaises(self.module.InstallationOutcomeUnknown):
            uncertain.revoke(binding)
        with owner, owner.cursor() as cur:
            cur.execute('SELECT revoked_at IS NOT NULL FROM admission_bootstrap.grants')
            self.assertEqual(cur.fetchall(), [(True,)])
        self.assertIsNone(authority.revoke(binding))
        with self.assertRaises(ValueError):
            authority.authorize('install', binding, 'files')
        self.assertIsNone(authority.authorize('rollback', binding, 'return'))
        revoked = self.module.rollback(self.backend, self.candidate, self.plan, self.store, self.attempt, authority)
        self.assertEqual(revoked['state'], 'REVOKED')
        self.assertEqual(self.query('SELECT stage FROM admission_installation.attempts'), [('REVOKED',)])
        with owner, owner.cursor() as cur:
            cur.execute('GRANT EXECUTE ON FUNCTION pg_catalog.lo_export(oid,text) TO issuer_client')
        with backend.readonly() as cur:
            self.assertEqual(backend._catalog(cur, ('admission_bootstrap', 'public'))[0], selection['catalog_sha256'])
        with self.assertRaises(ValueError):
            authority.authorize('rollback', binding, 'return')
        with owner, owner.cursor() as cur:
            cur.execute('REVOKE EXECUTE ON FUNCTION pg_catalog.lo_export(oid,text) FROM issuer_client')
        with owner, owner.cursor() as cur:
            cur.execute('GRANT UPDATE ON admission_bootstrap.grants TO issuer_client')
        with backend.readonly() as cur:
            selection['catalog_sha256'] = backend._catalog(cur, ('admission_bootstrap', 'public'))[0]
        with self.assertRaises(ValueError):
            self.module.OnlinePostgresAuthority(connection, selection).authorize('rollback', binding, 'return')
        with owner, owner.cursor() as cur:
            cur.execute('REVOKE UPDATE ON admission_bootstrap.grants FROM issuer_client')
            cur.execute('CREATE ROLE function_holder NOLOGIN; GRANT function_holder TO issuer_client WITH INHERIT FALSE, SET TRUE')
            cur.execute('ALTER FUNCTION admission_bootstrap.describe(uuid,text,jsonb,text,uuid) OWNER TO function_holder')
        with backend.readonly() as cur:
            selection['catalog_sha256'] = backend._catalog(cur, ('admission_bootstrap', 'public'))[0]
        with self.assertRaises(ValueError):
            self.module.OnlinePostgresAuthority(connection, selection).authorize('rollback', binding, 'return')

    def test_fixed_runtime_targets_and_database_boundaries_share_the_exact_plan(self):
        fixture = self.runtime_fixture()
        self.runtime_plan()
        receipt = self.install()
        self.assertEqual(receipt['state'], 'DATABASE_APPLIED_RUNTIME_FIXTURE_MATERIALIZED')
        self.assertFalse(receipt['runtime_installed'])
        self.assertNotIn('SYNTHETIC-PRIVATE-SECRET', json.dumps(receipt))
        verifier = self.verifier()
        observation = self.module.verify(verifier, self.candidate, self.plan, self.store, self.attempt, self.authority)
        self.assertFalse(observation['runtime_installed'])
        (fixture.namespace_root / fixture.configuration_target.lstrip('/')).chmod(0o755)
        with self.assertRaises(ValueError):
            self.module.verify(verifier, self.candidate, self.plan, self.store, self.attempt, self.authority)

    def test_reconstructed_rollback_revokes_before_damaged_target_inspection(self):
        fixture = self.runtime_fixture()
        self.runtime_plan()
        self.install()
        target = fixture.namespace_root / fixture.configuration_target.lstrip('/')
        target.write_bytes(b'damaged protected target; preserve for recovery')
        target.chmod(0o755)
        before = self.preserved()

        def reconstruct():
            self.assertTrue(self.authority.revoked, 'Target reconstruction ran before revocation')
            return self.module.RuntimeRevocationCustody(fixture.journal, self.plan, fixture.namespace)

        result = self.module.rollback(lambda: self.backend, self.candidate, self.plan,
            reconstruct, self.attempt, self.authority)
        self.assertEqual(result['state'], 'REVOKED')
        self.assertTrue(self.authority.revoked)
        self.assertEqual(target.read_bytes(), b'damaged protected target; preserve for recovery')
        self.assertEqual(target.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.preserved(), before)
        self.assertEqual(self.query('SELECT stage FROM admission_installation.attempts'), [('REVOKED',)])

    def test_configured_rollback_reconstructs_only_after_confirmed_revocation(self):
        fixture = self.runtime_fixture()
        self.runtime_plan()
        self.install()
        target = fixture.namespace_root / fixture.configuration_target.lstrip('/')
        target.write_bytes(b'damaged installed TOML')
        target.chmod(0o755)
        for name in fixture.credentials:
            (fixture.namespace_root / name.lstrip('/')).unlink()
        request = dict(schema='codestra.admission-installation-request.v1',
            candidate=str(self.candidate.root), manifest_sha256=self.candidate.manifest_sha256,
            runtime_selection=fixture.specification, adopted_sources=list(LEGACY),
            configuration_sha256=hashlib.sha256(self.configuration).hexdigest(),
            plan=self.plan.value, plan_sha256=self.plan.digest, attempt_id=self.attempt)
        config_raw = b'schema="codestra.admission-installer-config.v1"\n[issuer]\n'
        inputs = {self.module.INSTALLER_CONFIG: config_raw,
            self.module.INSTALLER_CREDENTIALS['issuer']: b'synthetic-issuer-reference',
            self.module.INSTALLER_CREDENTIALS['operator']: b'synthetic-operator-reference',
            '/etc/codestra/control-plane/fixture-ca.crt': b'synthetic-ca-reference'}

        def protected(namespace, path, **options):
            return inputs[path]  # No verifier/installed configuration is available.

        def parameters(raw):
            return dict(role=raw.decode(), sslrootcert='/etc/codestra/control-plane/fixture-ca.crt')

        class IssuerConnection:
            def close(self):
                pass

        target_connection = self.connect()
        self.addCleanup(target_connection.close)
        connections = []

        def connect(**params):
            connections.append(params['role'])
            if params['role'] == 'synthetic-issuer-reference':
                return IssuerConnection()
            self.assertTrue(self.authority.revoked, 'Configured target opened before revoke')
            return target_connection

        def journal():
            self.assertTrue(self.authority.revoked, 'Configured journal opened before revoke')
            return fixture.journal

        class ForbiddenRuntimeCustody(self.module.RuntimeCustody):
            def __init__(self, *args, **kwargs):
                raise AssertionError('Configured rollback reconstructed installed targets')

        # Replace only fixed-path/connection boundaries. Runtime execution,
        # request parsing, lazy composition, journal checks and PG recording are real.
        with patch.object(self.module, '_protected_input', protected), \
                patch.object(self.module, 'connection_parameters', parameters), \
                patch.object(psycopg2, 'connect', connect), \
                patch.object(self.module, 'OnlinePostgresAuthority', return_value=self.authority), \
                patch.object(self.module, '_installation_journal', journal), \
                patch.object(self.module, 'RuntimeCustody', ForbiddenRuntimeCustody):
            driver = fixture.driver + '/psycopg2/__init__.py'
            fixture.write(driver, b'corrupt executing native-client package')
            with self.assertRaises(ValueError):
                self.module._configured_connections('rollback', request, self.candidate,
                    fixture.namespace, config_raw, dict(schema='codestra.admission-installer-config.v1', issuer={}))
            self.assertEqual(connections, [])
            self.assertFalse(self.authority.revoked)
            fixture.write(driver, fixture.package['psycopg2/__init__.py'])
            result = self.module._configured_connections('rollback', request, self.candidate,
                fixture.namespace, config_raw, dict(schema='codestra.admission-installer-config.v1', issuer={}))
        self.assertEqual(result['state'], 'REVOKED')
        self.assertTrue(self.authority.revoked)
        self.assertEqual(target.read_bytes(), b'damaged installed TOML')
        self.assertEqual(self.query('SELECT stage FROM admission_installation.attempts'), [('REVOKED',)])

    def test_rollback_detects_journal_damage_after_final_authority_call(self):
        self.install()
        original = self.authority.authorize

        def damage(operation, binding, phase):
            original(operation, binding, phase)
            if operation == 'rollback' and phase == 'return':
                self.store.root.chmod(0o755)

        self.authority.authorize = damage
        with self.assertRaisesRegex(ValueError, 'REVOKED_RECORDING_INCOMPLETE'):
            self.module.rollback(self.backend, self.candidate, self.plan,
                self.store, self.attempt, self.authority)
        self.assertTrue(self.authority.revoked)
        self.assertEqual(self.query('SELECT stage FROM admission_installation.attempts'), [('REVOKED',)])

    def test_unavailable_target_connection_does_not_prevent_issuer_revocation(self):
        self.install()

        def unavailable():
            self.assertTrue(self.authority.revoked, 'Target connection ran before revocation')
            raise ConnectionError('synthetic target unavailable')

        with self.assertRaisesRegex(ValueError, 'REVOKED_RECORDING_INCOMPLETE'):
            self.module.rollback(unavailable, self.candidate, self.plan,
                lambda: self.store, self.attempt, self.authority)
        self.assertTrue(self.authority.revoked)
        self.assertEqual(self.query('SELECT stage FROM admission_installation.attempts'), [('RECEIPTED',)])

    def test_runtime_artifacts_are_fresh_after_the_final_authority_call(self):
        fixture = self.runtime_fixture()
        self.runtime_plan()
        self.install()
        verifier = self.verifier()
        original = self.authority.authorize
        def mutate(operation, binding, phase):
            original(operation, binding, phase)
            if operation == 'verify' and phase == 'return':
                (fixture.namespace_root / fixture.configuration_target.lstrip('/')).chmod(0o755)
        self.authority.authorize = mutate
        with self.assertRaises(ValueError):
            self.module.verify(verifier, self.candidate, self.plan, self.store, self.attempt, self.authority)

    def test_invalid_runtime_configuration_denies_before_intent_or_ddl(self):
        fixture = self.runtime_fixture()
        wrong = fixture.configuration.replace(b'app_id=123', b'app_id=true')
        specification = json.loads(json.dumps(fixture.specification))
        specification['configuration'][fixture.configuration_target]['sha256'] = hashlib.sha256(wrong).hexdigest()
        self.store = self.module.RuntimeCustody(fixture.journal, self.candidate, specification, fixture.namespace)
        self.configuration = fixture.bundle(wrong)
        self.runtime_plan()
        with self.assertRaisesRegex(ValueError, 'CONFIGURATION'):
            self.install()
        self.assertEqual(self.query("SELECT to_regnamespace('admission_installation'),to_regnamespace('scoped_admission')"), [(None, None)])
        self.assertFalse((fixture.namespace_root / ('opt/codestra-control-plane/releases/' + self.candidate.source_commit)).exists())


if __name__ == '__main__':
    unittest.main()
