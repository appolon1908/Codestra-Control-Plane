"""Candidate validation and inert CLI; no installed configuration or DB access."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import base64
import io
import zipfile
import ast
import stat
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))


class PrivilegedEntryTests(unittest.TestCase):
    def test_unsafe_candidate_cannot_import_project_code_before_root_custody_check(self):
        with tempfile.TemporaryDirectory(prefix='cp-unsafe-entry-') as temporary:
            root = Path(temporary)
            (root / 'bin').mkdir()
            package = root / 'lib/codestra_control'
            package.mkdir(parents=True)
            marker = root / 'PROJECT_CODE_EXECUTED'
            (package / '__init__.py').write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n')
            (package / 'admission_installation.py').write_text('def main(): return 0\n')
            entry = root / 'bin/codestra-install-admission'
            entry.write_bytes((ROOT / 'bin/codestra-install-admission').read_bytes())
            code = ('import os,runpy;os.geteuid=lambda:0;runpy.run_path(' + repr(str(entry)) + ',run_name="__main__")')
            result = subprocess.run([sys.executable, '-I', '-B', '-c', code], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertFalse(marker.exists(), 'Unsafe project code executed before custody refusal')

    def test_privileged_import_inventory_rejects_unlisted_cached_bytecode(self):
        # Non-root fixture simulates accepted UID metadata only. It never grants
        # privileges or imports project code; actual bytes and path walks run.
        with tempfile.TemporaryDirectory(prefix='cp-cached-entry-') as temporary:
            root = Path(temporary)
            (root / 'bin').mkdir()
            package = root / 'lib/codestra_control'
            package.mkdir(parents=True)
            entry = root / 'bin/codestra-install-admission'
            entry.write_bytes((ROOT / 'bin/codestra-install-admission').read_bytes())
            entry.chmod(0o755)
            (package / '__init__.py').write_bytes(b'')
            (package / '__init__.py').chmod(0o644)
            records = []
            for name in ('bin/codestra-install-admission', 'lib/codestra_control/__init__.py'):
                path = root / name
                records.append(dict(source_path=name, mode=oct(stat.S_IMODE(path.stat().st_mode)),
                    size=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
            raw = json.dumps({'files': records}).encode()
            (root / 'controller-release-manifest.json').write_bytes(raw)
            (root / 'controller-release-manifest.json').chmod(0o644)
            tree = ast.parse(entry.read_bytes())
            guard = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == '_private_import_guard')
            original_fstat, original_lstat = os.fstat, Path.lstat
            def accepted_metadata(info):
                fields = list(info)
                fields[0] &= ~0o022
                fields[4] = 0
                return os.stat_result(fields)
            class MetadataFixture:
                def __getattr__(self, name):
                    return getattr(os, name)
                getuid = staticmethod(lambda: 0)
                geteuid = staticmethod(lambda: 0)
                fstat = staticmethod(lambda fd: accepted_metadata(original_fstat(fd)))
            context = dict(__file__=str(entry), os=MetadataFixture(), pathlib=__import__('pathlib'),
                stat=stat, json=json, hashlib=hashlib,
                sys=SimpleNamespace(flags=SimpleNamespace(isolated=True),
                    argv=[str(entry), 'preflight', '--candidate', str(root), '--manifest-sha256', hashlib.sha256(raw).hexdigest()]))
            exec(compile(ast.Module(body=[guard], type_ignores=[]), str(entry), 'exec'), context)
            with patch.object(Path, 'lstat', lambda path: accepted_metadata(original_lstat(path))):
                context['_private_import_guard']()
                cache = package / '__pycache__'
                cache.mkdir()
                (cache / '__init__.cpython-312.pyc').write_bytes(b'unaccepted cached code')
                with self.assertRaisesRegex(ValueError, 'UNLISTED_IMPORT'):
                    context['_private_import_guard']()


class ConnectionPolicyTests(unittest.TestCase):
    def test_task_bootstrap_migration_requires_explicit_profile(self):
        module = importlib.import_module('codestra_control.admission_installation')
        self.assertEqual(module.migration_sources('admission-v1'), module.MIGRATIONS)
        self.assertNotIn('016-authenticated-task-bootstrap.sql', module.MIGRATIONS)
        self.assertEqual(module.migration_sources('task-bootstrap-v1'),
                         module.MIGRATIONS + ('016-authenticated-task-bootstrap.sql',))
        for invalid in ('', 'global', None, True):
            with self.subTest(profile=invalid), self.assertRaisesRegex(ValueError, 'MIGRATION_PROFILE'):
                module.migration_sources(invalid)

    def test_installation_request_binds_migration_profile_to_exact_plan(self):
        module = importlib.import_module('codestra_control.admission_installation')
        candidate = SimpleNamespace(root=Path('/synthetic/candidate'), manifest_sha256='a' * 64)
        request = dict(schema='codestra.admission-installation-request.v1',
            candidate=str(candidate.root), manifest_sha256=candidate.manifest_sha256,
            runtime_selection={}, adopted_sources=[], configuration_sha256='b' * 64)
        self.assertIsNone(module._request_plan('plan', request, candidate))
        self.assertIsNone(module._request_plan('plan', dict(request, migration_profile='task-bootstrap-v1'), candidate))
        value = dict(schema='codestra.admission-installation-plan.v1',
            source_commit='c' * 40, manifest_sha256='a' * 64, configuration_sha256='b' * 64,
            adopted_sources=[], filesystem={'runtime': {'selection_sha256': module.digest(module.canonical({}))}},
            target={}, migration_profile='task-bootstrap-v1')
        plan = module.InstallationPlan(module.canonical(value))
        operation = dict(request, plan=plan.value, plan_sha256=plan.digest,
            attempt_id='11111111-1111-4111-8111-111111111111')
        with self.assertRaisesRegex(ValueError, 'PLAN_CONFLICT'):
            module._request_plan('install', operation, candidate)
        self.assertEqual(module._request_plan('install',
            dict(operation, migration_profile='task-bootstrap-v1'), candidate), plan)
        with self.assertRaisesRegex(ValueError, 'MIGRATION_PROFILE'):
            module._request_plan('plan', dict(request, migration_profile='unsupported'), candidate)

    def setUp(self):
        self.module = importlib.import_module('codestra_control.admission_installation')
        self.assertTrue(hasattr(self.module, 'connection_parameters'),
                        'The operational connection has no explicit transport policy')
        self.raw = b'host=dev-desktop port=5432 dbname=fixture user=operator password=synthetic sslmode=verify-full sslrootcert=/etc/codestra/control-plane/fixture-ca.pem'

    def test_poisoned_environment_and_abstract_socket_fail_before_connection(self):
        with patch.dict(os.environ, {'PGHOSTADDR': '127.0.0.2'}):
            with self.assertRaisesRegex(ValueError, 'ENVIRONMENT'):
                self.module.connection_parameters(self.raw)
        for raw in (self.raw.replace(b'host=dev-desktop', b'host=@abstract'),
                    self.raw.replace(b'host=dev-desktop', b'host=/tmp/socket'),
                    self.raw.replace(b'dbname=fixture', b"dbname='host=other'")):
            with self.subTest(raw=raw), patch('psycopg2.extensions.libpq_version', return_value=170000):
                with self.assertRaisesRegex(ValueError, 'CONNECTION'):
                    self.module.connection_parameters(raw)

    def test_default_client_certificates_and_unaccepted_authentication_are_disabled(self):
        with patch.dict(os.environ, {}, clear=True), patch('psycopg2.extensions.libpq_version', return_value=160000):
            params = self.module.connection_parameters(self.raw)
        self.assertEqual(params['sslcertmode'], 'disable')
        self.assertEqual(params['require_auth'], 'scram-sha-256')
        self.assertEqual(params['channel_binding'], 'require')
        self.assertEqual(params['options'], '-csearch_path=pg_catalog,pg_temp')


class OnlineAuthoritySessionTests(unittest.TestCase):
    def test_standby_cannot_supply_authoritative_revocation_state(self):
        module = importlib.import_module('codestra_control.admission_installation')
        identity = dict(system_identifier='11', database_oid=1, database_name='issuer',
            session_user='client', role_oid=2, current_user='client', authentication='scram-sha-256:client',
            set_role='none', ssl=True, client_sslmode='verify-full', postgres_major=16)
        selection = dict(identity={k: identity[k] for k in ('system_identifier', 'database_oid',
            'database_name', 'session_user', 'role_oid')}, catalog_sha256='a' * 64,
            grant_id='11111111-1111-4111-8111-111111111111')
        class Readback:
            query = ''
            def execute(self, query, values=None):
                self.query = query
            def fetchone(self):
                return (True,) if 'pg_is_in_recovery()' in self.query else (False,)
            def fetchall(self):
                return [('admission_bootstrap',), ('public',)]
        backend = SimpleNamespace(_identity=lambda cursor: identity,
            _catalog=lambda cursor, namespaces: ('a' * 64, {}, []))
        with patch.object(module, 'PostgresTarget', return_value=backend):
            authority = module.OnlinePostgresAuthority(object(), selection)
        # Keep the real authenticated-identity validation while substituting
        # only server/catalog readbacks at this SQL observation boundary.
        with patch.object(module, '_has_writer_capability', return_value=False):
            with self.assertRaisesRegex(ValueError, 'STANDBY'):
                authority._check(Readback(), {'target': {'system_identifier': '22'}})


def candidate_fixture(directory, wheel=None, system_tools=None, source_sha='a' * 40, administration=False):
    from codestra_control.controller_release import (SCHEMA_SOURCES, CONTROLLER_ENTRYPOINTS,
        REQUIRED_LIBRARIES, CONFIGURATION_SOURCES, CONTRACT_SOURCES)
    from codestra_control.publisher_release import ENTRYPOINTS
    names = tuple(dict.fromkeys(tuple(SCHEMA_SOURCES) + CONTROLLER_ENTRYPOINTS + ENTRYPOINTS
        + REQUIRED_LIBRARIES + CONFIGURATION_SOURCES + CONTRACT_SOURCES
        + tuple(str(p.relative_to(ROOT)) for p in (ROOT / 'lib').rglob('*.py'))
        + ('015-admission-installation-state.sql', 'bin/codestra-install-admission',
           'config/examples/admission-installation.proposal.json', 'docs/admission-installation.md')))
    if administration:
        names += ('018-admission-installation-lock.sql',)
    files = []
    if wheel is None:
        wheel = b'synthetic offline driver fixture, never imported or installed'
    driver = directory / 'vendor/fixture.whl'
    driver.parent.mkdir()
    driver.write_bytes(wheel)
    driver.chmod(0o644)
    for name in names:
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        data = (ROOT / name).read_bytes()
        if name == 'runtime-publisher-tools.json' and system_tools is not None:
            data = json.dumps(system_tools, sort_keys=True).encode()
        if name == 'requirements-publisher.txt':
            data = ('psycopg2-binary==2.9.10 --hash=sha256:' + hashlib.sha256(wheel).hexdigest() + '\n').encode()
        target.write_bytes(data)
        mode = 0o755 if name.startswith(('bin/', 'legacy/bin/')) else 0o644
        target.chmod(mode)
        runtime_root = '/opt/codestra-control-plane/releases/' + source_sha
        proposed_target = (None if name in CONFIGURATION_SOURCES else
            '/opt/codestra-dev/control-plane/bin/github-status-sync' if name.startswith('legacy/') else runtime_root + '/' + name)
        files.append(dict(source_path=name, sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                          size=target.stat().st_size, mode=oct(mode), proposed_target=proposed_target))
    driver_metadata = dict(path='vendor/fixture.whl', size=len(wheel), sha256=hashlib.sha256(wheel).hexdigest())
    runtime_metadata = dict(python='CPython3.12', platform='Linux x86_64', target_interpreter_verified=False)
    publisher = dict(schema='codestra.publisher-candidate.v1', source_commit=source_sha,
        release_approved=False, install_allowed=False, activation_allowed=False,
        driver_artifact=driver_metadata, runtime=runtime_metadata,
        proposed_runtime_root=runtime_root, files=[entry for entry in files if entry['source_path'] in ENTRYPOINTS or entry['source_path'].startswith('lib/')])
    publisher_raw = (json.dumps(publisher, sort_keys=True) + '\n').encode()
    (directory / 'release-manifest.json').write_bytes(publisher_raw)
    (directory / 'release-manifest.json').chmod(0o644)
    manifest = dict(schema='codestra.controller-candidate.v1', source_commit=source_sha,
                    proposed_runtime_root=runtime_root, publisher_component_manifest='release-manifest.json',
                    publisher_component_manifest_sha256=hashlib.sha256(publisher_raw).hexdigest(),
                    install_allowed=False, activation_allowed=False, files=files,
                    release_approved=False, database_setup_approved=False, authority_provisioning_approved=False,
                    driver_artifact=driver_metadata, runtime=runtime_metadata,
                    schema_sources=list(SCHEMA_SOURCES))
    raw = (json.dumps(manifest, sort_keys=True) + '\n').encode()
    path = directory / 'controller-release-manifest.json'
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


class CandidateTests(unittest.TestCase):
    def test_restricted_profile_requires_separate_admin_source_without_applying_it(self):
        from codestra_control import admission_installation as module
        selected = module.migration_sources('task-bootstrap-restricted-v1')
        self.assertEqual(selected, module.migration_sources('task-bootstrap-v1'))
        self.assertNotIn('018-admission-installation-lock.sql', selected)

    def setUp(self):
        try:
            self.module = importlib.import_module('codestra_control.admission_installation')
        except ImportError:
            self.fail('Admission installer candidate validation is missing')
        self.tmp = tempfile.TemporaryDirectory(prefix='cp-installer-unit-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.digest = candidate_fixture(self.root)

    def load(self, digest=None):
        return self.module.SourceCandidate.load(self.root, digest or self.digest)

    def rewrite_manifest(self, change):
        path = self.root / 'controller-release-manifest.json'
        value = json.loads(path.read_text())
        change(value)
        raw = json.dumps(value).encode()
        path.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def test_candidate_captures_verified_bytes_and_cannot_be_mutated(self):
        candidate = self.load()
        original = (self.root / 'schema.sql').read_bytes()
        self.assertEqual(candidate.files['schema.sql'], original)
        with self.assertRaises(TypeError):
            candidate.files['schema.sql'] = b'changed'
        (self.root / 'schema.sql').write_bytes(b'changed')
        self.assertEqual(candidate.files['schema.sql'], original)
        with self.assertRaisesRegex(ValueError, 'CANDIDATE'):
            candidate.revalidate()

    def test_wrong_manifest_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'MANIFEST'):
            self.load('b' * 64)

    def test_missing_or_changed_migration_is_rejected(self):
        (self.root / '005-scoped-registration.sql').write_bytes(b'wrong source')
        with self.assertRaisesRegex(ValueError, 'CANDIDATE'):
            self.load()

    def test_symlinked_file_and_parent_are_rejected(self):
        original = self.root / 'schema.sql'
        original.unlink()
        original.symlink_to(ROOT / 'schema.sql')
        with self.assertRaises(ValueError):
            self.load()
        original.unlink()
        original.write_bytes((ROOT / 'schema.sql').read_bytes())
        (self.root / 'bin').rename(self.root / 'original-bin')
        (self.root / 'bin').symlink_to(ROOT / 'bin', target_is_directory=True)
        with self.assertRaises(ValueError):
            self.load()

    def test_unsafe_duplicate_or_omitted_paths_are_rejected(self):
        for change in (
            lambda v: v['files'].append(dict(v['files'][0])),
            lambda v: v['files'][0].update(source_path='../schema.sql'),
            lambda v: v['files'].pop(0),
            lambda v: v.update(schema_sources=v['schema_sources'][:-1]),
        ):
            with self.subTest(change=change):
                original = (self.root / 'controller-release-manifest.json').read_bytes()
                digest = self.rewrite_manifest(change)
                with self.assertRaises(ValueError):
                    self.load(digest)
                (self.root / 'controller-release-manifest.json').write_bytes(original)

    def test_wrong_executable_mode_and_active_source_authority_are_rejected(self):
        (self.root / 'bin/codestra-install-admission').chmod(0o644)
        with self.assertRaises(ValueError):
            self.load()
        (self.root / 'bin/codestra-install-admission').chmod(0o755)
        digest = self.rewrite_manifest(lambda v: v.update(install_allowed=True))
        with self.assertRaises(ValueError):
            self.load(digest)

    def test_duplicate_manifest_keys_are_not_last_value_wins(self):
        path = self.root / 'controller-release-manifest.json'
        raw = path.read_bytes().replace(b'{', b'{"source_commit":"' + b'b' * 40 + b'",', 1)
        path.write_bytes(raw)
        with self.assertRaises(ValueError):
            self.load(hashlib.sha256(raw).hexdigest())

    def test_graph_is_dependency_resolved_and_rejects_missing_or_cyclic_nodes(self):
        order = self.module.migration_order({'late': ('early',), 'early': ()})
        self.assertEqual(order, ('early', 'late'))
        for graph in ({'a': ('missing',)}, {'a': ('b',), 'b': ('a',)}):
            with self.assertRaisesRegex(ValueError, 'DEPENDENCY'):
                self.module.migration_order(graph)

    def test_ddl_selection_is_the_bounded_admission_closure_not_package_inventory(self):
        self.assertEqual(set(self.module.MIGRATIONS), {'schema.sql', '002-hierarchy-promotion.sql',
            '005-scoped-registration.sql', '007-assignment-leases.sql', '009-atomic-inspection.sql',
            '009-controller-coordinator.sql', '010-controller-coordinator-integration.sql',
            '010-scoped-operation-admission.sql', '015-admission-installation-state.sql'})
        self.assertIn('008-frozen-recovery.sql', self.load().files)

    def test_missing_runtime_library_is_rejected(self):
        digest = self.rewrite_manifest(lambda v: v.update(files=[e for e in v['files']
            if e['source_path'] != 'lib/codestra_control/lease_interface.py']))
        with self.assertRaises(ValueError):
            self.load(digest)

    def test_corrupt_driver_is_rejected(self):
        (self.root / 'vendor/fixture.whl').write_bytes(b'changed driver')
        with self.assertRaises(ValueError):
            self.load()

    def test_runtime_targets_and_component_manifest_are_bound(self):
        original = (self.root / 'controller-release-manifest.json').read_bytes()
        for change in (
            lambda v: v.update(proposed_runtime_root='/tmp/arbitrary-release'),
            lambda v: v['files'][0].update(proposed_target='/tmp/arbitrary-file'),
        ):
            altered = self.rewrite_manifest(change)
            with self.assertRaises(ValueError):
                self.load(altered)
            (self.root / 'controller-release-manifest.json').write_bytes(original)
        (self.root / 'release-manifest.json').write_bytes(b'changed component manifest')
        with self.assertRaises(ValueError):
            self.load()

    def test_rehashed_active_or_contradictory_component_manifest_is_rejected(self):
        path = self.root / 'release-manifest.json'
        original = path.read_bytes()
        original_manifest = (self.root / 'controller-release-manifest.json').read_bytes()
        for mutate in (
            lambda value: value.update(install_allowed=True),
            lambda value: value['driver_artifact'].update(sha256='b' * 64),
            lambda value: value['runtime'].update(target_interpreter_verified=True),
        ):
            value = json.loads(original)
            mutate(value)
            path.write_bytes(json.dumps(value).encode())
            checksum = hashlib.sha256(path.read_bytes()).hexdigest()
            altered = self.rewrite_manifest(lambda value: value.update(publisher_component_manifest_sha256=checksum))
            with self.assertRaises(ValueError):
                self.load(altered)
            (self.root / 'controller-release-manifest.json').write_bytes(original_manifest)
        path.write_bytes(original)

    def test_live_configuration_cannot_be_hidden_in_a_rehashed_candidate(self):
        name = 'config/examples/admission-installation.proposal.json'
        value = json.loads((self.root / name).read_text())
        value['install_allowed'] = True
        data = json.dumps(value).encode()
        (self.root / name).write_bytes(data)
        def update(value):
            for entry in value['files']:
                if entry['source_path'] == name:
                    entry.update(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
        digest = self.rewrite_manifest(update)
        with self.assertRaises(ValueError):
            self.load(digest)

    def test_untrusted_authority_data_cannot_supply_a_runtime_adapter(self):
        for value in ({'approved': True, 'owner': 'Ralph'}, True, 'accepted'):
            with self.assertRaisesRegex(ValueError, 'AUTHORITY'):
                self.module.require_authority(value)

    def test_cli_mutating_operations_are_denied_without_touching_candidate(self):
        before = sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*'))
        for operation in ('install', 'rollback'):
            result = subprocess.run([sys.executable, '-B', str(ROOT / 'bin/codestra-install-admission'), operation],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), 'ADMISSION_INSTALLATION_OPERATIONALLY_UNAVAILABLE')
            self.assertEqual(result.stderr, '')
        self.assertEqual(sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*')), before)


class RecoveryBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.module = importlib.import_module('codestra_control.admission_installation')
        self.plan = self.module.InstallationPlan(self.module.canonical(dict(
            schema='codestra.admission-installation-plan.v1', source_commit='a' * 40,
            manifest_sha256='b' * 64, configuration_sha256='c' * 64,
            filesystem={}, target={})))
        module = self.module

        class Issuer(module.Authority):
            revoked = False
            uncertain = False

            def authorize(self, operation, binding, phase):
                if operation != 'rollback':
                    raise ValueError('DENIED')

            def revoke(self, binding):
                if self.uncertain:
                    raise module.InstallationOutcomeUnknown('synthetic lost issuer acknowledgement')
                self.revoked = True

        self.authority = Issuer()
        self.attempt = '4a8b01bb-3646-4315-866f-cc8d016bef53'

    def test_interruption_after_confirmed_revoke_reports_recording_incomplete(self):
        def interrupted(phase):
            self.assertTrue(self.authority.revoked)
            raise RuntimeError('synthetic private diagnostic never printed')

        with self.assertRaises(self.module.InstallationRevokedRecordingFailed) as caught:
            self.module.rollback(None, None, self.plan, None, self.attempt,
                self.authority, progress=interrupted)
        self.assertEqual(caught.exception.recording_outcome, 'INCOMPLETE')
        self.assertNotIn('private diagnostic', str(caught.exception))

    def test_unknown_issuer_commit_never_opens_target_or_claims_confirmed_revocation(self):
        self.authority.uncertain = True
        opened = []

        def target():
            opened.append('target')
            raise AssertionError('Unknown issuer outcome must stop before target access')

        with self.assertRaises(self.module.InstallationOutcomeUnknown):
            self.module.rollback(target, None, self.plan, target, self.attempt, self.authority)
        self.assertFalse(self.authority.revoked)
        self.assertEqual(opened, [])


class FileCustodyTests(unittest.TestCase):
    def setUp(self):
        self.module = importlib.import_module('codestra_control.admission_installation')
        if not hasattr(self.module, 'FileCustody'):
            self.fail('Immutable installation file custody is missing')
        self.tmp = tempfile.TemporaryDirectory(prefix='cp-installer-custody-')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        source = self.path / 'source'
        source.mkdir()
        self.candidate = self.module.SourceCandidate.load(source, candidate_fixture(source))
        self.root = self.path / 'installed'
        self.root.mkdir(mode=0o700)
        self.store = self.module.FileCustody(self.root, owner_uid=os.getuid())
        self.attempt = '4a8b01bb-3646-4315-866f-cc8d016bef53'

    def test_immutable_release_and_exact_retry_preserve_existing_files(self):
        self.store.install_release(self.candidate, self.attempt)
        path = self.root / 'releases' / self.candidate.manifest_sha256 / 'schema.sql'
        self.assertEqual(path.read_bytes(), self.candidate.files['schema.sql'])
        inode = path.stat().st_ino
        self.store.install_release(self.candidate, self.attempt)
        self.assertEqual(path.stat().st_ino, inode)
        path.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            self.store.install_release(self.candidate, self.attempt)
        self.assertEqual(path.read_bytes(), b'changed')

    def test_symlinked_installed_file_cannot_satisfy_release_verification(self):
        self.store.install_release(self.candidate, self.attempt)
        path = self.root / 'releases' / self.candidate.manifest_sha256 / 'schema.sql'
        path.unlink()
        path.symlink_to(ROOT / 'schema.sql')
        with self.assertRaises(ValueError):
            self.store.verify_release(self.candidate)

    def test_private_configuration_is_hash_bound_and_never_overwritten(self):
        data = b'private fixture configuration'
        self.store.install_configuration(data, self.attempt, hashlib.sha256(data).hexdigest())
        path = self.root / 'configurations' / self.attempt / 'configuration'
        self.assertEqual(path.read_bytes(), data)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError):
            self.store.install_configuration(b'wrong data', self.attempt, hashlib.sha256(data).hexdigest())
        self.assertEqual(path.read_bytes(), data)

    def test_replaced_or_writable_custody_root_fails_closed(self):
        self.root.chmod(0o777)
        with self.assertRaises(ValueError):
            self.store.verify_release(self.candidate)
        self.root.chmod(0o700)
        self.root.rename(self.path / 'original')
        self.root.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            self.store.install_release(self.candidate, self.attempt)

    def test_filesystem_fence_is_exclusive_across_open_descriptors(self):
        other = self.module.FileCustody(self.root, owner_uid=os.getuid())
        with self.store.fence():
            with self.assertRaisesRegex(ValueError, 'BUSY'):
                with other.fence():
                    self.fail('competing file installer acquired the fence')

    def test_retry_after_rename_sync_failure_completes_parent_durability(self):
        data = b'private configuration for durability test'
        checksum = hashlib.sha256(data).hexdigest()
        parent = self.root / 'configurations'
        parent.mkdir(mode=0o700)
        inode = parent.stat().st_ino
        target = parent / self.attempt
        original = os.fsync
        def interrupted(fd):
            if os.fstat(fd).st_ino == inode and target.exists():
                raise OSError('synthetic interruption after rename')
            original(fd)
        with patch.object(self.module.os, 'fsync', interrupted), self.assertRaises(ValueError):
            self.store.install_configuration(data, self.attempt, checksum)
        self.assertTrue(target.is_dir())
        synced = []
        def observed(fd):
            original(fd)
            synced.append(os.fstat(fd).st_ino)
        with patch.object(self.module.os, 'fsync', observed):
            self.store.install_configuration(data, self.attempt, checksum)
        self.assertIn(inode, synced)

    def test_configuration_verification_rejects_directory_drift_and_extra_files(self):
        data = b'private configuration'
        checksum = hashlib.sha256(data).hexdigest()
        self.store.install_configuration(data, self.attempt, checksum)
        directory = self.root / 'configurations' / self.attempt
        directory.chmod(0o755)
        with self.assertRaises(ValueError):
            self.store.verify_configuration(self.attempt, checksum)
        directory.chmod(0o700)
        (directory / 'unaccepted').write_bytes(b'extra')
        with self.assertRaises(ValueError):
            self.store.verify_configuration(self.attempt, checksum)

    def test_unsupported_creation_group_is_rejected_before_any_write(self):
        before = tuple(self.root.iterdir())
        with patch.object(self.module.os, 'getegid', return_value=os.getegid() + 1):
            with self.assertRaisesRegex(ValueError, 'CUSTODY'):
                self.module.FileCustody(self.root, owner_uid=os.getuid())
        self.assertEqual(tuple(self.root.iterdir()), before)


class RuntimeTargetTests(unittest.TestCase):
    def group_reader_specification(self):
        spec,config=self.restricted_specification()
        spec.update(schema='codestra.admission-runtime-selection.v3',runtime_reader={'uid':os.getuid(),'gid':os.getgid(),'custody_reference_sha256':'e'*64})
        parent=self.namespace_root/'etc/codestra/control-plane/credentials/task-bootstrap-runtime';parent.chmod(0o750)
        for path in spec['credential_files']:(self.namespace_root/Path(path).relative_to('/')).chmod(0o640)
        spec['configuration'][self.module.TASK_CONFIGURATION_TARGET].update(mode='0o640',gid=os.getgid())
        return spec,config

    def test_explicit_runtime_reader_selection_installs_group_read_only_configuration(self):
        spec,config=self.group_reader_specification()
        store=self.module.RuntimeCustody(self.journal,self.candidate,spec,self.namespace)
        data=json.dumps({self.module.TASK_CONFIGURATION_TARGET:base64.b64encode(config).decode()},sort_keys=True).encode()
        store.install_configuration(data,self.attempt,hashlib.sha256(data).hexdigest());store.verify_configuration(self.attempt,hashlib.sha256(data).hexdigest())
        target=self.namespace_root/Path(self.module.TASK_CONFIGURATION_TARGET).relative_to('/')
        self.assertEqual(target.stat().st_mode&0o777,0o640);self.assertEqual(target.stat().st_gid,os.getgid())
        self.assertEqual(store.binding['runtime']['publication_mode'],'TASK_BOOTSTRAP_CLI_ONLY')

    def test_group_reader_needs_exact_identity_reference_and_narrow_private_metadata(self):
        spec,_=self.group_reader_specification()
        for changed in ({'uid':0,'gid':os.getgid(),'custody_reference_sha256':'e'*64},{'uid':os.getuid(),'gid':0,'custody_reference_sha256':'e'*64},{'uid':os.getuid(),'gid':os.getgid(),'custody_reference_sha256':None}):
            bad=json.loads(json.dumps(spec));bad['runtime_reader']=changed
            with self.assertRaises(ValueError):self.module._runtime_specification(bad,self.namespace)
        parent=self.namespace_root/'etc/codestra/control-plane/credentials/task-bootstrap-runtime';parent.chmod(0o755)
        with self.assertRaisesRegex(ValueError,'PRIVATE'):self.module.RuntimeCustody(self.journal,self.candidate,spec,self.namespace)

    def restricted_specification(self):
        spec=json.loads(json.dumps(self.specification))
        spec.update(schema='codestra.admission-runtime-selection.v2',publication_mode='TASK_BOOTSTRAP_CLI_ONLY',
            verifier_credentials={'database_dsn_file':'/etc/codestra/control-plane/credentials/task-bootstrap-runtime/connection.dsn',
                'app_key_file':'/etc/codestra/control-plane/credentials/task-bootstrap-runtime/app.pem'})
        old=list(self.credentials.values());private=spec['verifier_credentials']
        for name,data in zip(private.values(),old):
            self.write(name,data,0o600)
            (self.namespace_root/Path(name).parent.relative_to('/')).chmod(0o700)
        # write() normalizes fixture parents; restore after both writes.
        (self.namespace_root/'etc/codestra/control-plane/credentials/task-bootstrap-runtime').chmod(0o700)
        spec['credential_files']={name:hashlib.sha256(data).hexdigest() for name,data in zip(private.values(),old)}
        config=self.configuration.replace(b'/credentials/lease-verifier.dsn',b'/credentials/task-bootstrap-runtime/connection.dsn').replace(b'/credentials/lease-verifier-app.pem',b'/credentials/task-bootstrap-runtime/app.pem')
        spec['configuration']={self.module.TASK_CONFIGURATION_TARGET:{'sha256':hashlib.sha256(config).hexdigest(),'gid':os.getegid(),'mode':'0o600'}}
        return spec,config

    def test_cli_only_release_preserves_different_legacy_publisher_and_skips_its_ancestry(self):
        spec,config=self.restricted_specification();legacy=self.namespace_root/'opt/codestra-dev/control-plane/bin/github-status-sync'
        self.write('/opt/codestra-dev/control-plane/bin/github-status-sync',b'EXISTING_PUBLISHER_UNRELATED',0o755)
        (self.namespace_root/'opt/codestra-dev').chmod(0o777)
        before=(legacy.read_bytes(),legacy.stat().st_ino)
        store=self.module.RuntimeCustody(self.journal,self.candidate,spec,self.namespace)
        store.install_release(self.candidate,self.attempt);store.verify_release(self.candidate)
        data=json.dumps({self.module.TASK_CONFIGURATION_TARGET:base64.b64encode(config).decode()},sort_keys=True).encode();store.install_configuration(data,self.attempt,hashlib.sha256(data).hexdigest())
        self.assertEqual((legacy.read_bytes(),legacy.stat().st_ino),before)
        self.assertEqual(store.binding['runtime']['publication_mode'],'TASK_BOOTSTRAP_CLI_ONLY')
        self.assertFalse(any('/opt/codestra-dev/' in path for path in store.binding['runtime']['parent_bindings']))

    def test_cli_only_selection_requires_private_distinct_runtime_credentials(self):
        spec,_=self.restricted_specification();parent=self.namespace_root/'etc/codestra/control-plane/credentials/task-bootstrap-runtime'
        parent.chmod(0o755)
        with self.assertRaisesRegex(ValueError,'PRIVATE'):
            self.module.RuntimeCustody(self.journal,self.candidate,spec,self.namespace)
        for mode in ('PUBLISHER','ADMISSION_AND_LEGACY'):
            bad=json.loads(json.dumps(spec));bad['publication_mode']=mode
            with self.assertRaises(ValueError):self.module._runtime_specification(bad,self.namespace)
        bad=json.loads(json.dumps(spec));bad['verifier_credentials']['database_dsn_file']=self.module.INSTALLER_CREDENTIALS['operator']
        with self.assertRaises(ValueError):self.module._runtime_specification(bad,self.namespace)

    def test_private_installer_profile_changes_only_two_admission_paths(self):
        config={'schema':'codestra.admission-installer-config.v3','issuer':{},'lock_selection':{},'credential_profile':'pas233-private-v1'}
        paths=self.module.installer_credential_paths(config,restricted=True)
        self.assertEqual(paths['operator'],'/etc/codestra/control-plane/credentials/pas233-admission-install-20261028-v1/connection.dsn')
        self.assertEqual(paths['installation_verifier'],'/etc/codestra/control-plane/credentials/pas233-admission-verify-20261028-v1/connection.dsn')
        self.assertEqual(paths['issuer'],self.module.INSTALLER_CREDENTIALS['issuer']);self.assertEqual(paths['verifier'],self.module.INSTALLER_CREDENTIALS['verifier'])
        with self.assertRaises(ValueError):self.module.installer_credential_paths(config,restricted=False)
        bad=dict(config,credential_profile='other')
        with self.assertRaises(ValueError):self.module.installer_credential_paths(bad,restricted=True)

    def test_cli_only_request_cannot_be_used_with_broader_migration_profile(self):
        spec,_=self.restricted_specification()
        request=dict(schema='codestra.admission-installation-request.v1',candidate=str(self.candidate.root),
            manifest_sha256=self.candidate.manifest_sha256,runtime_selection=spec,adopted_sources=[],
            configuration_sha256='a'*64,migration_profile='admission-v1')
        with self.assertRaisesRegex(ValueError,'RESTRICTED'):
            self.module._request_plan('plan',request,self.candidate)

    def test_private_configured_connections_keep_new_dsns_private_during_rechecks(self):
        import psycopg2
        spec,_=self.restricted_specification()
        config={'schema':'codestra.admission-installer-config.v3','issuer':{},'lock_selection':{},'credential_profile':'pas233-private-v1'}
        paths=self.module.installer_credential_paths(config,restricted=True);raw=b'synthetic-config';ca='/etc/codestra/control-plane/fixture-ca.crt'
        inputs={self.module.INSTALLER_CONFIG:raw,ca:b'public-fixture-ca'}
        for role in ('operator','installation_verifier'):
            self.write(paths[role],role.encode(),0o600)
            (self.namespace_root/Path(paths[role]).parent.relative_to('/')).chmod(0o700)
            inputs[paths[role]]=role.encode()
        reads=[];opened=[]
        def read(ns,path,*,public=False):reads.append((path,public));return inputs[path]
        class Connection:
            autocommit=False
            def get_transaction_status(self):return 0
            def close(self):pass
        def connect(**params):opened.append(params['role']);return Connection()
        request=dict(schema='codestra.admission-installation-request.v1',candidate=str(self.candidate.root),
            manifest_sha256=self.candidate.manifest_sha256,runtime_selection=spec,adopted_sources=[],configuration_sha256='a'*64,
            migration_profile=self.module.RESTRICTED_PROFILE)
        with patch.object(self.module,'_protected_input',side_effect=read),patch.object(self.module,'connection_parameters',side_effect=lambda value:dict(role=value.decode(),sslrootcert=ca)),patch.object(psycopg2,'connect',connect),patch.object(self.module,'_installation_journal',return_value=self.journal),patch.object(self.module,'dispatch_request',return_value='composed'):
            self.assertEqual(self.module._configured_connections('plan',request,self.candidate,self.namespace,raw,config),'composed')
        self.assertEqual(opened,['operator','installation_verifier'])
        for role in ('operator','installation_verifier'):
            selected=[public for path,public in reads if path==paths[role]]
            self.assertGreaterEqual(len(selected),2);self.assertEqual(set(selected),{False})

    def test_configured_profile_uses_fixed_distinct_installation_reader(self):
        import psycopg2
        class Connection:
            autocommit = False
            def get_transaction_status(self):
                return 0
            def close(self):
                pass
        for profile, expected in (('admission-v1', ['operator']),
                                  ('task-bootstrap-restricted-v1', ['operator', 'installation_verifier'])):
            with self.subTest(profile=profile):
                request = dict(schema='codestra.admission-installation-request.v1',
                    candidate=str(self.candidate.root), manifest_sha256=self.candidate.manifest_sha256,
                    runtime_selection=self.specification, adopted_sources=['schema.sql', '002-hierarchy-promotion.sql'],
                    configuration_sha256=hashlib.sha256(self.bundle()).hexdigest(), migration_profile=profile)
                config = dict(schema='codestra.admission-installer-config.' + ('v2' if len(expected) == 2 else 'v1'), issuer={})
                if len(expected) == 2:
                    config['lock_selection'] = dict(profile_sha256='a' * 64)
                raw = b'synthetic-protected-configuration'
                ca = '/etc/codestra/control-plane/fixture-ca.crt'
                inputs = {self.module.INSTALLER_CONFIG: raw, ca: b'synthetic-public-ca'}
                inputs.update({self.module.INSTALLER_CREDENTIALS[role]: role.encode() for role in expected})
                opened = []
                def connect(**params):
                    opened.append(params['role'])
                    return Connection()
                def dispatch(operation, data, candidate, backend, store, **kwargs):
                    self.assertEqual(backend.reader is not None, len(expected) == 2)
                    return 'composed'
                with patch.object(self.module, '_protected_input', side_effect=lambda ns, path, **kw: inputs[path]), \
                        patch.object(self.module, 'connection_parameters', side_effect=lambda value: dict(role=value.decode(), sslrootcert=ca)), \
                        patch.object(psycopg2, 'connect', connect), \
                        patch.object(self.module, '_installation_journal', return_value=self.journal), \
                        patch.object(self.module, 'dispatch_request', dispatch):
                    self.assertEqual(self.module._configured_connections('plan', request, self.candidate,
                        self.namespace, raw, config), 'composed')
                self.assertEqual(opened, expected)

    def setUp(self):
        self.module = importlib.import_module('codestra_control.admission_installation')
        if not hasattr(self.module, 'RuntimeCustody'):
            self.fail('Concrete fixed-target runtime custody is missing')
        self.tmp = tempfile.TemporaryDirectory(prefix='cp-runtime-namespace-')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.namespace_root = self.path / 'namespace'
        self.namespace_root.mkdir(mode=0o700)
        self.namespace = self.module.RuntimeNamespace(self.namespace_root)
        self.driver = '/usr/lib/python3/dist-packages'
        self.package = {
            'psycopg2/__init__.py': b'__version__ = "2.9.10"\n',
            'psycopg2/_psycopg.cpython-312-x86_64-linux-gnu.so': b'fixture native bytes; never executed',
            'psycopg2_binary-2.9.10.dist-info/METADATA': b'Name: psycopg2-binary\nVersion: 2.9.10\n',
        }
        rows = [name + ',sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode() + ',' + str(len(data)) for name, data in self.package.items()]
        record = 'psycopg2_binary-2.9.10.dist-info/RECORD'
        self.package[record] = ('\n'.join(rows + [record + ',,']) + '\n').encode()
        wheel = io.BytesIO()
        with zipfile.ZipFile(wheel, 'w') as archive:
            for name, data in self.package.items():
                archive.writestr(name, data)
                self.write(self.driver + '/' + name, data)
        for name in ('/opt/codestra-control-plane/releases', '/opt/codestra-dev/control-plane/bin',
                     '/etc/codestra/control-plane', '/usr/lib/python3.12'):
            self.directory(name)
        self.write('/usr/lib/python3.12/fixture_stdlib.py', b'# protected fixture stdlib\n')
        self.write('/usr/bin/python3.12', b'protected fixture interpreter; never executed', 0o755)
        self.write('/etc/machine-id', b'fixture-machine-id\n')
        (self.namespace_root / 'usr/bin/python3').symlink_to('python3.12')
        self.credentials = {
            '/etc/codestra/control-plane/credentials/lease-verifier.dsn': b'SYNTHETIC-PRIVATE-SECRET-do-not-export',
            '/etc/codestra/control-plane/credentials/lease-verifier-app.pem': b'SYNTHETIC-KEY-REFERENCE-do-not-export',
        }
        for name, data in self.credentials.items():
            self.write(name, data, 0o600)
        tools = {}
        for name in ('/usr/bin/git', '/usr/bin/openssl', '/usr/lib/x86_64-linux-gnu/libcrypto.so.3', '/usr/lib/x86_64-linux-gnu/libssl.so.3'):
            data = ('protected fixture tool ' + name).encode()
            tools[name] = hashlib.sha256(data).hexdigest()
            self.write(name, data, 0o755 if name.startswith('/usr/bin/') else 0o644)
        self.configuration = b'database_dsn_file="/etc/codestra/control-plane/credentials/lease-verifier.dsn"\napp_id=123\ninstallation_id=456\napp_key_file="/etc/codestra/control-plane/credentials/lease-verifier-app.pem"\n'
        self.configuration_target = '/etc/codestra/control-plane/lease-verifier.toml'
        self.specification = {
            'schema': 'codestra.admission-runtime-selection.v1',
            'interpreter_sha256': hashlib.sha256((self.namespace_root / 'usr/bin/python3.12').read_bytes()).hexdigest(),
            'machine_id_sha256': hashlib.sha256(b'fixture-machine-id\n').hexdigest(),
            'writer_exclusion_reference': 'synthetic-fixture-exclusion',
            'recovery_reference': 'synthetic-fixture-exclusive-create-recovery',
            'driver_directory': self.driver,
            'import_roots': {name: self.namespace.snapshot(name) for name in ('/usr/lib/python3.12', self.driver)},
            'import_path_order': ['/usr/lib/python3.12', self.driver],
            'credential_files': {name: hashlib.sha256(data).hexdigest() for name, data in self.credentials.items()},
            'configuration': {self.configuration_target: {'sha256': hashlib.sha256(self.configuration).hexdigest(),
                                'gid': os.getegid(), 'mode': '0o600'}},
        }
        source = self.path / 'source'
        source.mkdir()
        self.candidate = self.module.SourceCandidate.load(source, candidate_fixture(source, wheel.getvalue(),
            dict(schema='codestra.publisher-system-tools.v1', target_verified=False, provisioning_approved=False, files=tools)))
        private = self.path / 'private'
        private.mkdir(mode=0o700)
        self.journal = self.module.FileCustody(private, owner_uid=os.getuid())
        self.store = self.module.RuntimeCustody(self.journal, self.candidate, self.specification, self.namespace)
        self.attempt = '4a8b01bb-3646-4315-866f-cc8d016bef53'

    def directory(self, absolute):
        directory = self.namespace_root / absolute.lstrip('/')
        directory.mkdir(parents=True, exist_ok=True)
        for parent in (directory, *directory.parents):
            if parent == self.namespace_root:
                break
            parent.chmod(0o755)

    def write(self, absolute, data, mode=0o644):
        self.directory(str(Path(absolute).parent))
        path = self.namespace_root / absolute.lstrip('/')
        path.write_bytes(data)
        path.chmod(mode)

    def bundle(self, configuration=None):
        return json.dumps({self.configuration_target: base64.b64encode(self.configuration if configuration is None else configuration).decode()}, sort_keys=True).encode()

    def test_writable_journal_ancestor_is_rejected_before_runtime_writes(self):
        self.path.chmod(0o777)
        try:
            with self.assertRaises(ValueError):
                self.module.RuntimeCustody(self.journal, self.candidate, self.specification, self.namespace)
        finally:
            self.path.chmod(0o700)
        self.assertFalse((self.namespace_root / ('opt/codestra-control-plane/releases/' + self.candidate.source_commit)).exists())

    def test_relocated_journal_with_same_inode_invalidates_ancestor_binding(self):
        previous = self.path.with_name(self.path.name + '-previous')
        inode = self.journal.root.stat().st_ino
        self.path.rename(previous)
        self.path.mkdir(mode=0o700)
        try:
            for child in list(previous.iterdir()):
                child.rename(self.path / child.name)
            self.assertEqual(self.journal.root.stat().st_ino, inode)
            with self.assertRaises(ValueError):
                self.store.verify_prerequisites()
        finally:
            for child in list(self.path.iterdir()):
                child.rename(previous / child.name)
            self.path.rmdir()
            previous.rename(self.path)

    def test_fixed_targets_are_durable_and_fixture_cannot_claim_host_installation(self):
        self.store.install_release(self.candidate, self.attempt)
        path = self.namespace_root / ('opt/codestra-control-plane/releases/' + self.candidate.source_commit + '/bin/codestra-admission')
        self.assertEqual(path.read_bytes(), self.candidate.files['bin/codestra-admission'])
        self.assertEqual(path.stat().st_mode & 0o777, 0o755)
        inode = path.stat().st_ino
        self.store.install_release(self.candidate, self.attempt)
        self.assertEqual(path.stat().st_ino, inode)
        legacy = self.namespace_root / 'opt/codestra-dev/control-plane/bin/github-status-sync'
        self.assertEqual(legacy.read_bytes(), self.candidate.files['legacy/bin/github-status-sync'])
        data = self.bundle()
        self.store.install_configuration(data, self.attempt, hashlib.sha256(data).hexdigest())
        self.store.verify_release(self.candidate)
        self.store.verify_configuration(self.attempt, hashlib.sha256(data).hexdigest())
        self.assertFalse(self.store.runtime_installed)
        release = path.parents[1]
        self.assertFalse((release / 'config/examples/lease-verifier.proposed.toml').exists())
        self.assertFalse((release / 'vendor/fixture.whl').exists())
        self.assertFalse((release / 'legacy/bin/github-status-sync').exists())
        self.assertEqual(self.store.binding['runtime']['namespace_kind'], 'DISPOSABLE_FIXTURE')
        self.assertNotIn('SYNTHETIC-PRIVATE-SECRET', json.dumps(self.store.binding))

    def test_differing_configuration_is_preserved_before_any_installation(self):
        self.write(self.configuration_target, b'original private configuration', 0o600)
        with self.assertRaises(ValueError):
            self.module.RuntimeCustody(self.journal, self.candidate, self.specification, self.namespace)
        self.assertEqual((self.namespace_root / self.configuration_target.lstrip('/')).read_bytes(), b'original private configuration')
        self.assertFalse((self.namespace_root / ('opt/codestra-control-plane/releases/' + self.candidate.source_commit)).exists())

    def test_recovery_client_checks_execution_without_installed_target_dependencies(self):
        self.assertTrue(hasattr(self.module, 'RuntimeExecution'),
                        'Recovery client custody is still coupled to installed targets')
        self.store.install_release(self.candidate, self.attempt)
        data = self.bundle()
        self.store.install_configuration(data, self.attempt, hashlib.sha256(data).hexdigest())
        self.write(self.configuration_target, b'damaged installed configuration', 0o755)
        for name in (*self.credentials, '/usr/bin/git', '/usr/bin/openssl'):
            (self.namespace_root / name.lstrip('/')).unlink()
        recovery = self.module.RuntimeExecution(self.candidate, self.specification, self.namespace)
        recovery.verify()
        self.write(self.driver + '/psycopg2/__init__.py', b'untrusted executing driver')
        with self.assertRaisesRegex(ValueError, 'DRIVER|PREREQUISITE'):
            recovery.verify()

    def test_rehashed_installed_record_cannot_override_pinned_driver_archive(self):
        self.write(self.driver + '/psycopg2/__init__.py', b'__version__="2.9.10"\n# tampered')
        self.write(self.driver + '/psycopg2_binary-2.9.10.dist-info/RECORD', b'forged self-consistent installed metadata')
        with self.assertRaisesRegex(ValueError, 'DRIVER|PREREQUISITE'):
            self.store.verify_prerequisites()

    def test_configuration_has_exact_schema_and_positive_integer_identities(self):
        wrong = self.configuration.replace(b'app_id=123', b'app_id=true')
        specification = json.loads(json.dumps(self.specification))
        specification['configuration'][self.configuration_target]['sha256'] = hashlib.sha256(wrong).hexdigest()
        store = self.module.RuntimeCustody(self.journal, self.candidate, specification, self.namespace)
        data = self.bundle(wrong)
        with self.assertRaisesRegex(ValueError, 'CONFIGURATION'):
            store.install_configuration(data, self.attempt, hashlib.sha256(data).hexdigest())
        self.assertFalse((self.namespace_root / self.configuration_target.lstrip('/')).exists())

    def test_prerequisite_drift_stops_configuration_after_release(self):
        self.store.install_release(self.candidate, self.attempt)
        self.write('/usr/bin/python3.12', b'changed interpreter', 0o755)
        data = self.bundle()
        with self.assertRaisesRegex(ValueError, 'INTERPRETER|PREREQUISITE'):
            self.store.install_configuration(data, self.attempt, hashlib.sha256(data).hexdigest())
        self.assertFalse((self.namespace_root / self.configuration_target.lstrip('/')).exists())
        self.assertTrue((self.namespace_root / ('opt/codestra-control-plane/releases/' + self.candidate.source_commit)).is_dir())

    def test_writable_ancestry_is_rejected_before_probe_or_write(self):
        (self.namespace_root / 'opt/codestra-control-plane').chmod(0o777)
        with patch.object(self.module.subprocess, 'run') as probe, self.assertRaises(ValueError):
            self.store.install_release(self.candidate, self.attempt)
        probe.assert_not_called()

    def test_host_namespace_requires_native_root_without_side_effects(self):
        if os.geteuid() != 0:
            with self.assertRaisesRegex(ValueError, 'NATIVE_ROOT'):
                self.module.RuntimeNamespace('/')
        with self.assertRaises(ValueError):
            self.module.RuntimeNamespace('//')
        with self.assertRaises(AttributeError):
            self.namespace.is_host = True

    def test_tool_pin_drift_is_rejected_before_any_target_write(self):
        self.write('/usr/bin/git', b'unaccepted git tool', 0o755)
        with self.assertRaisesRegex(ValueError, 'TOOL'):
            self.store.install_release(self.candidate, self.attempt)
        self.assertFalse((self.namespace_root / ('opt/codestra-control-plane/releases/' + self.candidate.source_commit)).exists())

    def test_runtime_store_cannot_be_rebound_to_a_different_exact_candidate(self):
        source = self.path / 'different-candidate'
        source.mkdir()
        candidate = self.module.SourceCandidate.load(source, candidate_fixture(source,
            self.candidate.files['vendor/fixture.whl'], json.loads(self.candidate.files['runtime-publisher-tools.json']),
            source_sha='b' * 40))
        data = self.bundle()
        with self.assertRaisesRegex(ValueError, 'CANDIDATE_CONFLICT'):
            self.store.preflight(candidate, data, hashlib.sha256(data).hexdigest())
        self.assertFalse((self.namespace_root / ('opt/codestra-control-plane/releases/' + candidate.source_commit)).exists())

    def test_running_client_requires_pinned_interpreter_and_import_environment(self):
        execution = self.store._execution
        self.assertTrue(hasattr(execution, 'verify_process'),
                        'The running issuer process is not bound to its verified environment')
        paths = [str(self.candidate.root / 'lib'), *self.specification['import_path_order']]
        with patch.dict(sys.modules), patch.object(sys, 'path', paths), \
                patch.object(sys, 'executable', '/usr/bin/python3.12'), \
                patch.object(sys, 'flags', SimpleNamespace(isolated=1)), \
                patch.object(sys, 'dont_write_bytecode', True):
            for name in list(sys.modules):
                if name == 'psycopg2' or name.startswith('psycopg2.'):
                    del sys.modules[name]
            execution.verify_process()
            for field, wrong in (('executable', '/tmp/alternate-python'),
                    ('path', [str(self.candidate.root / 'lib'), '/tmp/venv/site-packages', *self.specification['import_path_order']]),
                    ('version_info', (3, 13)), ('prefix', '/tmp/venv')):
                with self.subTest(field=field), patch.object(sys, field, wrong):
                    with self.assertRaisesRegex(ValueError, 'RUNNING_CLIENT'):
                        execution.verify_process()
            sys.modules['psycopg2'] = SimpleNamespace(__file__='/tmp/unverified/psycopg2/__init__.py',
                __spec__=SimpleNamespace(origin='/tmp/unverified/psycopg2/__init__.py'))
            with self.assertRaisesRegex(ValueError, 'RUNNING_CLIENT'):
                execution.verify_process()
            self.assertNotIn('psycopg2._psycopg', sys.modules)

    def test_loaded_driver_requires_the_pinned_package_and_native_extension(self):
        execution = self.store._execution
        self.assertTrue(hasattr(execution, 'verify_process'),
                        'Loaded driver custody is not checked in the running client')
        package = self.driver + '/psycopg2/__init__.py'
        extension = self.driver + '/psycopg2/_psycopg.cpython-312-x86_64-linux-gnu.so'
        with patch.dict(sys.modules), patch.object(sys, 'path',
                [str(self.candidate.root / 'lib'), *self.specification['import_path_order']]), \
                patch.object(sys, 'executable', '/usr/bin/python3.12'), \
                patch.object(sys, 'flags', SimpleNamespace(isolated=1)), \
                patch.object(sys, 'dont_write_bytecode', True):
            for name in list(sys.modules):
                if name == 'psycopg2' or name.startswith('psycopg2.'):
                    del sys.modules[name]
            sys.modules['psycopg2'] = SimpleNamespace(__file__=package, __spec__=SimpleNamespace(origin=package),
                __path__=[self.driver + '/psycopg2'], __version__='2.9.10 synthetic fixture')
            sys.modules['psycopg2._psycopg'] = SimpleNamespace(__file__=extension,
                __spec__=SimpleNamespace(origin=extension))
            execution.verify_process(require_driver=True)
            sys.modules['psycopg2._psycopg'].__file__ = '/tmp/unverified/driver.so'
            with self.assertRaisesRegex(ValueError, 'RUNNING_CLIENT'):
                execution.verify_process(require_driver=True)

    def test_probe_protocol_requires_exact_import_resolution(self):
        expected = dict(python=[3, 12], platform='linux', machine='x86_64', executable='/usr/bin/python3.12',
            paths=self.specification['import_path_order'], driver=self.driver + '/psycopg2/__init__.py',
            extension=self.driver + '/psycopg2/_psycopg.cpython-312-x86_64-linux-gnu.so', version='2.9.10')
        for field, wrong in (
            ('extension', self.driver + '/psycopg2/_psycopg.unaccepted.so'),
            ('driver', '/tmp/psycopg2/__init__.py'), ('python', [3, 11]),
            ('paths', list(reversed(expected['paths']))), ('version', '2.9.9'),
        ):
            value = dict(expected, **{field: wrong})
            result = subprocess.CompletedProcess([], 0, json.dumps(value).encode(), b'')
            with self.subTest(field=field), patch.object(self.module.subprocess, 'run', return_value=result) as probe:
                with self.assertRaisesRegex(ValueError, 'IMPORT_RESOLUTION'):
                    self.store._probe(self.specification)
            call = probe.call_args
            self.assertEqual(call.args[0][:3], ['/usr/bin/python3', '-I', '-B'])
            self.assertEqual(call.kwargs['cwd'], '/')
            self.assertEqual(call.kwargs['timeout'], 15)
            self.assertEqual(call.kwargs['env'], {'PATH': os.defpath, 'LC_ALL': 'C'})
        with patch.object(self.module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(expected).encode(), b'')):
            self.store._probe(self.specification)
        self.assertFalse(self.store.runtime_installed)


if __name__ == '__main__':
    unittest.main()
