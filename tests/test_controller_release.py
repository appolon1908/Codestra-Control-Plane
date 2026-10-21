"""Complete controller candidates must not omit the protected admission clients."""
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from codestra_control.publisher_release import ENTRYPOINTS, prepare_release


class ControllerReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'repo'
        self.root.mkdir()
        self.wheel = Path(self.temporary.name) / 'fixture.whl'
        self.wheel.write_bytes(b'controller driver fixture, never installed')
        self.git('init')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        for name in ENTRYPOINTS + ('bin/codestra-coordinate', 'bin/codestra-admission',
                                  'bin/codestra-register', 'bin/codestra-inspect-atomic', 'bin/codestra-install-admission',
                                  'lib/codestra_control/publisher_ownership.py',
                                  'lib/codestra_control/certifier_adapter.py'):
            self.write(name, b'# fixture source\n')
        self.write('requirements-publisher.txt', ('psycopg2-binary==2.9.10 --hash=sha256:'
                    + hashlib.sha256(self.wheel.read_bytes()).hexdigest() + '\n').encode())
        self.write('runtime-publisher-tools.json', json.dumps({
            'schema': 'codestra.publisher-system-tools.v1',
            'target_verified': False, 'provisioning_approved': False}).encode())
        source = Path(__file__).resolve().parents[1]
        for name in ('codestra-coordinate','codestra-admission','codestra-register','codestra-inspect-atomic','codestra-install-admission'):
            self.write('bin/'+name,(source/'bin'/name).read_bytes())
        for path in (source / 'lib').rglob('*.py'):
            self.write(str(path.relative_to(source)), path.read_bytes())
        for path in source.glob('*.sql'):
            self.write(path.name, path.read_bytes())
        for path in (source / 'config/examples').glob('*'):
            if path.is_file():
                self.write(str(path.relative_to(source)), path.read_bytes())
        for name in ('assignment-backed-leases', 'controller-coordinator',
                     'scoped-operation-admission', 'certifier-existing-receipt-source',
                     'publisher-certifier-action-time-approval','atomic-inclusion-receipts','global-controller-coverage', 'admission-installation'):
            self.write('docs/' + name + '.md', (source / 'docs' / (name + '.md')).read_bytes())
        self.write('config/contracts/global-coverage-acceptance.schema.json',
            (source/'config/contracts/global-coverage-acceptance.schema.json').read_bytes())
        self.git('add', '.')
        self.git('commit', '-m', 'fixture')
        self.sha = self.git('rev-parse', 'HEAD')

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        if name.startswith(('bin/', 'legacy/bin/')):
            path.chmod(0o755)

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args],
                                       stderr=subprocess.DEVNULL, text=True).strip()

    def test_new_candidate_is_distinct_and_contains_both_admission_clients(self):
        module = importlib.import_module('codestra_control.controller_release')
        manifest = module.prepare_controller_release(
            self.root, self.sha, Path(self.temporary.name) / 'complete', self.wheel)
        self.assertEqual(manifest['schema'], 'codestra.controller-candidate.v1')
        names = {item['source_path'] for item in manifest['files']}
        self.assertTrue({'bin/codestra-coordinate', 'bin/codestra-admission',
                         'bin/codestra-register', 'bin/codestra-inspect-atomic'} <= names)
        self.assertFalse(manifest['install_allowed'])
        self.assertFalse(manifest['activation_allowed'])
        self.assertFalse(manifest['database_setup_approved'])
        self.assertIn('010-scoped-operation-admission.sql', manifest['schema_sources'])
        self.assertIn('config/examples/lease-verifier.proposed.toml', manifest['configuration_templates'])
        self.assertFalse((Path(self.temporary.name) / 'complete/bin/codestra-certify-scope').exists())

    def test_missing_client_schema_or_configuration_refuses_before_output(self):
        module = importlib.import_module('codestra_control.controller_release')
        for number, name in enumerate(('bin/codestra-admission',
                                       '010-scoped-operation-admission.sql',
                                       'config/examples/lease-verifier.proposed.toml')):
            with self.subTest(missing=name):
                self.git('rm', name)
                self.git('commit', '-m', 'missing required fixture')
                changed = self.git('rev-parse', 'HEAD')
                output = Path(self.temporary.name) / ('missing-' + str(number))
                with self.assertRaisesRegex(ValueError, 'INCOMPLETE_CONTROLLER_PACKAGE'):
                    module.prepare_controller_release(self.root, changed, output, self.wheel)
                self.assertFalse(output.exists())
                self.git('reset', '--hard', self.sha)

    def test_installer_candidate_is_complete_and_still_has_no_operational_authority(self):
        module = importlib.import_module('codestra_control.controller_release')
        installer = importlib.import_module('codestra_control.admission_installation')
        output = Path(self.temporary.name) / 'installer-source'
        manifest = module.prepare_controller_release(self.root, self.sha, output, self.wheel)
        names = {entry['source_path'] for entry in manifest['files']}
        self.assertTrue({'bin/codestra-install-admission', 'lib/codestra_control/admission_installation.py',
                         '015-admission-installation-state.sql', 'config/examples/admission-installation.proposal.json',
                         'docs/admission-installation.md'} <= names)
        digest = hashlib.sha256((output / 'controller-release-manifest.json').read_bytes()).hexdigest()
        candidate = installer.SourceCandidate.load(output, digest)
        self.assertEqual(candidate.source_commit, self.sha)
        self.assertFalse(manifest['install_allowed'])
        self.assertFalse(manifest['activation_allowed'])
        self.assertFalse(manifest['database_setup_approved'])

    def test_missing_transitive_client_import_refuses_complete_candidate(self):
        module = importlib.import_module('codestra_control.controller_release')
        for name in ('lease_interface','atomic_inspection'):
            with self.subTest(module=name):
                self.git('rm','lib/codestra_control/'+name+'.py'); self.git('commit','-m','missing transitive import')
                output=Path(self.temporary.name)/('missing-import-'+name)
                with self.assertRaisesRegex(ValueError,'INCOMPLETE_CONTROLLER_IMPORT'):
                    module.prepare_controller_release(self.root,self.git('rev-parse','HEAD'),output,self.wheel)
                self.assertFalse(output.exists()); self.git('reset','--hard',self.sha)

    def test_nested_live_identities_created_flags_and_capability_flags_refuse_proposal(self):
        module = importlib.import_module('codestra_control.controller_release')
        name='config/examples/publisher-certifier-action-time-approval.json'
        original=json.loads((self.root/name).read_text())
        for index,(key,value) in enumerate((('EXTERNAL_EFFECTS',True),('PRODUCTION_GO','YES'),
            ('LIVE_CAPABILITIES_ENABLED','YES'),('publisher_app_id',99),('certificate_installation_id',100),
            ('app_id',99),('account_created',True))):
            changed=dict(original,adversarial_nested={key:value})
            self.write(name,json.dumps(changed).encode());self.git('add',name);self.git('commit','-m','unsafe proposal')
            output=Path(self.temporary.name)/('unsafe-proposal-'+str(index))
            with self.subTest(key=key),self.assertRaises(ValueError):
                module.prepare_controller_release(self.root,self.git('rev-parse','HEAD'),output,self.wheel)
            self.assertFalse(output.exists());self.git('reset','--hard',self.sha)

    def test_commit_and_blob_replacements_cannot_replace_admission_client(self):
        module = importlib.import_module('codestra_control.controller_release')
        name = 'bin/codestra-admission'
        approved_bytes = (self.root / name).read_bytes()
        approved_blob = self.git('rev-parse', self.sha + ':' + name)
        self.write(name, b'unreviewed admission client\n')
        self.git('add', name)
        self.git('commit', '-m', 'unreviewed fixture')
        replacement = self.git('rev-parse', 'HEAD')
        replacement_blob = self.git('rev-parse', replacement + ':' + name)
        for kind, original, substitute in (('commit', self.sha, replacement),
                                            ('blob', approved_blob, replacement_blob)):
            with self.subTest(kind=kind):
                self.git('replace', original, substitute)
                try:
                    output = Path(self.temporary.name) / kind
                    manifest = module.prepare_controller_release(self.root, self.sha, output, self.wheel)
                    self.assertEqual((output / name).read_bytes(), approved_bytes)
                    entry = next(item for item in manifest['files'] if item['source_path'] == name)
                    self.assertEqual(entry['sha256'], hashlib.sha256(approved_bytes).hexdigest())
                finally:
                    self.git('replace', '-d', original)

    def test_symlinked_or_nonexecutable_admission_client_is_rejected(self):
        module = importlib.import_module('codestra_control.controller_release')
        path = self.root / 'bin/codestra-admission'
        for kind in ('symlink', 'mode'):
            with self.subTest(kind=kind):
                if kind == 'symlink':
                    path.unlink()
                    path.symlink_to('/etc/passwd')
                else:
                    path.chmod(0o644)
                self.git('add', '.')
                self.git('commit', '-m', 'unsafe fixture')
                output = Path(self.temporary.name) / ('unsafe-' + kind)
                with self.assertRaisesRegex(ValueError, 'UNSAFE_CONTROLLER_PACKAGE_ENTRY'):
                    module.prepare_controller_release(self.root, self.git('rev-parse', 'HEAD'), output, self.wheel)
                self.assertFalse(output.exists())
                self.git('reset', '--hard', self.sha)

    def test_live_approval_cannot_be_packaged_as_proposed_configuration(self):
        module = importlib.import_module('codestra_control.controller_release')
        name = 'config/examples/publisher-certifier-action-time-approval.json'
        value = json.loads((self.root / name).read_text())
        value['activation_approved'] = True
        self.write(name, json.dumps(value).encode())
        self.git('add', name)
        self.git('commit', '-m', 'active fixture is not a source template')
        output = Path(self.temporary.name) / 'active'
        with self.assertRaisesRegex(ValueError, 'ACTIVE_APPROVAL_NOT_A_SOURCE_TEMPLATE'):
            module.prepare_controller_release(self.root, self.git('rev-parse', 'HEAD'), output, self.wheel)
        self.assertFalse(output.exists())

    def test_publisher_only_candidate_keeps_its_original_scope(self):
        manifest = prepare_release(self.root, self.sha,
                                   Path(self.temporary.name) / 'publisher', self.wheel)
        self.assertEqual(manifest['schema'], 'codestra.publisher-candidate.v1')
        names = {item['source_path'] for item in manifest['files']}
        self.assertNotIn('bin/codestra-coordinate', names)
        self.assertNotIn('bin/codestra-admission', names)


if __name__ == '__main__':
    unittest.main()
