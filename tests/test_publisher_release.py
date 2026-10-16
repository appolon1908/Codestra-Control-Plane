"""Candidate packaging uses disposable Git and synthetic dependency bytes."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from codestra_control.publisher_release import ENTRYPOINTS, prepare_release


class PublisherReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'repo'
        self.root.mkdir()
        self.wheel = Path(self.temp.name) / 'fixture.whl'
        self.wheel.write_bytes(b'synthetic wheel fixture; not a runtime binary')
        self.run_git('init')
        self.run_git('config', 'user.name', 'Fixture')
        self.run_git('config', 'user.email', 'fixture@example.invalid')
        for path in ENTRYPOINTS + ('lib/codestra_control/publisher_ownership.py', 'lib/codestra_control/routes.py'):
            p = self.root / path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('# fixture\n')
        (self.root / 'runtime-publisher-tools.json').write_text(json.dumps({'schema':'codestra.publisher-system-tools.v1','openssl_version':'synthetic fixture','files':{'/usr/bin/openssl':'a'*64},'provisioning_approved':False,'target_verified':False}))
        (self.root / 'requirements-publisher.txt').write_text('psycopg2-binary==2.9.10 --hash=sha256:' + hashlib.sha256(self.wheel.read_bytes()).hexdigest() + '\n')
        self.run_git('add', '.')
        self.run_git('commit', '-m', 'fixture')
        self.sha = self.run_git('rev-parse', 'HEAD').strip()
        self.output = Path(self.temp.name) / 'candidate'

    def run_git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], check=True, capture_output=True, text=True).stdout

    def test_pins_all_runtime_files_and_ignores_dirty_worktree(self):
        (self.root / 'lib/codestra_control/routes.py').write_text('uncommitted change')
        manifest = prepare_release(self.root, self.sha, self.output, self.wheel)
        self.assertFalse(manifest['install_allowed'])
        self.assertFalse(manifest['activation_allowed'])
        self.assertFalse(manifest['runtime']['system_tools']['target_verified'])
        self.assertFalse(manifest['runtime']['system_tools']['provisioning_approved'])
        self.assertIn('/usr/bin/openssl',manifest['runtime']['system_tools']['files'])
        self.assertEqual((self.output / 'lib/codestra_control/routes.py').read_text(), '# fixture\n')
        for entry in manifest['files']:
            data = (self.output / entry['source_path']).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), entry['sha256'])
            if not entry['source_path'].startswith('legacy/'):
                self.assertEqual(entry['proposed_target'],
                    '/opt/codestra-control-plane/releases/'+self.sha+'/'+entry['source_path'])
        self.assertEqual(json.loads((self.output / 'release-manifest.json').read_text()), manifest)
        name = Path(manifest['driver_artifact']['path']).name
        self.assertEqual(name, 'psycopg2_binary-2.9.10-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl')
        self.assertEqual(len(name.split('-')), 5)
        self.assertFalse(manifest['runtime']['target_interpreter_verified'])
        self.assertFalse(manifest['runtime']['target_driver_import_verified'])
        self.assertTrue(manifest['runtime']['builder_python_version'])

    def test_bad_wheel_or_existing_output_refused(self):
        self.wheel.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'DRIVER_HASH_MISMATCH'):
            prepare_release(self.root, self.sha, self.output, self.wheel)
        self.assertFalse(self.output.exists())
        self.wheel.write_bytes(b'synthetic wheel fixture; not a runtime binary')
        self.output.mkdir()
        with self.assertRaises(FileExistsError):
            prepare_release(self.root, self.sha, self.output, self.wheel)

    def test_commit_and_blob_replacements_cannot_substitute_approved_runtime_bytes(self):
        source_path='lib/codestra_control/routes.py'
        runtime_file=self.root/source_path
        approved=self.sha
        approved_bytes=runtime_file.read_bytes()
        runtime_file.write_bytes(b'unreviewed replacement runtime\n')
        self.run_git('add','.')
        self.run_git('commit','-m','unreviewed replacement fixture')
        replacement=self.run_git('rev-parse','HEAD').strip()
        approved_blob=self.run_git('rev-parse',approved+':'+source_path).strip()
        replacement_blob=self.run_git('rev-parse',replacement+':'+source_path).strip()
        for kind,original,substitute in (('commit',approved,replacement),
                                          ('blob',approved_blob,replacement_blob)):
            with self.subTest(replacement=kind):
                self.run_git('replace',original,substitute)
                try:
                    output=self.output/kind
                    self.output.mkdir(exist_ok=True)
                    manifest=prepare_release(self.root,approved,output,self.wheel)
                    self.assertEqual(manifest['source_commit'],approved)
                    self.assertEqual((output/source_path).read_bytes(),approved_bytes)
                    entry=next(item for item in manifest['files'] if item['source_path']==source_path)
                    self.assertEqual(entry['sha256'],hashlib.sha256(approved_bytes).hexdigest())
                finally:
                    self.run_git('replace','-d',original)

    def test_symlink_runtime_module_is_not_packaged(self):
        p = self.root / 'lib/codestra_control/routes.py'
        p.unlink();p.symlink_to('/etc/passwd')
        self.run_git('add', '.')
        self.run_git('commit', '-m', 'unsafe fixture')
        sha = self.run_git('rev-parse', 'HEAD').strip()
        with self.assertRaisesRegex(ValueError, 'UNSAFE_PACKAGE_ENTRY'):
            prepare_release(self.root, sha, self.output, self.wheel)
        self.assertFalse(self.output.exists())
