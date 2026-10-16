"""Offline proposal staging; disposable Git only, never an installed target."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class PublisherInstallationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'repo'
        self.root.mkdir()
        self.output = Path(self.temp.name) / 'packet'
        self.git('init')
        self.git('config', 'user.name', 'Offline Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        source = Path(__file__).resolve().parents[1] / 'config/examples'
        shutil.copytree(source, self.root / 'config/examples')
        self.commit()

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-m', 'offline fixture')
        self.sha = self.git('rev-parse', 'HEAD')

    def test_stages_committed_proposal_without_dirty_or_unlisted_files(self):
        from codestra_control.publisher_installation import prepare_installation_packet
        startup = self.root / 'config/examples/authenticated-publisher.toml'
        original = startup.read_bytes()
        startup.write_text('uncommitted secret fixture; must never be copied')
        (startup.parent / 'unlisted.pem').write_text('untracked secret fixture')
        manifest = prepare_installation_packet(self.root, self.sha, self.output)
        self.assertEqual((self.output / 'config/examples/authenticated-publisher.toml').read_bytes(), original)
        self.assertFalse((self.output / 'config/examples/unlisted.pem').exists())
        self.assertEqual(manifest['source_commit'], self.sha)
        self.assertFalse(manifest['install_allowed'])
        self.assertFalse(manifest['activation_allowed'])
        self.assertEqual(manifest['state'], 'PROPOSED')
        for entry in manifest['files']:
            self.assertEqual(hashlib.sha256((self.output / entry['path']).read_bytes()).hexdigest(), entry['sha256'])
            self.assertEqual((self.output / entry['path']).stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertEqual(json.loads((self.output / 'installation-packet-manifest.json').read_text()), manifest)

    def test_requires_exact_commit_and_new_output(self):
        from codestra_control.publisher_installation import prepare_installation_packet
        with self.assertRaisesRegex(ValueError, 'EXACT_SOURCE_SHA_REQUIRED'):
            prepare_installation_packet(self.root, 'HEAD', self.output)
        self.assertFalse(self.output.exists())
        self.output.mkdir()
        (self.output / 'preserve').write_text('existing bytes')
        with self.assertRaises(FileExistsError):
            prepare_installation_packet(self.root, self.sha, self.output)
        self.assertEqual((self.output / 'preserve').read_text(), 'existing bytes')

    def test_rejects_committed_symlink_before_creating_output(self):
        from codestra_control.publisher_installation import prepare_installation_packet
        path = self.root / 'config/examples/authenticated-publisher.toml'
        path.unlink()
        path.symlink_to('/etc/passwd')
        self.commit()
        with self.assertRaisesRegex(ValueError, 'UNSAFE_TEMPLATE_ENTRY'):
            prepare_installation_packet(self.root, self.sha, self.output)
        self.assertFalse(self.output.exists())

    def test_bundled_startup_defaults_refuse_before_database_access(self):
        import contextlib
        from unittest import mock
        from codestra_control.publisher_startup import run_operator_cycle
        from codestra_control.publisher_ownership import PublisherUnavailable
        config = (self.root / 'config/examples/authenticated-publisher.toml').read_bytes()
        with mock.patch('codestra_control.publisher_startup.publisher_session', contextlib.nullcontext), \
                mock.patch('codestra_control.publisher_startup.protected_read', return_value=config), \
                mock.patch('codestra_control.publisher_startup.verify_code_custody'), \
                mock.patch('psycopg2.connect', side_effect=AssertionError('database must remain untouched')):
            with self.assertRaises(PublisherUnavailable):
                run_operator_cycle()
