"""Real disposable object stores and inert local transport-execution markers."""
from pathlib import Path
import sys
import unittest
from unittest import mock
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))

from codestra_control.lease_materialization import GitMaterializer, MaterializationDenied
import test_admission_materialization as staged


class MaterializationGitSafetyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = staged.AdmissionMaterializationTests('test_l1_baseline_returns_exact_server_bound_observation')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        patch = mock.patch('codestra_control.lease_materialization.verify_system_tools')
        patch.start()
        self.addCleanup(patch.stop)
        self.baseline = GitMaterializer(self.fixture.observer, host=lambda: 'fixture-host',
                                       filesystem_anchor=self.fixture.root)

    def inspectors(self):
        return (('baseline', lambda: self.baseline.inspect({'binding': self.fixture.binding, 'dependencies': []})),
                ('stage', self.fixture.inspect))

    def object_path(self, oid):
        return self.fixture.repo / '.git' / 'objects' / oid[:2] / oid[2:]

    def ignore_configuration(self, oid):
        skip = self.fixture.repo / '.git' / 'fsck-skip'
        skip.write_text(oid + '\n')
        self.fixture.git('config', 'fsck.skipList', str(skip))
        self.fixture.git('config', 'fsck.missingEmail', 'ignore')
        self.fixture.git('config', 'fsck.treeNotSorted', 'ignore')

    def assert_denied_by_both(self):
        for name, inspect in self.inspectors():
            with self.subTest(observer=name), self.assertRaises(MaterializationDenied):
                inspect()

    def test_corrupt_commit_under_authentic_filename_denies_even_with_fsck_skips(self):
        oid = self.fixture.binding['head_sha']
        self.ignore_configuration(oid)
        path = self.object_path(oid)
        raw = zlib.decompress(path.read_bytes())
        altered = raw.replace(b'baseline\n', b'baselinE\n')
        self.assertNotEqual(altered, raw)
        path.chmod(0o600)
        path.write_bytes(zlib.compress(altered))
        self.assertEqual(self.fixture.git('rev-parse', 'HEAD'), oid)
        self.assert_denied_by_both()

    def test_corrupt_tree_under_authentic_filename_denies_even_with_fsck_skips(self):
        oid = self.fixture.git('rev-parse', 'HEAD^{tree}')
        self.ignore_configuration(oid)
        path = self.object_path(oid)
        raw = zlib.decompress(path.read_bytes())
        altered = raw.replace(b'100644 source.txt\0', b'100755 source.txt\0')
        self.assertNotEqual(altered, raw)
        path.chmod(0o600)
        path.write_bytes(zlib.compress(altered))
        (self.fixture.repo / 'source.txt').chmod(0o755)
        self.fixture.git('update-index', '--chmod=+x', 'source.txt')
        self.assertEqual(self.fixture.git('rev-parse', 'HEAD'), self.fixture.binding['head_sha'])
        self.assert_denied_by_both()

    def test_corrupt_blob_under_authentic_filename_denies_even_with_fsck_skips(self):
        oid = self.fixture.git('rev-parse', 'HEAD:source.txt')
        self.ignore_configuration(oid)
        path = self.object_path(oid)
        raw = zlib.decompress(path.read_bytes())
        altered = raw.replace(b'baseline\n', b'baselinE\n')
        self.assertNotEqual(altered, raw)
        path.chmod(0o600)
        path.write_bytes(zlib.compress(altered))
        self.assertEqual((self.fixture.repo / 'source.txt').read_text(), 'baseline\n')
        self.assert_denied_by_both()

    def test_missing_object_cannot_execute_promisor_transport(self):
        marker = self.fixture.root / 'transport-executed'
        self.fixture.git('config', 'remote.malicious.promisor', 'true')
        self.fixture.git('config', 'remote.malicious.url', 'ext::/usr/bin/touch ' + str(marker))
        self.fixture.git('config', 'extensions.partialClone', 'malicious')
        self.fixture.git('config', 'protocol.ext.allow', 'always')
        tree = self.fixture.git('rev-parse', 'HEAD^{tree}')
        self.object_path(tree).unlink()
        for name, inspect in self.inspectors():
            with self.subTest(observer=name):
                marker.unlink(missing_ok=True)
                with self.assertRaises(MaterializationDenied):
                    inspect()
                self.assertFalse(marker.exists(), 'inspection executed a repository-configured transport')

    def test_shared_git_reader_denies_transport_before_repository_checks(self):
        marker = self.fixture.root / 'transport-executed'
        self.fixture.git('config', 'remote.malicious.promisor', 'true')
        self.fixture.git('config', 'remote.malicious.url', 'ext::/usr/bin/touch ' + str(marker))
        self.fixture.git('config', 'extensions.partialClone', 'malicious')
        self.fixture.git('config', 'protocol.ext.allow', 'always')
        oid = self.fixture.git('rev-parse', 'HEAD^{tree}')
        self.object_path(oid).unlink()
        with self.assertRaises(MaterializationDenied):
            self.baseline._git(self.fixture.repo, 'cat-file', '-p', oid)
        self.assertFalse(marker.exists(), 'shared Git primitive allowed lazy-fetch execution')

    def test_missing_nonpromisor_object_denies(self):
        self.object_path(self.fixture.git('rev-parse', 'HEAD^{tree}')).unlink()
        self.assert_denied_by_both()

    def test_promisor_configuration_denies_even_when_objects_are_present(self):
        self.fixture.git('config', 'remote.origin.promisor', 'true')
        self.assert_denied_by_both()

    def test_promisor_pack_marker_denies_without_partial_clone_config(self):
        self.fixture.git('repack', '-ad')
        packs = list((self.fixture.repo / '.git' / 'objects' / 'pack').glob('*.pack'))
        self.assertEqual(len(packs), 1)
        packs[0].with_suffix('.promisor').write_bytes(b'')
        self.assert_denied_by_both()

    def test_healthy_packed_objects_and_valid_fsck_configuration_remain_accepted(self):
        self.ignore_configuration(self.fixture.binding['head_sha'])
        self.fixture.git('config', 'core.commitGraph', 'true')
        self.fixture.git('commit-graph', 'write', '--reachable')
        self.fixture.git('repack', '-ad')
        for name, inspect in self.inspectors():
            with self.subTest(observer=name):
                self.assertEqual(inspect()['head_sha'], self.fixture.binding['head_sha'])
        self.assertFalse((self.fixture.repo / '.git' / 'lost-found').exists())
