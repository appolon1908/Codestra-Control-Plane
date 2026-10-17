"""Real disposable Git observations; remote observers provide fixture data only."""
import copy
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))

from codestra_control.lease_materialization import MaterializationDenied
try:
    from codestra_control.admission_materialization import StageMaterializer
except ModuleNotFoundError:
    StageMaterializer = None


class StageObserver:
    def __init__(self, binding):
        self.binding = binding
        self.refs = []
        self.on_dependency = None

    def bind(self, binding):
        self.bound = binding

    def repository(self, name):
        return self.binding['repository_id']

    def ref(self, name, ref):
        self.refs.append(ref)
        return self.binding['head_sha' if ref == self.binding['source_ref'] else 'base_sha']

    def dependency(self, value):
        if self.on_dependency:
            self.on_dependency()
        return dict(value)


class AdmissionMaterializationTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(StageMaterializer, 'missing independent staged materializer')
        patch = mock.patch('codestra_control.admission_materialization.verify_system_tools')
        patch.start()
        self.addCleanup(patch.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'atomic'
        self.repo.mkdir(mode=0o700)
        self.git('init')
        self.git('config', 'user.name', 'Admission Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        for name in ('source.txt', 'outside.txt', 'delete.txt'):
            (self.repo / name).write_text('baseline\n')
        self.git('add', '.')
        self.git('commit', '-m', 'baseline')
        (self.repo / '.git').chmod(0o700)
        self.git('checkout', '-b', 'atomic/sec--sub--task')
        self.git('remote', 'add', 'origin', 'https://github.com/appolon1908/A.git')
        baseline = self.git('rev-parse', 'HEAD')
        info = self.repo.stat()
        self.binding = {'repository': 'appolon1908/A', 'repository_id': 123,
            'source_ref': 'atomic/sec--sub--task', 'target_ref': 'subsection/sec--sub',
            'head_sha': baseline, 'base_sha': baseline, 'worktree': str(self.repo),
            'host': 'fixture-host', 'root_path': str(self.root),
            'git_common_dir': str(self.repo / '.git'), 'worktree_uid': os.geteuid()}
        self.description = {'intent_id': str(uuid.uuid4()), 'operation': 'L1',
            'request_digest': 'c' * 64,
            'payload': {'paths': ['source.txt'], 'mutation_sha256': 'd' * 64},
            'grant': {'paths': ['delete.txt', 'new.txt', 'source.txt']},
            'binding': self.binding,
            'lease': {'lease_id': str(uuid.uuid4()), 'epoch': 4,
                      'directory_device': info.st_dev, 'directory_inode': info.st_ino},
            'dependencies': []}
        self.observer = StageObserver(self.binding)
        self.materializer = StageMaterializer(self.observer, host=lambda: 'fixture-host',
                                               filesystem_anchor=self.root)

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args],
            stderr=subprocess.DEVNULL, text=True).strip()

    def commit(self, name='source.txt', content='candidate\n'):
        (self.repo / name).write_text(content)
        self.git('add', name)
        self.git('commit', '-m', 'candidate')

    def l2(self, paths=None):
        self.description['operation'] = 'L2'
        self.description['payload'] = {
            'paths': paths or ['source.txt'],
            'candidate_sha': self.git('rev-parse', 'HEAD'),
            'candidate_tree_sha': self.git('rev-parse', 'HEAD^{tree}'),
            'expected_remote_sha': self.binding['head_sha'],
            'target_base_sha': self.binding['base_sha']}

    def inspect(self):
        return self.materializer.inspect(self.description)

    def denied(self):
        with self.assertRaises(MaterializationDenied):
            self.inspect()

    def test_l1_baseline_returns_exact_server_bound_observation(self):
        before = copy.deepcopy(self.description)
        observed = self.inspect()
        self.assertEqual(set(observed), {'intent_id', 'request_digest', 'operation',
            'lease_id', 'epoch', 'head_sha', 'tree_sha', 'changed_paths',
            'directory_device', 'directory_inode', 'dependencies', 'observed_at'})
        self.assertEqual(observed['changed_paths'], [])
        self.assertEqual(observed['head_sha'], self.binding['head_sha'])
        self.assertEqual(observed['lease_id'], self.description['lease']['lease_id'])
        self.assertEqual(observed['epoch'], 4)
        self.assertEqual(self.description, before)
        self.assertEqual(self.observer.refs,
            [self.binding['source_ref'], self.binding['target_ref']] * 2)

    def test_l1_dirty_staged_deleted_and_new_regular_files_are_scoped(self):
        (self.repo / 'source.txt').write_text('staged\n')
        self.git('add', 'source.txt')
        (self.repo / 'source.txt').write_text('dirty after staging\n')
        (self.repo / 'delete.txt').unlink()
        (self.repo / 'new.txt').write_text('untracked\n')
        observed = self.inspect()
        self.assertEqual(observed['changed_paths'], ['delete.txt', 'new.txt', 'source.txt'])
        self.assertEqual((self.repo / 'source.txt').read_text(), 'dirty after staging\n')

    def test_l1_staged_deletion_and_new_file_are_supported(self):
        self.git('rm', 'delete.txt')
        (self.repo / 'new.txt').write_text('staged new\n')
        self.git('add', 'new.txt')
        self.assertEqual(self.inspect()['changed_paths'], ['delete.txt', 'new.txt'])

    def test_l1_descendant_commit_remains_bound_to_baseline(self):
        self.commit()
        observed = self.inspect()
        self.assertEqual(observed['head_sha'], self.git('rev-parse', 'HEAD'))
        self.assertEqual(observed['changed_paths'], ['source.txt'])
        self.assertNotEqual(observed['head_sha'], self.binding['head_sha'])

    def test_l1_out_of_scope_dirty_and_ignored_files_deny(self):
        (self.repo / 'outside.txt').write_text('outside\n')
        self.denied()
        self.git('checkout', '--', 'outside.txt')
        (self.repo / '.git' / 'info' / 'exclude').write_text('hidden.txt\n')
        (self.repo / 'hidden.txt').write_text('ignored but outside scope\n')
        self.denied()

    def test_l2_clean_exact_candidate_is_observed(self):
        self.commit()
        self.l2()
        observed = self.inspect()
        self.assertEqual(observed['head_sha'], self.description['payload']['candidate_sha'])
        self.assertEqual(observed['tree_sha'], self.description['payload']['candidate_tree_sha'])
        self.assertEqual(observed['changed_paths'], ['source.txt'])
        self.assertEqual(observed['operation'], 'L2')

    def test_l2_dirty_staged_or_untracked_checkout_denies(self):
        self.commit()
        self.l2()
        (self.repo / 'source.txt').write_text('dirty\n')
        self.denied()
        self.git('add', 'source.txt')
        self.denied()
        self.git('reset', '--hard', 'HEAD')
        (self.repo / 'new.txt').write_text('new\n')
        self.denied()

    def test_l2_wrong_candidate_tree_head_or_remote_expectation_denies(self):
        self.commit()
        self.l2()
        for field in ('candidate_sha', 'candidate_tree_sha', 'expected_remote_sha', 'target_base_sha'):
            old = self.description['payload'][field]
            self.description['payload'][field] = 'a' * 40
            with self.subTest(field=field):
                self.denied()
            self.description['payload'][field] = old

    def test_unrelated_local_history_denies_even_with_exact_candidate(self):
        self.git('checkout', '--orphan', 'unrelated')
        self.git('commit', '-m', 'unrelated root')
        self.git('branch', '-M', self.binding['source_ref'])
        self.l2(['delete.txt', 'source.txt'])
        self.denied()

    def test_rename_counts_both_endpoints_and_deletion_is_observed(self):
        self.git('mv', 'source.txt', 'new.txt')
        self.git('rm', 'delete.txt')
        self.git('commit', '-m', 'rename and delete')
        self.l2(['delete.txt', 'new.txt', 'source.txt'])
        self.assertEqual(self.inspect()['changed_paths'], ['delete.txt', 'new.txt', 'source.txt'])
        self.description['payload']['paths'] = ['delete.txt', 'new.txt']
        self.denied()

    def test_out_of_scope_commit_later_reverted_cannot_hide_in_net_diff(self):
        self.commit('outside.txt', 'outside intermediate\n')
        self.git('revert', '--no-edit', 'HEAD')
        self.commit()
        self.l2()
        self.assertEqual(self.git('diff', '--name-only', self.binding['head_sha'], 'HEAD'), 'source.txt')
        self.denied()
        self.description['operation'] = 'L1'
        self.description['payload'] = {'paths': ['source.txt'], 'mutation_sha256': 'd' * 64}
        self.denied()

    def test_repository_grafts_cannot_hide_out_of_scope_history(self):
        self.commit('outside.txt', 'outside intermediate\n')
        self.git('revert', '--no-edit', 'HEAD')
        self.commit()
        self.l2()
        head = self.git('rev-parse', 'HEAD')
        (self.repo / '.git' / 'info' / 'grafts').write_text(head + ' ' + self.binding['head_sha'] + '\n')
        self.denied()

    def test_shallow_history_is_not_complete_scope_evidence(self):
        self.commit()
        self.l2()
        (self.repo / '.git' / 'shallow').write_text(self.binding['head_sha'] + '\n')
        self.denied()

    def test_merge_diff_against_nonfirst_parent_is_included(self):
        self.git('checkout', '-b', 'side')
        self.commit()
        self.git('checkout', self.binding['source_ref'])
        self.commit('outside.txt', 'accepted baseline\n')
        self.binding['head_sha'] = self.git('rev-parse', 'HEAD')
        self.binding['base_sha'] = self.binding['head_sha']
        self.git('merge', '--no-ff', 'side', '-m', 'merge side')
        self.l2()
        self.assertEqual(self.git('diff', '--name-only', 'HEAD^1', 'HEAD'), 'source.txt')
        self.assertEqual(self.git('diff', '--name-only', 'HEAD^2', 'HEAD'), 'outside.txt')
        self.denied()
        self.description['grant']['paths'].append('outside.txt')
        self.description['grant']['paths'].sort()
        self.description['payload']['paths'] = ['outside.txt', 'source.txt']
        self.assertEqual(self.inspect()['changed_paths'], ['outside.txt', 'source.txt'])

    def test_unrelated_introduced_root_is_compared_with_empty_tree(self):
        self.git('checkout', '--orphan', 'unrelated')
        self.git('commit', '-m', 'unrelated identical baseline tree')
        self.git('checkout', self.binding['source_ref'])
        self.git('merge', '--allow-unrelated-histories', '--no-ff', 'unrelated', '-m', 'merge root')
        self.commit()
        self.l2()
        self.assertEqual(self.git('diff', '--name-only', self.binding['head_sha'], 'HEAD'), 'source.txt')
        self.denied()

    def test_remote_drift_absence_and_observer_errors_deny(self):
        self.commit()
        self.l2()
        original = self.observer.ref
        for replacement in (lambda *_: None, lambda *_: 'f' * 40,
                            mock.Mock(side_effect=OSError('offline'))):
            self.observer.ref = replacement
            self.denied()
        self.observer.ref = original
        self.description['dependencies'] = [{'dependency_key': 'fixture'}]
        self.observer.on_dependency = lambda: setattr(self.observer, 'ref', lambda *_: 'f' * 40)
        self.denied()

    def test_dependency_map_and_directory_lease_identity_are_checked(self):
        dependency = {'dependency_key': 'fixture', 'receipt': 'synthetic'}
        self.description['dependencies'] = [dependency]
        self.assertEqual(self.inspect()['dependencies'], {'fixture': dependency})
        self.description['dependencies'].append(dependency)
        self.denied()
        self.description['dependencies'] = []
        self.description['lease']['directory_inode'] += 1
        self.denied()

    def test_dependency_failure_and_mid_observation_changes_deny(self):
        self.description['dependencies'] = [{'dependency_key': 'fixture'}]
        self.observer.dependency = mock.Mock(side_effect=MaterializationDenied('DEPENDENCY_UNAVAILABLE'))
        self.denied()
        self.observer.dependency = StageObserver.dependency.__get__(self.observer)
        self.observer.on_dependency = lambda: (self.repo / 'source.txt').write_text('changed during observation\n')
        self.denied()

    def test_replaced_directory_is_not_the_owned_lease_materialization(self):
        self.description['dependencies'] = [{'dependency_key': 'fixture'}]
        def replace():
            old = self.root / 'old'
            self.repo.rename(old)
            shutil.copytree(old, self.repo)
        self.observer.on_dependency = replace
        self.denied()

    def test_symlink_submodule_and_file_mode_drift_deny(self):
        (self.repo / 'new.txt').symlink_to(self.repo / 'source.txt')
        self.denied()
        (self.repo / 'new.txt').unlink()
        self.git('update-index', '--add', '--cacheinfo', '160000,' + self.binding['head_sha'] + ',new.txt')
        self.denied()
        self.git('reset', '--hard', 'HEAD')
        (self.repo / 'source.txt').chmod(0o755)
        self.denied()

    def test_intermediate_symlink_commit_is_rejected_even_after_removal(self):
        (self.repo / 'new.txt').symlink_to('source.txt')
        self.git('add', 'new.txt')
        self.git('commit', '-m', 'symlink')
        self.git('rm', 'new.txt')
        self.git('commit', '-m', 'remove symlink')
        self.l2(['new.txt'])
        self.denied()

    def test_host_common_dir_origin_detached_or_symlink_path_denies(self):
        for key, value in (('host', 'other'), ('git_common_dir', str(self.root)),
                           ('worktree_uid', os.geteuid() + 1)):
            original = self.binding[key]
            self.binding[key] = value
            with self.subTest(key=key):
                self.denied()
            self.binding[key] = original
        self.git('remote', 'set-url', 'origin', 'https://github.com/other/A.git')
        self.denied()
        self.git('remote', 'set-url', 'origin', 'https://github.com/appolon1908/A.git')
        alias = self.root / 'alias'
        alias.symlink_to(self.repo, target_is_directory=True)
        self.binding['worktree'] = str(alias)
        self.denied()
        self.binding['worktree'] = str(self.repo)
        self.git('checkout', '--detach')
        self.denied()

    def test_hostile_filters_hooks_and_fsmonitor_never_execute(self):
        marker = self.root / 'executed'
        self.git('config', 'core.fsmonitor', 'touch ' + str(marker))
        hook = self.repo / '.git' / 'hooks' / 'post-index-change'
        hook.write_text('#!/bin/sh\ntouch ' + str(marker) + '\n')
        hook.chmod(0o755)
        self.assertEqual(self.inspect()['changed_paths'], [])
        self.assertFalse(marker.exists())
        self.git('config', 'filter.malicious.clean', 'touch ' + str(marker))
        self.denied()
        self.assertFalse(marker.exists())

    def test_malformed_paths_and_stage_payloads_deny(self):
        for paths in ([], ['../source.txt'], ['/source.txt'], ['a\\b'], ['.git/config'],
                      ['source.txt', 'source.txt'], ['source.txt', 'new.txt'], ['dir/'],
                      ['space name'], ['é.txt']):
            original = self.description['payload']['paths']
            self.description['payload']['paths'] = paths
            with self.subTest(paths=paths):
                self.denied()
            self.description['payload']['paths'] = original
        self.description['payload']['approved'] = True
        self.denied()
        del self.description['payload']['approved']
        self.description['operation'] = 'CERTIFY'
        self.denied()
