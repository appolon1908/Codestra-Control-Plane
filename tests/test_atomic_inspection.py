"""Synthetic composition evidence; never runtime authority or a live test."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from codestra_control.atomic_inspection import (
    AtomicInspector, AtomicRegistry, InspectionDenied, InspectionLeaseObserver, main,
)
from codestra_control.effective_protection import ProtectionObservation

NOW = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)
BINDING = '11111111-1111-4111-8111-111111111111'
LEASE = '22222222-2222-4222-8222-222222222222'
REPO = 'appolon1908/Example'
HEAD, BASE, MERGE = ('a' * 40, 'b' * 40, 'c' * 40)


def description():
    workstation = dict(product='Example', workstation_id='Example-ws', section='sec',
                       subsection='sub', branch='subsection/sec--sub',
                       parent_branch='section/sec', worktree='/fixture/subsection', order_index=1)
    candidate = dict(product='Example', workstation_id='Example-ws', task_id='Example-task',
                     title='Synthetic task', branch='atomic/sec--sub--task',
                     target_branch=workstation['branch'], worktree='/fixture/atomic',
                     head_sha=HEAD, base_sha=BASE, prerequisites=[])
    binding = dict(binding_id=BINDING, product='Example', workstation_id='Example-ws',
                   task_id='Example-task', principal='builder', principal_oid=101,
                   repository=REPO, repository_id=123, source_ref=candidate['branch'],
                   target_ref=workstation['branch'], head_sha=HEAD, base_sha=BASE,
                   worktree='/fixture/atomic', host='fixture-host', root_path='/fixture',
                   git_common_dir='/fixture/repo.git', worktree_uid=1000,
                   valid_until=(NOW + timedelta(minutes=5)).isoformat(), active=True)
    return dict(schema='codestra.atomic-inspection.v1', product=dict(product='Example',
                repository=REPO, test_branch='testing',
                promotion_chain=['development', 'testing', 'staging', 'production']),
                section=dict(section_key='sec', branch='section/sec'),
                workstation=workstation, candidate=candidate,
                lease=dict(lease_id=LEASE, binding_id=BINDING, principal='builder', epoch=3,
                           state='ACTIVE', started_at=NOW.isoformat(),
                           expires_at=(NOW + timedelta(minutes=3)).isoformat(),
                           binding=binding, authority='ONLINE_DATABASE_RECEIPT'),
                materialization=dict(host='fixture-host', directory_device=1, directory_inode=2),
                dependencies=[], required_workstations=[],
                required_gates=['unit', 'security', 'review', 'clean_tree', 'remote_sha_match'])


PROTECTION = ProtectionObservation(1, True, True, True, True, True,
    (('codestra/control-plane', 99), ('quality', 15368)), 'd' * 64)
GATES = {'unit': {'name': 'quality', 'app_id': 15368},
         'security': {'name': 'quality', 'app_id': 15368}}


class Registry:
    def __init__(self):
        self.value = description()
        self.calls = 0
        self.change = None
    def acquire(self, binding):
        self.calls += 1
        value = deepcopy(self.value)
        if self.calls > 1 and self.change:
            self.change(value)
        return value


class Materializer:
    def __init__(self): self.calls = 0; self.change = None
    def inspect(self, value):
        self.calls += 1
        b = value['binding']
        observed = {key: b[key] for key in ('repository', 'repository_id', 'source_ref',
                    'target_ref', 'head_sha', 'base_sha', 'worktree', 'host',
                    'git_common_dir', 'worktree_uid')}
        observed.update(directory_device=1, directory_inode=2,
                        observed_at=NOW.isoformat(),
                        dependencies={d['dependency_key']: d for d in value['dependencies']})
        if self.change: self.change(observed)
        return observed


class API:
    def __init__(self):
        self.pr = dict(id=10, number=7, state='open', draft=False, user={'login': 'author'},
                       head=dict(ref='atomic/sec--sub--task', sha=HEAD, repo={'id': 123}),
                       base=dict(ref='subsection/sec--sub', sha=BASE, repo={'id': 123}),
                       mergeable=True, merge_commit_sha=MERGE)
        self.approved = self.resolved = self.eligible = True
        self.reviews = [dict(id=42, user={'login': 'reviewer'}, state='APPROVED', commit_id=HEAD)]
        self.checks = {sha: [dict(id=100+i, name='quality', app={'id': 15368},
                                head_sha=sha, status='completed', conclusion='success')]
                       for i, sha in enumerate((HEAD, MERGE))}
        self.pr_reads = 0
        self.change = None
        self.merge_parents = [BASE, HEAD]
        self.branch_sha = BASE
    def get(self, path):
        if path == '/repos/' + REPO: return {'id': 123, 'full_name': REPO}
        if path.endswith('/pulls/7'):
            self.pr_reads += 1
            value = deepcopy(self.pr)
            if self.pr_reads > 1 and self.change: self.change(value)
            return value
        if '/git/commits/' in path:
            return {'sha': MERGE, 'parents': [{'sha': sha} for sha in self.merge_parents]}
        if '/branches/' in path: return {'protected': True, 'commit': {'sha': self.branch_sha}}
        raise AssertionError(path)
    def pages(self, path, key=None):
        if path.endswith('/reviews'): return deepcopy(self.reviews)
        for sha, values in self.checks.items():
            if '/commits/' + sha + '/check-runs' in path: return deepcopy(values)
        raise AssertionError(path)
    def review_approved(self, repo, number): return self.approved
    def threads_resolved(self, repo, number): return self.resolved
    def eligible_reviewer(self, repo, login): return self.eligible


class AtomicInspectionTests(unittest.TestCase):
    def setUp(self):
        self.registry, self.api, self.materializer = Registry(), API(), Materializer()
        self.clock = lambda: NOW
        self.protection = patch('codestra_control.atomic_inspection.observe_protection',
                                return_value=PROTECTION)
        self.protection.start(); self.addCleanup(self.protection.stop)
    def inspect(self, **kwargs):
        return AtomicInspector(self.registry, self.api, self.materializer,
            controller_app_id=99, controller_contexts=('codestra/control-plane',),
            gate_checks=GATES, clock=self.clock, **kwargs).inspect(BINDING, 7)
    def test_current_real_receipt_shape_allows_observation_only(self):
        result = self.inspect()
        self.assertTrue(result['eligible_for_source_update'])
        self.assertTrue(result['non_bearer'])
        for field in ('certified', 'lease_granted', 'promotion_authorized'):
            self.assertIs(result[field], False)
        self.assertEqual(result['lease_id'], LEASE)
        self.assertEqual(result['lease_epoch'], 3)
        self.assertGreaterEqual(self.registry.calls, 2)
        self.assertGreaterEqual(self.materializer.calls, 2)
    def test_feature_route_or_wrong_registered_parent_cannot_pass(self):
        for change in (lambda d: d['lease']['binding'].update(source_ref='feature/task'),
                       lambda d: d['section'].update(branch='section/other'),
                       lambda d: d['candidate'].update(base_sha='f'*40)):
            with self.subTest(change=change):
                self.registry.value = description(); change(self.registry.value)
                with self.assertRaises(InspectionDenied): self.inspect()
    def test_legacy_receipt_missing_epoch_or_inactive_lease_denies(self):
        for change in (dict(authority='LEGACY_PASS'), dict(epoch=True), dict(epoch=0),
                       dict(state='FREE'), dict(binding_id=str(uuid.uuid4())),
                       dict(expires_at=NOW.isoformat())):
            with self.subTest(change=change):
                self.registry.value = description(); self.registry.value['lease'].update(change)
                with self.assertRaises(InspectionDenied): self.inspect()
    def test_changed_or_missing_leased_materialization_denies(self):
        for field in ('host', 'directory_device', 'directory_inode'):
            with self.subTest(field=field):
                self.registry.value = description(); del self.registry.value['materialization'][field]
                with self.assertRaises(InspectionDenied): self.inspect()
        self.registry.value = description()
        self.materializer.change = lambda value: value.update(directory_inode=99)
        with self.assertRaises(InspectionDenied): self.inspect()
    def test_final_database_or_remote_drift_and_expiry_deny(self):
        self.registry.change = lambda value: value['lease'].update(epoch=4)
        with self.assertRaises(InspectionDenied): self.inspect()
        self.registry.change = None
        self.api.change = lambda value: value['base'].update(sha='f'*40)
        with self.assertRaises(InspectionDenied): self.inspect()
        self.api.change = None
        moments = iter((NOW, NOW, NOW, NOW + timedelta(minutes=4)))
        self.clock = lambda: next(moments, NOW + timedelta(minutes=4))
        with self.assertRaises(InspectionDenied): self.inspect()
    def test_failed_missing_wrong_producer_or_merge_check_denies(self):
        for sha in (HEAD, MERGE):
            for change in ('missing', 'failed', 'wrong_app'):
                with self.subTest(sha=sha, change=change):
                    self.api = API()
                    if change == 'missing': self.api.checks[sha] = []
                    elif change == 'failed': self.api.checks[sha][0]['conclusion'] = 'failure'
                    else: self.api.checks[sha][0]['app']['id'] = 999
                    with self.assertRaises(InspectionDenied): self.inspect()
    def test_current_independent_exact_head_eligible_review_is_required(self):
        for changes in ({'state': 'DISMISSED'}, {'state': 'CHANGES_REQUESTED'},
                        {'commit_id': BASE}, {'user': {'login': 'author'}},
                        {'user': {'login': 'builder'}}):
            with self.subTest(changes=changes):
                self.api = API(); self.api.reviews[0].update(changes)
                with self.assertRaises(InspectionDenied): self.inspect()
        for field in ('approved', 'resolved', 'eligible'):
            self.api = API(); setattr(self.api, field, False)
            with self.subTest(field=field), self.assertRaises(InspectionDenied): self.inspect()
    def test_gate_inventory_cannot_be_empty_unsupported_or_unmapped(self):
        for gates in ([], ['custom-unverified'], ['unit', 'unit'], ['regression']):
            self.registry.value['required_gates'] = gates
            with self.subTest(gates=gates), self.assertRaises(InspectionDenied): self.inspect()
    def test_claimed_prerequisite_cannot_hide_missing_evidence(self):
        self.registry.value['candidate']['prerequisites'] = [dict(product='Example',
            scope_type='SUBSECTION', scope_name='subsection/sec--other', sha='f'*40)]
        with self.assertRaises(InspectionDenied): self.inspect()
    def test_effective_protection_and_controller_producer_are_enforced(self):
        from dataclasses import replace
        self.protection.stop()
        for protection in (replace(PROTECTION, approvals=0),
                           replace(PROTECTION, strict=False),
                           replace(PROTECTION, checks=(('codestra/control-plane', 999), ('quality', 15368))),
                           replace(PROTECTION, checks=(('codestra/control-plane', 99),))):
            with self.subTest(protection=protection), patch(
                'codestra_control.atomic_inspection.observe_protection', return_value=protection), \
                self.assertRaises(InspectionDenied): self.inspect()
        self.protection.start()

    def test_wrong_merge_parents_or_fork_identity_denies(self):
        for parents in ([BASE], [BASE, 'f'*40], [HEAD, BASE], [BASE, HEAD, MERGE]):
            self.api.merge_parents = parents
            with self.subTest(parents=parents), self.assertRaises(InspectionDenied): self.inspect()
        self.api = API(); self.api.pr['head']['repo']['id'] = 999
        with self.assertRaises(InspectionDenied): self.inspect()

    def test_protection_or_current_check_receipts_moving_during_observation_deny(self):
        from dataclasses import replace
        self.protection.stop()
        changed = replace(PROTECTION, evidence_digest='e'*64)
        with patch('codestra_control.atomic_inspection.observe_protection',
                   side_effect=(PROTECTION, changed)), self.assertRaises(InspectionDenied): self.inspect()
        self.protection.start()

    def test_long_final_online_read_cannot_return_expired_observation(self):
        moment = [NOW]
        self.registry.value['lease']['expires_at'] = (NOW + timedelta(hours=1)).isoformat()
        self.registry.value['lease']['binding']['valid_until'] = (NOW + timedelta(hours=1)).isoformat()
        inspector = AtomicInspector(self.registry, self.api, self.materializer,
            controller_app_id=99, controller_contexts=('codestra/control-plane',),
            gate_checks=GATES, clock=lambda: moment[0])
        online = inspector._online
        calls = [0]
        def slow_final(*args):
            result = online(*args); calls[0] += 1
            if calls[0] == 2: moment[0] += timedelta(minutes=6)
            return result
        with patch.object(inspector, '_online', side_effect=slow_final), \
                self.assertRaises(InspectionDenied): inspector.inspect(BINDING, 7)

    def test_expiry_at_final_output_time_denies_even_within_snapshot_age(self):
        moments = iter([NOW] * 6 + [NOW + timedelta(minutes=3, microseconds=1)])
        self.clock = lambda: next(moments, NOW + timedelta(minutes=3, microseconds=1))
        with self.assertRaises(InspectionDenied): self.inspect()

    def test_branch_movement_during_final_check_pagination_denies(self):
        pages = self.api.pages; calls = [0]
        def moving(path, key=None):
            result = pages(path, key)
            if '/check-runs' in path:
                calls[0] += 1
                if calls[0] == 3: self.api.branch_sha = 'f' * 40
            return result
        with patch.object(self.api, 'pages', side_effect=moving), \
                self.assertRaises(InspectionDenied): self.inspect()

    def test_dependency_issuer_app_must_differ_from_custom_ci_app(self):
        from dataclasses import replace
        p = dict(product='Example', scope_type='SUBSECTION',
                 scope_name='subsection/sec--dep', sha='f'*40)
        d = dict(binding_id=BINDING, dependency_key='subsection:dep', prerequisite=p,
                 active=True, valid_until=(NOW + timedelta(minutes=3)).isoformat(),
                 issuer_name='scope-certification', issuer_app_id=42)
        self.registry.value['candidate']['prerequisites'] = [p]
        self.registry.value['dependencies'] = [d]
        self.registry.value['required_workstations'] = [dict(workstation_id='Example-dep',
            product='Example', branch=p['scope_name'], status='CERTIFIED',
            remote_sha=p['sha'], exact_sha_certified=p['sha'])]
        for checks in self.api.checks.values(): checks[0]['app']['id'] = 42
        protection = replace(PROTECTION, checks=(('codestra/control-plane', 99), ('quality', 42)))
        inspector = AtomicInspector(self.registry, self.api, self.materializer,
            controller_app_id=99, controller_contexts=('codestra/control-plane',),
            gate_checks={gate: dict(name='quality', app_id=42) for gate in ('unit', 'security')},
            clock=self.clock)
        with patch('codestra_control.atomic_inspection.observe_protection', return_value=protection):
            with self.assertRaises(InspectionDenied): inspector.inspect(BINDING, 7)
            d['issuer_app_id'] = 77
            self.assertTrue(inspector.inspect(BINDING, 7)['eligible_for_source_update'])


class AtomicRegistryTests(unittest.TestCase):
    def test_each_acquisition_uses_a_fresh_readonly_snapshot_and_typed_server_api(self):
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.side_effect = [(description(),), (description(),)]
        registry = AtomicRegistry(connection)
        self.assertEqual(registry.acquire(BINDING), registry.acquire(BINDING))
        self.assertEqual(connection.__exit__.call_count, 2)
        self.assertEqual(connection.set_session.call_count, 2)
        connection.set_session.assert_called_with(isolation_level='REPEATABLE READ',
                                                   readonly=True, autocommit=False)
        cursor.execute.assert_called_with('SELECT atomic_inspection.inspect(%s::uuid)', (BINDING,))


class DependencyFreshnessTests(unittest.TestCase):
    def test_subsection_digest_and_current_dependency_refs_are_required(self):
        from codestra_control.evidence import PromotionRequest
        from codestra_control.lease_materialization import dependency_digest
        from dataclasses import asdict
        b = PromotionRequest(REPO, 'Example', 'subsection/sec--other', 'section/sec', HEAD, BASE)
        prerequisite = dict(product='Example', scope_type='SUBSECTION',
                            scope_name=b.source_ref, sha=HEAD)
        d = dict(repository=REPO, repository_id=123, binding=asdict(b), prerequisite=prerequisite,
                 binding_hash=dependency_digest(b, prerequisite), approved_by='Ralph L. Appolon',
                 purpose='SCOPE_CERTIFICATION', capability_receipt='synthetic',
                 issuer_app_id=77, issuer_name='scope-certification', check_id=10)
        class DependencyAPI:
            moved = False
            target_moved = False
            def authorize_readonly(self, *args): pass
            def get(self, path):
                if path.endswith('/Example'): return {'id': 123, 'full_name': REPO}
                if '/git/ref/' in path:
                    source = 'subsection' in path
                    ref = b.source_ref if source else b.target_ref
                    return dict(ref='refs/heads/'+ref, object=dict(type='commit',
                        sha=('f'*40 if self.moved else HEAD) if source
                            else ('f'*40 if self.target_moved else BASE)))
                if '/check-runs/' in path:
                    return dict(id=10, app={'id': 77}, name='scope-certification',
                                external_id=d['binding_hash'], head_sha=HEAD,
                                status='completed', conclusion='success')
                raise AssertionError(path)
        api = DependencyAPI()
        observer = InspectionLeaseObserver(api, 88, 99, clock=lambda: NOW)
        self.assertEqual(observer.dependency(d), d)
        api.moved = True
        with self.assertRaisesRegex(InspectionDenied, 'DEPENDENCY_REF_MOVED'): observer.dependency(d)
        api.moved = False; api.target_moved = True
        with self.assertRaisesRegex(InspectionDenied, 'DEPENDENCY_REF_MOVED'): observer.dependency(d)


class AtomicCliTests(unittest.TestCase):
    def test_invalid_input_or_private_configuration_failure_is_generic(self):
        for argv in (['--binding', BINDING, '--pr', '7'],
                     ['--binding', 'invalid', '--pr', '7']):
            with self.subTest(argv=argv), patch('codestra_control.atomic_inspection.verify_code_custody'), \
                patch('codestra_control.atomic_inspection.protected_read', side_effect=ValueError('secret-dsn')), \
                patch('sys.stdout', new_callable=io.StringIO) as output:
                self.assertEqual(main(argv), 1)
                self.assertEqual(output.getvalue(), 'ATOMIC_INSPECTION_UNAVAILABLE\n')
                self.assertNotIn('secret', output.getvalue())

    def test_close_failure_never_prints_success_or_private_diagnostics(self):
        config = b'''database_dsn_file="/protected/inspector.dsn"
app_id=88
installation_id=89
app_key_file="/protected/inspector.pem"
controller_app_id=99
controller_contexts=["codestra/control-plane"]
gate_checks={}
'''
        connection = MagicMock()
        connection.close.side_effect = ValueError('secret-connection-detail')
        with patch('codestra_control.atomic_inspection.verify_code_custody'), \
             patch('codestra_control.atomic_inspection.protected_read', return_value=config), \
             patch('codestra_control.atomic_inspection.connect_protected', return_value=connection), \
             patch('codestra_control.atomic_inspection.AtomicInspector') as inspector, \
             patch('sys.stdout', new_callable=io.StringIO) as output:
            inspector.return_value.inspect.return_value = {'eligible_for_source_update': True}
            self.assertEqual(main(['--binding', BINDING, '--pr', '7']), 1)
            self.assertEqual(output.getvalue(), 'ATOMIC_INSPECTION_UNAVAILABLE\n')
