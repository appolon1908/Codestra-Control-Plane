"""Purpose-bound inclusion evidence; all GitHub and identities are synthetic."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib
import json
import unittest
from types import SimpleNamespace
import copy
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))

from codestra_control.publisher_adapter import PublicationDenied


NOW = datetime(2026, 10, 16, 20, 0, tzinfo=timezone.utc)


def policy():
    return dict(schema='codestra.atomic-inclusion-acceptance.v1', state='ACCEPTED',
        accepted_by='Ralph L. Appolon', acceptance_ref='operator:atomic', revision='r1',
        purpose='ATOMIC_INCLUSION', repository='appolon1908/codestra', repository_id=123,
        app_id=99, installation_id=100, name='atomic-inclusion', custody_receipt='custody:atomic',
        capability_receipt='capability:atomic', max_receipt_lifetime_seconds=86400,
        max_observation_age_seconds=60, accepted_at=(NOW-timedelta(hours=2)).isoformat(),
        expires_at=(NOW+timedelta(hours=2)).isoformat())


class AtomicReceiptTests(unittest.TestCase):
    def module(self):
        return importlib.import_module('codestra_control.atomic_receipts')

    def test_separate_purpose_policy_is_required_and_proposal_denies(self):
        module = self.module()
        accepted = module.load_atomic_policy(json.dumps(policy()).encode(), NOW)
        self.assertEqual(accepted.purpose, 'ATOMIC_INCLUSION')
        for key, value in (('state', 'PROPOSED'), ('purpose', 'SCOPE_CERTIFICATION'),
                           ('app_id', 15368), ('installation_id', 0),
                           ('capability_receipt', ''), ('max_receipt_lifetime_seconds', True)):
            with self.subTest(key=key), self.assertRaises(PublicationDenied):
                module.load_atomic_policy(json.dumps(dict(policy(), **{key: value})).encode(), NOW)

    def test_policy_duplicate_fields_or_implicit_repository_expansion_deny(self):
        module = self.module()
        raw = json.dumps(policy())
        for data in (raw[:-1]+',"app_id":99}', json.dumps(dict(policy(), repositories=['*'])),
                     json.dumps(dict(policy(), repository='appolon1908/*'))):
            with self.subTest(data=data), self.assertRaises(PublicationDenied):
                module.load_atomic_policy(data.encode(), NOW)

    def test_domain_separated_digest_binds_issuance_and_original_head(self):
        module = self.module()
        payload = dict(purpose='ATOMIC_INCLUSION', head_sha='a'*40, candidate_sha='b'*40,
                       lease_id='fixture-lease', epoch=1)
        digest = module.receipt_digest(payload)
        self.assertNotEqual(digest, module.receipt_digest(dict(payload, head_sha='c'*40)))
        self.assertNotEqual(digest, module.receipt_digest(dict(payload, candidate_sha='c'*40)))
        self.assertEqual(len(digest), 64)

    def test_atomic_graph_rejects_missing_extra_and_cyclic_tasks(self):
        module = self.module()
        self.assertEqual(module.validate_task_graph({'one': [], 'two': ['one']}),
                         (('one', ()), ('two', ('one',))))
        for graph in ({'one': ['absent']}, {'one': ['one']},
                      {'one': ['two'], 'two': ['one']}, {'one': ['two','two'], 'two': []}):
            with self.subTest(graph=graph), self.assertRaises(PublicationDenied):
                module.validate_task_graph(graph)

    def test_unconfigured_online_atomic_verifier_cannot_accept_nonempty_inventory(self):
        module = self.module()
        with self.assertRaisesRegex(PublicationDenied, 'ATOMIC_ACCEPTANCE_UNCONFIGURED'):
            module.verify_inclusions(None, None, None, None, None, NOW)

    def test_atomic_issuer_is_default_deny_without_privileged_composition(self):
        module = importlib.import_module('codestra_control.atomic_issuer')
        with self.assertRaisesRegex(PublicationDenied,'ATOMIC_ISSUER_UNCONFIGURED'):
            module.AtomicInclusionIssuer(host='dev-desktop').issue('delegation','request')

    def test_emitter_uses_fresh_clock_and_short_sql_delegation_deadline(self):
        from codestra_control.atomic_issuer import AtomicIssuerGitHubVerifier
        api=SimpleNamespace(post=lambda *args: self.fail('expired authority emitted a check'),bind_effect_expiry=lambda _:None)
        issuer=AtomicIssuerGitHubVerifier(api,clock=lambda:NOW+timedelta(seconds=2))
        issuer.observe=lambda *args:(None,None,None)
        later=(NOW+timedelta(minutes=4)).isoformat()
        prepared=dict(payload=dict(lease=dict(expires_at=later),proof=dict(expires_at=later),
            delegation=dict(expires_at=(NOW+timedelta(seconds=1)).isoformat(),receipt_expires_at=later),issue_grant_expires_at=later))
        acquired=SimpleNamespace(snapshot=SimpleNamespace(observed_at=NOW,observed_binding=None),authority=SimpleNamespace(expires_at=NOW+timedelta(minutes=4)))
        accepted=SimpleNamespace(expires_at=NOW+timedelta(minutes=4))
        with self.assertRaisesRegex(PublicationDenied,'ATOMIC_PRE_EFFECT_AUTHORITY_EXPIRED'):
            issuer.emit(prepared,acquired,accepted,accepted,NOW,before_effect=lambda:None)

    def online_fixture(self):
        module = self.module(); repo = 'appolon1908/codestra'
        records = {}; receipts = []
        for index, (base,candidate,merge,age) in enumerate((('a','b','c',3600),('c','e','f',1800)),1):
            task = 'task'+str(index); source = 'atomic/sec--sub--'+task
            prepared = NOW-timedelta(seconds=age); completed = prepared+timedelta(seconds=1)
            context = dict(purpose='ATOMIC_INCLUSION',repository=repo,repository_id=123,
                task_id=task,source_ref=source,target_ref='subsection/sec--sub',head_sha='d'*40,
                base_sha=base*40,app_id=99,installation_id=100,name='atomic-inclusion',policy_revision='r1',
                custody_receipt='custody:atomic',capability_receipt='capability:atomic',
                candidate_sha=candidate*40,candidate_tree='1'*40,merge_sha=merge*40,merge_tree='2'*40,
                pr_number=index,pr_id=1000+index)
            payload = dict(binding=dict(task_id=task,source_ref=source,head_sha='d'*40,base_sha=base*40),
                           delegation=dict(context=context))
            external = module.receipt_digest(payload)
            check = dict(id=100+index,app=dict(id=99),name='atomic-inclusion',head_sha=candidate*40,
                external_id=external,status='completed',conclusion='success',completed_at=completed.isoformat(),
                check_suite=dict(id=200+index))
            pr = dict(id=1000+index,number=index,merged=True,state='closed',merge_commit_sha=merge*40,
                merged_at=(prepared-timedelta(seconds=1)).isoformat(),
                head=dict(ref=source,sha=candidate*40,repo=dict(id=123)),
                base=dict(ref='subsection/sec--sub',repo=dict(id=123)))
            merge_value = dict(sha=merge*40,tree=dict(sha='2'*40),parents=[dict(sha=base*40),dict(sha=candidate*40)])
            candidate_value = dict(sha=candidate*40,tree=dict(sha='1'*40))
            receipt = module.AtomicInclusionReceipt('receipt-'+task,module.canonical(payload),100+index,200+index,
                external,module.observation_digest(context,check,pr,merge_value,candidate_value),prepared,
                completed,completed+timedelta(seconds=1),NOW+timedelta(hours=1))
            receipts.append(receipt)
            records[f'/repos/{repo}/check-runs/{100+index}'] = check
            records[f'/repos/{repo}/check-suites/{200+index}'] = dict(id=200+index,app=dict(id=99),head_sha=candidate*40,status='completed',conclusion='success')
            records[f'/repos/{repo}/pulls/{index}'] = pr
            records[f'/repos/{repo}/git/commits/{merge*40}'] = merge_value
            records[f'/repos/{repo}/git/commits/{candidate*40}'] = candidate_value
            records[f'/repos/{repo}/compare/{merge*40}...'+('f'*40)] = dict(status='ahead' if index==1 else 'identical',merge_base_commit=dict(sha=merge*40))
            records[f'/repos/{repo}/branches/atomic%2Fsec--sub--{task}'] = dict(commit=dict(sha=candidate*40))
        records[f'/repos/{repo}/branches/subsection%2Fsec--sub'] = dict(commit=dict(sha='f'*40))
        api = SimpleNamespace(assert_identity=lambda *args: None,get=lambda path: copy.deepcopy(records[path]))
        acquired = SimpleNamespace(authority=SimpleNamespace(app_id=99,installation_id=100,custody_receipt='custody:atomic'),
            repository_id=123,snapshot=SimpleNamespace(observed_at=NOW,observed_binding=SimpleNamespace(
                repository=repo,source_ref='subsection/sec--sub',source_sha='f'*40)))
        contract = SimpleNamespace(publisher_app_id=7,certificate_name='scope-certification')
        inventory = module.AtomicInventory('ws',(('task1',()),('task2',('task1',))),tuple(receipts),'inventory')
        return api,acquired,contract,inventory,records

    def test_old_sequential_receipts_verify_against_one_current_parent_with_distinct_policy(self):
        module = self.module(); api,acquired,contract,inventory,_ = self.online_fixture()
        deadline = module.verify_inclusions(api,lambda:json.dumps(policy()).encode(),acquired,contract,inventory,NOW)
        self.assertEqual(deadline,NOW+timedelta(seconds=60))
        # A later preflight keeps the same deadline; no timestamp laundering.
        self.assertEqual(deadline,module.verify_inclusions(api,lambda:json.dumps(policy()).encode(),acquired,
            contract,inventory,NOW+timedelta(seconds=1)))

    def test_wrong_app_merge_parent_tree_or_ancestry_denies(self):
        module = self.module()
        for mutation in ('app','parent','tree','ancestry','observation','source','expired'):
            api,acquired,contract,inventory,records = self.online_fixture(); repo='appolon1908/codestra'
            if mutation=='app': records[f'/repos/{repo}/check-runs/101']['app']['id']=15368
            if mutation=='parent': records[f'/repos/{repo}/git/commits/'+('c'*40)]['parents'][0]['sha']='9'*40
            if mutation=='tree': records[f'/repos/{repo}/git/commits/'+('c'*40)]['tree']['sha']='9'*40
            if mutation=='ancestry': records[f'/repos/{repo}/compare/'+('c'*40)+'...'+('f'*40)]['status']='diverged'
            if mutation=='source': records[f'/repos/{repo}/branches/atomic%2Fsec--sub--task1']['commit']['sha']='9'*40
            if mutation=='observation': inventory=replace(inventory,receipts=(replace(inventory.receipts[0],observation_digest='0'*64),inventory.receipts[1]))
            if mutation=='expired': inventory=replace(inventory,receipts=(replace(inventory.receipts[0],expires_at=NOW),inventory.receipts[1]))
            with self.subTest(mutation=mutation), self.assertRaises(PublicationDenied):
                module.verify_inclusions(api,lambda:json.dumps(policy()).encode(),acquired,contract,inventory,NOW)


if __name__ == '__main__':
    unittest.main()
