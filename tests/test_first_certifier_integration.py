"""Actual 012/013 + TLS/SCRAM registry + first issuer; GitHub alone is synthetic.

Only the fixture's fresh local PostgreSQL cluster is used; no environment DSN,
installed database, actual credentials or external service can be selected.
"""
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest import mock

import test_decision as fixture
from test_certifier_adapter import CertifierAPI
from codestra_control.certifier_adapter import (
    AcceptedFirstCertificationContractVerifier, AuthenticatedFirstCertifier,
    CertifierGitHubVerifier, RestrictedFirstCertificationRegistry,
)
from codestra_control.publisher_adapter import Authority, PublicationDenied, binding_digest
from codestra_control.publisher_effect import IntentLedger
from codestra_control.policy import ScopeEdge

import test_scope_assignment_leases as scope_fixture
from codestra_control import publisher_acceptance

ROOT = Path(__file__).resolve().parents[1]


class FirstCertificationSQLIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scope_fixture.ScopeAssignmentLeaseTests.setUpClass()
        cls.harness = scope_fixture.ScopeAssignmentLeaseTests()
        try:
            for migration in ('009-controller-coordinator.sql','011-certifier-authority.sql',
                              '013-first-certification-pending.sql','014-atomic-inclusion-receipts.sql'):
                cls.harness.admin((ROOT / migration).read_text())
            cls.harness.admin('GRANT USAGE ON SCHEMA certifier_authority,scoped_registration TO verifier')
            cls.harness.admin('GRANT SELECT ON ALL TABLES IN SCHEMA certifier_authority TO verifier')
            cls.harness.admin('GRANT SELECT ON public.products,public.sections,public.workstations,public.atomic_tasks TO verifier')
            cls.harness.admin('GRANT SELECT ON scoped_registration.products,scoped_registration.workstations,scoped_registration.lanes,scoped_registration.candidates TO verifier')
            cls.harness.admin('GRANT SELECT ON scope_assignment_leases.products TO verifier')
            cls.harness.admin('GRANT USAGE ON SCHEMA atomic_receipts TO verifier,reviewer,operator')
            cls.harness.admin('GRANT SELECT ON ALL TABLES IN SCHEMA atomic_receipts TO verifier')
            cls.harness.admin('GRANT SELECT ON scoped_registration.task_assignments,scoped_registration.grants,scoped_registration.principals TO verifier')
            cls.harness.admin('GRANT SELECT ON assignment_leases.bindings,assignment_leases.coordinator_tasks,assignment_leases.leases,assignment_leases.proofs,assignment_leases.permissions TO verifier')
            cls.harness.admin('GRANT EXECUTE ON FUNCTION atomic_receipts.prepare(uuid,uuid),atomic_receipts.seal(uuid,bigint,bigint,text,text,timestamptz) TO reviewer')
            cls.harness.admin('GRANT EXECUTE ON FUNCTION atomic_receipts.revoke(uuid,text,uuid) TO operator')
            cls.harness.admin('GRANT EXECUTE ON FUNCTION assignment_leases.inspect_binding(uuid) TO reviewer')
            cls.harness.admin('GRANT EXECUTE ON FUNCTION assignment_leases.describe(uuid),assignment_leases.attest(uuid,jsonb) TO operator')
            for schema in ('scope_assignment_leases', 'assignment_leases', 'scoped_registration', 'frozen_recovery'):
                cls.harness.admin('REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA ' + schema + ' FROM verifier')
            cls.harness.admin('GRANT EXECUTE ON FUNCTION scope_assignment_leases.inspect_binding(uuid) TO verifier')
        except BaseException:
            cls.tearDownClass(); raise

    @classmethod
    def tearDownClass(cls):
        scope_fixture.ScopeAssignmentLeaseTests.tearDownClass()

    def setUp(self):
        from psycopg2.extras import Json
        self.harness.admin('TRUNCATE certifier_authority.pending_bindings,certifier_authority.existing_receipts,certifier_authority.product_grants')
        self.harness.admin('TRUNCATE atomic_receipts.revocations,atomic_receipts.receipts,atomic_receipts.preparations,atomic_receipts.delegations,atomic_receipts.task_dependencies,atomic_receipts.product_grants')
        self.harness.admin('TRUNCATE assignment_leases.bindings,assignment_leases.slots,assignment_leases.policies,assignment_leases.permissions,scoped_registration.candidates,scoped_registration.task_assignments CASCADE')
        self.harness.admin("DELETE FROM scoped_registration.grants WHERE product='ScopeFixture'")
        self.harness.admin("DELETE FROM public.atomic_tasks WHERE workstation_id='scope-fixture-ws'; DELETE FROM scoped_registration.lanes WHERE product='ScopeFixture' AND kind='candidate'")
        self.harness.setUp()
        # The shared source catalog is real; move the disposable product mapping
        # to an approved repository before claiming its scope assignment.
        repository = fixture.REQUEST.repository
        self.harness.admin("UPDATE public.products SET repository=%s WHERE product='ScopeFixture'", (repository,))
        self.harness.admin("UPDATE scoped_registration.products SET payload=jsonb_set(payload,'{repository}',to_jsonb(%s::text)) WHERE product='ScopeFixture'", (repository,))
        self.harness.admin('UPDATE scope_assignment_leases.products SET repository=%s', (repository,))
        self.harness.admin('UPDATE scope_assignment_leases.assignments SET repository=%s', (repository,))
        lease = self.harness.claim()
        self.lease = lease
        self.now = datetime.now(timezone.utc)
        self.binding = replace(fixture.REQUEST, product='ScopeFixture', source_ref='section/sec', target_ref='development')
        mapping = replace(fixture.ready().mapping, product='ScopeFixture', production_ref='production',
                          scope_edges=(ScopeEdge('section', 'section/sec', 'development', 'development'),
                                       ScopeEdge('subsection', 'subsection/sec--sub', 'section', 'section/sec')))
        snapshot = fixture.ready()
        snapshot = replace(snapshot, mapping=mapping, observed_binding=self.binding, certificate=None,
            observed_at=self.now, evaluated_at=self.now,
            checks=tuple(replace(value, binding=self.binding) for value in snapshot.checks),
            reviews=tuple(replace(value, binding=self.binding) for value in snapshot.reviews),
            lease=replace(snapshot.lease, binding=self.binding, owner='alice', expected_owner='alice',
                          assignment_id=self.harness.assignment, expires_at=datetime.fromisoformat(lease['expires_at'])))
        self.child_binding = replace(self.binding, source_ref='subsection/sec--sub', target_ref='section/sec',
                                     source_sha='e' * 40, target_base_sha=self.binding.source_sha)
        self.dependencies = [dict(binding=asdict(self.child_binding), repository_id=123, check_id=88,
                                  issuer_app_id=99, name='scope-certification',
                                  expires_at=(self.now + timedelta(minutes=2)).isoformat())]
        authority = Authority('Ralph L. Appolon', 'dev-desktop', 99, 100, 1,
                              self.now + timedelta(minutes=4), 'certifier-custody:fixture', (repository,))
        encode = lambda value: json.loads(json.dumps(asdict(value), default=lambda dt: dt.isoformat()))
        self.harness.admin("INSERT INTO certifier_authority.product_grants SELECT rolname,oid,'ScopeFixture',%s,123,true,clock_timestamp()+interval '4 minutes' FROM pg_roles WHERE rolname='verifier'", (repository,))
        self.harness.admin("INSERT INTO atomic_receipts.product_grants SELECT rolname,oid,'ScopeFixture','read',clock_timestamp()+interval '4 minutes',true FROM pg_roles WHERE rolname='verifier'")
        self.harness.admin("""INSERT INTO certifier_authority.pending_bindings(
          binding_hash,principal,role_oid,product,repository,repository_id,pr_number,authority,snapshot,
          scope_type,scope_name,assignment_id,lease_id,lease_epoch,lease_principal,delegation_ref,
          capability_receipt,dependency_policy,accepted_by,purpose,issued_at,expires_at,active)
          SELECT %s,rolname,oid,'ScopeFixture',%s,123,9,%s,%s,'SECTION','section/sec',%s,%s,%s,'alice',
          'operator:integration-delegation','scope-capability:fixture',%s,'Ralph L. Appolon',
          'FIRST_SCOPE_CERTIFICATION',%s,%s,true FROM pg_roles WHERE rolname='verifier'""",
          (binding_digest(self.binding), repository, Json(encode(authority)), Json(encode(snapshot)),
           self.harness.assignment, lease['lease_id'], lease['epoch'], Json(self.dependencies), self.now, self.now + timedelta(minutes=2)))
        policy = dict(schema='codestra.producer-acceptance.v1', state='ACCEPTED', accepted_by='Ralph L. Appolon',
            acceptance_ref='operator:integration-policy', publisher_app_id=7, publisher_installation_id=8,
            certificate_app_id=99, certificate_installation_id=100, certificate_name='scope-certification',
            controller_contexts=['codestra-control-plane', 'codestra/control-plane'],
            repositories=[{'repository': repository, 'repository_id': 123}], custody_receipt='publisher-custody:fixture',
            certifier_custody_receipt='certifier-custody:fixture', certifier_capability_receipt='scope-capability:fixture',
            accepted_at=self.now.isoformat(), expires_at=(self.now + timedelta(minutes=4)).isoformat(), max_receipt_age_seconds=300)
        self.policy_bytes = json.dumps(policy).encode()
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.api = CertifierAPI()
        original = self.api.get
        def get(path):
            if path.endswith('/branches/subsection%2Fsec--sub'): return {'commit': {'sha': self.child_binding.source_sha}}
            if path.endswith('/branches/section%2Fsec'): return {'commit': {'sha': self.binding.source_sha}}
            if path.endswith('/check-runs/88'):
                return {'id': 88, 'app': {'id': 99}, 'name': 'scope-certification',
                        'head_sha': self.child_binding.source_sha, 'external_id': binding_digest(self.child_binding),
                        'status': 'completed', 'conclusion': 'success',
                        'completed_at': self.now.isoformat(), 'check_suite': {'id': 188}}
            if path.endswith('/check-suites/188'):
                return {'id': 188, 'app': {'id': 99}, 'head_sha': self.child_binding.source_sha,
                        'status': 'completed', 'conclusion': 'success'}
            value = original(path)
            if path.endswith('/pulls/9'):
                value['head'].update(ref=self.binding.source_ref, sha=self.binding.source_sha)
                value['base'].update(ref=self.binding.target_ref, sha=self.binding.target_base_sha)
            return value
        self.api.get = get
        self.connection = self.harness.connect('verifier'); self.addCleanup(self.connection.close)
        # The fixture CA is in a private temporary directory; TLS validation and
        # SCRAM are actual. Operator path-ownership validation is tested separately.
        patcher = mock.patch('codestra_control.publisher_startup.protected_read', return_value=b'synthetic-protected-reader')
        patcher.start(); self.addCleanup(patcher.stop)
        self.certifier = AuthenticatedFirstCertifier(RestrictedFirstCertificationRegistry(self.connection),
            CertifierGitHubVerifier(self.api), IntentLedger(Path(self.temp.name) / 'intents.sqlite'),
            contract_verifier=AcceptedFirstCertificationContractVerifier(lambda: self.policy_bytes), host='dev-desktop')

    def test_actual_authenticated_pending_scope_lease_and_protected_policy_issue_first_check(self):
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT session_user,current_user,system_user')
            self.assertEqual(cursor.fetchone(), ('verifier', 'verifier', 'scram-sha-256:verifier'))
        self.connection.rollback()
        with mock.patch('codestra_control.decision.evaluate_promotion', side_effect=AssertionError('not certification')):
            result = self.certifier.publish(self.binding)
        self.assertEqual(result.state, 'COMPLETE')
        self.assertEqual(len(self.api.effects), 1)
        self.assertEqual(self.api.effects[0][1]['external_id'], binding_digest(self.binding))
        self.assertEqual(self.api.result['app']['id'], 99)
        self.assertFalse(any('/check-runs/10' in path for path in self.api.paths))

    def test_live_scope_lease_revocation_denies_before_first_effect(self):
        self.harness.admin('UPDATE scope_assignment_leases.assignments SET active=false')
        with self.assertRaises(PublicationDenied): self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects, [])

    def test_actual_pending_product_grant_revocation_denies_before_first_effect(self):
        self.harness.admin('UPDATE certifier_authority.product_grants SET active=false')
        with self.assertRaises(PublicationDenied): self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects, [])

    def test_online_changed_head_or_base_denies_with_actual_pending_authority(self):
        original = self.api.get
        for field in ('head', 'base'):
            def get(path):
                value = original(path)
                if path.endswith('/pulls/9'): value[field]['sha'] = 'd' * 40
                return value
            self.api.get = get
            with self.subTest(field=field), self.assertRaises(PublicationDenied): self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects, [])

    def test_omitted_configured_child_cannot_be_hidden_by_empty_policy_or_snapshot_mapping(self):
        self.harness.admin("UPDATE certifier_authority.pending_bindings SET dependency_policy='[]', snapshot=jsonb_set(snapshot,'{mapping,scope_edges}',(snapshot->'mapping'->'scope_edges')-1)")
        with self.assertRaises(PublicationDenied): self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects, [])

    def test_new_configured_child_during_final_registry_read_denies_before_effect(self):
        original = self.certifier.registry.acquire
        calls = [0]
        def changed(binding, now):
            calls[0] += 1
            if calls[0] == 2:
                self.harness.admin("INSERT INTO public.workstations(workstation_id,product,section,subsection,branch,parent_branch,worktree,order_index) VALUES('scope-new-child','ScopeFixture','sec','new','subsection/sec--new','section/sec','/fixture/scope/new',2)")
                self.harness.admin("INSERT INTO scoped_registration.workstations SELECT product,workstation_id,branch,worktree,jsonb_build_object('product',product,'workstation_id',workstation_id,'section',section,'subsection',subsection,'branch',branch,'parent_branch',parent_branch,'worktree',worktree,'order_index',order_index) FROM public.workstations WHERE workstation_id='scope-new-child'")
                self.harness.admin("INSERT INTO scoped_registration.lanes VALUES('/fixture/scope/new','ScopeFixture','workstation','scope-new-child','subsection/sec--new')")
            return original(binding, now)
        self.certifier.registry.acquire = changed
        with self.assertRaises(PublicationDenied): self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects, [])

    def test_empty_declared_policy_denies_even_with_complete_snapshot_mapping(self):
        self.harness.admin("UPDATE certifier_authority.pending_bindings SET dependency_policy='[]'")
        with self.assertRaisesRegex(PublicationDenied, 'CURRENT_DEPENDENCY_INVENTORY_MISMATCH'):
            self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects, [])

    def test_extra_declared_dependency_denies_before_online_receipt_read(self):
        from psycopg2.extras import Json
        extra = dict(self.dependencies[0], binding=asdict(replace(self.binding,
            source_ref='testing', target_ref='staging', source_sha='f' * 40, target_base_sha='e' * 40)), check_id=89)
        self.harness.admin('UPDATE certifier_authority.pending_bindings SET dependency_policy=%s', (Json([*self.dependencies, extra]),))
        with self.assertRaisesRegex(PublicationDenied, 'CURRENT_DEPENDENCY_INVENTORY_MISMATCH'):
            self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects, [])

    def test_subsection_with_actual_atomic_task_cannot_claim_empty_dependencies(self):
        from psycopg2.extras import Json
        assignment = self.harness.assign('subsection', 'section', 'subsection/sec--sub', 'section/sec')
        self.harness.admin('UPDATE scope_assignment_leases.assignments SET repository=%s WHERE assignment_id=%s',
                           (self.binding.repository, assignment))
        lease = self.harness.claim(assignment=assignment)
        binding = replace(self.binding, source_ref='subsection/sec--sub', target_ref='section/sec')
        raw = self.harness.admin('SELECT snapshot FROM certifier_authority.pending_bindings')[0][0]
        raw['observed_binding'] = asdict(binding)
        for value in raw['checks']: value['binding'] = asdict(binding)
        for value in raw['reviews']: value['binding'] = asdict(binding)
        raw['lease'].update(binding=asdict(binding), assignment_id=assignment, expires_at=lease['expires_at'])
        self.harness.admin("UPDATE certifier_authority.pending_bindings SET binding_hash=%s,snapshot=%s,scope_type='SUBSECTION',scope_name='subsection/sec--sub',assignment_id=%s,lease_id=%s,lease_epoch=%s,dependency_policy='[]'",
            (binding_digest(binding), Json(raw), assignment, lease['lease_id'], lease['epoch']))
        self.harness.admin("INSERT INTO public.atomic_tasks(task_id,workstation_id,title,owner) VALUES('configured-atomic','scope-fixture-ws','configured task','alice')")
        with self.assertRaisesRegex(PublicationDenied, 'ATOMIC_CANONICAL_CHILD_UNSEALED_OR_UNREGISTERED'):
            self.certifier.publish(binding)
        self.assertEqual(self.api.effects, [])

    def _sealed_atomic_child(self, release=True, source_issuer=False, issuer_mutation=None):
        """Actual authenticated prepare/seal with synthetic authoritative GitHub."""
        from psycopg2.extras import Json
        from codestra_control.atomic_receipts import receipt_digest,observation_digest
        assignment = self.harness.assign('subsection','section','subsection/sec--sub','section/sec')
        self.harness.admin('UPDATE scope_assignment_leases.assignments SET repository=%s WHERE assignment_id=%s',
                           (self.binding.repository,assignment))
        scope_lease = self.harness.claim(assignment=assignment)
        self.binding = replace(self.binding,source_ref='subsection/sec--sub',target_ref='section/sec')
        raw = self.harness.admin('SELECT snapshot FROM certifier_authority.pending_bindings')[0][0]
        raw['observed_binding'] = asdict(self.binding)
        for value in raw['checks']: value['binding']=asdict(self.binding)
        for value in raw['reviews']: value['binding']=asdict(self.binding)
        raw['lease'].update(binding=asdict(self.binding),assignment_id=assignment,expires_at=scope_lease['expires_at'])
        self.harness.admin("UPDATE certifier_authority.pending_bindings SET binding_hash=%s,snapshot=%s,scope_type='SUBSECTION',scope_name='subsection/sec--sub',assignment_id=%s,lease_id=%s,lease_epoch=%s,dependency_policy='[]'",
            (binding_digest(self.binding),Json(raw),assignment,scope_lease['lease_id'],scope_lease['epoch']))
        self.harness.admin("INSERT INTO scoped_registration.principals SELECT rolname,oid,true FROM pg_roles WHERE rolname IN ('alice','operator','reviewer') ON CONFLICT(principal) DO UPDATE SET role_oid=excluded.role_oid,active=true")
        self.harness.admin("INSERT INTO scoped_registration.grants VALUES('alice','ScopeFixture','candidate',%s)", (self.binding.repository,))
        self.harness.admin("INSERT INTO scoped_registration.task_assignments VALUES('ScopeFixture','scope-fixture-ws','atomic-child','alice',true)")
        self.harness.admin("INSERT INTO public.atomic_tasks(task_id,workstation_id,title,owner,status) VALUES('atomic-child','scope-fixture-ws','atomic child','alice','IN_PROGRESS')")
        candidate = dict(product='ScopeFixture',workstation_id='scope-fixture-ws',task_id='atomic-child',title='atomic child',
            branch='atomic/sec--sub--child',target_branch='subsection/sec--sub',worktree='/fixture/scope/atomic',
            head_sha='d'*40,base_sha='c'*40,prerequisites=[])
        self.harness.admin("INSERT INTO scoped_registration.candidates VALUES('ScopeFixture','scope-fixture-ws','atomic-child','alice','atomic/sec--sub--child','/fixture/scope/atomic',%s)",(Json(candidate),))
        self.harness.admin("INSERT INTO scoped_registration.lanes VALUES('/fixture/scope/atomic','ScopeFixture','candidate','atomic-child','atomic/sec--sub--child')")
        binding = str(uuid.uuid4()); self.atomic_binding = binding
        self.harness.admin("""INSERT INTO assignment_leases.bindings(binding_id,product,workstation_id,task_id,principal,principal_oid,
         repository,repository_id,source_ref,target_ref,head_sha,base_sha,worktree,host,root_path,git_common_dir,worktree_uid,valid_until,active)
         SELECT %s,'ScopeFixture','scope-fixture-ws','atomic-child','alice',oid,%s,123,'atomic/sec--sub--child','subsection/sec--sub',%s,%s,
         '/fixture/scope/atomic','fixture-host','/fixture/scope','/fixture/scope/repo.git',1000,clock_timestamp()+interval '5 minutes',true FROM pg_roles WHERE rolname='alice'""",
         (binding,self.binding.repository,'d'*40,'c'*40))
        self.harness.admin("INSERT INTO assignment_leases.coordinator_tasks VALUES(%s,'atomic child','[]',true)",(binding,))
        self.harness.admin("INSERT INTO assignment_leases.policies VALUES('ScopeFixture',120,120,300,90,true)")
        self.harness.admin("INSERT INTO assignment_leases.permissions VALUES('operator','ScopeFixture','attest',true),('operator','ScopeFixture','revoke',true),('reviewer','ScopeFixture','read',true)")
        self.harness.admin("INSERT INTO atomic_receipts.product_grants SELECT rolname,oid,'ScopeFixture',CASE WHEN rolname='reviewer' THEN 'issue' ELSE 'revoke' END,clock_timestamp()+interval '4 minutes',true FROM pg_roles WHERE rolname IN ('reviewer','operator')")
        self.harness.admin("INSERT INTO atomic_receipts.task_dependencies VALUES('ScopeFixture','scope-fixture-ws','atomic-child','[]')")
        def call(user,query,args):
            with self.harness.connect(user) as connection,connection.cursor() as cursor:
                cursor.execute(query,args); return cursor.fetchone()[0]
        self.atomic_call = call
        description = call('operator','SELECT assignment_leases.describe(%s)',(binding,))['binding']
        observed = {k:description[k] for k in ('repository','repository_id','source_ref','target_ref','head_sha','base_sha','worktree','host','git_common_dir','worktree_uid')}
        observed.update(directory_device=1,directory_inode=2,observed_at=datetime.now(timezone.utc).isoformat(),dependencies={})
        proof = call('operator','SELECT assignment_leases.attest(%s,%s)',(binding,Json(observed)))
        lease = call('alice','SELECT assignment_leases.claim(%s,%s,%s)',(binding,proof['proof_id'],'fixture-claim'))
        self.atomic_lease = lease
        context = dict(purpose='ATOMIC_INCLUSION',repository=self.binding.repository,repository_id=123,task_id='atomic-child',
            source_ref='atomic/sec--sub--child',target_ref='subsection/sec--sub',head_sha='d'*40,base_sha='c'*40,
            app_id=99,installation_id=100,name='atomic-inclusion',policy_revision='atomic-r1',
            custody_receipt='certifier-custody:fixture',capability_receipt='atomic-capability:fixture',
            candidate_sha='e'*40,candidate_tree='1'*40,merge_sha='a'*40,merge_tree='2'*40,pr_number=10,pr_id=1010)
        delegation = str(uuid.uuid4())
        self.harness.admin("""INSERT INTO atomic_receipts.delegations(delegation_id,binding_id,lease_id,epoch,principal,role_oid,
         product,purpose,context,accepted_by,acceptance_ref,expires_at,receipt_expires_at,active)
         SELECT %s,%s,%s,%s,'reviewer',oid,'ScopeFixture','ATOMIC_INCLUSION',%s,'Ralph L. Appolon','operator:atomic',
         clock_timestamp()+interval '2 minutes',clock_timestamp()+interval '3 minutes',true FROM pg_roles WHERE rolname='reviewer'""",
         (delegation,binding,lease['lease_id'],lease['epoch'],Json(context)))
        request=str(uuid.uuid4())
        prepared = call('reviewer','SELECT atomic_receipts.prepare(%s,%s)',(delegation,request))
        self.atomic_prepared = prepared
        completed = datetime.now(timezone.utc)
        check = dict(id=110,app=dict(id=99),name='atomic-inclusion',head_sha='e'*40,external_id=receipt_digest(prepared['payload']),
            status='completed',conclusion='success',completed_at=completed.isoformat(),check_suite=dict(id=210))
        pr = dict(id=1010,number=10,state='closed',merged=True,merge_commit_sha='a'*40,user=dict(login='author'),
            merged_at=(datetime.fromisoformat(prepared['prepared_at']).astimezone(timezone.utc)-timedelta(seconds=1)).isoformat(),
            head=dict(ref='atomic/sec--sub--child',sha='e'*40,repo=dict(id=123)),
            base=dict(ref='subsection/sec--sub',repo=dict(id=123)))
        merge = dict(sha='a'*40,tree=dict(sha='2'*40),parents=[dict(sha='c'*40),dict(sha='e'*40)])
        candidate_commit = dict(sha='e'*40,tree=dict(sha='1'*40))
        original = self.api.get; repo=self.binding.repository
        values = {f'/repos/{repo}/check-runs/110':check,f'/repos/{repo}/pulls/10':pr,
            f'/repos/{repo}/check-suites/210':dict(id=210,app=dict(id=99),head_sha='e'*40,status='completed',conclusion='success'),
            f'/repos/{repo}/git/commits/'+('a'*40):merge,f'/repos/{repo}/git/commits/'+('e'*40):candidate_commit,
            f'/repos/{repo}/compare/'+('a'*40)+'...'+('a'*40):dict(status='identical',merge_base_commit=dict(sha='a'*40)),
            f'/repos/{repo}/branches/atomic%2Fsec--sub--child':dict(commit=dict(sha='e'*40)),
            f'/repos/{repo}/branches/subsection%2Fsec--sub':dict(commit=dict(sha='a'*40),protected=True),
            f'/repos/{repo}/branches/section%2Fsec':dict(commit=dict(sha='b'*40),protected=True)}
        self.api.get = lambda path: values[path] if path in values else original(path)
        policy = dict(schema='codestra.atomic-inclusion-acceptance.v1',state='ACCEPTED',accepted_by='Ralph L. Appolon',
            acceptance_ref='operator:atomic',revision='atomic-r1',purpose='ATOMIC_INCLUSION',repository=repo,repository_id=123,
            app_id=99,installation_id=100,name='atomic-inclusion',custody_receipt='certifier-custody:fixture',
            capability_receipt='atomic-capability:fixture',max_receipt_lifetime_seconds=86400,max_observation_age_seconds=300,
            accepted_at=(self.now-timedelta(seconds=1)).isoformat(),expires_at=(self.now+timedelta(minutes=4)).isoformat())
        self.certifier.github.atomic_policy_reader = lambda: json.dumps(policy).encode()
        if source_issuer:
            from codestra_control.atomic_issuer import (AtomicInclusionIssuer,AtomicIssuerAcquisition,
                AtomicIssuerGitHubVerifier,RestrictedAtomicIssuerRegistry)
            from codestra_control.publisher_acquisition import decode_snapshot
            original_pages=self.api.pages; original_post=self.api.post
            original_get=self.api.get
            def issuer_get(path):
                value=original_get(path)
                if path.endswith('/protection') and issuer_mutation:
                    import copy
                    value=copy.deepcopy(value)
                    first=value['required_status_checks']['checks'][0]
                    if issuer_mutation=='self-ci': first['app_id']=99
                    if issuer_mutation=='alias-ci': first['context']='atomic-inclusion'
                return value
            self.api.get=issuer_get
            def pages(path,key=None):
                if path.endswith('/pulls/10/reviews'):
                    return [dict(id=12,commit_id='e'*40,user=dict(login='independent-reviewer'),state='APPROVED',
                                 submitted_at=(datetime.fromisoformat(pr['merged_at'])-timedelta(seconds=1)).isoformat())]
                if '/commits/' in path and '/check-runs' in path:
                    sha=path.split('/commits/')[1].split('/')[0]
                    completed_at=(datetime.fromisoformat(pr['merged_at'])-timedelta(seconds=1)).isoformat() if sha=='e'*40 else completed.isoformat()
                    return [dict(id=120,head_sha=sha,app=dict(id=99 if issuer_mutation=='self-ci' else 15368),
                        name='atomic-inclusion' if issuer_mutation=='alias-ci' else 'quality',
                        status='completed',conclusion='success',completed_at=completed_at)]
                return original_pages(path,key)
            def post(path,body):
                if body.get('name')!='atomic-inclusion': return original_post(path,body)
                self.api.effects.append((path,body))
                values[f'/repos/{repo}/check-runs/110']=dict(body,id=110,app=dict(id=99),check_suite=dict(id=210),completed_at=datetime.now(timezone.utc).isoformat())
                return values[f'/repos/{repo}/check-runs/110']
            self.api.pages,self.api.post=pages,post
            atomic_binding=replace(self.binding,source_ref=context['source_ref'],target_ref=context['target_ref'],source_sha='e'*40,target_base_sha='c'*40)
            snapshot=decode_snapshot(raw)
            snapshot=replace(snapshot,observed_binding=atomic_binding,observed_at=datetime.now(timezone.utc),
                checks=tuple(replace(v,binding=atomic_binding) for v in snapshot.checks),
                reviews=tuple(replace(v,binding=atomic_binding) for v in snapshot.reviews))
            if issuer_mutation=='self-ci': snapshot=replace(snapshot,required_checks=tuple(replace(v,producer='github-actions:99') for v in snapshot.required_checks))
            if issuer_mutation=='alias-ci': snapshot=replace(snapshot,required_checks=tuple(replace(v,name='atomic-inclusion') for v in snapshot.required_checks))
            acquisition=AtomicIssuerAcquisition(Authority('Ralph L. Appolon','dev-desktop',99,100,1,
                self.now+timedelta(minutes=4),'certifier-custody:fixture',(repo,)),snapshot,123,10)
            issuer_connection=self.harness.connect('reviewer');self.addCleanup(issuer_connection.close)
            issuer=AtomicInclusionIssuer(RestrictedAtomicIssuerRegistry(issuer_connection),AtomicIssuerGitHubVerifier(self.api),
                IntentLedger(Path(self.temp.name)/'atomic.sqlite'),lambda:json.dumps(policy).encode(),lambda:self.policy_bytes,
                lambda _:acquisition,host='dev-desktop')
            result=issuer.issue(delegation,request)
            self.assertEqual(result.state,'COMPLETE')
            receipt=result.receipts[0]
        else:
            receipt = call('reviewer','SELECT atomic_receipts.seal(%s,%s,%s,%s,%s,%s)',
                (prepared['preparation_id'],110,210,check['external_id'],observation_digest(context,check,pr,merge,candidate_commit),completed))
        self.atomic_receipt=receipt
        if release: call('alice','SELECT assignment_leases.release(%s,%s,%s)',(lease['lease_id'],lease['epoch'],'fixture-release'))
        return receipt

    def test_nonempty_subsection_first_issuance_accepts_real_sealed_released_history(self):
        self._sealed_atomic_child()
        self.assertEqual(self.harness.admin('SELECT state FROM assignment_leases.leases')[0][0],'RELEASED')
        self.assertEqual(self.certifier.publish(self.binding).state,'COMPLETE')
        self.assertEqual(len(self.api.effects),1)

    def test_concrete_atomic_issuer_then_released_child_then_first_subsection(self):
        self._sealed_atomic_child(source_issuer=True)
        self.assertEqual(self.certifier.publish(self.binding).state,'COMPLETE')
        self.assertEqual([body['name'] for _,body in self.api.effects],['atomic-inclusion','scope-certification'])

    def test_concrete_atomic_issuer_cannot_use_privileged_app_as_ci(self):
        with self.assertRaisesRegex(PublicationDenied,'ATOMIC_INDEPENDENT_CI_REQUIRED'):
            self._sealed_atomic_child(source_issuer=True,issuer_mutation='self-ci')
        self.assertEqual(self.api.effects,[])

    def test_concrete_atomic_issuer_cannot_alias_ci_to_atomic_certificate(self):
        with self.assertRaisesRegex(PublicationDenied,'ATOMIC_INDEPENDENT_CI_REQUIRED'):
            self._sealed_atomic_child(source_issuer=True,issuer_mutation='alias-ci')
        self.assertEqual(self.api.effects,[])

    def test_released_binding_revocation_still_invalidates_sealed_receipt(self):
        self._sealed_atomic_child()
        self.atomic_call('operator','SELECT assignment_leases.revoke(%s,%s,%s)',(self.atomic_binding,'fixture revoke','fixture-revoke'))
        self.assertEqual(self.harness.admin('SELECT state FROM assignment_leases.leases')[0][0],'RELEASED')
        with self.assertRaises(PublicationDenied): self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects,[])

    def test_released_history_cannot_be_backfilled_or_resealed(self):
        import psycopg2
        self._sealed_atomic_child()
        with self.assertRaises(psycopg2.Error):
            self.atomic_call('reviewer','SELECT atomic_receipts.prepare(%s,%s)',
                (self.atomic_prepared['delegation_id'],str(uuid.uuid4())))
        with self.assertRaises(psycopg2.Error):
            self.atomic_call('reviewer','SELECT atomic_receipts.seal(%s,%s,%s,%s,%s,%s)',
                (self.atomic_prepared['preparation_id'],999,999,'a'*64,'b'*64,datetime.now(timezone.utc)))

    def test_sealed_history_is_immutable_and_reader_has_no_issuer_capability(self):
        import psycopg2
        self._sealed_atomic_child()
        for query in ('UPDATE atomic_receipts.receipts SET observation_digest=repeat(\'a\',64)',
                      'DELETE FROM atomic_receipts.preparations'):
            with self.subTest(query=query),self.assertRaisesRegex(psycopg2.Error,'ATOMIC_HISTORY_IMMUTABLE'):
                self.harness.admin(query)
        with self.assertRaises(psycopg2.Error):
            self.atomic_call('verifier','SELECT atomic_receipts.prepare(%s,%s)',
                (self.atomic_prepared['delegation_id'],str(uuid.uuid4())))

    def test_partial_candidate_mirror_or_changed_delegation_denies(self):
        from psycopg2.extras import Json
        self._sealed_atomic_child()
        original=self.harness.admin("SELECT payload FROM scoped_registration.candidates WHERE task_id='atomic-child'")[0][0]
        for key in ('task_id','product','workstation_id','branch','worktree','title'):
            self.harness.admin("UPDATE scoped_registration.candidates SET payload=%s WHERE task_id='atomic-child'",(Json(dict(original,**{key:'changed'})),))
            with self.subTest(field=key),self.assertRaises(PublicationDenied): self.certifier.publish(self.binding)
        self.harness.admin("UPDATE scoped_registration.candidates SET payload=%s WHERE task_id='atomic-child'",(Json(original),))
        self.harness.admin("UPDATE atomic_receipts.delegations SET acceptance_ref='changed'")
        with self.assertRaises(PublicationDenied): self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects,[])

    def test_noninherited_authority_writer_membership_cannot_read_as_restricted_certifier(self):
        self._sealed_atomic_child()
        self.harness.admin('CREATE ROLE atomic_fixture_writer NOLOGIN NOINHERIT')
        self.harness.admin('GRANT UPDATE ON atomic_receipts.product_grants TO atomic_fixture_writer')
        self.harness.admin('GRANT atomic_fixture_writer TO verifier WITH INHERIT FALSE')
        try:
            with self.assertRaises(PublicationDenied): self.certifier.publish(self.binding)
            self.assertEqual(self.api.effects,[])
        finally:
            self.harness.admin('REVOKE atomic_fixture_writer FROM verifier')
            self.harness.admin('DROP OWNED BY atomic_fixture_writer; DROP ROLE atomic_fixture_writer')

    def test_explicit_atomic_receipt_revocation_denies_before_scope_effect(self):
        receipt=self._sealed_atomic_child()
        self.atomic_call('operator','SELECT atomic_receipts.revoke(%s,%s,%s)',(receipt['receipt_id'],'fixture revocation',str(uuid.uuid4())))
        with self.assertRaises(PublicationDenied): self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects,[])

    def test_missing_atomic_purpose_policy_denies_despite_valid_scope_policy(self):
        self._sealed_atomic_child(); self.certifier.github.atomic_policy_reader=None
        with self.assertRaisesRegex(PublicationDenied,'ATOMIC_ACCEPTANCE_UNCONFIGURED'): self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects,[])

    def test_configured_pending_atomic_assignment_cannot_disappear(self):
        self._sealed_atomic_child()
        self.harness.admin("INSERT INTO scoped_registration.task_assignments VALUES('ScopeFixture','scope-fixture-ws','pending-child','alice',true)")
        with self.assertRaisesRegex(PublicationDenied,'ATOMIC_CANONICAL_CHILD_UNSEALED_OR_UNREGISTERED'): self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects,[])

    def _configure_section_prerequisite(self, identifier='pre', section_id='scope-prerequisite-section', include_receipt=False):
        from psycopg2.extras import Json
        self.harness.admin("INSERT INTO public.sections(section_id,product,section_key,branch,order_index) VALUES(%s,'ScopeFixture','pre','section/pre',2)", (section_id,))
        self.harness.admin("UPDATE public.sections SET depends_on=%s WHERE section_key='sec' AND product='ScopeFixture'", (Json([identifier]),))
        raw = self.harness.admin('SELECT snapshot FROM certifier_authority.pending_bindings')[0][0]
        raw['mapping']['scope_edges'].append(dict(source_level='section', source_ref='section/pre', target_level='development', target_ref='development'))
        dependencies = list(self.dependencies)
        dependency_binding = replace(self.binding, source_ref='section/pre', target_ref='development', source_sha='f' * 40)
        if include_receipt:
            dependencies.append(dict(binding=asdict(dependency_binding),repository_id=123,check_id=89,issuer_app_id=99,
                name='scope-certification',expires_at=(self.now+timedelta(minutes=2)).isoformat()))
        self.harness.admin('UPDATE certifier_authority.pending_bindings SET snapshot=%s,dependency_policy=%s', (Json(raw),Json(dependencies)))
        original = self.api.get
        def get(path):
            if path.endswith('/branches/section%2Fpre'): return {'commit': {'sha': 'f' * 40}}
            if path.endswith('/check-runs/89'):
                return {'id':89,'app':{'id':99},'name':'scope-certification','head_sha':'f'*40,
                    'external_id':binding_digest(dependency_binding),'status':'completed','conclusion':'success',
                    'completed_at':self.now.isoformat(),'check_suite':{'id':189}}
            if path.endswith('/check-suites/189'):
                return {'id':189,'app':{'id':99},'head_sha':'f'*40,'status':'completed','conclusion':'success'}
            return original(path)
        self.api.get = get

    def test_configured_section_prerequisite_omitted_from_policy_denies(self):
        self._configure_section_prerequisite()
        with self.assertRaisesRegex(PublicationDenied, 'CURRENT_DEPENDENCY_INVENTORY_MISMATCH'):
            self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects, [])

    def test_section_prerequisite_key_with_exact_live_receipt_can_certify(self):
        self._configure_section_prerequisite(include_receipt=True)
        self.assertEqual(self.certifier.publish(self.binding).state, 'COMPLETE')
        self.assertEqual(len(self.api.effects), 1)

    def test_section_prerequisite_id_with_exact_live_receipt_can_certify(self):
        self._configure_section_prerequisite(identifier='scope-prerequisite-section', include_receipt=True)
        self.assertEqual(self.certifier.publish(self.binding).state, 'COMPLETE')
        self.assertEqual(len(self.api.effects), 1)

    def test_section_prerequisite_cycle_is_denied(self):
        self._configure_section_prerequisite(include_receipt=True)
        self.harness.admin("UPDATE public.sections SET depends_on='[\"sec\"]' WHERE section_key='pre' AND product='ScopeFixture'")
        with self.assertRaisesRegex(PublicationDenied, 'SECTION_DEPENDENCY_CYCLE'):
            self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects, [])

    def test_ambiguous_section_id_key_reference_is_denied(self):
        self._configure_section_prerequisite(identifier='sec', section_id='sec', include_receipt=True)
        with self.assertRaisesRegex(PublicationDenied, 'SECTION_DEPENDENCY_REFERENCE_INVALID'):
            self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects, [])

    def test_invalid_section_prerequisite_shapes_unknown_self_and_duplicate_references_deny(self):
        from psycopg2.extras import Json
        for declaration in (None, {}, 'sec', ['unknown'], ['sec'], ['scope-fixture-section'], ['sec','sec']):
            self.harness.admin("UPDATE public.sections SET depends_on=%s WHERE product='ScopeFixture' AND section_key='sec'", (Json(declaration),))
            with self.subTest(declaration=declaration), self.assertRaisesRegex(PublicationDenied, 'SECTION_DEPENDENCY_'):
                self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects, [])

    def test_distinct_id_and_key_aliases_cannot_repeat_the_same_section_dependency(self):
        from psycopg2.extras import Json
        self._configure_section_prerequisite(include_receipt=True)
        self.harness.admin("UPDATE public.sections SET depends_on=%s WHERE product='ScopeFixture' AND section_key='sec'", (Json(['pre','scope-prerequisite-section']),))
        with self.assertRaisesRegex(PublicationDenied, 'SECTION_DEPENDENCY_REFERENCE_INVALID'):
            self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects, [])

    def _configure_subsection_graph(self, cycle=False):
        from psycopg2.extras import Json
        self.harness.admin("INSERT INTO public.workstations(workstation_id,product,section,subsection,branch,parent_branch,worktree,order_index,depends_on) VALUES('scope-fixture-ws-b','ScopeFixture','sec','sub-b','subsection/sec--sub-b','section/sec','/fixture/scope/sub-b',2,%s)",
            (Json(['scope-fixture-ws'] if cycle else []),))
        self.harness.admin("INSERT INTO scoped_registration.workstations SELECT product,workstation_id,branch,worktree,jsonb_build_object('product',product,'workstation_id',workstation_id,'section',section,'subsection',subsection,'branch',branch,'parent_branch',parent_branch,'worktree',worktree,'order_index',order_index) FROM public.workstations WHERE workstation_id='scope-fixture-ws-b'")
        self.harness.admin("INSERT INTO scoped_registration.lanes VALUES('/fixture/scope/sub-b','ScopeFixture','workstation','scope-fixture-ws-b','subsection/sec--sub-b')")
        self.harness.admin("UPDATE public.workstations SET depends_on='[\"scope-fixture-ws-b\"]' WHERE workstation_id='scope-fixture-ws'")
        raw = self.harness.admin('SELECT snapshot FROM certifier_authority.pending_bindings')[0][0]
        raw['mapping']['scope_edges'].append(dict(source_level='subsection',source_ref='subsection/sec--sub-b',target_level='section',target_ref='section/sec'))
        binding = replace(self.child_binding,source_ref='subsection/sec--sub-b',source_sha='f'*40)
        dependencies = [*self.dependencies,dict(binding=asdict(binding),repository_id=123,check_id=89,issuer_app_id=99,
            name='scope-certification',expires_at=(self.now+timedelta(minutes=2)).isoformat())]
        self.harness.admin('UPDATE certifier_authority.pending_bindings SET snapshot=%s,dependency_policy=%s', (Json(raw),Json(dependencies)))
        original = self.api.get
        def get(path):
            if path.endswith('/branches/subsection%2Fsec--sub-b'): return {'commit':{'sha':'f'*40}}
            if path.endswith('/check-runs/89'):
                return {'id':89,'app':{'id':99},'name':'scope-certification','head_sha':'f'*40,
                    'external_id':binding_digest(binding),'status':'completed','conclusion':'success',
                    'completed_at':self.now.isoformat(),'check_suite':{'id':189}}
            if path.endswith('/check-suites/189'):
                return {'id':189,'app':{'id':99},'head_sha':'f'*40,'status':'completed','conclusion':'success'}
            return original(path)
        self.api.get = get

    def test_cyclic_current_subsections_deny_section_issuance_despite_fresh_child_receipts(self):
        self._configure_subsection_graph(cycle=True)
        with self.assertRaisesRegex(PublicationDenied, 'SUBSECTION_DEPENDENCY_CYCLE'):
            self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects, [])

    def test_acyclic_current_subsections_with_complete_fresh_receipts_can_certify(self):
        self._configure_subsection_graph()
        self.assertEqual(self.certifier.publish(self.binding).state, 'COMPLETE')
        self.assertEqual(len(self.api.effects), 1)

    def test_unknown_self_alias_and_duplicate_subsection_references_deny_all_scopes(self):
        from psycopg2.extras import Json
        for declaration in (['unknown'],['scope-fixture-ws'],['sub'],['subsection/sec--sub'],['scope-fixture-ws','scope-fixture-ws']):
            self.harness.admin('UPDATE public.workstations SET depends_on=%s WHERE workstation_id=%s', (Json(declaration),'scope-fixture-ws'))
            with self.subTest(declaration=declaration), self.assertRaisesRegex(PublicationDenied, 'SUBSECTION_DEPENDENCY_'):
                self.certifier.publish(self.binding)
        self.assertEqual(self.api.effects, [])
