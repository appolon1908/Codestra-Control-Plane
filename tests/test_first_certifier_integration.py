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
            for migration in ('011-certifier-authority.sql', '013-first-certification-pending.sql'):
                cls.harness.admin((ROOT / migration).read_text())
            cls.harness.admin('GRANT USAGE ON SCHEMA certifier_authority,scoped_registration TO verifier')
            cls.harness.admin('GRANT SELECT ON ALL TABLES IN SCHEMA certifier_authority TO verifier')
            cls.harness.admin('GRANT SELECT ON public.products,public.sections,public.workstations,public.atomic_tasks TO verifier')
            cls.harness.admin('GRANT SELECT ON scoped_registration.products,scoped_registration.workstations,scoped_registration.lanes,scoped_registration.candidates TO verifier')
            cls.harness.admin('GRANT SELECT ON scope_assignment_leases.products TO verifier')
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
        with self.assertRaisesRegex(PublicationDenied, 'ATOMIC_DEPENDENCY_CERTIFICATE_UNSUPPORTED'):
            self.certifier.publish(binding)
        self.assertEqual(self.api.effects, [])

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
