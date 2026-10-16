import unittest
from dataclasses import replace,asdict
from datetime import timedelta
from unittest import mock
import test_decision as fixture
from test_authenticated_publisher import Store
from codestra_control.publisher_acquisition import GitHubVerifier, RestrictedRegistry, decode_snapshot
from codestra_control.publisher_adapter import PublicationDenied,binding_digest

class FixtureProvenance:
    """Synthetic privileged verifier, never a deployed issuer acceptance."""
    def verify(self,acquired,now):
        from codestra_control.publisher_provenance import VerifiedProducerContract
        return VerifiedProducerContract(binding_digest(acquired.snapshot.observed_binding),
            acquired.repository_id,acquired.pr_number,acquired.authority.app_id,
            acquired.issuer.app_id,acquired.issuer.name,
            ('codestra-control-plane','codestra/control-plane'),
            acquired.issuer.capability_receipt,acquired.issuer.expires_at,'STATUS_PUBLICATION')

class API:
    def effective_rules(self,repo,branch):return []
    def __init__(self):self.paths=[];self.bad=False
    def get(self,path):
        self.paths.append(path)
        if path.endswith('/pulls/9'):
            return {'state':'open','draft':False,'head':{'sha':fixture.REQUEST.source_sha,'ref':fixture.REQUEST.source_ref,'repo':{'id':123}},'base':{'sha':fixture.REQUEST.target_base_sha,'ref':fixture.REQUEST.target_ref,'repo':{'id':123}},'mergeable':True,'user':{'login':'author'},'merge_commit_sha':'c'*40}
        if '/branches/' in path and not path.endswith('/protection'):return {'protected':True,'commit':{'sha':fixture.REQUEST.target_base_sha}}
        if path.endswith('/protection'):
            return {'enforce_admins':{'enabled':True},'required_status_checks':{'strict':True,'checks':[{'context':'quality','app_id':15368},{'context':'codestra-control-plane','app_id':7},{'context':'codestra/control-plane','app_id':7}]},'required_pull_request_reviews':{'required_approving_review_count':1,'require_code_owner_reviews':True,'dismiss_stale_reviews':True,'require_last_push_approval':True,'bypass_pull_request_allowances':{'users':[],'teams':[],'apps':[]}},'required_conversation_resolution':{'enabled':True}}
        if path.endswith('/check-runs/10'):
            return {'id':10,'head_sha':fixture.REQUEST.source_sha,'app':{'id':99},'name':'scope-certification','status':'completed','conclusion':'success','external_id':binding_digest(fixture.REQUEST)}
        raise AssertionError(path)
    def pages(self,path,key=None):
        if '/check-runs' in path:
            return [{'id':123,'head_sha':'c'*40 if '/commits/'+('c'*40) in path else fixture.REQUEST.source_sha,'app':{'id':15368},'name':'quality','status':'completed','conclusion':'success'}]
        if '/reviews' in path:return [{'id':12,'commit_id':fixture.REQUEST.source_sha,'user':{'login':'independent-reviewer'},'state':'APPROVED'}]
        raise AssertionError(path)
    def threads_resolved(self,*args):return True
    def eligible_reviewer(self,*args):return True
    def review_approved(self,*args):return True
    def assert_identity(self,*args):pass

class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        patch=mock.patch('codestra_control.publisher_acquisition.protected_read',return_value=b'synthetic accepted CA fixture')
        patch.start();self.addCleanup(patch.stop)
        self.api=API();self.acquired=Store().acquire(fixture.REQUEST)
        self.acquired=replace(self.acquired,snapshot=replace(fixture.ready(),certificate=replace(fixture.ready().certificate,receipt_id='check:10')))
        self.verifier=GitHubVerifier(self.api,certificate_name='scope-certification',certificate_app_id=99,provenance_verifier=FixtureProvenance())
    def test_online_receipt_and_merge_result_and_protection_are_observed(self):
        self.verifier.verify(self.acquired,fixture.NOW)
        self.assertTrue(any('/protection' in p for p in self.api.paths))
    def test_wrong_app_receipt_ref_binding_or_missing_protection_denies(self):
        original=self.api.get
        for change in ('app','external_id','protected','mergeable'):
            def bad(path):
                value=original(path)
                if path.endswith('/check-runs/10') and change=='app':value['app']['id']=999
                if path.endswith('/check-runs/10') and change=='external_id':value['external_id']='forged'
                if '/branches/' in path and not path.endswith('/protection') and change=='protected':value['protected']=False
                if path.endswith('/pulls/9') and change=='mergeable':value['mergeable']=None
                return value
            self.api.get=bad
            with self.subTest(change=change),self.assertRaises(PublicationDenied):self.verifier.verify(self.acquired,fixture.NOW)
        self.api.get=original
    def test_restricted_session_rejects_superuser_role_switch_and_mutation_access(self):
        connection=mock.MagicMock();connection.get_dsn_parameters.return_value={'sslmode':'verify-full','host':'authority.example','sslrootcert':'/fixture/ca.pem'};cursor=connection.cursor.return_value.__enter__.return_value
        registry=RestrictedRegistry(connection)
        for row in ((False,False),(True,False)):
            cursor.fetchone.return_value=row
            with self.assertRaises(PublicationDenied):registry.acquire(fixture.REQUEST)
    def test_snapshot_decoder_does_not_accept_legacy_pass(self):
        with self.assertRaises((PublicationDenied,KeyError,TypeError)):decode_snapshot({'status':'PASS'})

    def test_decoder_roundtrip_preserves_exact_internal_binding(self):
        import json
        raw=json.loads(json.dumps(asdict(fixture.ready()),default=lambda v:v.isoformat()))
        self.assertEqual(decode_snapshot(raw),fixture.ready())
    def test_current_failed_merge_check_or_changed_review_denies(self):
        original=self.api.pages
        for failure in ('merge','review'):
            def pages(path,key=None):
                result=original(path,key)
                if failure=='merge' and '/commits/'+('c'*40) in path:result[0]['conclusion']='failure'
                if failure=='review' and '/reviews' in path:result[0]['state']='CHANGES_REQUESTED'
                return result
            self.api.pages=pages
            with self.subTest(failure=failure),self.assertRaises(PublicationDenied):self.verifier.verify(self.acquired,fixture.NOW)
    def test_complete_restricted_reader_decodes_bound_operator_record(self):
        import json
        connection=mock.MagicMock();connection.get_dsn_parameters.return_value={'sslmode':'verify-full','host':'authority.example','sslrootcert':'/fixture/ca.pem'};cursor=connection.cursor.return_value.__enter__.return_value
        a=Store().authority
        assignment='11111111-1111-4111-8111-111111111111'
        snapshot=replace(fixture.ready(),lease=replace(fixture.ready().lease,assignment_id=assignment))
        receipt={'authority':'ONLINE_DATABASE_RECEIPT','binding_id':assignment,'lease_id':'22222222-2222-4222-8222-222222222222',
                 'epoch':7,'state':'ACTIVE','principal':snapshot.lease.owner,'expires_at':snapshot.lease.expires_at.isoformat(),
                 'binding':dict(asdict(fixture.REQUEST),repository_id=123,principal=snapshot.lease.owner)}
        receipt['binding']['head_sha']=receipt['binding'].pop('source_sha')
        receipt['binding']['base_sha']=receipt['binding'].pop('target_base_sha')
        cursor.fetchall.return_value=[(json.loads(json.dumps(asdict(a),default=lambda v:v.isoformat())),
                                      json.loads(json.dumps(asdict(snapshot),default=lambda v:v.isoformat())),123,9,10,json.loads(json.dumps(asdict(Store().acquire(fixture.REQUEST).issuer),default=lambda v:v.isoformat())))]
        cursor.fetchone.side_effect=[(True,True),(receipt,)]
        result=RestrictedRegistry(connection).acquire(fixture.REQUEST)
        self.assertEqual(result.snapshot,snapshot);self.assertEqual(result.authority,a)
        self.assertEqual(result.lease_id,receipt['lease_id']);self.assertEqual(result.lease_epoch,7)
        self.assertEqual(cursor.execute.call_args.args,('SELECT scope_assignment_leases.inspect_binding(%s)',(assignment,)))
        for field,value in [('state','REVOKED'),('principal','forged'),('epoch',0),('binding_id','different')]:
            cursor.fetchone.side_effect=[(True,True),(dict(receipt,**{field:value}),)]
            with self.subTest(field=field),self.assertRaises(PublicationDenied):RestrictedRegistry(connection).acquire(fixture.REQUEST)
        moved=dict(receipt,binding=dict(receipt['binding'],head_sha='d'*40))
        cursor.fetchone.side_effect=[(True,True),(moved,)]
        with self.assertRaises(PublicationDenied):RestrictedRegistry(connection).acquire(fixture.REQUEST)
    def test_source_catalog_exactly_matches_approved_publisher(self):
        import ast
        from pathlib import Path
        from codestra_control.publisher_scope import APPROVED_REPOSITORIES
        tree=ast.parse((Path(__file__).resolve().parents[1]/'bin/codestra-github-statusd').read_text())
        names=set()
        for node in tree.body:
            if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ('PRIOR_GOVERNED_REPOS','ADDITIONAL_GOVERNED_REPOS'):
                names.update(ast.literal_eval(node.value.args[0]))
        self.assertEqual(APPROVED_REPOSITORIES,frozenset('appolon1908/'+v for v in names))
        self.assertEqual(len(APPROVED_REPOSITORIES),49)
    def test_live_protection_drift_in_approvals_or_required_checks_denies(self):
        original=self.api.get
        for kind in ('approvals','checks'):
            def changed(path):
                value=original(path)
                if path.endswith('/protection'):
                    if kind=='approvals':value['required_pull_request_reviews']['required_approving_review_count']=2
                    else:value['required_status_checks']['checks'].append({'context':'new-quality','app_id':456})
                return value
            self.api.get=changed
            with self.subTest(kind=kind),self.assertRaises(PublicationDenied):self.verifier.verify(self.acquired,fixture.NOW)
    def test_final_ref_reread_denies_target_moved_during_inventory(self):
        original=self.api.get;count=0
        def changed(path):
            nonlocal count
            value=original(path)
            if path.endswith('/pulls/9'):
                count+=1
                if count>1:value['base']['sha']='d'*40
            return value
        self.api.get=changed
        with self.assertRaises(PublicationDenied):self.verifier.verify(self.acquired,fixture.NOW)
    def test_conflicting_publisher_context_app_binding_denies(self):
        original=self.api.get
        for context in ('codestra-control-plane','codestra/control-plane'):
            def changed(path):
                value=original(path)
                if path.endswith('/protection'):
                    value['required_status_checks']['checks'].append({'context':context,'app_id':999})
                return value
            self.api.get=changed
            with self.subTest(context=context),self.assertRaisesRegex(PublicationDenied,'CONTROLLER_CHECK_PRODUCER_MISMATCH|UNBOUND_REQUIRED_CHECK_PRODUCER'):
                self.verifier.verify(self.acquired,fixture.NOW)
    def test_matching_publisher_contexts_do_not_require_circular_success(self):
        original=self.api.get
        def changed(path):
            value=original(path)
            if path.endswith('/protection'):
                value['required_status_checks']['checks']=[v for v in value['required_status_checks']['checks'] if v['context'] not in ('codestra-control-plane','codestra/control-plane')]
                value['required_status_checks']['checks'].extend(
                    {'context':context,'app_id':self.acquired.authority.app_id}
                    for context in ('codestra-control-plane','codestra/control-plane'))
            return value
        self.api.get=changed
        self.verifier.verify(self.acquired,fixture.NOW)
    def test_unbound_contexts_cannot_satisfy_explicit_provenance_contract(self):
        original=self.api.get
        for app_id in (None,-1):
            def changed(path):
                value=original(path)
                if path.endswith('/protection'):
                    value['required_status_checks']['checks'].extend(
                        {'context':context,'app_id':app_id}
                        for context in ('codestra-control-plane','codestra/control-plane'))
                return value
            self.api.get=changed
            with self.subTest(app_id=app_id),self.assertRaises(PublicationDenied):self.verifier.verify(self.acquired,fixture.NOW)
    def test_invalid_publisher_context_app_binding_denies(self):
        original=self.api.get
        for context in ('codestra-control-plane','codestra/control-plane'):
            for app_id in (0,-2,True,'7'):
                def changed(path):
                    value=original(path)
                    if path.endswith('/protection'):
                        value['required_status_checks']['checks'].append({'context':context,'app_id':app_id})
                    return value
                self.api.get=changed
                with self.subTest(context=context,app_id=app_id),self.assertRaisesRegex(PublicationDenied,'CONTROLLER_CHECK_PRODUCER_MISMATCH|UNBOUND_REQUIRED_CHECK_PRODUCER'):
                    self.verifier.verify(self.acquired,fixture.NOW)
    def test_other_control_context_does_not_acquire_publisher_app_binding(self):
        original=self.api.get
        def changed(path):
            value=original(path)
            if path.endswith('/protection'):
                value['required_status_checks']['checks'].append({'context':'promotion-gate','app_id':999})
            return value
        self.api.get=changed
        self.verifier.verify(self.acquired,fixture.NOW)
    def test_encrypted_but_unverified_database_transport_denies(self):
        for mode in ('require','verify-ca','prefer'):
            connection=mock.MagicMock();connection.get_dsn_parameters.return_value={'sslmode':mode,'host':'authority.example','sslrootcert':'/fixture/ca.pem'}
            with self.subTest(mode=mode),self.assertRaises(PublicationDenied):RestrictedRegistry(connection).acquire(fixture.REQUEST)
    def test_untrusted_database_ca_denied_even_with_verify_full(self):
        from codestra_control.publisher_ownership import PublisherUnavailable
        connection=mock.MagicMock();connection.get_dsn_parameters.return_value={'sslmode':'verify-full','host':'authority.example','sslrootcert':'/fixture/attacker-ca.pem'}
        with mock.patch('codestra_control.publisher_acquisition.protected_read',side_effect=PublisherUnavailable('UNTRUSTED_OPERATOR_ANCESTOR')):
            with self.assertRaisesRegex(PublicationDenied,'UNTRUSTED_DATABASE_CA'):RestrictedRegistry(connection).acquire(fixture.REQUEST)
    def test_ordinary_ci_or_self_issued_certificate_is_not_certification(self):
        from codestra_control.publisher_adapter import CertificateIssuer
        from dataclasses import replace
        original=self.api.get
        for app_id in (15368,7):
            def wrong(path):
                value=original(path)
                if path.endswith('/check-runs/10'):value['app']['id']=app_id
                return value
            self.api.get=wrong
            acquired=replace(self.acquired,issuer=CertificateIssuer(app_id,'scope-certification',binding_digest(fixture.REQUEST),'synthetic-issuer-capability',fixture.NOW+timedelta(minutes=2),'Ralph L. Appolon','SCOPE_CERTIFICATION'))
            self.verifier.certificate_app_id=app_id
            with self.subTest(app_id=app_id),self.assertRaises(PublicationDenied):self.verifier.verify(acquired,fixture.NOW)
    def test_missing_expired_wrong_target_capability_and_ci_alias_denied(self):
        issuer=self.acquired.issuer
        for value in (None,replace(issuer,expires_at=fixture.NOW),replace(issuer,binding_hash='0'*64),replace(issuer,name='quality'),replace(issuer,name='codestra-control-plane')):
            with self.subTest(value=value),self.assertRaises(PublicationDenied):self.verifier.verify(replace(self.acquired,issuer=value),fixture.NOW)


    def test_ruleset_only_flows_through_full_online_publisher_verification(self):
        from test_effective_protection import API as NativeAPI
        native=NativeAPI()
        for rule in native.rules:rule['ruleset_source']=fixture.REQUEST.repository
        native.detail['source']=fixture.REQUEST.repository
        checks=[{'context':'quality','integration_id':15368},
                {'context':'codestra-control-plane','integration_id':7},
                {'context':'codestra/control-plane','integration_id':7}]
        native.rules[1]['parameters']['required_status_checks']=checks
        native.detail['rules'][1]['parameters']['required_status_checks']=checks
        original=self.api.get
        def get(path):
            if path.endswith('/protection') or '/rulesets/' in path:return native.get(path)
            return original(path)
        self.api.get=get
        self.api.effective_rules=native.effective_rules
        self.verifier.verify(self.acquired,fixture.NOW)
        self.assertEqual(sum(isinstance(v,tuple) and v[0]=='effective' for v in native.calls),2)

    def test_ruleset_bypass_added_during_online_review_denies(self):
        from test_effective_protection import API as NativeAPI
        native=NativeAPI()
        # Classic protection is sufficient initially; a new effective native
        # restriction at final readback must never be silently ignored.
        self.api.effective_rules=lambda *args:[] if not native.detail.get('changed') else native.rules
        def threads(*args):native.detail['changed']=True;return True
        self.api.threads_resolved=threads
        with self.assertRaises(PublicationDenied):self.verifier.verify(self.acquired,fixture.NOW)


class AuthenticatedSessionPredicateTests(unittest.TestCase):
    """Exercise the reader's scalar SQL identity predicate with synthetic SQL rows.

    SQLite evaluates the shared equality/AND/IS NULL subset only. Privilege/TLS
    result is deliberately true to isolate authentication; no PostgreSQL session,
    credential, role or authority store is created or used by these tests.
    """
    class Cursor:
        def __init__(self, authenticated_identity, current='publisher-fixture'):
            self.authenticated_identity=authenticated_identity
            self.current=current
        def execute(self, statement):
            import sqlite3
            predicate=statement.split('SELECT',1)[1].split(',\n',1)[0].strip()
            with sqlite3.connect(':memory:') as database:
                row=database.execute(
                    'SELECT '+predicate+' FROM (SELECT ? AS session_user, ? AS current_user, ? AS system_user)',
                    ('publisher-fixture',self.current,self.authenticated_identity),
                ).fetchone()
            self.result=(bool(row[0]),True)
        def fetchone(self):return self.result

    def test_trust_cannot_supply_authenticated_role_even_with_verified_tls(self):
        with self.assertRaisesRegex(PublicationDenied,'RESTRICTED_AUTHENTICATED_SESSION_REQUIRED'):
            RestrictedRegistry._roles(self.Cursor(None))

    def test_authenticated_identity_with_unchanged_role_preserves_reader_gate(self):
        RestrictedRegistry._roles(self.Cursor('scram-sha-256:publisher-fixture'))

    def test_authenticated_role_switch_still_denied(self):
        with self.assertRaisesRegex(PublicationDenied,'RESTRICTED_AUTHENTICATED_SESSION_REQUIRED'):
            RestrictedRegistry._roles(self.Cursor('scram-sha-256:publisher-fixture',current='different-role'))
