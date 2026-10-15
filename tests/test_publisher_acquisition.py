import unittest
from dataclasses import replace,asdict
from datetime import timedelta
from unittest import mock
import test_decision as fixture
from test_authenticated_publisher import Store
from codestra_control.publisher_acquisition import GitHubVerifier, RestrictedRegistry, decode_snapshot
from codestra_control.publisher_adapter import PublicationDenied,binding_digest

class API:
    def __init__(self):self.paths=[];self.bad=False
    def get(self,path):
        self.paths.append(path)
        if path.endswith('/pulls/9'):
            return {'state':'open','draft':False,'head':{'sha':fixture.REQUEST.source_sha,'ref':fixture.REQUEST.source_ref,'repo':{'id':123}},'base':{'sha':fixture.REQUEST.target_base_sha,'ref':fixture.REQUEST.target_ref,'repo':{'id':123}},'mergeable':True,'user':{'login':'author'},'merge_commit_sha':'c'*40}
        if '/branches/' in path and not path.endswith('/protection'):return {'protected':True,'commit':{'sha':fixture.REQUEST.target_base_sha}}
        if path.endswith('/protection'):
            return {'enforce_admins':{'enabled':True},'required_status_checks':{'strict':True,'checks':[{'context':'quality','app_id':15368}]},'required_pull_request_reviews':{'required_approving_review_count':1,'require_code_owner_reviews':True,'dismiss_stale_reviews':True,'require_last_push_approval':True},'required_conversation_resolution':{'enabled':True}}
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
        self.verifier=GitHubVerifier(self.api,certificate_name='scope-certification',certificate_app_id=99)
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
        cursor.fetchone.return_value=(True,True)
        a=Store().authority
        cursor.fetchall.return_value=[(json.loads(json.dumps(asdict(a),default=lambda v:v.isoformat())),
                                      json.loads(json.dumps(asdict(fixture.ready()),default=lambda v:v.isoformat())),123,9,10,json.loads(json.dumps(asdict(Store().acquire(fixture.REQUEST).issuer),default=lambda v:v.isoformat())))]
        result=RestrictedRegistry(connection).acquire(fixture.REQUEST)
        self.assertEqual(result.snapshot,fixture.ready());self.assertEqual(result.authority,a)
        self.assertEqual(cursor.execute.call_args.args[1],(binding_digest(fixture.REQUEST),))
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
