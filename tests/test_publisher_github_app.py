import unittest
from datetime import timedelta
from test_authenticated_publisher import Store
import test_decision as fixture
from codestra_control.publisher_github import GitHubAppClient
from codestra_control.publisher_adapter import PublicationDenied

class GitHubAppTests(unittest.TestCase):
    def setUp(self):
        self.calls=[]
        def request(method,path,token,body=None):
            self.calls.append((method,path,body))
            if path=='/app':return {'id':7}
            if path=='/app/installations/8':return {'id':8,'app_id':7,'suspended_at':None}
            if path.endswith('/access_tokens'):return {'token':'synthetic-token','expires_at':(fixture.NOW+timedelta(minutes=2)).isoformat(),'permissions':dict(GitHubAppClient.PERMISSIONS),'repositories':[{'id':123}]}
            if path.startswith('/things'):return [{'id':1}]
            raise AssertionError(path)
        self.request=request
        self.client=GitHubAppClient(lambda:'synthetic-jwt',request=request,clock=lambda:fixture.NOW)
    def test_verified_app_and_scoped_installation_token(self):
        self.client.assert_identity(Store().authority,123,fixture.NOW)
        body=self.calls[-1][2]
        self.assertEqual(body['repository_ids'],[123]);self.assertEqual(body['permissions']['statuses'],'write')
        self.assertNotIn('workflows',body['permissions'])
    def test_suspended_installation_or_wrong_app_denies(self):
        original=self.request
        for change in ({'id':8,'app_id':99,'suspended_at':None},{'id':8,'app_id':7,'suspended_at':'now'}):
            def request(method,path,token,body=None):
                return change if path=='/app/installations/8' else original(method,path,token,body)
            self.client.request=request
            with self.assertRaises(PublicationDenied):self.client.assert_identity(Store().authority,123,fixture.NOW)
    def test_api_use_before_identity_or_after_expiration_denies(self):
        with self.assertRaises(PublicationDenied):self.client.get('/things')
        self.client.assert_identity(Store().authority,123,fixture.NOW)
        self.client.clock=lambda:fixture.NOW+timedelta(minutes=3)
        with self.assertRaises(PublicationDenied):self.client.get('/things')
    def test_pagination_is_bounded_and_duplicate_ids_refused(self):
        self.client.assert_identity(Store().authority,123,fixture.NOW)
        self.assertEqual(self.client.pages('/things'),[{'id':1}])
        self.client.get=lambda *_:[{'id':1}]*100
        with self.assertRaises(PublicationDenied):self.client.pages('/things')
    def test_review_and_thread_graphql_require_complete_resolved_authority(self):
        self.client.assert_identity(Store().authority,123,fixture.NOW)
        self.client.post=lambda *_:{'data':{'repository':{'pullRequest':{'reviewDecision':'APPROVED'}}}}
        self.assertTrue(self.client.review_approved('owner/repo',1))
        self.client.post=lambda *_:{'data':{'repository':{'pullRequest':{'reviewThreads':{'nodes':[{'id':'thread:1','isResolved':False}],'pageInfo':{'hasNextPage':False,'endCursor':None}}}}}}
        self.assertFalse(self.client.threads_resolved('owner/repo',1))
        self.client.post=lambda *_:{'errors':[{'message':'unavailable'}]}
        with self.assertRaises(PublicationDenied):self.client.threads_resolved('owner/repo',1)
    def test_extra_installation_permissions_or_repository_denied(self):
        original=self.request
        def expanded(method,path,token,body=None):
            value=original(method,path,token,body)
            if path.endswith('/access_tokens'):value['permissions']['contents']='write'
            return value
        self.client.request=expanded
        with self.assertRaises(PublicationDenied):self.client.assert_identity(Store().authority,123,fixture.NOW)
    def test_complete_inventory_uses_read_only_token_and_actual_repository_ids(self):
        def request(method,path,token,body=None):
            self.calls.append((method,path,body))
            if path=='/app':return {'id':7}
            if path=='/app/installations/8':return {'id':8,'app_id':7,'suspended_at':None,'account':{'login':'appolon1908'}}
            if path.endswith('/access_tokens'):
                return {'token':'synthetic-read-token','expires_at':(fixture.NOW+timedelta(minutes=2)).isoformat(),'permissions':{'metadata':'read','pull_requests':'read'},'repositories':[{'id':123,'full_name':'appolon1908/Breero.com'}]}
            if '/pulls?' in path:return [{'id':1,'number':9,'state':'open','head':{'ref':'staging','sha':'a'*40},'base':{'ref':'production/environment','sha':'b'*40,'repo':{'id':123}}}]
            raise AssertionError(path)
        self.client.request=request
        values=self.client.inventory(7,8,('appolon1908/Breero.com',))
        self.assertEqual(values[0].repository_id,123);self.assertEqual(values[0].number,9)
        minted=next(body for method,path,body in self.calls if path.endswith('/access_tokens'))
        self.assertEqual(minted['repositories'],['Breero.com']);self.assertNotIn('statuses',minted['permissions'])
    def test_incomplete_inventory_repository_scope_denies_before_pr_reads(self):
        def request(method,path,token,body=None):
            if path=='/app':return {'id':7}
            if path=='/app/installations/8':return {'id':8,'app_id':7,'suspended_at':None,'account':{'login':'appolon1908'}}
            if path.endswith('/access_tokens'):return {'permissions':{'metadata':'read','pull_requests':'read'},'repositories':[]}
            raise AssertionError('PR read must not occur')
        self.client.request=request
        with self.assertRaises(PublicationDenied):self.client.inventory(7,8,('appolon1908/Breero.com',))
    def test_materialization_token_has_no_status_or_workflow_write_permission(self):
        original=self.request
        def request(method,path,token,body=None):
            if path=='/app/installations/8':return {'id':8,'app_id':7,'suspended_at':None,'permissions':{'metadata':'read','contents':'read','checks':'read'}}
            if path.endswith('/access_tokens'):
                self.calls.append((method,path,body))
                return {'token':'synthetic-materializer-token','expires_at':(fixture.NOW+timedelta(minutes=2)).isoformat(),'permissions':{'metadata':'read','contents':'read','checks':'read'},'repositories':[{'id':123}]}
            return original(method,path,token,body)
        self.client.request=request
        self.client.authorize_readonly(7,8,123,fixture.NOW)
        body=self.calls[-1][2]
        self.assertEqual(body['repository_ids'],[123]);self.assertTrue(all(v=='read' for v in body['permissions'].values()))
    def test_materializer_key_with_write_installation_grant_is_rejected_before_token(self):
        original=self.request
        def request(method,path,token,body=None):
            if path=='/app/installations/8':return {'id':8,'app_id':7,'suspended_at':None,'permissions':{'metadata':'read','contents':'read','checks':'read','statuses':'write'}}
            return original(method,path,token,body)
        self.client.request=request
        with self.assertRaisesRegex(PublicationDenied,'READONLY_INSTALLATION_REQUIRED'):self.client.authorize_readonly(7,8,123,fixture.NOW)
        self.assertFalse(any(path.endswith('/access_tokens') for _,path,_ in self.calls))
