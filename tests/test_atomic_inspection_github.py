"""Synthetic transport tests; no keys, HTTP requests or runtime authority."""
import copy
import importlib
import importlib.util
import unittest
from datetime import timedelta

import test_decision as fixture
from codestra_control.publisher_adapter import PublicationDenied


PERMISSIONS = {
    'metadata': 'read', 'contents': 'read', 'checks': 'read',
    'pull_requests': 'read', 'administration': 'read',
}
THREAD_QUERY = 'query($owner:String!,$name:String!,$number:Int!,$after:String){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewThreads(first:100,after:$after){nodes{id isResolved} pageInfo{hasNextPage endCursor}}}}}'
REVIEW_QUERY = 'query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewDecision}}}'
OUT_OF_SCOPE_GETS = (
    '/repos/appolon1908/Other', '/repos/appolon1908/Middleware-other/checks',
    '/users/appolon1908', '/orgs/appolon1908/repos', '/repositories/123',
    '/repos/appolon1908/Middleware-/../Other',
    '/repos/appolon1908/Middleware-/%2e%2e/Other',
    '/repos/appolon1908/Middleware-/%252e%252e/Other',
    '/repos/appolon1908/Middleware-/contents/foo%2f..%2f..%2f..%2fOther',
    '/repos/appolon1908/Middleware-/contents/foo%5c..%5cOther',
    '/repos/appolon1908/Middleware-#outside',
    '//api.github.com/repos/appolon1908/Middleware-',
)


class InspectionGitHubTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.app = {'id': 7}
        self.installation = {
            'id': 8, 'app_id': 7, 'suspended_at': None,
            'account': {'login': 'appolon1908'},
            'permissions': dict(PERMISSIONS),
        }
        self.token = {
            'token': 'synthetic-read-token',
            'expires_at': (fixture.NOW + timedelta(minutes=2)).isoformat(),
            'permissions': dict(PERMISSIONS),
            'repositories': [{'id': 123, 'full_name': 'appolon1908/Middleware-'}],
        }
        self.repository = {'id': 123, 'full_name': 'appolon1908/Middleware-'}
        self.now = fixture.NOW

    def client(self):
        # Missing implementation is an explicit assertion failure in the RED run.
        module_name = 'codestra_control.atomic_inspection_github'
        self.assertIsNotNone(importlib.util.find_spec(module_name),
                             'Read-only inspection client is not implemented')
        implementation = importlib.import_module(module_name).InspectionGitHubClient
        return implementation(lambda: 'synthetic-jwt', request=self.request,
                              clock=lambda: self.now)

    def request(self, method, path, token, body=None):
        self.calls.append((method, path, token, copy.deepcopy(body)))
        if method == 'GET' and path == '/app':
            return copy.deepcopy(self.app)
        if method == 'GET' and path == '/app/installations/8':
            return copy.deepcopy(self.installation)
        if method == 'POST' and path == '/app/installations/8/access_tokens':
            return copy.deepcopy(self.token)
        if method == 'GET' and path == '/repositories/123':
            return copy.deepcopy(self.repository)
        if method == 'GET' and path in OUT_OF_SCOPE_GETS:
            return {'public_data': True}
        if method == 'GET' and path == '/repos/appolon1908/Middleware-':
            return {'id': 123, 'full_name': 'appolon1908/Middleware-'}
        if method == 'GET' and '/collaborators/' in path:
            return {'user': {'login': 'reviewer'}, 'permission': 'write'}
        if method == 'GET' and '/rules/branches/' in path:
            return [{'type': 'pull_request', 'ruleset_id': 2}]
        if method == 'GET' and '/checks?' in path:
            return [{'id': 4}]
        if method == 'POST' and path == '/graphql':
            if body['query'] == REVIEW_QUERY:
                return {'data': {'repository': {'pullRequest': {'reviewDecision': 'APPROVED'}}}}
            if body['query'] == THREAD_QUERY:
                after = body['variables']['after']
                return {'data': {'repository': {'pullRequest': {'reviewThreads': {
                    'nodes': [{'id': 'thread-1' if after is None else 'thread-2', 'isResolved': True}],
                    'pageInfo': {'hasNextPage': after is None,
                                 'endCursor': 'cursor-1' if after is None else None},
                }}}}}
        raise AssertionError('Unexpected synthetic request: ' + method + ' ' + path)

    def authorized(self):
        client = self.client()
        client.authorize_readonly(7, 8, 123, fixture.NOW)
        return client

    def assert_not_minted(self):
        self.assertFalse(any(path.endswith('/access_tokens') for _, path, _, _ in self.calls))

    def test_authorization_mints_only_exact_repository_and_inspection_read_permissions(self):
        self.installation['permissions']['issues'] = 'read'
        client = self.authorized()
        minted = [call for call in self.calls if call[0] == 'POST']
        self.assertEqual(minted, [('POST', '/app/installations/8/access_tokens',
                                  'synthetic-jwt', {'repository_ids': [123], 'permissions': PERMISSIONS})])
        self.assertEqual(client.get('/repos/appolon1908/Middleware-')['id'], 123)
        self.assertEqual(self.calls[-1][2], 'synthetic-read-token')
        self.assertEqual(self.calls[-2][:3], ('GET', '/repositories/123', 'synthetic-read-token'))

    def test_installation_write_or_missing_read_permissions_deny_before_mint(self):
        for permissions in ({**PERMISSIONS, 'statuses': 'write'},
                            {**PERMISSIONS, 'checks': 'write'},
                            {**PERMISSIONS, 'issues': 'none'},
                            {**PERMISSIONS, 'issues': True},
                            *(dict((key, value) for key, value in PERMISSIONS.items() if key != missing)
                              for missing in PERMISSIONS)):
            self.calls.clear()
            self.installation['permissions'] = permissions
            with self.subTest(permissions=permissions), self.assertRaises(PublicationDenied):
                self.client().authorize_readonly(7, 8, 123, fixture.NOW)
            self.assert_not_minted()

    def test_invalid_requested_ids_deny_without_http(self):
        for values in ((15368, 8, 123), (True, 8, 123), (0, 8, 123),
                       ('7', 8, 123), (7, False, 123), (7, -8, 123),
                       (7, 8, True), (7, 8, 0), (7, 8, '123')):
            self.calls.clear()
            with self.subTest(values=values), self.assertRaises(PublicationDenied):
                self.client().authorize_readonly(*values, fixture.NOW)
            self.assertEqual(self.calls, [])

    def test_actual_app_id_must_match_and_be_an_integer(self):
        for value in (15368, 99, True, '7', None):
            self.calls.clear()
            self.app['id'] = value
            with self.subTest(value=value), self.assertRaises(PublicationDenied):
                self.client().authorize_readonly(7, 8, 123, fixture.NOW)
            self.assert_not_minted()

    def test_installation_must_be_active_owned_and_match_exact_ids(self):
        original = copy.deepcopy(self.installation)
        for change in ({'id': 9}, {'id': True}, {'app_id': 99},
                       {'suspended_at': '2026-10-07T00:00:00Z'},
                       {'account': {'login': 'different-owner'}}, {'account': {}}):
            self.calls.clear()
            self.installation = {**original, **change}
            with self.subTest(change=change), self.assertRaises(PublicationDenied):
                self.client().authorize_readonly(7, 8, 123, fixture.NOW)
            self.assert_not_minted()

    def test_token_cannot_expand_or_omit_any_permission(self):
        for permissions in ({**PERMISSIONS, 'statuses': 'read'},
                            {**PERMISSIONS, 'checks': 'write'},
                            *(dict((key, value) for key, value in PERMISSIONS.items() if key != missing)
                              for missing in PERMISSIONS)):
            self.token['permissions'] = permissions
            with self.subTest(permissions=permissions), self.assertRaises(PublicationDenied):
                self.client().authorize_readonly(7, 8, 123, fixture.NOW)

    def test_token_must_contain_one_exact_repository_without_duplicates(self):
        for repositories in ([], [{'id': 999}], [{'id': 123}, {'id': 999}],
                             [{'id': 123}, {'id': 123}], [{'id': True}],
                             [{'id': '123'}], [{}]):
            self.token['repositories'] = repositories
            with self.subTest(repositories=repositories), self.assertRaises(PublicationDenied):
                self.client().authorize_readonly(7, 8, 123, fixture.NOW)

    def test_expired_naive_or_malformed_token_expiry_denies(self):
        for expiry in (fixture.NOW.isoformat(),
                       (fixture.NOW - timedelta(seconds=1)).isoformat(),
                       (fixture.NOW + timedelta(minutes=2)).replace(tzinfo=None).isoformat(),
                       'not-a-timestamp', None):
            self.token['expires_at'] = expiry
            with self.subTest(expiry=expiry), self.assertRaises(PublicationDenied):
                self.client().authorize_readonly(7, 8, 123, fixture.NOW)

    def test_missing_or_empty_token_denies(self):
        for token in ('', None, ' ', 123):
            self.token['token'] = token
            with self.subTest(token=token), self.assertRaises(PublicationDenied):
                self.client().authorize_readonly(7, 8, 123, fixture.NOW)

    def test_invalid_observation_time_denies_before_http(self):
        for now in (None, fixture.NOW.replace(tzinfo=None)):
            self.calls.clear()
            with self.subTest(now=now), self.assertRaises(PublicationDenied):
                self.client().authorize_readonly(7, 8, 123, now)
            self.assertEqual(self.calls, [])

    def test_token_expiry_is_rechecked_against_current_clock_after_mint(self):
        self.now = fixture.NOW + timedelta(minutes=3)
        with self.assertRaises(PublicationDenied):
            self.client().authorize_readonly(7, 8, 123, fixture.NOW)

    def test_session_expiry_and_failed_reauthorization_invalidate_old_token(self):
        client = self.authorized()
        self.now = fixture.NOW + timedelta(minutes=3)
        with self.assertRaises(PublicationDenied):
            client.get('/repos/appolon1908/Middleware-')
        self.now = fixture.NOW
        self.app['id'] = 99
        with self.assertRaises(PublicationDenied):
            client.authorize_readonly(7, 8, 123, fixture.NOW)
        count = len(self.calls)
        with self.assertRaises(PublicationDenied):
            client.get('/repos/appolon1908/Middleware-')
        self.assertEqual(len(self.calls), count)

    def test_inherited_read_helpers_and_fixed_graphql_queries_work(self):
        client = self.authorized()
        self.assertEqual(client.pages('/repos/appolon1908/Middleware-/checks'), [{'id': 4}])
        self.assertTrue(client.eligible_reviewer('appolon1908/Middleware-', 'reviewer'))
        self.assertEqual(client.effective_rules('appolon1908/Middleware-', 'subsection/one'),
                         [{'type': 'pull_request', 'ruleset_id': 2}])
        self.assertTrue(client.threads_resolved('appolon1908/Middleware-', 453))
        self.assertTrue(client.review_approved('appolon1908/Middleware-', 453))
        queries = [body for method, path, _, body in self.calls if method == 'POST' and path == '/graphql']
        self.assertEqual([query['query'] for query in queries], [THREAD_QUERY, THREAD_QUERY, REVIEW_QUERY])
        self.assertEqual(queries[1]['variables']['after'], 'cursor-1')

    def test_arbitrary_rest_and_graphql_posts_never_reach_transport(self):
        client = self.authorized()
        for path, body in (('/repos/appolon1908/Middleware-/statuses/' + 'a' * 40, {'state': 'success'}),
                           ('/app/installations/8/access_tokens', {}),
                           ('/graphql', {'query': 'mutation { deleteRepository(input:{repositoryId:"x"}) { clientMutationId } }', 'variables': {}}),
                           ('/graphql', {'query': 'query { viewer { login } }', 'variables': {}}),
                           ('/graphql', {'query': REVIEW_QUERY, 'variables': {'owner': 'appolon1908', 'name': 'Middleware-', 'number': 453}, 'extensions': {}})):
            count = len(self.calls)
            with self.subTest(path=path, body=body), self.assertRaises(PublicationDenied):
                client.post(path, body)
            self.assertEqual(len(self.calls), count)

    def test_fixed_graphql_queries_require_exact_valid_variables(self):
        client = self.authorized()
        valid = {'owner': 'appolon1908', 'name': 'Middleware-', 'number': 453}
        for variables in ({**valid, 'owner': 'other-owner'}, {**valid, 'name': '../repo'},
                          {**valid, 'name': ''}, {**valid, 'number': True},
                          {**valid, 'number': 0}, {**valid, 'number': 2147483648},
                          {**valid, 'extra': 'value'}, {'owner': 'appolon1908', 'name': 'Middleware-'},
                          {**valid, 'after': 'cursor'}):
            count = len(self.calls)
            with self.subTest(variables=variables), self.assertRaises(PublicationDenied):
                client.post('/graphql', {'query': REVIEW_QUERY, 'variables': variables})
            self.assertEqual(len(self.calls), count)
        for cursor in ('', 3, '\nsecret', 'x' * 2049):
            count = len(self.calls)
            with self.subTest(cursor=cursor), self.assertRaises(PublicationDenied):
                client.post('/graphql', {'query': THREAD_QUERY, 'variables': {**valid, 'after': cursor}})
            self.assertEqual(len(self.calls), count)

    def test_direct_call_and_inherited_mint_interfaces_cannot_bypass_readonly_authorization(self):
        client = self.authorized()
        count = len(self.calls)
        with self.assertRaises(PublicationDenied):
            client._call('POST', '/repos/appolon1908/Middleware-/issues', {})
        with self.assertRaises(PublicationDenied):
            client.assert_identity(object(), 123, fixture.NOW)
        with self.assertRaises(PublicationDenied):
            client.inventory(7, 8, ('appolon1908/Middleware-',))
        self.assertEqual(len(self.calls), count)

    def test_cross_repository_and_unscoped_gets_deny_before_transport(self):
        client = self.authorized()
        for path in OUT_OF_SCOPE_GETS:
            count = len(self.calls)
            with self.subTest(path=path), self.assertRaises(PublicationDenied):
                client.get(path)
            self.assertEqual(len(self.calls), count)

    def test_fixed_graphql_query_cannot_read_a_different_public_repository(self):
        client = self.authorized()
        count = len(self.calls)
        with self.assertRaises(PublicationDenied):
            client.post('/graphql', {'query': REVIEW_QUERY, 'variables': {
                'owner': 'appolon1908', 'name': 'Other', 'number': 453,
            }})
        self.assertEqual(len(self.calls), count)

    def test_actual_repository_metadata_must_match_minted_id_and_full_name(self):
        for repository in ({'id': 999, 'full_name': 'appolon1908/Middleware-'},
                           {'id': True, 'full_name': 'appolon1908/Middleware-'},
                           {'id': 123, 'full_name': 'appolon1908/Other'},
                           {'id': 123, 'full_name': 'different-owner/Middleware-'},
                           {'id': 123, 'full_name': 'appolon1908/../Other'},
                           {'id': 123}, {}):
            self.repository = repository
            client = self.client()
            with self.subTest(repository=repository), self.assertRaises(PublicationDenied):
                client.authorize_readonly(7, 8, 123, fixture.NOW)
            count = len(self.calls)
            with self.assertRaises(PublicationDenied):
                client.get('/repos/appolon1908/Middleware-')
            self.assertEqual(len(self.calls), count)

    def test_token_repository_name_cannot_disagree_with_actual_metadata(self):
        for name in ('appolon1908/Other', 'different-owner/Middleware-', '', None):
            self.token['repositories'][0]['full_name'] = name
            with self.subTest(name=name), self.assertRaises(PublicationDenied):
                self.client().authorize_readonly(7, 8, 123, fixture.NOW)

    def test_expiry_during_initial_repository_observation_denies_session(self):
        client = self.client()
        original = client.request
        def request(method, path, token, body=None):
            value = original(method, path, token, body)
            if path == '/repositories/123':
                self.now = fixture.NOW + timedelta(minutes=3)
            return value
        client.request = request
        with self.assertRaises(PublicationDenied):
            client.authorize_readonly(7, 8, 123, fixture.NOW)


if __name__ == '__main__':
    unittest.main()
