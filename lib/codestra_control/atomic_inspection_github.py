"""Read-only GitHub App session for atomic inspection; no runtime provisioning.

Only token minting and the two existing, fixed read GraphQL queries use POST.
The publisher transport remains unchanged and no publisher credential is reused.
"""
from datetime import datetime
import re
from urllib.parse import unquote, urlsplit

from .publisher_adapter import PublicationDenied, require
from .publisher_github import GitHubAppClient


THREAD_QUERY = 'query($owner:String!,$name:String!,$number:Int!,$after:String){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewThreads(first:100,after:$after){nodes{id isResolved} pageInfo{hasNextPage endCursor}}}}}'
REVIEW_QUERY = 'query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewDecision}}}'


class InspectionGitHubClient(GitHubAppClient):
    PERMISSIONS = {
        'metadata': 'read', 'contents': 'read', 'checks': 'read',
        'pull_requests': 'read', 'administration': 'read',
    }

    @staticmethod
    def _aware(value):
        return isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None

    def authorize_readonly(self, app_id, installation_id, repository_id, now):
        """Validate App/installation custody and mint exactly one read-scoped token."""
        self._token = None
        self._expires = None
        self._repository = None
        try:
            require(all(type(value) is int and value > 0 for value in
                        (app_id, installation_id, repository_id)) and app_id != 15368,
                    'INSPECTION_APP_IDENTITY_INVALID')
            require(self._aware(now), 'INSPECTION_TIME_INVALID')
            jwt = self.jwt_provider()
            app = self.request('GET', '/app', jwt)
            require(type(app['id']) is int and app['id'] == app_id,
                    'APP_IDENTITY_MISMATCH')
            installation = self.request('GET', f'/app/installations/{installation_id}', jwt)
            require(type(installation['id']) is int and installation['id'] == installation_id
                    and type(installation['app_id']) is int and installation['app_id'] == app_id
                    and installation['suspended_at'] is None
                    and installation['account']['login'] == 'appolon1908',
                    'INSPECTION_INSTALLATION_MISMATCH')
            permissions = installation['permissions']
            require(type(permissions) is dict
                    and self.PERMISSIONS.items() <= permissions.items()
                    and all(type(key) is str and value == 'read' for key, value in permissions.items()),
                    'READONLY_INSTALLATION_REQUIRED')
            # This is the only effectful HTTP operation supported by this adapter.
            token = self.request('POST', f'/app/installations/{installation_id}/access_tokens', jwt,
                                 {'repository_ids': [repository_id], 'permissions': dict(self.PERMISSIONS)})
            repositories = token['repositories']
            require(type(token['permissions']) is dict and token['permissions'] == self.PERMISSIONS
                    and type(repositories) is list and len(repositories) == 1
                    and type(repositories[0]['id']) is int and repositories[0]['id'] == repository_id,
                    'TOKEN_SCOPE_MISMATCH')
            require(type(token['expires_at']) is str, 'TOKEN_EXPIRED')
            expiry = datetime.fromisoformat(token['expires_at'].replace('Z', '+00:00'))
            current = self.clock()
            require(self._aware(expiry) and self._aware(current) and expiry > now and expiry > current,
                    'TOKEN_EXPIRED')
            require(type(token['token']) is str and bool(token['token'])
                    and token['token'].strip() == token['token'], 'TOKEN_UNAVAILABLE')
            # Resolve the real name from the numeric resource using the scoped
            # token before enabling ordinary reads. Token metadata alone does
            # not establish the repository namespace used by subsequent calls.
            repository = self.request('GET', f'/repositories/{repository_id}', token['token'])
            name = repository['full_name']
            require(type(repository['id']) is int and repository['id'] == repository_id
                    and type(name) is str
                    and re.fullmatch(r'appolon1908/[A-Za-z0-9_.-]{1,100}', name) is not None
                    and name.split('/')[1] not in ('.', '..')
                    and repositories[0]['full_name'] == name, 'INSPECTION_REPOSITORY_MISMATCH')
            current = self.clock()
            require(self._aware(current) and expiry > current, 'TOKEN_EXPIRED')
            self._repository = name
            self._token = token['token']
            self._expires = expiry
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
            raise PublicationDenied('INSPECTION_AUTHORIZATION_UNAVAILABLE') from None

    def _fixed_read_query(self, path, body):
        if path != '/graphql' or type(body) is not dict or set(body) != {'query', 'variables'}:
            return False
        query, variables = body['query'], body['variables']
        if type(query) is not str or query not in (THREAD_QUERY, REVIEW_QUERY) or type(variables) is not dict:
            return False
        keys = {'owner', 'name', 'number'} | ({'after'} if query == THREAD_QUERY else set())
        if set(variables) != keys:
            return False
        if (variables['owner'] != 'appolon1908'
                or type(variables['name']) is not str
                or re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', variables['name']) is None
                or variables['name'] in ('.', '..')
                or variables['owner'] + '/' + variables['name'] != getattr(self, '_repository', None)
                or type(variables['number']) is not int
                or not 0 < variables['number'] <= 2147483647):
            return False
        if query == THREAD_QUERY and variables['after'] is not None:
            cursor = variables['after']
            if (type(cursor) is not str or not 0 < len(cursor) <= 2048
                    or any(not 33 <= ord(character) <= 126 for character in cursor)):
                return False
        return True

    def _scoped_get(self, path):
        repository = getattr(self, '_repository', None)
        if (repository is None or type(path) is not str or not path.startswith('/')
                or path.startswith('//') or '\\' in path or '#' in path or '://' in path
                or any(ord(character) <= 32 or ord(character) == 127 for character in path)):
            return False
        try:
            parsed = urlsplit(path)
            if parsed.scheme or parsed.netloc or parsed.fragment:
                return False
            namespace = '/repos/' + repository
            value = parsed.path
            # Reject dot segments, separators and controls at every bounded
            # decoding layer, while allowing encoded slashes in branch refs.
            for _ in range(10):
                if (not (value == namespace or value.startswith(namespace + '/'))
                        or '\\' in value
                        or any(part in ('.', '..') for part in value.split('/'))
                        or any(ord(character) <= 32 or ord(character) == 127 for character in value)):
                    return False
                decoded = unquote(value, errors='strict')
                if decoded == value:
                    return True
                value = decoded
        except (TypeError, ValueError):
            return False
        return False

    def _call(self, method, path, body=None):
        require((method == 'GET' and body is None and self._scoped_get(path))
                or (method == 'POST' and self._fixed_read_query(path, body)),
                'INSPECTION_EFFECT_REFUSED')
        return super()._call(method, path, body)

    def post(self, path, body):
        return self._call('POST', path, body)

    def assert_identity(self, authority, repository_id, now):
        raise PublicationDenied('INSPECTION_EFFECT_REFUSED')

    def inventory(self, app_id, installation_id, repositories):
        raise PublicationDenied('INSPECTION_EFFECT_REFUSED')
