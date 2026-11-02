"""Owner-approved source repairs; read-only evidence, never certification.

This is shared by the GitHub checker and compatibility publisher validator.
It does not grant authenticated-publisher custody, bindings or certificates.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
import subprocess

from .publisher_github import APIUnavailable, GitHubAppClient
from .atomic_inspection_github import REVIEW_QUERY, THREAD_QUERY
from .effective_protection import observe_protection


@dataclass(frozen=True)
class Admission:
    repository: str
    number: int
    head: str
    head_sha: str
    base: str
    base_sha: str
    expires_at: datetime
    stacked: bool = False


EXPIRY = datetime(2026, 11, 3, 22, 10, tzinfo=timezone.utc)
ADMISSIONS = (
    Admission('appolon1908/klyrow.com', 196, 'repair/pr195-main-sync-20261102',
              '8f5490cd3e636613c2aecc227a22041231c3c35c', 'development',
              '3cf2ccd0d511d50d14f96aabaccaacfbb03250b9', EXPIRY),
    Admission('appolon1908/klyrow.com', 197, 'repair/pr194-staging-sync-20261102',
              'de4a52f0578d89667ac6ccec8a5d210712722dea', 'staging',
              '09bcb9addc26460b727c7bea0872db09a299ab56', EXPIRY),
    Admission('appolon1908/klyrow.com', 186, 'implementation/klyrow-ses-transport-20261008',
              'e6f7faf6ecd499542aca17689a1a568042b9e14e', 'main',
              '45a94da2628974fd45224b821a26653580a36c20', EXPIRY, True),
    Admission('appolon1908/klyrow.com', 187, 'implementation/klyrow-ses-feedback-sqs-20261008',
              '6600b94cc3b1401f48a4e423815d64eb8c55cd25', 'implementation/klyrow-ses-transport-20261008',
              'e6f7faf6ecd499542aca17689a1a568042b9e14e', EXPIRY, True),
    Admission('appolon1908/klyrow.com', 188, 'implementation/klyrow-ux-api-route-certification-20261008',
              '8e37a9995f19c849362d2e27f1d1df3da37b4ac7', 'implementation/klyrow-ses-feedback-sqs-20261008',
              '6600b94cc3b1401f48a4e423815d64eb8c55cd25', EXPIRY, True),
)
REQUIRED_CHECKS = frozenset((
    'contracts', 'frontend', 'test', 'secrets', 'image', 'repository-foundation',
    'deploy-readiness / source-ci', 'deploy-readiness / deploy-readiness / source-ci',
    'deploy-readiness / deploy-readiness / secret-scan',
))


def repair_candidate(product, head):
    """Select listed heads for evaluation even if their parent is a feature ref."""
    return product == 'klyrow.com' and any(a.head == head for a in ADMISSIONS)


def _git(repo_path, *arguments):
    result = subprocess.run(
        ['git', '-c', f'safe.directory={repo_path}', '-C', repo_path, *arguments],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=20, check=False,
    )
    if result.returncode:
        raise RuntimeError('repair repository unavailable')
    return result.stdout.strip()


def remote_repository(repo_path):
    origin = _git(repo_path, 'remote', 'get-url', 'origin')
    for prefix in ('https://github.com/', 'git@github.com:', 'ssh://git@github.com/'):
        if origin.startswith(prefix):
            return origin[len(prefix):].removesuffix('.git')
    return ''


def remote_sha(repo_path, ref):
    lines = _git(repo_path, 'ls-remote', 'origin', f'refs/heads/{ref}').splitlines()
    if len(lines) != 1:
        return ''
    parts = lines[0].split()
    return parts[0] if len(parts) == 2 and parts[1] == f'refs/heads/{ref}' else ''


class ReadOnlyGitHub(GitHubAppClient):
    """Reuse bounded inventory readers with the existing operator gh identity.

    There is no write method: inherited POST operations other than GraphQL read
    queries are refused. Credentials remain inside gh and never enter arguments.
    """
    def __init__(self):
        super().__init__(lambda: None)

    def _call(self, method, path, body=None):
        if not path.startswith('/') or path.startswith('//') or '://' in path:
            raise RuntimeError('invalid evidence path')
        if method != 'GET' and not (
            method == 'POST' and path == '/graphql' and type(body) is dict
            and body.get('query') in (REVIEW_QUERY, THREAD_QUERY)
        ):
            raise RuntimeError('read-only evidence operation required')
        command = ['gh', 'api', '--hostname', 'github.com', '--include', '--method', method, path.lstrip('/')]
        if body is not None:
            command.extend(['--input', '-'])
        result = subprocess.run(command, input=None if body is None else json.dumps(body),
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=20, check=False)
        if len(result.stdout) > 4*1024*1024:
            raise RuntimeError('repair evidence unavailable')
        headers, separator, payload = result.stdout.replace('\r\n', '\n').partition('\n\n')
        status = re.fullmatch(r'HTTP/[0-9.]+ ([0-9]{3})(?: .*)?', headers.split('\n', 1)[0])
        if not separator or status is None:
            raise RuntimeError('repair evidence unavailable')
        code = int(status.group(1))
        if result.returncode or not 200 <= code < 300:
            raise APIUnavailable(code)
        return json.loads(payload)

    def threads_resolved(self, repo, number):
        owner, name = repo.split('/')
        cursor = None
        seen = set()
        for _ in range(100):
            response = self.post('/graphql', {'query': THREAD_QUERY, 'variables': {
                'owner': owner, 'name': name, 'number': number, 'after': cursor}})
            if response.get('errors'):
                raise RuntimeError('repair thread inventory unavailable')
            threads = response['data']['repository']['pullRequest']['reviewThreads']
            nodes, page = threads['nodes'], threads['pageInfo']
            if type(nodes) is not list or len(nodes) > 100 or type(page) is not dict:
                raise RuntimeError('invalid repair thread inventory')
            for node in nodes:
                if (type(node) is not dict or type(node.get('id')) is not str or not node['id']
                        or node['id'] in seen or type(node.get('isResolved')) is not bool):
                    raise RuntimeError('invalid repair thread')
                seen.add(node['id'])
                if not node['isResolved']:
                    return False
            if page['hasNextPage'] is False:
                return True
            if (page['hasNextPage'] is not True or type(page['endCursor']) is not str
                    or not page['endCursor'] or page['endCursor'] == cursor):
                raise RuntimeError('invalid repair thread pagination')
            cursor = page['endCursor']
        raise RuntimeError('incomplete repair thread inventory')


def _current_refs(admission, repo_path):
    return (remote_repository(repo_path) == admission.repository
            and remote_sha(repo_path, admission.head) == admission.head_sha
            and remote_sha(repo_path, admission.base) == admission.base_sha)


def _pr_matches(pr, admission):
    return (type(pr['number']) is int and pr['number'] == admission.number
            and pr['state'] == 'open' and pr['draft'] is False
            and pr['head']['repo']['full_name'] == admission.repository
            and pr['base']['repo']['full_name'] == admission.repository
            and (type(pr.get('stack')) is dict if admission.stacked else pr.get('stack') is None)
            and (pr['head']['ref'], pr['head']['sha'], pr['base']['ref'], pr['base']['sha'])
            == (admission.head, admission.head_sha, admission.base, admission.base_sha))


def _stack_snapshot(api, group):
    """Bind exactly 186/187/188 to one native stack with ultimate base main."""
    root = group[0]
    memberships = []
    identity = None
    for position, admission in enumerate(group, 1):
        pr = api.get(f'/repos/{admission.repository}/pulls/{admission.number}')
        if not _pr_matches(pr, admission):
            raise RuntimeError('repair stack PR mismatch')
        membership = pr['stack']
        if (type(membership['id']) is not int or membership['id'] <= 0
                or type(membership['number']) is not int or membership['number'] <= 0
                or type(membership['position']) is not int or membership['position'] != position
                or type(membership['size']) is not int or membership['size'] != 3
                or membership['base'] != {'ref': root.base, 'sha': root.base_sha}):
            raise RuntimeError('repair stack membership mismatch')
        if identity is None:
            identity = membership['id'], membership['number']
        if (membership['id'], membership['number']) != identity:
            raise RuntimeError('repair stack identity mismatch')
        memberships.append(membership)
    stack = api.get(f'/repos/{root.repository}/stacks/{identity[1]}')
    if (stack['id'] != identity[0] or stack['number'] != identity[1]
            or stack['open'] is not True or stack['base'] != {'ref': root.base}
            or type(stack['pull_requests']) is not list or len(stack['pull_requests']) != 3):
        raise RuntimeError('repair stack mismatch')
    for member, admission in zip(stack['pull_requests'], group):
        if (type(member['number']) is not int or member['number'] != admission.number
                or member['state'] != 'open' or member['draft'] is not False or member['merged_at'] is not None
                or (member['head']['ref'], member['head']['sha']) != (admission.head, admission.head_sha)):
            raise RuntimeError('repair stack member mismatch')
    return stack, memberships


def _evidence_passes(api, admission):
    repo, number = admission.repository, admission.number
    path = f'/repos/{repo}/pulls/{number}'
    pr = api.get(path)
    if not _pr_matches(pr, admission):
        return False
    checks = api.pages(f'/repos/{repo}/commits/{admission.head_sha}/check-runs?filter=latest', 'check_runs')
    latest = {}
    for check in checks:
        if check['name'] in REQUIRED_CHECKS:
            if (type(check['id']) is not int or check['app']['id'] != 15368
                    or check['head_sha'] != admission.head_sha):
                return False
            previous = latest.get(check['name'])
            if previous is None or check['id'] > previous['id']:
                latest[check['name']] = check
    if (set(latest) != REQUIRED_CHECKS
            or any(c['status'] != 'completed' or c['conclusion'] != 'success' for c in latest.values())):
        return False
    if not api.review_approved(repo, number):
        return False
    reviews = {}
    for review in api.pages(path + '/reviews'):
        if review['state'] not in ('APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'):
            continue
        login = review['user']['login'].casefold()
        if type(review['id']) is not int:
            return False
        previous = reviews.get(login)
        if previous is None or review['id'] > previous['id']:
            reviews[login] = review
    approved = any(
        r['state'] == 'APPROVED' and r['commit_id'] == admission.head_sha
        and r['user']['type'] == 'User'
        and r['user']['login'].casefold() != pr['user']['login'].casefold()
        and api.eligible_reviewer(repo, r['user']['login'])
        for r in reviews.values()
    )
    return (approved and api.threads_resolved(repo, number)
            and _pr_matches(api.get(path), admission))


def repair_admission(product, repo_path, head, base, head_sha, *, api=None,
                     clock=lambda: datetime.now(timezone.utc)):
    """None means unrelated; a listed repair always receives an explicit verdict.

    No request file, caller evidence flag, database row or CI status can expand
    the compiled allowlist. Every failure stays denied, including API errors.
    """
    admission = next((a for a in ADMISSIONS if a.head == head), None)
    if admission is None:
        return None
    denied = (False, f'klyrow source repair {admission.number}: exact scope/evidence required')
    try:
        group = tuple(a for a in ADMISSIONS if a.stacked) if admission.stacked else (admission,)
        now = clock()
        if (product != 'klyrow.com' or (head_sha, base) != (admission.head_sha, admission.base)
                or now.tzinfo is None or now >= admission.expires_at
                or not all(_current_refs(a, repo_path) for a in group)):
            return denied
        api = api if api is not None else ReadOnlyGitHub()
        stack = _stack_snapshot(api, group) if admission.stacked else None
        protection_branch = group[0].base
        protection = observe_protection(api, admission.repository, protection_branch)
        if (protection.approvals < 1 or not all((protection.stale, protection.conversations, protection.strict))
                or admission.stacked and not protection.last_push
                or set(protection.checks) != {(name, 15368) for name in REQUIRED_CHECKS}):
            return denied
        if not all(_evidence_passes(api, a) for a in group):
            return denied
        if admission.stacked and _stack_snapshot(api, group) != stack:
            return denied
        if observe_protection(api, admission.repository, protection_branch) != protection:
            return denied
        fresh = clock()
        if (fresh.tzinfo is None or fresh >= admission.expires_at
                or not all(_current_refs(a, repo_path) for a in group)):
            return denied
        return True, f'klyrow source repair {admission.number}: exact evidence; expires=2026-11-03T22:10Z'
    except Exception:
        # Remote output may contain secrets; return only the fixed denial text.
        return denied
