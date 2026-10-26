"""Read-only source inspection for V3 bootstrap candidates, never admission."""
import argparse
import base64
import binascii
import json
import math
import re
import subprocess

DEFAULT_REPOSITORIES = tuple('appolon1908/' + name for name in (
    'Codestra-Communication-CC', 'Vicidialer-Codestra', 'Agent-Desktop-WebRTC',
    'Codestra-Document-Intelligence', 'Codestra-OCR-Workers', 'Codestra-Document-Schemas',
    'Codestra-Document-SDK', 'Codestra-Document-Console', 'Breero.com', 'klyrow.com',
    'klyrow-Website-', 'Codestra-Voice-Agent', 'Codestra-TTS-Kokoro', 'Codestra-TTS-Piper',
    'Codestra-TTS-F5', 'LARIM-A-Backend', 'LARIM-A-Fornt-end',
    'transportation-backend-', 'transportaion-Frontend', 'Moneybee-Backend',
    'Moneybee-frontend-', 'beyvra-backend', 'beyvra-frontend', 'Codestra-Connect'))
FIELDS = 'number,state,headRefName,headRefOid,baseRefName,baseRefOid,isCrossRepository,url'
CHAIN = ['subsection', 'section', 'development', 'testing', 'staging', 'production']
MAX_FILE = 1048576


class InvalidSource(ValueError):
    """Only fixed public diagnostics are raised by this module."""


def strict_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise InvalidSource('DUPLICATE_JSON_KEY')
            out[key] = value
        return out
    def constant(_):
        raise InvalidSource('NONFINITE_JSON')
    def number(value):
        result = float(value)
        if not math.isfinite(result):
            raise InvalidSource('NONFINITE_JSON')
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=number)
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        if isinstance(error, InvalidSource):
            raise
        raise InvalidSource('INVALID_JSON') from None


class GitHubReader:
    """All commands are read-only; subprocess diagnostics never enter the report."""
    def read(self, arguments):
        try:
            result = subprocess.run(['gh', *arguments], capture_output=True, timeout=30, check=False)
        except (OSError, subprocess.SubprocessError):
            raise InvalidSource('GITHUB_READ_UNAVAILABLE') from None
        if result.returncode != 0:
            raise InvalidSource('GITHUB_READ_UNAVAILABLE')
        if len(result.stdout) > 4 * MAX_FILE:
            raise InvalidSource('GITHUB_RESPONSE_TOO_LARGE')
        return strict_json(result.stdout)

    @staticmethod
    def _candidate(value):
        try:
            head, base = value['head'], value['base']
            return {'number': value['number'], 'state': value['state'].upper(),
                    'headRefName': head['ref'], 'headRefOid': head['sha'],
                    'baseRefName': base['ref'], 'baseRefOid': base['sha'],
                    'isCrossRepository': head['repo']['full_name'] != base['repo']['full_name'],
                    'url': value['html_url']}
        except (KeyError, TypeError, AttributeError):
            raise InvalidSource('INVALID_CANDIDATE_BINDING') from None

    def candidates(self, repository):
        rows = self.read(['api', '--method', 'GET',
                          f'repos/{repository}/pulls?state=open&base=development&per_page=100'])
        if type(rows) is not list:
            raise InvalidSource('INCOMPLETE_CANDIDATE_LIST')
        return [self._candidate(row) for row in rows]

    def candidate(self, repository, number):
        return self._candidate(self.read(['api', '--method', 'GET',
                                         f'repos/{repository}/pulls/{number}']))

    def content(self, repository, sha, path):
        return self.read(['api', '--method', 'GET',
                          f'repos/{repository}/contents/{path}?ref={sha}'])


def _identity(candidate, repository):
    if (type(candidate) is not dict or type(candidate.get('number')) is not int
            or candidate['number'] < 1 or candidate.get('state') != 'OPEN'
            or candidate.get('baseRefName') != 'development'
            or candidate.get('isCrossRepository') is not False
            or type(candidate.get('headRefName')) is not str
            or re.fullmatch(r'workstation/standalone-v3(?:-r[1-9][0-9]*)?-[0-9]{8}', candidate['headRefName']) is None
            or candidate.get('url') != f"https://github.com/{repository}/pull/{candidate['number']}"):
        raise InvalidSource('INVALID_CANDIDATE_BINDING')
    for field in ('headRefOid', 'baseRefOid'):
        if type(candidate.get(field)) is not str or re.fullmatch('[0-9a-f]{40}', candidate[field]) is None:
            raise InvalidSource('INVALID_CANDIDATE_BINDING')
    return tuple(candidate[field] for field in FIELDS.split(','))


def _file(reader, repository, sha, path):
    response = reader.content(repository, sha, path)
    if (type(response) is not dict or response.get('type') != 'file'
            or response.get('encoding') != 'base64' or type(response.get('size')) is not int
            or not 0 < response['size'] <= MAX_FILE or type(response.get('content')) is not str
            or len(response['content']) > 2 * MAX_FILE):
        raise InvalidSource('INVALID_SOURCE_FILE')
    try:
        raw = base64.b64decode(response['content'].replace('\n', ''), validate=True)
    except (ValueError, binascii.Error):
        raise InvalidSource('INVALID_SOURCE_FILE') from None
    if len(raw) != response['size']:
        raise InvalidSource('INVALID_SOURCE_FILE')
    return raw


def inspect_repository(reader, repository, head=None):
    result = {'repository': repository, 'source_validated': False,
              'authority': 'NONE', 'certified': False, 'publication_authorized': False}
    try:
        if type(repository) is not str or re.fullmatch(r'appolon1908/[A-Za-z0-9][A-Za-z0-9_.-]*', repository) is None:
            raise InvalidSource('INVALID_REPOSITORY')
        candidates = reader.candidates(repository)
        if type(candidates) is not list or len(candidates) >= 100 or any(type(c) is not dict for c in candidates):
            raise InvalidSource('INCOMPLETE_CANDIDATE_LIST')
        candidates = [c for c in candidates if type(c.get('headRefName')) is str
                      and re.fullmatch(r'workstation/standalone-v3(?:-r[1-9][0-9]*)?-[0-9]{8}', c['headRefName'])
                      and (head is None or c['headRefName'] == head)]
        if not candidates:
            raise InvalidSource('PR_MISSING')
        if len(candidates) != 1:
            raise InvalidSource('AMBIGUOUS_BOOTSTRAP_CANDIDATES')
        candidate = candidates[0]
        identity = _identity(candidate, repository)
        sha = candidate['headRefOid']
        result.update(pr=candidate['number'], head_sha=sha, base_sha=candidate['baseRefOid'], url=candidate['url'])
        policy = strict_json(_file(reader, repository, sha, '.codestra/governance/policy.json'))
        if (type(policy) is not dict or policy.get('schema_version') != 'codestra.governance.v3'
                or policy.get('repository') != repository
                or policy.get('required_status') != 'codestra-control-plane'
                or policy.get('promotion_chain') != CHAIN
                or policy.get('force_push') is not False
                or policy.get('direct_protected_branch_writes') is not False
                or type(policy.get('production')) is not dict
                or any(policy['production'].get(k) != v for k, v in {
                    'PRODUCTION_GO': 'NO', 'LIVE_CAPABILITIES_ENABLED': 'NO', 'EXTERNAL_EFFECTS': 'false'}.items())):
            raise InvalidSource('POLICY_INVALID')
        workstations = strict_json(_file(reader, repository, sha, '.codestra/governance/workstations.json'))
        if type(workstations) is not dict or not workstations:
            raise InvalidSource('WORKSTATIONS_INVALID')
        try:
            agents = _file(reader, repository, sha, 'AGENTS.md').decode('utf-8')
        except UnicodeError:
            raise InvalidSource('AGENTS_INVALID') from None
        if not agents.strip():
            raise InvalidSource('AGENTS_INVALID')
        if _identity(reader.candidate(repository, candidate['number']), repository) != identity:
            raise InvalidSource('CANDIDATE_CHANGED')
        result.update(source_validated=True, reason='SOURCE_FILES_VALIDATED_ONLY')
    except InvalidSource as error:
        result['reason'] = error.args[0]
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', action='append', help='Exact repository; repeat for a bounded selection.')
    parser.add_argument('--head', help='Choose an exact V3 head when multiple candidates are open.')
    args = parser.parse_args(argv)
    repositories = args.repo or DEFAULT_REPOSITORIES
    reader = GitHubReader()
    results = [inspect_repository(reader, repo, args.head) for repo in dict.fromkeys(repositories)]
    print(json.dumps({'schema': 'codestra.bootstrap-source-inspection.v1', 'results': results,
                      'authority': 'NONE', 'certified': False, 'status_writes': 0}, sort_keys=True))
    return 0 if all(result['source_validated'] for result in results) else 1
