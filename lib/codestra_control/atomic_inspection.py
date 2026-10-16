"""Authenticated, read-only atomic evidence inspection; no promotion authority."""
import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import tomllib
import uuid
from urllib.parse import quote

from .decision import CONTROL_PLANE_CONTEXTS, MAX_SNAPSHOT_AGE
from .effective_protection import observe_protection, validate_protection
from .evidence import PromotionRequest
from .lease_interface import connect_protected
from .lease_materialization import GitMaterializer, GitHubLeaseObserver
from .publisher_startup import AppJWT, protected_read, verify_code_custody as publisher_custody

CONFIG = Path('/etc/codestra/control-plane/atomic-inspector.toml')
CI_GATES = frozenset({'lint', 'unit', 'integration', 'contract', 'security',
                      'regression', 'migration', 'performance', 'ci_exact_sha'})
LOCAL_GATES = frozenset({'clean_tree', 'remote_sha_match', 'review'})


class InspectionDenied(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise InspectionDenied(reason)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def timestamp(value):
    result = datetime.fromisoformat(value)
    require(result.tzinfo is not None and result.utcoffset() is not None, 'INVALID_TIME')
    return result


def exact_sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{40}', value) and value != '0' * 40


def verify_code_custody():
    publisher_custody()
    protected_read(Path(__file__).resolve().parents[2] / 'bin' / 'codestra-inspect-atomic',
                   allow_public=True)


class AtomicRegistry:
    """Only the restricted server API supplies mapping, ownership and evidence."""
    def __init__(self, connection):
        self.connection = connection

    def acquire(self, binding_id):
        self.connection.set_session(isolation_level='REPEATABLE READ',
                                    readonly=True, autocommit=False)
        # End each snapshot before external reads; final acquisition starts anew.
        with self.connection:
            with self.connection.cursor() as cursor:
                cursor.execute('SELECT atomic_inspection.inspect(%s::uuid)', (binding_id,))
                row = cursor.fetchone()
                require(row is not None and type(row[0]) is dict, 'REGISTRY_UNAVAILABLE')
                return row[0]


class InspectionLeaseObserver(GitHubLeaseObserver):
    def dependency(self, value):
        binding = PromotionRequest(**value['binding'])
        require(value['prerequisite']['scope_type'] == 'SUBSECTION'
                and value['prerequisite']['scope_name'] == binding.source_ref,
                'DEPENDENCY_SCOPE_MISMATCH')
        self._authorize(value['repository'], value['repository_id'])
        def current_refs():
            require(self.ref(binding.repository, binding.source_ref) == binding.source_sha
                    and self.ref(binding.repository, binding.target_ref) == binding.target_base_sha,
                    'DEPENDENCY_REF_MOVED')
        current_refs()
        result = super().dependency(value)
        current_refs()
        return result


class AtomicInspector:
    """A result is a current observation, never an offline bearer admission."""
    def __init__(self, registry, api, materializer, *, controller_app_id,
                 controller_contexts, gate_checks, clock=lambda: datetime.now(timezone.utc)):
        self.registry, self.api, self.materializer = registry, api, materializer
        self.controller_app_id, self.controller_contexts = controller_app_id, controller_contexts
        self.gate_checks, self.clock = gate_checks, clock

    def _description(self, value, binding_id):
        require(type(value) is dict and set(value) == {'schema', 'lease', 'product',
                'section', 'workstation', 'candidate', 'dependencies',
                'required_workstations', 'materialization', 'required_gates'}
                and value['schema'] == 'codestra.atomic-inspection.v1', 'REGISTRY_SCHEMA_MISMATCH')
        lease, product, ws, candidate = (value[key] for key in ('lease', 'product', 'workstation', 'candidate'))
        b = lease['binding']; section = value['section']; now = self.clock()
        require(lease['authority'] == 'ONLINE_DATABASE_RECEIPT' and lease['state'] == 'ACTIVE'
                and lease['binding_id'] == binding_id == b['binding_id']
                and str(uuid.UUID(lease['lease_id'])) == lease['lease_id']
                and type(lease['epoch']) is int and lease['epoch'] > 0
                and timestamp(lease['expires_at']) > now
                and timestamp(b['valid_until']) > now and b['active'] is True
                and lease['principal'] == b['principal'], 'CURRENT_LEASE_REQUIRED')
        require(all(exact_sha(b[key]) for key in ('head_sha', 'base_sha'))
                and b['head_sha'] != b['base_sha']
                and type(b['repository_id']) is int and b['repository_id'] > 0,
                'EXACT_BINDING_REQUIRED')
        require(b['product'] == product['product'] == ws['product'] == candidate['product']
                and b['repository'] == product['repository']
                and b['workstation_id'] == ws['workstation_id'] == candidate['workstation_id']
                and b['task_id'] == candidate['task_id']
                and b['source_ref'] == candidate['branch']
                and b['target_ref'] == candidate['target_branch'] == ws['branch']
                and b['worktree'] == candidate['worktree']
                and b['head_sha'] == candidate['head_sha'] and b['base_sha'] == candidate['base_sha'],
                'CANDIDATE_MAPPING_MISMATCH')
        require(re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', ws['section'])
                and re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', ws['subsection'])
                and ws['branch'] == 'subsection/' + ws['section'] + '--' + ws['subsection']
                and section['section_key'] == ws['section']
                and section['branch'] == ws['parent_branch'] == 'section/' + ws['section']
                and re.fullmatch('atomic/' + re.escape(ws['section'] + '--' + ws['subsection'])
                                 + r'--[a-z0-9]+(?:-[a-z0-9]+)*', b['source_ref']),
                'CANONICAL_ATOMIC_ROUTE_REQUIRED')
        materialization = value['materialization']
        require(set(materialization) == {'host', 'directory_device', 'directory_inode'}
                and materialization['host'] == b['host']
                and type(materialization['directory_device']) is int
                and materialization['directory_device'] >= 0
                and type(materialization['directory_inode']) is int
                and materialization['directory_inode'] > 0, 'LEASED_MATERIALIZATION_REQUIRED')
        gates = value['required_gates']
        require(type(gates) is list and bool(gates) and all(type(g) is str for g in gates)
                and len(set(gates)) == len(gates) and set(gates) <= CI_GATES | LOCAL_GATES,
                'UNSUPPORTED_REQUIRED_GATES')
        require(type(value['dependencies']) is list and type(candidate['prerequisites']) is list
                and type(value['required_workstations']) is list, 'DEPENDENCY_INVENTORY_REQUIRED')
        prerequisites = candidate['prerequisites']; dependencies = value['dependencies']
        require(len({digest(p) for p in prerequisites}) == len(prerequisites)
                and sorted(digest(d['prerequisite']) for d in dependencies)
                    == sorted(digest(p) for p in prerequisites)
                and len({d['dependency_key'] for d in dependencies}) == len(dependencies),
                'DEPENDENCY_INVENTORY_MISMATCH')
        required = value['required_workstations']
        require(len({w['workstation_id'] for w in required}) == len(required)
                and len(required) == len(prerequisites), 'WORKSTATION_DEPENDENCY_MISMATCH')
        for dependency in dependencies:
            p = dependency['prerequisite']
            require(set(p) == {'product', 'scope_type', 'scope_name', 'sha'}
                    and p['product'] == b['product'] and p['scope_type'] == 'SUBSECTION'
                    and exact_sha(p['sha']) and dependency['binding_id'] == binding_id
                    and dependency['active'] is True and timestamp(dependency['valid_until']) > now,
                    'DEPENDENCY_UNAVAILABLE')
            matches = [w for w in required if w['product'] == p['product']
                       and w['branch'] == p['scope_name'] and w['status'] == 'CERTIFIED'
                       and w['remote_sha'] == w['exact_sha_certified'] == p['sha']]
            require(len(matches) == 1, 'WORKSTATION_DEPENDENCY_MISMATCH')
        return b

    def _materialize(self, description):
        b = description['lease']['binding']
        observed = self.materializer.inspect({'binding': b, 'dependencies': description['dependencies']})
        for key in ('repository', 'repository_id', 'source_ref', 'target_ref', 'head_sha',
                    'base_sha', 'worktree', 'host', 'git_common_dir', 'worktree_uid'):
            require(observed[key] == b[key], 'MATERIALIZATION_BINDING_MISMATCH')
        for key, value in description['materialization'].items():
            require(type(observed[key]) is type(value) and observed[key] == value,
                    'LEASED_DIRECTORY_CHANGED')
        require(observed['dependencies'] == {d['dependency_key']: d for d in description['dependencies']},
                'DEPENDENCY_OBSERVATION_MISMATCH')
        stamp = timestamp(observed['observed_at']); now = self.clock()
        require(stamp <= now and now - stamp <= MAX_SNAPSHOT_AGE, 'OBSERVATION_EXPIRED')
        return {key: value for key, value in observed.items() if key != 'observed_at'}

    def _online(self, description, pr_number):
        b = description['lease']['binding']; repo = b['repository']; api = self.api
        actual_repo = api.get('/repos/' + repo)
        require(actual_repo['id'] == b['repository_id'] and actual_repo['full_name'] == repo,
                'ONLINE_REPOSITORY_MISMATCH')
        pr = api.get(f'/repos/{repo}/pulls/{pr_number}')
        require(pr['number'] == pr_number and pr['state'] == 'open' and pr['draft'] is False,
                'PR_NOT_READY')
        for key, ref, sha in (('head', b['source_ref'], b['head_sha']),
                              ('base', b['target_ref'], b['base_sha'])):
            require(pr[key]['ref'] == ref and pr[key]['sha'] == sha
                    and pr[key]['repo']['id'] == b['repository_id'], 'ONLINE_BINDING_MISMATCH')
        merge = pr['merge_commit_sha']
        require(pr['mergeable'] is True and exact_sha(merge), 'CURRENT_MERGE_RESULT_REQUIRED')
        commit = api.get(f'/repos/{repo}/git/commits/{merge}')
        require(commit['sha'] == merge and [v['sha'] for v in commit['parents']]
                == [b['base_sha'], b['head_sha']], 'MERGE_PARENTS_MISMATCH')
        branch = api.get(f'/repos/{repo}/branches/{quote(b["target_ref"], safe="")}')
        require(branch['protected'] is True and branch['commit']['sha'] == b['base_sha'],
                'TARGET_MOVED_OR_UNPROTECTED')
        protection = observe_protection(api, repo, b['target_ref'])
        checks = {(name, 'github-actions:' + str(app)) for name, app in protection.checks
                  if name not in CONTROL_PLANE_CONTEXTS}
        require(bool(checks), 'GENUINE_CI_REQUIRED')
        validate_protection(protection, protection.approvals, checks,
                            self.controller_app_id, self.controller_contexts)
        for gate in description['required_gates']:
            if gate in CI_GATES:
                evidence = self.gate_checks.get(gate)
                require(type(evidence) is dict and set(evidence) == {'name', 'app_id'}
                        and type(evidence['app_id']) is int and evidence['app_id'] > 0
                        and (evidence['name'], 'github-actions:' + str(evidence['app_id'])) in checks,
                        'REQUIRED_GATE_UNBOUND')
        require(all(d['issuer_name'] not in {name for name, _ in checks}
                    and d['issuer_app_id'] not in {app for _, app in protection.checks}
                    and d['issuer_app_id'] != self.controller_app_id for d in description['dependencies']),
                'INDEPENDENT_DEPENDENCY_ISSUER_REQUIRED')
        check_receipts = []
        for sha in (b['head_sha'], merge):
            online = api.pages(f'/repos/{repo}/commits/{sha}/check-runs?filter=latest', 'check_runs')
            for name, producer in sorted(checks):
                matches = [v for v in online if v['name'] == name
                           and 'github-actions:' + str(v['app']['id']) == producer]
                require(len(matches) == 1, 'REQUIRED_CHECK_MISSING_OR_AMBIGUOUS')
                v = matches[0]
                require(type(v['id']) is int and v['id'] > 0 and v['head_sha'] == sha
                        and v['status'] == 'completed' and v['conclusion'] == 'success',
                        'REQUIRED_CHECK_NOT_SUCCESS')
                check_receipts.append(dict(id=v['id'], name=name, producer=producer, sha=sha))
        reviews = api.pages(f'/repos/{repo}/pulls/{pr_number}/reviews')
        latest = {}
        for review in reviews:
            if review['state'] in ('PENDING', 'COMMENTED'):
                continue
            login = review['user']['login'].casefold()
            require(type(review['id']) is int and review['id'] > 0, 'INVALID_REVIEW_RECEIPT')
            if login not in latest or review['id'] > latest[login]['id']:
                latest[login] = review
        require(not any(v['state'] == 'CHANGES_REQUESTED' for v in latest.values()),
                'CHANGES_REQUESTED')
        approved = []
        excluded = {pr['user']['login'].casefold(), b['principal'].casefold()}
        for login, review in sorted(latest.items()):
            if review['state'] == 'APPROVED' and review['commit_id'] == b['head_sha'] and login not in excluded:
                if api.eligible_reviewer(repo, review['user']['login']):
                    approved.append(review['id'])
        require(len(approved) >= protection.approvals and api.review_approved(repo, pr_number)
                and api.threads_resolved(repo, pr_number), 'CURRENT_INDEPENDENT_REVIEW_REQUIRED')
        require(api.get(f'/repos/{repo}/pulls/{pr_number}') == pr
                and api.get(f'/repos/{repo}/branches/{quote(b["target_ref"], safe="")}') == branch
                and observe_protection(api, repo, b['target_ref']) == protection,
                'ONLINE_REFS_OR_PROTECTION_CHANGED')
        return dict(pr=pr, branch=branch, protection=asdict(protection),
                    checks=check_receipts, approved_reviews=approved)

    def inspect(self, binding_id, pr_number):
        try:
            started = self.clock()
            require(str(uuid.UUID(binding_id)) == binding_id
                    and type(pr_number) is int and pr_number > 0, 'INVALID_INSPECTION_REQUEST')
            original = self.registry.acquire(binding_id)
            b = self._description(original, binding_id)
            materialization = self._materialize(original)
            online = self._online(original, pr_number)
            fresh = self.registry.acquire(binding_id)
            self._description(fresh, binding_id)
            require(fresh == original, 'REGISTRY_OR_LEASE_CHANGED')
            require(self._materialize(fresh) == materialization, 'MATERIALIZATION_CHANGED')
            require(self._online(fresh, pr_number) == online, 'ONLINE_EVIDENCE_CHANGED')
            final = self.registry.acquire(binding_id)
            self._description(final, binding_id)
            require(final == original, 'FINAL_AUTHORITY_CHANGED')
            lease = final['lease']
            completed = self.clock()
            require(started.tzinfo is not None and completed.tzinfo is not None
                    and started <= completed and completed - started <= MAX_SNAPSHOT_AGE,
                    'INSPECTION_EVIDENCE_EXPIRED')
            require(timestamp(lease['expires_at']) > completed
                    and timestamp(lease['binding']['valid_until']) > completed
                    and all(timestamp(d['valid_until']) > completed for d in final['dependencies']),
                    'FINAL_AUTHORITY_EXPIRED')
            return dict(schema='codestra.atomic-observation.v1', non_bearer=True,
                        eligible_for_source_update=True, binding_id=binding_id,
                        binding=asdict(PromotionRequest(b['repository'], b['product'],
                            b['source_ref'], b['target_ref'], b['head_sha'], b['base_sha'])),
                        pr_number=pr_number, lease_id=lease['lease_id'], lease_epoch=lease['epoch'],
                        observed_at=completed.isoformat(), evidence_digest=digest(final),
                        materialization_digest=digest(materialization), github_digest=digest(online),
                        certified=False, lease_granted=False, promotion_authorized=False)
        except InspectionDenied:
            raise
        except Exception:
            raise InspectionDenied('ATOMIC_INSPECTION_UNAVAILABLE') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only atomic candidate inspection; no bearer authority.')
    parser.add_argument('--binding', required=True)
    parser.add_argument('--pr', required=True, type=int)
    args = parser.parse_args(argv)
    connection = None
    try:
        require(str(uuid.UUID(args.binding)) == args.binding and args.pr > 0, 'INVALID_REQUEST')
        verify_code_custody()
        config = tomllib.loads(protected_read(CONFIG).decode())
        require(set(config) == {'database_dsn_file', 'app_id', 'installation_id', 'app_key_file',
                'controller_app_id', 'controller_contexts', 'gate_checks'}
                and all(type(config[k]) is int and config[k] > 0
                        for k in ('app_id', 'installation_id', 'controller_app_id'))
                and config['app_id'] != config['controller_app_id']
                and config['app_id'] != 15368 and type(config['gate_checks']) is dict
                and type(config['controller_contexts']) is list, 'INVALID_CONFIG')
        from .atomic_inspection_github import InspectionGitHubClient
        api = InspectionGitHubClient(AppJWT(config['app_key_file'], config['app_id']))
        observer = InspectionLeaseObserver(api, config['app_id'], config['installation_id'])
        connection = connect_protected(config['database_dsn_file'])
        result = AtomicInspector(AtomicRegistry(connection), api, GitMaterializer(observer),
            controller_app_id=config['controller_app_id'],
            controller_contexts=tuple(config['controller_contexts']),
            gate_checks=config['gate_checks']).inspect(args.binding, args.pr)
        # Surface close/transaction failures before claiming a successful read.
        connection.close(); connection = None
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print('ATOMIC_INSPECTION_UNAVAILABLE')
        return 1
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
