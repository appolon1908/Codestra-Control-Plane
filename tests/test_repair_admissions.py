"""No-effect exact-source repair admission regressions."""
from copy import deepcopy
from datetime import datetime, timezone
import contextlib
import io
import json
from pathlib import Path
import runpy
import sys
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
from codestra_control import repair_admissions as repair
from codestra_control.publisher_github import APIUnavailable

REPO = 'appolon1908/klyrow.com'
NOW = datetime(2026, 11, 2, 22, 30, tzinfo=timezone.utc)
CASES = (
    (196, 'repair/pr195-main-sync-20261102', '8f5490cd3e636613c2aecc227a22041231c3c35c',
     'development', '3cf2ccd0d511d50d14f96aabaccaacfbb03250b9'),
    (197, 'repair/pr194-staging-sync-20261102', 'de4a52f0578d89667ac6ccec8a5d210712722dea',
     'staging', '09bcb9addc26460b727c7bea0872db09a299ab56'),
)
STACK_CASES = (
    (186, 'implementation/klyrow-ses-transport-20261008', 'e6f7faf6ecd499542aca17689a1a568042b9e14e',
     'main', '45a94da2628974fd45224b821a26653580a36c20'),
    (187, 'implementation/klyrow-ses-feedback-sqs-20261008', '6600b94cc3b1401f48a4e423815d64eb8c55cd25',
     'implementation/klyrow-ses-transport-20261008', 'e6f7faf6ecd499542aca17689a1a568042b9e14e'),
    (188, 'implementation/klyrow-ux-api-route-certification-20261008', '8e37a9995f19c849362d2e27f1d1df3da37b4ac7',
     'implementation/klyrow-ses-feedback-sqs-20261008', '6600b94cc3b1401f48a4e423815d64eb8c55cd25'),
)
CHECKS = ('contracts', 'frontend', 'test', 'secrets', 'image', 'repository-foundation',
          'deploy-readiness / source-ci', 'deploy-readiness / deploy-readiness / source-ci',
          'deploy-readiness / deploy-readiness / secret-scan')


class Evidence:
    def __init__(self, case):
        number, head, sha, base, base_sha = case
        self.pr = dict(number=number, state='open', draft=False, user={'login': 'author'},
                       head=dict(ref=head, sha=sha, repo={'full_name': REPO}),
                       base=dict(ref=base, sha=base_sha, repo={'full_name': REPO}))
        self.checks = [dict(id=i+1, name=name, head_sha=sha, status='completed',
                            conclusion='success', app={'id': 15368}) for i, name in enumerate(CHECKS)]
        self.reviews = [dict(id=1, state='APPROVED', commit_id=sha,
                             user=dict(login='reviewer', type='User'))]
        self.resolved = self.approved = self.eligible = True
        self.calls = []
        self.rules = [dict(ruleset_id=1, ruleset_source_type='Repository', ruleset_source=REPO,
                           type='pull_request', parameters=dict(required_approving_review_count=1,
                           require_code_owner_review=False, dismiss_stale_reviews_on_push=True,
                           require_last_push_approval=False, required_review_thread_resolution=True)),
                      dict(ruleset_id=1, ruleset_source_type='Repository', ruleset_source=REPO,
                           type='required_status_checks', parameters=dict(strict_required_status_checks_policy=True,
                           required_status_checks=[dict(context=name, integration_id=15368) for name in CHECKS]))]

    def effective_rules(self, repo, branch):
        assert (repo, branch) == (REPO, self.pr['base']['ref'])
        return deepcopy(self.rules)

    def get(self, path):
        self.calls.append(('get', path))
        if path == f'/repos/{REPO}/pulls/{self.pr["number"]}':
            return deepcopy(self.pr)
        if path == f'/repos/{REPO}/branches/{self.pr["base"]["ref"]}/protection':
            raise APIUnavailable(404)
        if path == f'/repos/{REPO}/rulesets/1?includes_parents=true':
            return dict(id=1, source_type='Repository', source=REPO, target='branch',
                        enforcement='active', bypass_actors=[], rules=[dict(type=r['type'], parameters=r['parameters']) for r in self.rules])
        raise AssertionError(path)

    def pages(self, path, key=None):
        self.calls.append(('pages', path, key))
        if path == f'/repos/{REPO}/commits/{self.pr["head"]["sha"]}/check-runs?filter=latest' and key == 'check_runs':
            return deepcopy(self.checks)
        if path == f'/repos/{REPO}/pulls/{self.pr["number"]}/reviews' and key is None:
            return deepcopy(self.reviews)
        raise AssertionError((path, key))

    def review_approved(self, repo, number):
        assert (repo, number) == (REPO, self.pr['number'])
        return self.approved

    def threads_resolved(self, repo, number):
        assert (repo, number) == (REPO, self.pr['number'])
        return self.resolved

    def eligible_reviewer(self, repo, login):
        assert (repo, login) == (REPO, 'reviewer')
        return self.eligible


class RepairAdmissionTests(unittest.TestCase):
    def evaluate(self, case=CASES[0], *, api=None, now=NOW, origin=REPO,
                 remote=None, product='klyrow.com', head=None, base=None, sha=None):
        number, expected_head, expected_sha, expected_base, base_sha = case
        refs = {ref: sha for c in (*CASES, *STACK_CASES) for ref, sha in ((c[1], c[2]), (c[3], c[4]))}
        with mock.patch.object(repair, 'remote_repository', return_value=origin), \
                mock.patch.object(repair, 'remote_sha', side_effect=remote or (lambda path, ref: refs.get(ref, ''))):
            return repair.repair_admission(product, '/unused', head or expected_head,
                                           base or expected_base, sha or expected_sha,
                                           api=api or Evidence(case), clock=lambda: now)

    def test_each_exact_approved_pair_with_complete_evidence_passes(self):
        for case in CASES:
            with self.subTest(pr=case[0]):
                result = self.evaluate(case)
                self.assertTrue(result[0], result)
                self.assertIn(str(case[0]), result[1])

    def test_scope_and_both_immutable_shas_are_required(self):
        for case in CASES:
            for change in ({'origin': 'attacker/klyrow.com'}, {'product': 'other'},
                           {'sha': '0'*40}, {'base': 'main'},
                           {'remote': lambda *_: '0'*40}):
                with self.subTest(case=case[0], change=change):
                    self.assertFalse(self.evaluate(case, **change)[0])

    def test_unlisted_branch_has_no_exception(self):
        self.assertIsNone(self.evaluate(head='repair/unapproved'))

    def test_standalone_repairs_cannot_be_admitted_as_part_of_any_stack(self):
        for case in CASES:
            api = Evidence(case); api.pr['stack'] = dict(id=2, number=200, position=2, size=2,
                                                       base=dict(ref='main', sha='a'*40))
            self.assertFalse(self.evaluate(case, api=api)[0])

    def test_exact_expiry_and_after_expiry_are_denied(self):
        for hour in (22, 23):
            with self.subTest(hour=hour):
                self.assertFalse(self.evaluate(now=datetime(2026, 11, 3, hour, 10, tzinfo=timezone.utc))[0])
        self.assertFalse(self.evaluate(now=datetime(2026, 11, 2, 22, 30))[0])

    def test_pr_identity_draft_closed_fork_and_changed_base_are_denied(self):
        for key, value in (('number', 999), ('draft', True), ('state', 'closed')):
            api = Evidence(CASES[0]); api.pr[key] = value
            self.assertFalse(self.evaluate(api=api)[0])
        for part, key, value in (('base', 'sha', '0'*40), ('base', 'ref', 'main'),
                                 ('head', 'sha', '0'*40), ('head', 'repo', {'full_name': 'attacker/klyrow.com'})):
            api = Evidence(CASES[0]); api.pr[part][key] = value
            self.assertFalse(self.evaluate(api=api)[0])

    def test_every_required_ci_context_must_be_successful_on_exact_head_from_actions(self):
        for name in CHECKS:
            for mutation in ('missing', 'pending', 'failure', 'neutral', 'wrong_sha', 'wrong_app'):
                api = Evidence(CASES[0]); check = next(c for c in api.checks if c['name'] == name)
                if mutation == 'missing': api.checks.remove(check)
                elif mutation == 'pending': check['status'] = 'in_progress'
                elif mutation in ('failure', 'neutral'): check['conclusion'] = mutation
                elif mutation == 'wrong_sha': check['head_sha'] = '0'*40
                else: check['app']['id'] = 99
                with self.subTest(name=name, mutation=mutation):
                    self.assertFalse(self.evaluate(api=api)[0])

    def test_newer_failed_duplicate_check_does_not_inherit_old_success(self):
        api = Evidence(CASES[0]); api.checks.append(dict(api.checks[0], id=999, conclusion='failure'))
        self.assertFalse(self.evaluate(api=api)[0])

    def test_independent_current_eligible_approval_and_resolved_threads_required(self):
        for field in ('approved', 'resolved', 'eligible'):
            api = Evidence(CASES[0]); setattr(api, field, False)
            self.assertFalse(self.evaluate(api=api)[0])
        for mutation in ('missing', 'self', 'bot', 'old', 'dismissed', 'changes_requested'):
            api = Evidence(CASES[0]); review = api.reviews[0]
            if mutation == 'missing': api.reviews.clear()
            elif mutation == 'self': review['user']['login'] = 'author'
            elif mutation == 'bot': review['user']['type'] = 'Bot'
            elif mutation == 'old': review['commit_id'] = '0'*40
            else: api.reviews.append(dict(review, id=2, state=mutation.upper()))
            with self.subTest(mutation=mutation):
                self.assertFalse(self.evaluate(api=api)[0])

    def test_api_failure_or_malformed_evidence_is_denied_without_error_details(self):
        for error in (RuntimeError('sensitive body'), KeyError('secret'), ValueError('malformed')):
            api = Evidence(CASES[0]); api.get = mock.Mock(side_effect=error)
            result = self.evaluate(api=api)
            self.assertFalse(result[0]); self.assertNotIn('sensitive', result[1]); self.assertNotIn('secret', result[1])

    def test_required_protection_cannot_be_weakened_or_changed_during_collection(self):
        for field, value in (('required_approving_review_count', 0), ('dismiss_stale_reviews_on_push', False),
                             ('required_review_thread_resolution', False)):
            api = Evidence(CASES[0]); api.rules[0]['parameters'][field] = value
            self.assertFalse(self.evaluate(api=api)[0])
        for field, value in (('strict_required_status_checks_policy', False), ('required_status_checks', [])):
            api = Evidence(CASES[0]); api.rules[1]['parameters'][field] = value
            self.assertFalse(self.evaluate(api=api)[0])
        api = Evidence(CASES[0])
        def change(*_):
            api.rules[0]['parameters']['require_last_push_approval'] = True
            return True
        api.threads_resolved = change
        self.assertFalse(self.evaluate(api=api)[0])

    def test_moving_base_during_evidence_collection_is_denied(self):
        api = Evidence(CASES[0]); refs = {CASES[0][1]: CASES[0][2], CASES[0][3]: CASES[0][4]}
        def resolve(*_):
            refs[CASES[0][3]] = '0'*40
            return True
        api.threads_resolved = resolve
        self.assertFalse(self.evaluate(api=api, remote=lambda path, ref: refs[ref])[0])

    def test_expiring_during_evidence_collection_is_denied(self):
        clock = mock.Mock(side_effect=(NOW, datetime(2026, 11, 3, 22, 10, tzinfo=timezone.utc)))
        refs = {CASES[0][1]: CASES[0][2], CASES[0][3]: CASES[0][4]}
        with mock.patch.object(repair, 'remote_repository', return_value=REPO), \
                mock.patch.object(repair, 'remote_sha', side_effect=lambda path, ref: refs[ref]):
            self.assertFalse(repair.repair_admission('klyrow.com', '/unused', CASES[0][1], CASES[0][3], CASES[0][2], api=Evidence(CASES[0]), clock=clock)[0])


class EntryPointTests(unittest.TestCase):
    def load(self, name):
        driver = types.ModuleType('psycopg2')
        extras = types.ModuleType('psycopg2.extras')
        driver.connect = mock.Mock(side_effect=AssertionError('database effects forbidden'))
        extras.RealDictCursor = object
        driver.extras = extras
        with mock.patch.dict(sys.modules, {'psycopg2': driver, 'psycopg2.extras': extras}):
            return runpy.run_path(str(ROOT / 'bin' / name), run_name='offline_repair_test')

    def test_checker_and_publisher_share_real_evidence_policy_without_database_access(self):
        checker = self.load('codestra-github-check')['main']
        publisher = self.load('codestra-github-statusd')['validate']
        for case in (*CASES, *STACK_CASES):
            number, head, sha, base, base_sha = case
            for allowed in (True, False):
                api = StackEvidence() if case in STACK_CASES else Evidence(case)
                api.resolved = allowed
                refs = {ref: value for c in (*CASES, *STACK_CASES) for ref, value in ((c[1], c[2]), (c[3], c[4]))}
                policy = lambda *args: repair.repair_admission(*args, api=api, clock=lambda: NOW)
                argv = ['checker', '--product', 'klyrow.com', '--repo-path', '/unused',
                        '--head-ref', head, '--base-ref', base, '--head-sha', sha]
                with self.subTest(pr=number, allowed=allowed), \
                        mock.patch.object(repair, 'remote_repository', return_value=REPO), \
                        mock.patch.object(repair, 'remote_sha', side_effect=lambda path, ref: refs[ref]), \
                        mock.patch.dict(checker.__globals__, {'remote_sha': lambda *_: sha, 'repair_admission': policy}), \
                        mock.patch.dict(publisher.__globals__, {'remote_sha': lambda *_: sha, 'REPAIR_ADMISSION': policy}), \
                        mock.patch.object(sys, 'argv', argv), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(checker(), 0 if allowed else 1)
                    self.assertEqual(publisher(None, 'klyrow.com', 'testing', '/unused', head, base, sha)[0], allowed)

    def test_stack_members_are_evaluated_even_when_direct_base_is_not_governed(self):
        candidate = self.load('codestra-github-statusd')['reconciliation_candidate']
        with mock.patch.dict(candidate.__globals__, {
            'MIGRATION_REASON': lambda *_: None,
            'governed': mock.Mock(side_effect=AssertionError('must not skip exact source repair')),
        }):
            for case in STACK_CASES:
                self.assertTrue(candidate(None, 'klyrow.com', 'testing', case[1], case[3], case[2]))

    def test_unverified_remote_head_never_collects_exception_evidence(self):
        publisher = self.load('codestra-github-statusd')['validate']
        with mock.patch.dict(publisher.__globals__, {
            'remote_sha': lambda *_: '0'*40,
            'REPAIR_ADMISSION': mock.Mock(side_effect=AssertionError('must not collect evidence')),
        }):
            self.assertFalse(publisher(None, 'klyrow.com', 'testing', '/unused', CASES[0][1], CASES[0][3], CASES[0][2])[0])

    def test_evidence_transport_refuses_writes_before_subprocess(self):
        api = repair.ReadOnlyGitHub()
        with mock.patch.object(repair.subprocess, 'run', side_effect=AssertionError('effects forbidden')):
            for path, body in (('/repos/appolon1908/klyrow.com/statuses/' + 'a'*40, {'state': 'success'}),
                               ('/graphql', {'query': 'mutation{danger}'}),
                               ('/graphql', {'query': 'query($x:Int!){viewer{login}} mutation {danger}'})):
                with self.subTest(path=path), self.assertRaisesRegex(RuntimeError, 'read-only'):
                    api.post(path, body)

    def test_readonly_transport_retains_bounded_pagination_and_fails_on_duplicates(self):
        api = repair.ReadOnlyGitHub()
        first = [dict(id=i) for i in range(100)]
        responses = [types.SimpleNamespace(returncode=0, stdout='HTTP/2.0 200 OK\n\n' + json.dumps(first)),
                     types.SimpleNamespace(returncode=0, stdout='HTTP/2.0 200 OK\n\n[{"id": 1}]')]
        with mock.patch.object(repair.subprocess, 'run', side_effect=responses) as run:
            with self.assertRaisesRegex(Exception, 'DUPLICATE_OR_INVALID_API_ITEM'):
                api.pages('/repos/appolon1908/klyrow.com/pulls/196/reviews')
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args.args[0][:7], ['gh', 'api', '--hostname', 'github.com', '--include', '--method', 'GET'])
        self.assertIn('page=2', run.call_args.args[0][-1])

    def test_fixed_review_and_thread_queries_remain_readable(self):
        api = repair.ReadOnlyGitHub()
        values = [{'data': {'repository': {'pullRequest': {'reviewDecision': 'APPROVED'}}}},
                  {'data': {'repository': {'pullRequest': {'reviewThreads': {
                      'nodes': [], 'pageInfo': {'hasNextPage': False, 'endCursor': None}}}}}}]
        responses = [types.SimpleNamespace(returncode=0, stdout='HTTP/2.0 200 OK\n\n' + json.dumps(value)) for value in values]
        with mock.patch.object(repair.subprocess, 'run', side_effect=responses) as run:
            self.assertTrue(api.review_approved(REPO, 196))
            self.assertTrue(api.threads_resolved(REPO, 196))
        for call in run.call_args_list:
            self.assertEqual(call.args[0], ['gh', 'api', '--hostname', 'github.com', '--include', '--method', 'POST', 'graphql', '--input', '-'])

    def test_missing_classic_protection_remains_distinct_from_unavailable_evidence(self):
        api = repair.ReadOnlyGitHub()
        for code in (404, 403, 500):
            response = types.SimpleNamespace(returncode=1, stdout=f'HTTP/2.0 {code} Error\n\n{{}}')
            with mock.patch.object(repair.subprocess, 'run', return_value=response):
                with self.assertRaises(APIUnavailable) as raised:
                    api.get(f'/repos/{REPO}/branches/development/protection')
                self.assertEqual(raised.exception.status, code)

    def test_malformed_thread_inventory_is_denied(self):
        api = repair.ReadOnlyGitHub()
        for nodes in ({}, '', None):
            response = {'data': {'repository': {'pullRequest': {'reviewThreads': {
                'nodes': nodes, 'pageInfo': {'hasNextPage': False, 'endCursor': None}}}}}}
            with self.subTest(nodes=nodes), mock.patch.object(api, 'post', return_value=response):
                with self.assertRaises(Exception):
                    api.threads_resolved(REPO, 196)


class StackEvidence(Evidence):
    def __init__(self):
        super().__init__(STACK_CASES[0])
        self.rules[0]['parameters']['require_last_push_approval'] = True
        self.members = {case[0]: Evidence(case) for case in STACK_CASES}
        self.stack = dict(id=123, number=201, open=True, base={'ref': 'main'}, pull_requests=[])
        for position, case in enumerate(STACK_CASES, 1):
            pr = self.members[case[0]].pr
            pr['stack'] = dict(id=123, number=201, position=position, size=3,
                               base=dict(ref='main', sha=STACK_CASES[0][4]))
            self.stack['pull_requests'].append(dict(number=case[0], state='open', draft=False,
                                                   merged_at=None, head=dict(ref=case[1], sha=case[2])))

    def get(self, path):
        if path == f'/repos/{REPO}/stacks/201':
            return deepcopy(self.stack)
        for number, evidence in self.members.items():
            if path == f'/repos/{REPO}/pulls/{number}':
                self.pr, self.checks, self.reviews = evidence.pr, evidence.checks, evidence.reviews
                return deepcopy(self.pr)
        if path == f'/repos/{REPO}/branches/main/protection':
            raise APIUnavailable(404)
        return super().get(path)

    def effective_rules(self, repo, branch):
        assert (repo, branch) == (REPO, 'main')
        return deepcopy(self.rules)


class StackRepairAdmissionTests(unittest.TestCase):
    evaluate = RepairAdmissionTests.evaluate
    def test_each_legacy_member_requires_complete_exact_three_member_stack(self):
        for case in STACK_CASES:
            result = self.evaluate(case, api=StackEvidence())
            self.assertIsNotNone(result)
            self.assertTrue(result[0], result)

    def test_missing_wrong_extra_reordered_or_closed_stack_is_denied(self):
        for mutation in ('missing', 'wrong_base', 'extra', 'reordered', 'closed', 'wrong_sha', 'wrong_position'):
            api = StackEvidence()
            if mutation == 'missing': api.members[187].pr['stack'] = None
            elif mutation == 'wrong_base': api.stack['base']['ref'] = 'development'
            elif mutation == 'extra': api.stack['pull_requests'].append(deepcopy(api.stack['pull_requests'][0]))
            elif mutation == 'reordered': api.stack['pull_requests'].reverse()
            elif mutation == 'closed': api.stack['open'] = False
            elif mutation == 'wrong_sha': api.stack['pull_requests'][1]['head']['sha'] = '0'*40
            else: api.members[187].pr['stack']['position'] = 1
            with self.subTest(mutation=mutation):
                result = self.evaluate(STACK_CASES[0], api=api)
                self.assertIsNotNone(result)
                self.assertFalse(result[0])

    def test_each_member_needs_all_checks_and_independent_review(self):
        for number in (186, 187, 188):
            for failure in ('ci', 'review'):
                api = StackEvidence()
                if failure == 'ci': api.members[number].checks[0]['conclusion'] = 'failure'
                else: api.members[number].reviews.clear()
                result = self.evaluate(STACK_CASES[2], api=api)
                self.assertIsNotNone(result)
                self.assertFalse(result[0])

    def test_main_last_push_protection_is_required_and_group_protection_cannot_drift(self):
        api = StackEvidence(); api.rules[0]['parameters']['require_last_push_approval'] = False
        self.assertFalse(self.evaluate(STACK_CASES[0], api=api)[0])
        api = StackEvidence()
        def change(*_):
            if api.pr['number'] == 186:
                api.rules[0]['parameters']['required_approving_review_count'] = 2
            return True
        api.threads_resolved = change
        self.assertFalse(self.evaluate(STACK_CASES[0], api=api)[0])

    def test_main_base_move_and_stack_change_during_collection_are_denied(self):
        refs = {ref: sha for c in STACK_CASES for ref, sha in ((c[1], c[2]), (c[3], c[4]))}
        api = StackEvidence()
        def move(*_):
            refs['main'] = '0'*40
            return True
        api.threads_resolved = move
        result = self.evaluate(STACK_CASES[1], api=api, remote=lambda path, ref: refs[ref])
        self.assertIsNotNone(result)
        self.assertFalse(result[0])
        api = StackEvidence()
        def change(*_):
            api.stack['number'] = 999
            return True
        api.threads_resolved = change
        result = self.evaluate(STACK_CASES[1], api=api)
        self.assertIsNotNone(result)
        self.assertFalse(result[0])


if __name__ == '__main__':
    unittest.main()
