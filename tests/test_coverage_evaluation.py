"""Offline synthetic trusted-reader fixtures; never publish statuses."""
from dataclasses import replace
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from test_decision import REQUEST, ready
from codestra_control.coverage import CoverageBinding, CoverageReceipt, CoverageEvidence, evaluate_coverage


class CoverageEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.binding = CoverageBinding(123, 7, 'request-fixture', 'assignment:1', 'owner', REQUEST, 'codestra-control-plane', 'synthetic-publisher')
        receipt = lambda kind: CoverageReceipt(self.binding, kind, 'synthetic-' + kind)
        self.evidence = CoverageEvidence(self.binding, ready(), receipt('publisher_capability'), receipt('context_ownership'))

    def evaluate(self, evidence=None, binding=None):
        return evaluate_coverage((binding or self.binding,), lambda request: evidence or self.evidence)[0]

    def test_default_reports_every_supplied_repo_without_filtering(self):
        requests = tuple(replace(self.binding, repository_id=i, pr_number=i) for i in range(1, 14))
        results = evaluate_coverage(requests)
        self.assertEqual(len(results), 13)
        self.assertTrue(all(r.status == 'UNAVAILABLE' and not r.authority and not r.publish for r in results))

    def test_complete_mock_evidence_remains_inactive(self):
        result = self.evaluate()
        self.assertEqual(result.reasons, ('INACTIVE_PUBLISHER',))
        self.assertFalse(result.publish)
        self.assertFalse(result.authority)

    def test_raw_json_bool_and_verifier_exception_never_succeed(self):
        for value in ({'success': True}, True, None):
            self.assertEqual(evaluate_coverage((self.binding,), lambda request: value)[0].status, 'UNAVAILABLE')
        def broken(request):
            raise RuntimeError('sensitive detail')
        self.assertEqual(evaluate_coverage((self.binding,), broken)[0].reasons, ('VERIFIER_FAILED',))

    def test_all_outer_and_promotion_fields_bound(self):
        for field, value in (('repository_id', 456), ('pr_number', 8), ('request_id', 'other'),
                             ('assignment_id', 'other'), ('owner_principal', 'other'),
                             ('status_context', 'codestra/control-plane'), ('publisher_principal', 'other')):
            with self.subTest(field=field):
                self.assertEqual(self.evaluate(binding=replace(self.binding, **{field: value})).status, 'DENIED')
        for field in REQUEST.__dataclass_fields__:
            value = 'c' * 40 if field.endswith('sha') else 'other/ref'
            with self.subTest(field=field):
                binding = replace(self.binding, promotion=replace(REQUEST, **{field: value}))
                self.assertEqual(self.evaluate(binding=binding).status, 'DENIED')

    def test_capability_and_ownership_receipts_required_and_bound(self):
        for field in ('publisher_capability', 'context_ownership'):
            for value in (None, True, CoverageReceipt(replace(self.binding, repository_id=456), field, 'wrong')):
                with self.subTest(field=field, value=value):
                    result = self.evaluate(replace(self.evidence, **{field: value}))
                    self.assertFalse(result.publish)
                    self.assertIn(field.upper() + '_UNVERIFIED', result.reasons)

    def test_wrong_assignment_owner_or_missing_lease_denies(self):
        snapshot = ready()
        for lease in (None, replace(snapshot.lease, assignment_id='wrong'), replace(snapshot.lease, owner='wrong')):
            self.assertEqual(self.evaluate(replace(self.evidence, snapshot=replace(snapshot, lease=lease))).status, 'DENIED')

    def test_unregistered_route_reported_not_silently_skipped(self):
        request = replace(REQUEST, source_ref='main', target_ref='development')
        binding = replace(self.binding, promotion=request)
        evidence = replace(self.evidence, binding=binding, snapshot=replace(ready(), observed_binding=request))
        result = self.evaluate(evidence, binding)
        self.assertEqual(result.status, 'DENIED')
        self.assertIn('ILLEGAL_PROMOTION_EDGE', result.reasons)

    def test_forged_equality_binding_and_duplicate_pr_denied(self):
        class Spoof:
            def __eq__(self, other): return True
            def __ne__(self, other): return False
        self.assertEqual(self.evaluate(replace(self.evidence, binding=Spoof())).status, 'DENIED')
        results = evaluate_coverage((self.binding, self.binding), lambda request: self.evidence)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.reasons == ('DUPLICATE_PR',) for r in results))

    def test_toolkit_foundation_priority_prs_explicitly_deny_unregistered_main_routes(self):
        # Reported head SHAs are fixture inputs, not independently observed proof.
        # Repo IDs below are SYNTHETIC; real stable GitHub IDs remain unobserved.
        cases = (
            ('codestra-ruleset-toolkit', 1001, 4, 'e8d7d1e3540491c331b22e0b188894f2707c58bf'),
            ('codestra-ruleset-toolkit', 1001, 3, '9f21ff9b45056f0f9e62964fe7a882a3bb08782f'),
            ('codestra-foundation', 1002, 7, 'cf71f928034663b76fe89d0e56e3f4532ee2ec0a'),
            ('codestra-foundation', 1002, 6, 'bf396546aa040d8e3aeb2fb2bcb4281ab55b960b'),
            ('codestra-foundation', 1002, 2, 'd1ab4589125f3171ac31e0ca91d379d1e0d4497a'),
        )
        for repo, repo_id, number, sha in cases:
            with self.subTest(repo=repo, pr=number):
                request = replace(REQUEST, repository='appolon1908/' + repo, product=repo,
                                  source_ref='feature/fixture', target_ref='main', source_sha=sha)
                binding = replace(self.binding, repository_id=repo_id, pr_number=number, promotion=request)
                snapshot = replace(ready(), mapping=replace(ready().mapping, repository=request.repository, product=repo),
                                   observed_binding=request)
                evidence = replace(self.evidence, binding=binding, snapshot=snapshot)
                result = self.evaluate(evidence, binding)
                self.assertEqual(result.status, 'DENIED')
                self.assertIn('ILLEGAL_PROMOTION_EDGE', result.reasons)
                self.assertFalse(result.publish)
                self.assertEqual(evaluate_coverage((binding,))[0].status, 'UNAVAILABLE')

    def test_request_id_cannot_be_reused_for_other_pr(self):
        other = replace(self.binding, pr_number=8)
        results = evaluate_coverage((self.binding, other), lambda request: self.evidence)
        self.assertTrue(all(r.reasons == ('DUPLICATE_REQUEST_ID',) for r in results))
