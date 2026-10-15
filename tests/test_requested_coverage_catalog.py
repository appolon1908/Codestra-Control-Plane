"""Validate an inactive proposal against its actual disposable patched publisher."""
import ast
from collections import Counter
import json
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PROPOSAL = ROOT / 'governance/coverage-proposals/requested-13-bindings.json'
PATCH = ROOT / 'governance/coverage-proposals/requested-13-catalog.patch'
ADDITIONS = {'Codestra-Control-Plane', 'Codestra-PostgreSQL', 'OpenAPI',
             'codestra-foundation', 'codestra-ruleset-toolkit', 'openrerefine-'}


def constants(source):
    result = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in ('PRIOR_GOVERNED_REPOS', 'ADDITIONAL_GOVERNED_REPOS'):
                result[name] = ast.literal_eval(node.value.args[0])
    return result


class RequestedCoverageCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / 'tests/fixtures/publisher-catalog-f3a010c.py.txt').read_text()
        assert hashlib.sha256(cls.source.encode()).hexdigest() == 'd6c9585cc69077222de183fd058160d5581040592bd0bb91fd62b5fff5a867b8'
        with tempfile.TemporaryDirectory(prefix='cp-catalog-test-') as temp:
            directory = Path(temp)
            (directory / 'bin').mkdir()
            target = directory / 'bin/codestra-github-statusd'
            target.write_text(cls.source)
            subprocess.run(['git', 'apply', '--check', str(PATCH)], cwd=directory, check=True, capture_output=True)
            subprocess.run(['git', 'apply', str(PATCH)], cwd=directory, check=True, capture_output=True)
            cls.candidate = target.read_text()
        cls.proposal = json.loads(PROPOSAL.read_text())

    def test_exact_union_no_removals_duplicates_or_unknown_names(self):
        before, after = constants(self.source), constants(self.candidate)
        original = set.union(*(set(value) for value in before.values()))
        proposed = set.union(*(set(value) for value in after.values()))
        self.assertEqual(len(original), 43)
        self.assertEqual(len(proposed), 49)
        self.assertEqual(proposed, original | ADDITIONS)
        self.assertFalse(original - proposed)
        for values in after.values():
            self.assertEqual(len(values), len(set(values)))
        self.assertEqual(set(self.proposal['additions']), ADDITIONS)
        self.assertEqual(len(self.proposal['requested_repositories']), 13)
        self.assertEqual(len(set(self.proposal['requested_repositories'])), 13)
        self.assertEqual({repo.split('/', 1)[1] for repo in self.proposal['requested_repositories']} - original, ADDITIONS)

    def test_proposal_stays_inactive_and_bindings_unverified(self):
        for key in ('activated', 'authority', 'publication_enabled'):
            self.assertIs(self.proposal[key], False)
        self.assertIsNone(self.proposal['operator_approval_receipt'])
        self.assertEqual(self.proposal['canonical_publisher_sha256'], hashlib.sha256(self.source.encode()).hexdigest())
        self.assertEqual(self.proposal['proposed_publisher_sha256'], hashlib.sha256(self.candidate.encode()).hexdigest())
        self.assertEqual(self.proposal['catalog_patch_sha256'], hashlib.sha256(PATCH.read_bytes()).hexdigest())
        self.assertEqual(len(self.proposal['bindings']), 13)
        self.assertEqual(len({b['repository'] for b in self.proposal['bindings']}), 13)
        self.assertEqual({b['repository'] for b in self.proposal['bindings']}, set(self.proposal['requested_repositories']))
        for binding in self.proposal['bindings']:
            for key, value in binding.items():
                if key != 'repository':
                    self.assertIsNone(value, key)
        self.assertEqual((ROOT / 'tests/fixtures/publisher-catalog-f3a010c.py.txt').read_text(), self.source)

    def test_registry_mismatch_and_duplicate_mapping_still_refuse_added_repos(self):
        # Compile only the real alias-selector AST: no script imports, DB or effects.
        node = next(n for n in ast.parse(self.candidate).body if isinstance(n, ast.FunctionDef) and n.name == 'aliases')
        values = constants(self.candidate)
        namespace = {'OWNER': 'appolon1908', 'Counter': Counter, 'RealDictCursor': object, 'print': mock.Mock(),
                     'ADDITIONAL_GOVERNED_REPOS': set(values['ADDITIONAL_GOVERNED_REPOS']),
                     'GOVERNED_REPOS': set.union(*(set(v) for v in values.values()))}
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'proposed-alias-selector', 'exec'), namespace)
        connection = mock.MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        for repo in ADDITIONS:
            row = {'product': repo, 'repository': 'appolon1908/' + repo, 'test_branch': 'testing',
                   'promotion_chain': ['development', 'testing', 'staging', 'production']}
            cursor.fetchall.return_value = [row]
            self.assertEqual(len(namespace['aliases'](connection)), 1)
            for bad in ([row, dict(row)], [dict(row, product='Other')], [dict(row, test_branch='test')],
                        [dict(row, promotion_chain=['development', 'production'])]):
                with self.subTest(repo=repo, rows=bad):
                    cursor.fetchall.return_value = bad
                    self.assertEqual(namespace['aliases'](connection), [])
