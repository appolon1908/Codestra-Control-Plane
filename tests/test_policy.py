"""Registered refs, never branch-name guesses, determine promotion edges."""

from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from codestra_control.policy import PolicyError, ProductMapping, ScopeEdge, resolve_edge


BREERO = ProductMapping(
    repository="appolon1908/Breero.com", product="Breero",
    development_ref="development", testing_ref="testing", staging_ref="staging",
    production_ref="production/environment", release_ref="main",
)


class PolicyTests(unittest.TestCase):
    def test_breero_effective_edges(self):
        for source, target, levels in (
            ("development", "testing", ("development", "testing")),
            ("testing", "staging", ("testing", "staging")),
            ("staging", "production/environment", ("staging", "production")),
            ("production/environment", "main", ("production", "main")),
        ):
            with self.subTest(source=source, target=target):
                self.assertEqual(resolve_edge(BREERO, source, target), levels)

    def test_breero_wrong_refs_and_skipped_stages_rejected(self):
        for source, target in (
            ("development", "test"), ("staging", "production"),
            ("production", "main"), ("production/arbitrary", "main"),
            ("development", "main"), ("main", "development"),
            ("staging", "staging"), ("atomic/guess", "subsection/guess"),
            ("section/guess", "development"),
        ):
            with self.subTest(source=source, target=target), self.assertRaises(PolicyError):
                resolve_edge(BREERO, source, target)

    def test_other_products_keep_registered_refs(self):
        other = replace(BREERO, repository="example/other", product="Other",
                        testing_ref="test", production_ref="production")
        self.assertEqual(resolve_edge(other, "development", "test"), ("development", "testing"))
        self.assertEqual(resolve_edge(other, "staging", "production"), ("staging", "production"))
        with self.assertRaises(PolicyError):
            resolve_edge(other, "development", "testing")

    def test_only_registered_hierarchy_edges_are_resolved(self):
        mapping = replace(BREERO, scope_edges=(
            ScopeEdge("subsection", "subsection/foundation--01", "section", "section/foundation"),
            ScopeEdge("section", "section/foundation", "development", "development"),
        ))
        self.assertEqual(resolve_edge(mapping, "subsection/foundation--01", "section/foundation"),
                         ("subsection", "section"))
        self.assertEqual(resolve_edge(mapping, "section/foundation", "development"),
                         ("section", "development"))
        with self.assertRaises(PolicyError):
            resolve_edge(mapping, "subsection/foundation--02", "section/foundation")

    def test_ambiguous_or_invalid_registry_is_rejected(self):
        invalid = [
            replace(BREERO, testing_ref="development"),
            replace(BREERO, production_ref="refs/heads/production/environment"),
            replace(BREERO, repository="https://github.com/appolon1908/Breero.com"),
            replace(BREERO, staging_ref="staging..bad"),
            replace(BREERO, scope_edges=(ScopeEdge("section", "section/a", "main", "main"),)),
            replace(BREERO, scope_edges=(ScopeEdge("section", "staging", "development", "development"),)),
            replace(BREERO, scope_edges=(
                ScopeEdge("subsection", "subsection/a", "section", "section/a"),
                ScopeEdge("subsection", "subsection/a", "section", "section/b"),
            )),
        ]
        for mapping in invalid:
            with self.subTest(mapping=mapping), self.assertRaises(PolicyError):
                resolve_edge(mapping, "development", "testing")
