"""Supplementary offline checks of the exact delivered companion bytes."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1] / 'companions' / 'pas233_public_handoff'
_SPEC = importlib.util.spec_from_file_location('pas233_public_handoff_companion', ROOT / 'public_handoff.py')
helper = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(helper)


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def fixture(name):
    return json.loads((ROOT / 'fixtures' / name).read_text())


def paths(row, prefix=()):
    for key, value in row.items():
        current = prefix + (key,)
        yield current
        if type(value) is dict:
            yield from paths(value, current)


def parent_at(row, path):
    for name in path[:-1]:
        row = row[name]
    return row


class CertificationInputTests(unittest.TestCase):
    def setUp(self):
        self.candidate = fixture('synthetic-unit-candidate.json')
        self.review = fixture('synthetic-review-reference.json')

    def safe(self, candidate, review, *, rejected=True):
        first = helper.validate(candidate, review)
        self.assertEqual(first, helper.validate(candidate, review))
        self.assertEqual(first['disposition'], 'NONEXECUTING')
        for flag in ('execution_authorized', 'operational_trust_verified', 'owner_schema_acknowledged'):
            self.assertIs(first[flag], False)
        self.assertIn('OWNER_HANDSHAKE_INTEGRATION_REQUIRED', first['remaining_gates'])
        self.assertNotIn('CANARY_CERT_239817', json.dumps(first))
        self.assertEqual(first['candidate_consistency'], 'REJECTED' if rejected else 'CONSISTENT')
        return first

    def test_every_required_candidate_and_reference_field_is_checked(self):
        for which, original in (('candidate', self.candidate), ('review', self.review)):
            for path in paths(original):
                with self.subTest(input=which, path=path):
                    altered = copy.deepcopy(original)
                    del parent_at(altered, path)[path[-1]]
                    candidate, review = ((altered, self.review) if which == 'candidate'
                                         else (self.candidate, altered))
                    self.safe(encode(candidate), encode(review))

    def test_wrong_json_types_and_nonmatching_values_fail_closed(self):
        for which, original in (('candidate', self.candidate), ('review', self.review)):
            for path in paths(original):
                for value in (None, False, 0, [], {}, 'CANARY_CERT_239817'):
                    with self.subTest(input=which, path=path, value_type=type(value).__name__):
                        altered = copy.deepcopy(original)
                        parent_at(altered, path)[path[-1]] = value
                        candidate, review = ((altered, self.review) if which == 'candidate'
                                             else (self.candidate, altered))
                        self.safe(encode(candidate), encode(review))

    def test_unknown_keys_at_every_object_level_are_rejected_without_echo(self):
        for which, original in (('candidate', self.candidate), ('review', self.review)):
            objects = [()] + [path for path in paths(original)
                             if type(parent_at(original, path)[path[-1]]) is dict]
            for path in objects:
                with self.subTest(input=which, path=path):
                    altered = copy.deepcopy(original)
                    target = altered
                    for name in path:
                        target = target[name]
                    target['CANARY_CERT_239817'] = 'CANARY_CERT_239817'
                    candidate, review = ((altered, self.review) if which == 'candidate'
                                         else (self.candidate, altered))
                    self.safe(encode(candidate), encode(review))

    def test_exact_byte_budget_and_overrun(self):
        candidate = encode(self.candidate)
        bounded = candidate + b' ' * (32768 - len(candidate))
        self.safe(bounded, encode(self.review), rejected=False)
        self.safe(bounded + b' ', encode(self.review))
        review = encode(self.review)
        bounded_review = review + b' ' * (32768 - len(review))
        self.safe(candidate, bounded_review, rejected=False)
        self.safe(candidate, bounded_review + b' ')

    def test_nested_duplicate_fields_and_trailing_objects_are_rejected(self):
        candidate = encode(self.candidate)
        duplicate = candidate.replace(b'"issuer":"fixture-issuer"',
                                      b'"issuer":"fixture-issuer","issuer":"fixture-issuer"', 1)
        self.safe(duplicate, encode(self.review))
        self.safe(candidate + b'{}', encode(self.review))

    def test_unsupported_types_and_nested_payloads_return_fixed_rejection(self):
        for raw in (None, '', bytearray(b'{}'), b'{"x":1e999}',
                    b'{"x":' + b'[' * 900 + b'0' + b']' * 900 + b'}',
                    b'{"x":' + b'[' * 1200 + b'0' + b']' * 1200 + b'}'):
            self.safe(raw, encode(self.review))
