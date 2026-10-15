"""Synthetic verifier receipts only; no live credentials or remote effects."""
from dataclasses import replace
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from codestra_control.bootstrap_interface import (
    BootstrapRequest, Attestation, VerifiedAuthorization, inspect_bootstrap)


class BootstrapInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.request = BootstrapRequest('example/fixture', 'Fixture', 'development',
            'section/example', 'a' * 40, 'b' * 40, 'task-fixture', 'owner-fixture')
        receipt = lambda kind: Attestation(self.request, kind, 'synthetic-' + kind)
        self.authorization = VerifiedAuthorization(
            receipt('operator_grant'), receipt('owned_lease'), receipt('independent_review'))

    def inspect(self, authorization=None):
        return inspect_bootstrap(self.request, lambda request: authorization or self.authorization)

    def test_default_has_no_verifier_and_denies(self):
        self.assertEqual(inspect_bootstrap(self.request).reason, 'VERIFIER_UNAVAILABLE')

    def test_valid_synthetic_receipts_remain_inactive(self):
        result = self.inspect()
        self.assertTrue(result.bindings_validated)
        self.assertFalse(result.authority)
        self.assertFalse(result.ready)
        self.assertEqual(result.reason, 'INACTIVE_INTERFACE')

    def test_none_boolean_and_raw_json_are_not_authorization(self):
        for value in (None, True, {'authorized': True}):
            with self.subTest(value=value):
                result = inspect_bootstrap(self.request, lambda request: value)
                self.assertFalse(result.bindings_validated)

    def test_verifier_exception_is_generic_denial(self):
        def fail(request):
            raise RuntimeError('sensitive diagnostic')
        self.assertEqual(inspect_bootstrap(self.request, fail).reason, 'VERIFIER_FAILED')

    def test_each_binding_field_must_match_for_each_receipt(self):
        for field in self.request.__dataclass_fields__:
            for receipt_field in self.authorization.__dataclass_fields__:
                with self.subTest(field=field, receipt=receipt_field):
                    changed = replace(self.request, **{field: 'c' * 40 if field.endswith('sha') else 'other'})
                    receipt = replace(getattr(self.authorization, receipt_field), binding=changed)
                    result = self.inspect(replace(self.authorization, **{receipt_field: receipt}))
                    self.assertFalse(result.bindings_validated)

    def test_missing_swapped_and_empty_receipts_deny(self):
        for field in self.authorization.__dataclass_fields__:
            for value in (None, Attestation(self.request, 'wrong', 'synthetic'),
                          Attestation(self.request, field, '')):
                with self.subTest(field=field, value=value):
                    self.assertFalse(self.inspect(replace(self.authorization, **{field: value})).bindings_validated)

    def test_invalid_request_never_calls_verifier(self):
        for field, value in (('source_sha', 'a' * 39), ('target_base_sha', '0' * 40),
                             ('repository', ''), ('assignment_id', ''), ('owner_principal', ''),
                             ('source_ref', 'development\n'), ('target_ref', 'section/../bad'),
                             ('target_ref', 'section/.hidden')):
            with self.subTest(field=field):
                def unexpected(request):
                    self.fail('invalid request reached verifier')
                result = inspect_bootstrap(replace(self.request, **{field: value}), unexpected)
                self.assertEqual(result.reason, 'INVALID_REQUEST')

    def test_verifier_receives_exact_immutable_request(self):
        observed = []
        result = inspect_bootstrap(self.request, lambda request: observed.append(request) or self.authorization)
        self.assertEqual(observed, [self.request])
        self.assertTrue(result.bindings_validated)
        with self.assertRaises(AttributeError):
            self.request.source_sha = 'c' * 40

    def test_foreign_binding_cannot_spoof_exact_request_equality(self):
        class Spoof:
            def __eq__(self, other):
                return True
            def __ne__(self, other):
                return False
        for binding in (Spoof(), dict(self.request.__dict__)):
            with self.subTest(binding=type(binding).__name__):
                receipt = replace(self.authorization.operator_grant, binding=binding)
                self.assertFalse(self.inspect(replace(self.authorization, operator_grant=receipt)).bindings_validated)

    def test_foreign_receipt_kind_cannot_spoof_expected_kind(self):
        class Spoof:
            def __eq__(self, other):
                return True
            def __ne__(self, other):
                return False
        receipt = replace(self.authorization.operator_grant, kind=Spoof())
        self.assertFalse(self.inspect(replace(self.authorization, operator_grant=receipt)).bindings_validated)
