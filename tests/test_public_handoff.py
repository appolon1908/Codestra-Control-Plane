"""Synthetic companion tests. No operational keys, imports, network or grants."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1] / 'companions' / 'pas233_public_handoff'
_SPEC = importlib.util.spec_from_file_location('pas233_public_handoff_companion', ROOT / 'public_handoff.py')
helper = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(helper)


def raw(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def fixture():
    return json.loads((ROOT / 'fixtures/synthetic-unit-candidate.json').read_text())


def reference():
    return json.loads((ROOT / 'fixtures/synthetic-review-reference.json').read_text())


class PublicHandoffTests(unittest.TestCase):
    def evaluate(self, candidate=None, review=None):
        return helper.validate(raw(fixture() if candidate is None else candidate),
                               raw(reference() if review is None else review))

    def reject(self, candidate, code, review=None):
        result = self.evaluate(candidate, review)
        self.assertEqual(result.get('candidate_consistency'), 'REJECTED')
        self.assertIn(code, {issue['code'] for issue in result['issues']})
        self.assertEqual(result['disposition'], 'NONEXECUTING')
        self.assertFalse(result['execution_authorized'])
        self.assertFalse(result['operational_trust_verified'])
        self.assertFalse(result['owner_schema_acknowledged'])
        self.assertIn('OWNER_HANDSHAKE_INTEGRATION_REQUIRED', result['remaining_gates'])
        return result

    def test_consistent_synthetic_candidate_is_only_nonexecuting_review_material(self):
        result = self.evaluate()
        self.assertEqual(result.get('candidate_consistency'), 'CONSISTENT')
        self.assertEqual(result.get('disposition'), 'NONEXECUTING')
        self.assertFalse(result['execution_authorized'])
        self.assertFalse(result['operational_trust_verified'])
        self.assertFalse(result['owner_schema_acknowledged'])
        self.assertIn('INDEPENDENT_OPERATIONAL_TRUST_REQUIRED', result['remaining_gates'])

    def test_missing_each_public_channel_input_fails_closed(self):
        for field in fixture()['channel']:
            with self.subTest(field=field):
                row = fixture(); del row['channel'][field]
                self.reject(row, 'MISSING_FIELD')

    def test_bad_reference_forms_cannot_be_used_as_public_endpoints(self):
        for url in ('', 'http://issuer.example.invalid/status',
                    'https://user:password@issuer.example.invalid/status',
                    'https://issuer.example.invalid/status?token=SECRET',
                    'https://issuer.example.invalid/status#SECRET',
                    'https://issuer.example.invalid/\r\nSECRET',
                    'https://issuer.example.invalid:0/status',
                    'https://issuer.example.invalid:65536/status',
                    'https://issuer.example.invalid/\\status', 42):
            with self.subTest(url=url):
                row = fixture(); row['channel']['status_url'] = url
                self.reject(row, 'INVALID_PUBLIC_ENDPOINT')

    def test_public_key_reference_must_be_the_existing_independent_directory(self):
        for path in ('', '/tmp/key.pub', '/etc/codestra/control-plane/unit-issuer/../key.pub',
                     '/etc/codestra/control-plane/unit-issuer/key.pem',
                     '-----BEGIN PRIVATE KEY-----', None):
            row = fixture(); row['channel']['public_key_path'] = path
            self.reject(row, 'INVALID_PUBLIC_KEY_REFERENCE')

    def test_all_digest_fields_reject_malformed_values(self):
        for section in ('channel', 'binding'):
            for field in fixture()[section]:
                if field.endswith('sha256'):
                    for invalid in ('', 'a' * 63, 'A' * 64, 1, None):
                        row = fixture(); row[section][field] = invalid
                        self.reject(row, 'INVALID_DIGEST')

    def test_key_issuer_status_action_and_channel_substitution_rejected(self):
        vectors = [('channel', 'issuer', 'another-issuer'),
                   ('channel', 'public_key_sha256', 'f' * 64),
                   ('channel', 'status_url', 'https://other.example.invalid/status'),
                   ('channel', 'status_address', '192.0.2.99'),
                   ('binding', 'issuer', 'another-issuer'),
                   ('binding', 'action_sha256', 'f' * 64),
                   ('binding', 'issuer_channel_sha256', 'f' * 64),
                   ('binding', 'review_sha256', 'f' * 64),
                   ('binding', 'approval_sha256', 'f' * 64),
                   ('binding', 'admission_sha256', 'f' * 64)]
        for section, field, value in vectors:
            with self.subTest(field=field):
                row = fixture(); row[section][field] = value
                self.reject(row, 'REVIEW_REFERENCE_MISMATCH')

    def test_authenticated_status_descriptor_must_bind_exact_channel_and_issuer(self):
        for key, value in [('issuer', 'other'), ('issuer_channel_sha256', 'f' * 64),
                           ('status_url', 'https://other.example.invalid/status'),
                           ('purpose', 'source-unit-grant-v1'), ('schema', 'unsigned-v1')]:
            row = fixture(); row['status_source'][key] = value
            self.reject(row, 'STATUS_SOURCE_MISMATCH')

    def test_unauthenticated_or_caller_supplied_status_never_grants_authority(self):
        for injected in ({'revoked': False}, {'authenticated': True},
                         {'status': {'issuer': 'fixture-issuer', 'revoked': False}},
                         {'raw_base64': 'ZmFrZQ==', 'signature_base64': 'ZmFrZQ=='}):
            row = fixture(); row['status_source'].update(injected)
            self.reject(row, 'UNEXPECTED_FIELD')

    def test_staging_receipt_old_expired_or_future_is_never_active_authority(self):
        for expiry in ('2000-01-01T00:00:00Z', '2099-01-01T00:00:00Z', None):
            row = fixture()
            row['staging_receipt'] = {
                'status': 'CRM_ISOLATED_PRINCIPAL_AND_INDEPENDENT_PKI_STAGED_NOT_TRUSTED_OR_ENABLED',
                'expires_at': expiry}
            self.reject(row, 'STAGING_NOT_EXECUTION_AUTHORITY')

    def test_installation_roles_do_not_supply_unit_or_pg_scope(self):
        for scope in ('cp_ia_operator', 'cp_ia_verifier', 'cp_ia_client', 'INSTALLATION_AUTHORITY'):
            row = fixture(); row['scope'] = scope
            self.reject(row, 'UNIT_SCOPE_REQUIRED')
        row = fixture(); row['installation_roles'] = ['cp_ia_operator']
        self.reject(row, 'INSTALLATION_ROLE_NOT_EXECUTION_SCOPE')

    def test_pg_remains_separate_even_with_matching_caller_reference(self):
        row = fixture(); ref = reference()
        row['scope'] = ref['scope'] = 'PG'
        self.reject(row, 'PG_CONTRACT_UNCONFIRMED', ref)
        row = fixture(); row['provenance']['provisioning']['scope'] = 'PG'
        self.reject(row, 'PROVENANCE_BINDING_MISMATCH')

    def test_missing_and_conflicting_provenance_rejected(self):
        for section in ('custody', 'provisioning'):
            row = fixture(); del row['provenance'][section]
            self.reject(row, 'MISSING_FIELD')
            for field in fixture()['provenance'][section]:
                row = fixture(); del row['provenance'][section][field]
                self.reject(row, 'MISSING_FIELD')
            row = fixture(); row['provenance'][section]['evidence_sha256'] = 'f' * 64
            self.reject(row, 'REVIEW_REFERENCE_MISMATCH')
        row = fixture(); row['provenance']['provisioning']['public_key_sha256'] = 'f' * 64
        self.reject(row, 'PROVENANCE_BINDING_MISMATCH')

    def test_self_provided_custody_is_not_independent(self):
        for section in ('custody', 'provisioning'):
            row = fixture(); ref = reference()
            row['provenance'][section]['actor'] = row['binding']['source_owner']
            ref['provenance'] = copy.deepcopy(row['provenance'])
            self.reject(row, 'INDEPENDENT_PROVENANCE_REQUIRED', ref)

    def test_provenance_requires_public_noncredential_reference(self):
        for url in ('file:///root/private-key', 'https://secret@example.invalid/evidence',
                    'https://example.invalid/evidence?password=SECRET', None):
            row = fixture(); row['provenance']['custody']['evidence_url'] = url
            self.reject(row, 'INVALID_PUBLIC_EVIDENCE_REFERENCE')

    def test_malformed_percent_escapes_rejected_even_when_review_matches(self):
        for url in ('https://evidence.example.invalid/%',
                    'https://evidence.example.invalid/%2',
                    'https://evidence.example.invalid/%ZZ',
                    'https://evidence.example.invalid/path#part%GG'):
            row, ref = fixture(), reference()
            row['provenance']['custody']['evidence_url'] = url
            ref['provenance']['custody']['evidence_url'] = url
            self.reject(row, 'INVALID_PUBLIC_EVIDENCE_REFERENCE', ref)

    def test_malformed_status_url_has_explicit_endpoint_diagnostic(self):
        for url in ('https://issuer.example.invalid/%ZZ', 'https://../status',
                    'https://issuer..invalid/status', 'https://-issuer.invalid/status'):
            row = fixture()
            row['channel']['status_url'] = url
            self.reject(row, 'INVALID_PUBLIC_ENDPOINT')

    def test_malformed_hostname_rejected_even_when_review_matches(self):
        for host in ('..', '.example.invalid', 'example..invalid', '-example.invalid',
                     'example-.invalid', 'a' * 64 + '.invalid'):
            row, ref = fixture(), reference()
            url = 'https://' + host + '/evidence'
            row['provenance']['custody']['evidence_url'] = url
            ref['provenance']['custody']['evidence_url'] = url
            self.reject(row, 'INVALID_PUBLIC_EVIDENCE_REFERENCE', ref)

    def test_valid_escaped_public_references_remain_candidate_only(self):
        for url in ('https://evidence.example.invalid/path%20name#part%2Fone',
                    'https://evidence.example.invalid./evidence',
                    'https://[2001:db8::1]/evidence',
                    'https://192.0.2.1/evidence'):
            row, ref = fixture(), reference()
            row['provenance']['custody']['evidence_url'] = url
            ref['provenance']['custody']['evidence_url'] = url
            result = self.evaluate(row, ref)
            self.assertEqual(result['candidate_consistency'], 'CONSISTENT')
            self.assertFalse(result['execution_authorized'])
            self.assertFalse(result['operational_trust_verified'])

    def test_actor_separation_and_attempt_id_follow_binding_contract(self):
        for field, value in [('reviewer', 'fixture-owner'), ('issuer', 'fixture-owner'),
                             ('reviewer', 'fixture-executor'), ('attempt_id', 'not-an-id')]:
            row = fixture(); row['binding'][field] = value
            self.reject(row, 'INVALID_BINDING')

    def test_numeric_status_address_only(self):
        for value in ('issuer.example.invalid', '192.0.2.1%eth0', '', 12):
            row = fixture(); row['channel']['status_address'] = value
            self.reject(row, 'INVALID_STATUS_ADDRESS')

    def test_reference_is_required_and_cannot_be_self_asserted_as_trusted(self):
        result = helper.validate(raw(fixture()))
        self.assertEqual(result.get('candidate_consistency'), 'REJECTED')
        self.assertIn('REVIEW_REFERENCE_REQUIRED', {i['code'] for i in result['issues']})
        ref = reference(); ref['independently_trusted'] = True
        self.reject(fixture(), 'UNEXPECTED_FIELD', ref)

    def test_input_content_is_never_echoed_in_output(self):
        marker = 'TOP_SECRET_CANARY_724'
        for key in ('private_key', 'password', 'token', marker):
            row = fixture(); row[key] = marker
            result = self.reject(row, 'UNEXPECTED_FIELD')
            self.assertNotIn(marker, json.dumps(result))
            self.assertNotIn(key, json.dumps(result))
        row = fixture(); row['channel']['issuer'] = marker
        result = self.evaluate(row)
        self.assertNotIn(marker, json.dumps(result))

    def test_malformed_duplicate_deep_oversized_and_nonobject_json_rejected_safely(self):
        for payload in (b'{', b'[]', b'null', b'{"schema":1,"schema":2}',
                        b'"' + b'x' * 32768 + b'"', b'[' * 1200 + b']' * 1200,
                        b'{"x":NaN}', b'\xff'):
            result = helper.validate(payload, raw(reference()))
            self.assertEqual(result.get('candidate_consistency'), 'REJECTED')
            self.assertIn('INVALID_INPUT', {i['code'] for i in result['issues']})

    def test_overflow_number_in_public_channel_is_rejected_without_exception(self):
        payload = raw(fixture()).replace(b'"public_key_sha256":"' + b'1' * 64 + b'"',
                                          b'"public_key_sha256":1e999')
        result = helper.validate(payload, raw(reference()))
        self.assertEqual(result['candidate_consistency'], 'REJECTED')
        self.assertFalse(result['execution_authorized'])

    def test_invalid_section_types_fail_closed_without_exceptions(self):
        for section in ('channel', 'binding', 'status_source', 'provenance'):
            for invalid in (None, [], 1, True, 'SECRET'):
                row = fixture(); row[section] = invalid
                result = self.reject(row, 'INVALID_OBJECT')
                self.assertNotIn('SECRET', json.dumps(result))
        for kind in ('custody', 'provisioning'):
            row = fixture(); row['provenance'][kind] = []
            self.reject(row, 'INVALID_OBJECT')

    def test_action_hash_cannot_be_inserted_into_static_channel(self):
        row = fixture(); row['channel']['action_sha256'] = row['binding']['action_sha256']
        self.reject(row, 'UNEXPECTED_FIELD')

    def test_reference_scope_and_nested_evidence_require_exact_shape(self):
        for field in ('scope', 'channel_sha256', 'binding', 'provenance'):
            ref = reference(); del ref[field]
            self.reject(fixture(), 'MISSING_FIELD', ref)
        ref = reference(); ref['scope'] = 'PG'
        self.reject(fixture(), 'PG_CONTRACT_UNCONFIRMED', ref)

    def test_every_report_preserves_unresolved_owner_handshake_gate(self):
        reports = (self.evaluate(), helper.validate(b'{'),
                   helper.validate(raw(fixture()), b'{'),
                   helper.validate(raw(fixture())), helper.missing_input_handoff())
        for result in reports:
            with self.subTest(disposition=result['disposition']):
                self.assertIn('OWNER_HANDSHAKE_INTEGRATION_REQUIRED', result['remaining_gates'])
                self.assertFalse(result['execution_authorized'])
                self.assertFalse(result['operational_trust_verified'])
                self.assertFalse(result['owner_schema_acknowledged'])

    def test_handshake_inputs_do_not_extend_candidate_or_static_channel_schema(self):
        for section in (None, 'binding', 'channel'):
            for field in ('ready_nonce', 'process_id', 'dependency_state', 'grant_sha256'):
                with self.subTest(section=section, field=field):
                    row = fixture()
                    target = row if section is None else row[section]
                    target[field] = 'SYNTHETIC_UNACCEPTED_INPUT'
                    self.reject(row, 'UNEXPECTED_FIELD')

    def test_machine_and_boot_substitution_cannot_match_existing_review(self):
        for field in ('machine_sha256', 'boot_sha256'):
            row = fixture()
            row['binding'][field] = 'f' * 64
            self.reject(row, 'REVIEW_REFERENCE_MISMATCH')

    def test_relabelled_receipt_never_becomes_an_accepted_candidate(self):
        for schema in ('codestra.source-unit-lease.v2',
                       'codestra.source-unit-status-envelope.v1'):
            row = fixture()
            row['schema'] = schema
            self.reject(row, 'UNSUPPORTED_SCHEMA')

    def test_missing_handoff_names_real_inputs_without_claiming_actual_values(self):
        result = helper.missing_input_handoff()
        self.assertEqual(result.get('disposition'), 'NONEXECUTING')
        self.assertFalse(result['execution_authorized'])
        self.assertIn('public_key_path', result['missing_unit_channel_fields'])
        self.assertIn('issuer_channel_sha256', result['missing_reviewed_binding_fields'])
        self.assertEqual(result['pg_status'], 'SEPARATE_ACCEPTED_CONTRACT_REQUIRED')


if __name__ == '__main__':
    unittest.main()
