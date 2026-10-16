"""Client transaction/custody tests; SQL authority is tested on real PostgreSQL."""
import contextlib
import importlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))


INTENT = '11111111-1111-4111-8111-111111111111'
PROOF = '22222222-2222-4222-8222-222222222222'
GRANT = '33333333-3333-4333-8333-333333333333'
LEASE = '44444444-4444-4444-8444-444444444444'


class Transport:
    """A transaction transport double, not an authorization decision fixture."""
    autocommit = False

    def __init__(self, fail_commit=False):
        self.pending = 0
        self.committed = 0
        self.fail_commit = fail_commit
        self.closed = False
        self.queries = []

    def get_transaction_status(self):
        return 0

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query, values):
        self.queries.append(query)
        if 'scoped_admission.consume(' in query:
            self.pending += 1
            self.response = {'intent_id': INTENT, 'operation': 'L2', 'state': 'CONSUMED',
                             'authority': 'ONLINE_SCOPED_OPERATION_RECEIPT', 'usable': True}
        elif 'scoped_admission.inspect(' in query:
            self.response = {'intent_id': INTENT, 'operation': 'L2', 'state': 'CONSUMED',
                             'authority': 'NONE', 'usable': False, 'current': True}
        elif 'scoped_admission.request(' in query:
            self.pending += 1
            self.response = {'intent_id': INTENT, 'operation': 'L1', 'state': 'PENDING',
                             'authority': 'NONE', 'usable': False}
        elif 'scoped_admission.describe(' in query:
            self.response = {'intent_id': INTENT, 'operation': 'L2'}
        elif 'scoped_admission.attest(' in query:
            self.pending += 1
            self.response = {'proof_id': PROOF, 'intent_id': INTENT}
        else:
            raise AssertionError('Unexpected transport operation: '+query)

    def fetchone(self):
        return (self.response,)

    def commit(self):
        self.committed += self.pending
        self.pending = 0
        if self.fail_commit:
            raise ConnectionError('synthetic response loss after commit')

    def rollback(self):
        self.pending = 0

    def close(self):
        self.closed = True


class ScopedAdmissionClientTests(unittest.TestCase):
    def api(self):
        try:
            return importlib.import_module('codestra_control.scoped_admission')
        except ImportError:
            self.fail('Protected scoped L1/L2 admission client is missing')

    def test_default_dry_run_never_exposes_consumed_permission_or_receipt(self):
        connection = Transport()
        result = self.api().operate(connection, 'consume', {'intent': INTENT, 'proof': PROOF})
        self.assertEqual(connection.committed, 0)
        self.assertEqual(connection.pending, 0)
        self.assertFalse(result['usable'])
        self.assertFalse(result['committed'])
        self.assertEqual(result['authority'], 'NONE_DRY_RUN')
        self.assertNotIn('result', result)

    def test_applied_consumption_commits_once_before_exposing_server_decision(self):
        connection = Transport()
        result = self.api().operate(connection, 'consume', {'intent': INTENT, 'proof': PROOF}, apply=True)
        self.assertEqual(connection.committed, 1)
        self.assertEqual(connection.pending, 0)
        self.assertTrue(result['usable'])
        self.assertTrue(result['committed'])
        self.assertEqual(result['result']['intent_id'], INTENT)
        self.assertFalse(result['certified'])
        self.assertFalse(result['promotion_authorized'])

    def test_lost_consumption_commit_response_never_retries_the_effect(self):
        api = self.api()
        connection = Transport(fail_commit=True)
        with self.assertRaisesRegex(api.AdmissionOutcomeUnknown, 'OUTCOME_UNKNOWN'):
            api.operate(connection, 'consume', {'intent': INTENT, 'proof': PROOF}, apply=True)
        self.assertEqual(connection.committed, 1)
        self.assertEqual(connection.pending, 0)

    def test_inspection_does_not_reissue_a_previously_consumed_permission(self):
        connection = Transport()
        result = self.api().operate(connection, 'inspect', {'intent': INTENT}, apply=True)
        self.assertFalse(result['usable'])
        self.assertFalse(result['result']['usable'])
        self.assertEqual(connection.committed, 0)

    def test_autocommit_or_existing_transaction_is_rejected_before_mutation(self):
        api = self.api()
        for autocommit, status in [(True, 0), (False, 2)]:
            connection = Transport()
            connection.autocommit = autocommit
            connection.get_transaction_status = lambda: status
            with self.subTest(autocommit=autocommit, status=status), self.assertRaises(ValueError):
                api.operate(connection, 'consume', {'intent': INTENT, 'proof': PROOF}, apply=True)
            self.assertEqual(connection.committed, 0)

    def test_invalid_operation_or_identifier_never_reaches_the_database(self):
        api = self.api()
        for operation, values in [('grant', {}), ('consume', {'intent': '../escape', 'proof': PROOF})]:
            connection = Transport()
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                api.operate(connection, operation, values, apply=True)
            self.assertEqual(connection.committed, 0)

    def test_builder_cli_uses_only_fixed_builder_custody_and_no_environment_dsn(self):
        api = self.api()
        connection = Transport()
        selected = []

        def connect(path):
            selected.append(path)
            return connection

        output = io.StringIO()
        with mock.patch.object(api, 'verify_code_custody'), mock.patch.object(api, 'connect_protected', side_effect=connect), \
             mock.patch.object(api, 'protected_read', side_effect=AssertionError('Builder accessed verifier credentials')), \
             mock.patch.dict('os.environ', {'CODESTRA_CONTROL_DSN': 'secret://not-accepted'}), contextlib.redirect_stdout(output):
            code = api.main(['consume', '--intent', INTENT, '--proof', PROOF, '--apply'])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output.getvalue())['usable'])
        self.assertEqual(selected, [Path('/etc/codestra/control-plane/lease-builder.dsn')])
        self.assertNotIn('secret://', output.getvalue())
        self.assertTrue(connection.closed)

    def test_cli_reports_unknown_outcome_without_claiming_failure_or_retrying(self):
        api = self.api()
        connection = Transport(fail_commit=True)
        output = io.StringIO()
        with mock.patch.object(api, 'verify_code_custody'), mock.patch.object(api, 'connect_protected', return_value=connection), contextlib.redirect_stdout(output):
            code = api.main(['consume', '--intent', INTENT, '--proof', PROOF, '--apply'])
        self.assertEqual(code, 1)
        self.assertIn('OUTCOME_UNKNOWN_USE_INSPECT', output.getvalue())
        self.assertEqual(connection.committed, 1)

    def test_verifier_uses_trusted_observer_and_rolls_back_proof_by_default(self):
        api = self.api()
        connection = Transport()
        observer = object()
        with mock.patch('codestra_control.admission_materialization.StageMaterializer') as materializer:
            materializer.return_value.inspect.return_value = {'intent_id': INTENT}
            result = api.operate(connection, 'verify', {'intent': INTENT}, observer=observer)
        materializer.assert_called_once_with(observer)
        materializer.return_value.inspect.assert_called_once_with({'intent_id': INTENT, 'operation': 'L2'})
        self.assertEqual(connection.committed, 0)
        self.assertEqual(connection.pending, 0)
        self.assertFalse(result['usable'])
        self.assertNotIn('result', result)
        self.assertNotIn(PROOF, json.dumps(result))

    def test_verifier_cannot_accept_caller_supplied_raw_observation_fields(self):
        connection = Transport()
        with self.assertRaises(ValueError):
            self.api().operate(connection, 'verify', {'intent': INTENT, 'observations': {}}, apply=True)
        self.assertEqual(connection.queries, [])

    def test_custody_failure_prevents_any_database_connection(self):
        api = self.api()
        output = io.StringIO()
        with mock.patch.object(api, 'verify_code_custody', side_effect=ValueError('synthetic custody failure')), \
             mock.patch.object(api, 'connect_protected') as connect, contextlib.redirect_stdout(output):
            code = api.main(['inspect', '--intent', INTENT, '--apply'])
        self.assertEqual(code, 1)
        connect.assert_not_called()
        self.assertEqual(output.getvalue().strip(), 'SCOPED_ADMISSION_UNAVAILABLE')

    def test_manifest_duplicate_keys_and_symlink_inputs_are_rejected(self):
        api = self.api()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'manifest.json'
            path.write_text('{"paths":[],"paths":["secret"]}')
            with self.assertRaises(ValueError):
                api.read_manifest(path)
            path.write_text('{"paths":["app.py"],"mutation_sha256":"'+('a'*64)+'"}')
            link = Path(directory)/'link.json'
            link.symlink_to(path)
            with self.assertRaises((ValueError, OSError)):
                api.read_manifest(link)
