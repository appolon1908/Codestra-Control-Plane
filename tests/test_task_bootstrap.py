"""Protected bootstrap client behavior; SQL authority has separate real-PG tests."""
import contextlib
import copy
import importlib
import io
import json
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))

REQUEST = '11111111-1111-4111-8111-111111111111'
PROOF = '22222222-2222-4222-8222-222222222222'
PROFILE = '33333333-3333-4333-8333-333333333333'


class Transport:
    """Transactional transport only; it does not decide bootstrap authority."""
    autocommit = False

    def __init__(self, *, fail_commit=False):
        self.fail_commit = fail_commit
        self.pending = 0
        self.committed = 0
        self.queries = []
        self.arguments = []
        self.closed = False
        self.description = {'request_id': REQUEST, 'request_digest': 'a' * 64,
                            'binding': {}, 'dependencies': []}
        self.stage_description = {'request_id': REQUEST, 'request_digest': 'c' * 64,
                                  'bootstrap_request_id': REQUEST, 'bootstrap_request_digest': 'a' * 64,
                                  'permitted_remote': 'https://github.com/appolon1908/A.git',
                                  'description': {}}
        self.lease_description = {'request_id': REQUEST, 'request_digest': 'a' * 64,
                                  'bootstrap_request_id': PROFILE, 'bootstrap_request_digest': 'a' * 64,
                                  'permitted_remote': 'https://github.com/appolon1908/A.git',
                                  'description': {'binding': {}, 'dependencies': []}}

    def get_transaction_status(self): return 0
    def cursor(self): return self
    def __enter__(self): return self
    def __exit__(self, *args): return False

    def execute(self, query, values):
        self.queries.append(query)
        self.arguments.append(values)
        self.response = {'request_id': REQUEST, 'request_digest': 'a' * 64,
                         'state': 'PENDING', 'usable': False}
        if 'task_bootstrap.lease_description(' in query:
            self.response = copy.deepcopy(self.lease_description)
        elif 'task_bootstrap.lease_attest(' in query:
            self.pending += 1
            self.response.update(request_id=values[0], request_digest='a' * 64, proof_id=PROOF)
        elif 'task_bootstrap.stage_description(' in query:
            self.response = copy.deepcopy(self.stage_description)
        elif 'task_bootstrap.stage_attest(' in query:
            self.pending += 1
            self.response.update(request_id=values[0], request_digest='c' * 64, proof_id=PROOF)
        elif 'task_bootstrap.describe(' in query:
            self.response = copy.deepcopy(self.description)
        elif 'task_bootstrap.inspect(' in query:
            self.response.update(state='ISSUED', usable=True, authority='ONLINE_TASK_BOOTSTRAP_RECEIPT')
        elif 'task_bootstrap.issue(' in query:
            self.pending += 1
            self.response.update(state='ISSUED', authority='ONLINE_TASK_BOOTSTRAP_BINDING',
                                 ready_for_admission=True, source_authorized=False,
                                 publication_authorized=False, certified=False)
        elif 'task_bootstrap.attest(' in query:
            self.pending += 1
            self.response['proof_id'] = PROOF
        elif any('task_bootstrap.' + name + '(' in query for name in ('request', 'revoke', 'acknowledge')):
            self.pending += 1
        else:
            raise AssertionError('Unexpected SQL operation')

    def fetchone(self): return (self.response,)

    def commit(self):
        self.committed += self.pending
        self.pending = 0
        if self.fail_commit: raise ConnectionError('password=opaque private SQL response loss')

    def rollback(self): self.pending = 0
    def close(self): self.closed = True


class TaskBootstrapClientTests(unittest.TestCase):
    def api(self):
        try: return importlib.import_module('codestra_control.task_bootstrap')
        except ImportError: self.fail('Protected task bootstrap client is missing')

    def test_default_issuance_rolls_back_and_discloses_no_receipt(self):
        connection = Transport()
        result = self.api().operate(connection, 'issue', {'operation_id': REQUEST, 'proof_id': PROOF})
        self.assertEqual((connection.pending, connection.committed), (0, 0))
        self.assertEqual(result['authority'], 'NONE_DRY_RUN')
        self.assertFalse(result['committed'])
        self.assertFalse(result['usable'])
        self.assertNotIn('result', result)
        self.assertNotIn(REQUEST, json.dumps(result))

    def test_committed_issuance_returns_bootstrap_receipt_without_admission_claims(self):
        connection = Transport()
        result = self.api().operate(connection, 'issue', {'operation_id': REQUEST, 'proof_id': PROOF}, apply=True)
        self.assertEqual(connection.committed, 1)
        self.assertTrue(result['committed'])
        self.assertEqual(result['result']['request_id'], REQUEST)
        for field in ('usable', 'certified', 'promotion_authorized', 'lease_granted'):
            self.assertIs(result[field], False)

    def test_issue_commit_response_loss_requires_same_operation_inspection_without_retry(self):
        api = self.api(); connection = Transport(fail_commit=True)
        with self.assertRaisesRegex(api.BootstrapOutcomeUnknown, 'USE_INSPECT'):
            api.operate(connection, 'issue', {'operation_id': REQUEST, 'proof_id': PROOF}, apply=True)
        self.assertEqual(connection.committed, 1)
        self.assertEqual(sum('task_bootstrap.issue(' in q for q in connection.queries), 1)

    def test_inspection_cannot_upgrade_old_bootstrap_receipt_into_current_admission(self):
        connection = Transport()
        result = self.api().operate(connection, 'inspect', {'operation_id': REQUEST}, apply=True)
        self.assertEqual(connection.committed, 0)
        self.assertFalse(result['usable'])
        self.assertFalse(result['result']['usable'])
        self.assertEqual(result['result']['authority'], 'NONE')

    def test_invalid_operation_uuid_and_caller_observations_never_reach_sql(self):
        api = self.api()
        for operation, values in [('grant', {}), ('inspect', {'operation_id': '../bad'}),
                                  ('verify', {'operation_id': REQUEST, 'observations': {}}),
                                  ('acknowledge', {'operation_id': REQUEST, 'ack': True})]:
            connection = Transport()
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                api.operate(connection, operation, values, apply=True)
            self.assertEqual(connection.queries, [])

    def test_existing_transaction_or_autocommit_denies_before_sql(self):
        api = self.api()
        for autocommit, status in ((True, 0), (False, 2)):
            connection = Transport(); connection.autocommit = autocommit
            connection.get_transaction_status = lambda: status
            with self.subTest(autocommit=autocommit), self.assertRaises(ValueError):
                api.operate(connection, 'inspect', {'operation_id': REQUEST})
            self.assertEqual(connection.queries, [])

    def test_verification_requires_independent_observer_and_never_accepts_raw_proof(self):
        connection = Transport()
        with self.assertRaises(ValueError):
            self.api().operate(connection, 'verify', {'operation_id': REQUEST}, apply=True)
        self.assertEqual(connection.queries, [])

    def test_actual_checkout_observation_is_wrapped_with_server_request_digest(self):
        import test_lease_materialization as fixture
        harness = fixture.MaterializationTests(); harness.setUp()
        self.addCleanup(harness.doCleanups)
        connection = Transport(); connection.description['binding'] = harness.binding
        api = self.api()
        connection.description['permitted_remote'] = 'https://github.com/appolon1908/A.git'
        actual = api.BootstrapMaterializer(harness.observer, host=lambda: 'fixture-host', filesystem_anchor=harness.root)
        with mock.patch.object(api, 'BootstrapMaterializer', return_value=actual):
            result = api.operate(connection, 'verify', {'operation_id': REQUEST}, observer=harness.observer)
        self.assertFalse(result['committed']); self.assertEqual(connection.committed, 0)
        observation = connection.arguments[-1][1].adapted
        self.assertEqual(observation['request_digest'], 'a' * 64)
        self.assertEqual(observation['materialization']['head_sha'], harness.binding['head_sha'])
        self.assertEqual(observation['materialization']['directory_inode'], harness.repo.stat().st_ino)
        self.assertNotIn(PROOF, json.dumps(result))

    def test_failed_actual_observation_never_attests(self):
        api = self.api(); connection = Transport()
        with mock.patch.object(api, 'BootstrapMaterializer') as materializer:
            materializer.return_value.inspect.side_effect = RuntimeError('opaque private filesystem')
            with self.assertRaises(Exception):
                api.operate(connection, 'verify', {'operation_id': REQUEST}, observer=object(), apply=True)
        self.assertFalse(any('task_bootstrap.attest(' in q for q in connection.queries))
        self.assertEqual(connection.committed, 0)

    def test_operator_profile_is_fixed_and_manifest_cannot_select_another_profile(self):
        api = self.api(); connection = Transport(); output = io.StringIO(); selected = []
        config = 'database_dsn_file="/etc/codestra/control-plane/operator-private.dsn"\nprofile_id="'+PROFILE+'"\n'
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / 'request.json'
            manifest.write_text(json.dumps({'schema': 'codestra.task-bootstrap-request.v1'}))
            with mock.patch.object(api, 'verify_code_custody'), \
                 mock.patch.object(api, 'protected_read', side_effect=lambda path: selected.append(path) or config.encode()), \
                 mock.patch.object(api, 'connect_protected', return_value=connection), contextlib.redirect_stdout(output):
                code = api.main(['request', '--manifest', str(manifest), '--request-id', 'bootstrap-1', '--apply'])
            self.assertEqual(code, 0)
            self.assertEqual(selected, [Path('/etc/codestra/control-plane/task-bootstrap-operator.toml')])
            self.assertEqual(connection.arguments[0][0].adapted['profile_id'], PROFILE)
            manifest.write_text(json.dumps({'profile_id': PROOF}))
            connection = Transport()
            with mock.patch.object(api, 'verify_code_custody'), mock.patch.object(api, 'protected_read', return_value=config.encode()), \
                 mock.patch.object(api, 'connect_protected', return_value=connection), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(api.main(['request', '--manifest', str(manifest), '--request-id', 'bootstrap-1']), 1)
            self.assertEqual(connection.queries, [])

    def test_receiving_ack_uses_fixed_builder_custody_with_no_ack_body(self):
        api = self.api(); connection = Transport(); selected = []
        with mock.patch.object(api, 'verify_code_custody'), \
             mock.patch.object(api, 'connect_protected', side_effect=lambda path: selected.append(path) or connection), \
             mock.patch.object(api, 'protected_read', side_effect=AssertionError('Builder accessed operator profile')), \
             contextlib.redirect_stdout(io.StringIO()):
            code = api.main(['acknowledge', '--operation-id', REQUEST, '--apply'])
        self.assertEqual(code, 0)
        self.assertEqual(selected, [Path('/etc/codestra/control-plane/lease-builder.dsn')])
        self.assertEqual(connection.arguments, [(REQUEST,)])

    def test_cli_has_no_caller_dsn_profile_or_observation_route(self):
        api = self.api()
        for flag in ('--dsn', '--profile', '--observations'):
            connection = Transport()
            with self.subTest(flag=flag), mock.patch.object(api, 'connect_protected', return_value=connection), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(api.main(['inspect', '--operation-id', REQUEST, flag, 'opaque-private']), 1)
            self.assertEqual(connection.queries, [])

    def test_opaque_errors_and_close_failure_never_print_private_diagnostics_or_success(self):
        api = self.api(); output = io.StringIO(); connection = Transport()
        connection.close = mock.Mock(side_effect=RuntimeError('private credential close diagnostic'))
        with mock.patch.object(api, 'verify_code_custody'), mock.patch.object(api, 'connect_protected', return_value=connection), \
             contextlib.redirect_stdout(output):
            code = api.main(['acknowledge', '--operation-id', REQUEST, '--apply'])
        self.assertEqual(code, 1)
        self.assertNotIn('committed', output.getvalue()); self.assertNotIn('private', output.getvalue())
        output = io.StringIO()
        with mock.patch.object(api, 'verify_code_custody', side_effect=RuntimeError('password=private')), \
             contextlib.redirect_stdout(output):
            self.assertEqual(api.main(['inspect', '--operation-id', REQUEST]), 1)
        self.assertEqual(output.getvalue().strip(), 'TASK_BOOTSTRAP_CODE_CUSTODY_UNAVAILABLE')

    def test_duplicate_or_symlink_manifest_denies(self):
        api = self.api()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'request.json'; path.write_text('{"schema":1,"schema":2}')
            with self.assertRaises(ValueError): api.read_manifest(path)
            path.write_text('{}'); link = Path(directory) / 'link'; link.symlink_to(path)
            with self.assertRaises((ValueError, OSError)): api.read_manifest(link)

    def test_sql_denials_remain_distinct_and_unknown_exception_messages_are_private(self):
        api = self.api()
        for reason in ('BOOTSTRAP_PROFILE_DENIED', 'BOOTSTRAP_SESSION_DENIED', 'BOOTSTRAP_ROUTE_DENIED',
                       'BOOTSTRAP_CUSTODY_MISMATCH', 'BOOTSTRAP_ACK_REQUIRED',
                       'BOOTSTRAP_AUTHENTICATION_REQUIRED', 'BOOTSTRAP_VERIFIER_REQUIRED', 'BOOTSTRAP_AUTHORITY_CHANGED',
                       'BOOTSTRAP_EXECUTOR_UNSUPPORTED', 'BOOTSTRAP_EXECUTOR_MALFORMED'):
            error = RuntimeError('private SQL statement and secret')
            error.pgcode = 'P0001'; error.diag = mock.Mock(message_primary=reason)
            connection = Transport(); connection.execute = mock.Mock(side_effect=error)
            with self.subTest(reason=reason), self.assertRaises(api.BootstrapDenied) as caught:
                api.operate(connection, 'inspect', {'operation_id': REQUEST}, apply=True)
            self.assertEqual(str(caught.exception), reason)
        for error in (RuntimeError('password=private'), api.BootstrapDenied('private-opaque-dependency-message')):
            connection = Transport(); connection.execute = mock.Mock(side_effect=error)
            with self.subTest(error=type(error)), self.assertRaises(api.BootstrapDenied) as caught:
                api.operate(connection, 'inspect', {'operation_id': REQUEST}, apply=True)
            self.assertEqual(str(caught.exception), 'TASK_BOOTSTRAP_UNAVAILABLE')

    def test_forged_issuance_markers_are_rolled_back_before_receipt_disclosure(self):
        api = self.api()
        for field, changed in (('request_id', PROOF), ('state', 'PENDING'), ('authority', 'PASS'),
                               ('ready_for_admission', False), ('usable', True),
                               ('source_authorized', True), ('publication_authorized', True), ('certified', True)):
            connection = Transport(); original = connection.execute
            def execute(query, values):
                original(query, values); connection.response[field] = changed
            connection.execute = execute
            with self.subTest(field=field), self.assertRaises(ValueError):
                api.operate(connection, 'issue', {'operation_id': REQUEST, 'proof_id': PROOF}, apply=True)
            self.assertEqual((connection.pending, connection.committed), (0, 0))

    def test_issue_and_inspect_name_each_missing_admission_authority_separately(self):
        for operation, values in (('issue', {'operation_id': REQUEST, 'proof_id': PROOF}),
                                  ('inspect', {'operation_id': REQUEST})):
            result = self.api().operate(Transport(), operation, values, apply=True)
            self.assertEqual(result['result']['missing_authority'],
                             ['ACTIVE_ASSIGNMENT_LEASE_REQUIRED', 'L1_OPERATION_RECEIPT_REQUIRED', 'L2_OPERATION_RECEIPT_REQUIRED'])

    def test_nonissuance_commit_loss_discloses_no_unconfirmed_receipt(self):
        api = self.api(); connection = Transport(fail_commit=True)
        with self.assertRaises(api.BootstrapDenied) as caught:
            api.operate(connection, 'acknowledge', {'operation_id': REQUEST}, apply=True)
        self.assertEqual(str(caught.exception), 'TASK_BOOTSTRAP_COMMIT_UNCONFIRMED_USE_SAME_REQUEST')
        self.assertEqual(connection.committed, 1)

    def test_verifier_uses_only_fixed_protected_config_and_read_observer(self):
        api = self.api(); connection = Transport(); selected = []
        config = ('database_dsn_file="/etc/codestra/control-plane/verifier-private.dsn"\n'
                  'app_id=71\ninstallation_id=81\napp_key_file="/etc/codestra/control-plane/verifier.pem"\n')
        output = io.StringIO()
        with mock.patch.object(api, 'verify_code_custody'), \
             mock.patch.object(api, 'protected_read', side_effect=lambda path: selected.append(path) or config.encode()), \
             mock.patch.object(api, 'connect_protected', return_value=connection), \
             mock.patch.object(api, 'GitHubAppClient') as app, contextlib.redirect_stdout(output):
            self.assertEqual(api.main(['describe', '--operation-id', REQUEST, '--apply']), 0)
        self.assertEqual(selected, [Path('/etc/codestra/control-plane/task-bootstrap-verifier.toml')])
        self.assertEqual(connection.queries, ['SELECT task_bootstrap.describe(%s)'])
        self.assertEqual(app.return_value.mock_calls, [])
        self.assertFalse(json.loads(output.getvalue())['usable'])

    def test_entrypoint_refuses_root_before_project_import(self):
        import builtins
        original = builtins.__import__
        def guarded_import(name, *args, **kwargs):
            if name.startswith('codestra_control'):
                raise AssertionError('Root imported mutable project code')
            return original(name, *args, **kwargs)
        output = io.StringIO()
        with mock.patch('os.geteuid', return_value=0), mock.patch('builtins.__import__', side_effect=guarded_import), \
             contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
            runpy.run_path(str(Path(__file__).resolve().parents[1] / 'bin/codestra-task-bootstrap'), run_name='__main__')
        self.assertEqual(stopped.exception.code, 1)
        self.assertEqual(output.getvalue().strip(), 'TASK_BOOTSTRAP_UNPRIVILEGED_CLIENT_REQUIRED')

    def test_actual_materializer_denies_other_canonical_transport_and_seals_exact_remote(self):
        import test_lease_materialization as fixture
        harness = fixture.MaterializationTests(); harness.setUp(); self.addCleanup(harness.doCleanups)
        api = self.api()
        self.assertTrue(hasattr(api, 'BootstrapMaterializer'), 'Exact remote bootstrap materializer is missing')
        materializer = api.BootstrapMaterializer(harness.observer, host=lambda: 'fixture-host', filesystem_anchor=harness.root)
        description = {'binding': harness.binding, 'dependencies': [],
                       'permitted_remote': 'https://github.com/appolon1908/A.git'}
        result = materializer.inspect(description)
        self.assertEqual(result['permitted_remote'], 'https://github.com/appolon1908/A.git')
        harness.git('remote', 'set-url', 'origin', 'git@github.com:appolon1908/A.git')
        with self.assertRaises(Exception): materializer.inspect(description)

    def test_exact_remote_is_checked_again_after_independent_remote_observation(self):
        import test_lease_materialization as fixture
        harness = fixture.MaterializationTests(); harness.setUp(); self.addCleanup(harness.doCleanups)
        api = self.api()
        self.assertTrue(hasattr(api, 'BootstrapMaterializer'), 'Exact remote bootstrap materializer is missing')
        materializer = api.BootstrapMaterializer(harness.observer, host=lambda: 'fixture-host', filesystem_anchor=harness.root)
        original = harness.observer.ref
        def moving(name, ref):
            result = original(name, ref)
            if ref == harness.binding['target_ref']:
                harness.git('remote', 'set-url', 'origin', 'git@github.com:appolon1908/A.git')
            return result
        harness.observer.ref = moving
        with self.assertRaises(Exception):
            materializer.inspect({'binding': harness.binding, 'dependencies': [],
                                  'permitted_remote': 'https://github.com/appolon1908/A.git'})

    def test_stage_verifier_seals_real_l1_and_l2_snapshots_to_exact_remote(self):
        import test_admission_materialization as fixture
        harness = fixture.AdmissionMaterializationTests(); harness.setUp(); self.addCleanup(harness.doCleanups)
        api = self.api()
        self.assertTrue(hasattr(api, 'BootstrapStageMaterializer'), 'Exact remote stage materializer is missing')
        envelope = {'request_id': harness.description['intent_id'], 'request_digest': 'c' * 64,
                    'bootstrap_request_id': REQUEST, 'bootstrap_request_digest': 'a' * 64,
                    'permitted_remote': 'https://github.com/appolon1908/A.git', 'description': harness.description}
        actual = api.BootstrapStageMaterializer(harness.observer, host=lambda: 'fixture-host', filesystem_anchor=harness.root)
        connection = Transport(); connection.stage_description = envelope
        with mock.patch.object(api, 'BootstrapStageMaterializer', return_value=actual):
            dry = api.operate(connection, 'verify-stage', {'operation_id': envelope['request_id']}, observer=harness.observer)
        self.assertFalse(dry['committed']); self.assertNotIn('result', dry)
        observed = connection.arguments[-1][1].adapted
        self.assertEqual(observed['request_digest'], 'c' * 64)
        self.assertEqual(observed['materialization']['operation'], 'L1')
        self.assertEqual(observed['materialization']['permitted_remote'], 'https://github.com/appolon1908/A.git')
        self.assertEqual(connection.committed, 0)
        harness.commit(); harness.l2()
        observed = actual.inspect(envelope)
        self.assertEqual(observed['head_sha'], harness.description['payload']['candidate_sha'])
        self.assertEqual(observed['operation'], 'L2')

    def test_stage_verifier_denies_other_canonical_remote_and_mid_observation_route_change(self):
        import test_admission_materialization as fixture
        harness = fixture.AdmissionMaterializationTests(); harness.setUp(); self.addCleanup(harness.doCleanups)
        api = self.api()
        self.assertTrue(hasattr(api, 'BootstrapStageMaterializer'), 'Exact remote stage materializer is missing')
        envelope = {'request_id': harness.description['intent_id'], 'request_digest': 'c' * 64,
                    'bootstrap_request_id': REQUEST, 'bootstrap_request_digest': 'a' * 64,
                    'permitted_remote': 'https://github.com/appolon1908/A.git', 'description': harness.description}
        actual = api.BootstrapStageMaterializer(harness.observer, host=lambda: 'fixture-host', filesystem_anchor=harness.root)
        harness.git('remote', 'set-url', 'origin', 'git@github.com:appolon1908/A.git')
        with self.assertRaises(Exception): actual.inspect(envelope)
        harness.git('remote', 'set-url', 'origin', 'https://github.com/appolon1908/A.git')
        original = harness.observer.ref
        def moving(name, ref):
            result = original(name, ref)
            if ref == harness.binding['target_ref']:
                harness.git('remote', 'set-url', 'origin', 'git@github.com:appolon1908/A.git')
            return result
        harness.observer.ref = moving
        with self.assertRaises(Exception): actual.inspect(envelope)

    def test_stage_envelope_cannot_substitute_intent_digest_or_bootstrap_identity(self):
        import test_admission_materialization as fixture
        harness = fixture.AdmissionMaterializationTests(); harness.setUp(); self.addCleanup(harness.doCleanups)
        api = self.api()
        self.assertTrue(hasattr(api, 'BootstrapStageMaterializer'), 'Exact remote stage materializer is missing')
        envelope = {'request_id': harness.description['intent_id'], 'request_digest': 'c' * 64,
                    'bootstrap_request_id': REQUEST, 'bootstrap_request_digest': 'a' * 64,
                    'permitted_remote': 'https://github.com/appolon1908/A.git', 'description': harness.description}
        actual = api.BootstrapStageMaterializer(harness.observer, host=lambda: 'fixture-host', filesystem_anchor=harness.root)
        for field, value in (('request_id', PROOF), ('request_digest', 'd' * 64),
                             ('bootstrap_request_id', '../bad'), ('bootstrap_request_digest', 'PASS')):
            changed = dict(envelope, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError): actual.inspect(changed)

    def test_stage_commit_loss_requires_original_intent_inspection_without_proof_disclosure(self):
        api = self.api(); connection = Transport(fail_commit=True)
        self.assertTrue(hasattr(api, 'BootstrapStageMaterializer'), 'Exact remote stage materializer is missing')
        with mock.patch.object(api, 'BootstrapStageMaterializer') as materializer:
            materializer.return_value.inspect.return_value = {'permitted_remote': 'https://github.com/appolon1908/A.git'}
            with self.assertRaises(api.BootstrapDenied) as caught:
                api.operate(connection, 'verify-stage', {'operation_id': REQUEST}, observer=object(), apply=True)
        self.assertEqual(str(caught.exception), 'TASK_BOOTSTRAP_STAGE_COMMIT_UNCONFIRMED_INSPECT_INTENT')
        self.assertEqual(connection.committed, 1)
        self.assertEqual(sum('task_bootstrap.stage_attest(' in q for q in connection.queries), 1)

    def test_stage_cli_uses_fixed_verifier_custody_and_rejects_raw_observations(self):
        api = self.api(); connection = Transport(); selected = []
        config = ('database_dsn_file="/etc/codestra/control-plane/verifier-private.dsn"\n'
                  'app_id=71\ninstallation_id=81\napp_key_file="/etc/codestra/control-plane/verifier.pem"\n')
        output = io.StringIO()
        self.assertTrue(hasattr(api, 'BootstrapStageMaterializer'), 'Exact remote stage materializer is missing')
        with mock.patch.object(api, 'verify_code_custody'), \
             mock.patch.object(api, 'protected_read', side_effect=lambda path: selected.append(path) or config.encode()), \
             mock.patch.object(api, 'connect_protected', return_value=connection), \
             mock.patch.object(api, 'BootstrapStageMaterializer') as materializer, contextlib.redirect_stdout(output):
            materializer.return_value.inspect.return_value = {'permitted_remote': 'https://github.com/appolon1908/A.git'}
            self.assertEqual(api.main(['verify-stage', '--operation-id', REQUEST, '--apply']), 0)
        self.assertEqual(selected, [Path('/etc/codestra/control-plane/task-bootstrap-verifier.toml')])
        self.assertFalse(json.loads(output.getvalue())['source_authorized'])
        self.assertFalse(json.loads(output.getvalue())['publication_authorized'])
        for values in ({'operation_id': REQUEST, 'observations': {}}, {'operation_id': REQUEST, 'dsn': 'private'}):
            blocked = Transport()
            with self.assertRaises(ValueError): api.operate(blocked, 'verify-stage', values, observer=object(), apply=True)
            self.assertEqual(blocked.queries, [])

    def test_lease_verifier_uses_bound_description_and_seals_actual_exact_remote(self):
        import test_lease_materialization as fixture
        harness = fixture.MaterializationTests(); harness.setUp(); self.addCleanup(harness.doCleanups)
        api = self.api(); connection = Transport()
        connection.lease_description['description']['binding'] = dict(harness.binding, binding_id=REQUEST)
        actual = api.BootstrapMaterializer(harness.observer, host=lambda: 'fixture-host', filesystem_anchor=harness.root)
        with mock.patch.object(api, 'BootstrapMaterializer', return_value=actual):
            result = api.operate(connection, 'verify-lease', {'operation_id': REQUEST}, observer=harness.observer, apply=True)
        self.assertEqual(connection.committed, 1)
        self.assertFalse(result['lease_granted'])
        self.assertEqual(result['result']['proof_id'], PROOF)
        observed = connection.arguments[-1][1].adapted
        self.assertEqual(observed['request_digest'], 'a' * 64)
        self.assertEqual(observed['materialization']['permitted_remote'], 'https://github.com/appolon1908/A.git')
        self.assertEqual(observed['materialization']['head_sha'], harness.binding['head_sha'])

    def test_lease_envelope_substitution_or_raw_observations_cannot_attest(self):
        api = self.api()
        for changes in ({'request_digest': 'd' * 64}, {'bootstrap_request_id': '../bad'},
                        {'description': {'binding': {'binding_id': PROOF}, 'dependencies': []}}):
            connection = Transport(); connection.lease_description.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                api.operate(connection, 'verify-lease', {'operation_id': REQUEST}, observer=object(), apply=True)
            self.assertFalse(any('task_bootstrap.lease_attest(' in q for q in connection.queries))
        connection = Transport()
        with self.assertRaises(ValueError):
            api.operate(connection, 'verify-lease', {'operation_id': REQUEST, 'observations': {}}, observer=object(), apply=True)
        self.assertEqual(connection.queries, [])


if __name__ == '__main__': unittest.main()
