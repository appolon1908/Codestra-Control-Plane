"""Synthetic client tests; never access installed credentials or a live server."""
import contextlib
import io
import json
import unittest
from unittest import mock

from codestra_control import recovery_interface as cli

GRANT = '11111111-1111-4111-8111-111111111111'
PROOF = '22222222-2222-4222-8222-222222222222'
DIGEST = 'a' * 64


class RecoveryInterfaceTests(unittest.TestCase):
    def run_cli(self, args, result=None, commit_error=None):
        connection = mock.MagicMock()
        connection.cursor.return_value.__enter__.return_value.fetchone.return_value = (
            result or {'released': True, 'certified': False, 'lease_granted': False},)
        if commit_error:
            connection.commit.side_effect = commit_error
        with mock.patch.object(cli, 'verify_code_custody'), \
             mock.patch.object(cli, 'connect_protected', return_value=connection) as connect, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main(args)
        return code, connection, connect, output.getvalue()

    def recovery_args(self):
        return ['execute', '--grant', GRANT, '--proof', PROOF,
                '--digest', DIGEST, '--request-id', 'synthetic']

    def test_recovery_dry_run_cannot_emit_a_released_or_usable_receipt(self):
        code, connection, connect, output = self.run_cli(self.recovery_args())
        self.assertEqual(code, 0)
        connection.rollback.assert_called_once()
        connection.commit.assert_not_called()
        connection.close.assert_called_once()
        connect.assert_called_once_with(cli.DIRECTORY / 'recovery-executor.dsn')
        result = json.loads(output)
        self.assertFalse(result['committed'])
        self.assertFalse(result['result']['released'])
        self.assertFalse(result['result']['usable'])
        self.assertEqual(result['result']['authority'], 'NONE_DRY_RUN')
        self.assertEqual(connection.cursor.return_value.__enter__.return_value.execute.call_args.args,
                         ('SELECT frozen_recovery.execute(%s,%s,%s,%s)',
                          (GRANT, PROOF, DIGEST, 'synthetic')))

    def test_explicit_apply_commits_and_still_cannot_grant_lease_or_certification(self):
        code, connection, _, output = self.run_cli(self.recovery_args() + ['--apply'])
        self.assertEqual(code, 0)
        connection.commit.assert_called_once()
        connection.rollback.assert_not_called()
        result = json.loads(output)
        self.assertTrue(result['committed'])
        self.assertFalse(result['certified'])
        self.assertFalse(result['result']['lease_granted'])

    def test_commit_failure_never_prints_success_or_secret_error(self):
        code, connection, _, output = self.run_cli(
            self.recovery_args() + ['--apply'], commit_error=RuntimeError('fixture-secret'))
        self.assertEqual(code, 1)
        connection.rollback.assert_called_once()
        connection.close.assert_called_once()
        self.assertEqual(output.strip(), 'RECOVERY_OPERATION_UNAVAILABLE')

    def test_connection_close_failure_cannot_leak_private_error_details(self):
        connection = mock.MagicMock()
        connection.cursor.side_effect = RuntimeError('fixture-query-secret')
        connection.close.side_effect = RuntimeError('fixture-close-secret')
        with mock.patch.object(cli, 'verify_code_custody'), \
             mock.patch.object(cli, 'connect_protected', return_value=connection), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(self.recovery_args()), 1)
        self.assertEqual(output.getvalue().strip(), 'RECOVERY_OPERATION_UNAVAILABLE')

    def test_recovery_launcher_receives_its_own_protected_custody_check(self):
        with mock.patch.object(cli, 'publisher_code_custody') as common, \
             mock.patch.object(cli, 'protected_read') as read:
            cli.verify_code_custody()
        common.assert_called_once()
        read.assert_called_once_with(
            cli.Path(cli.__file__).resolve().parents[2] / 'bin' / 'codestra-frozen-recovery',
            allow_public=True)

    def test_reviewer_and_operator_use_separate_fixed_credentials(self):
        for args, role in (
            (['review', '--grant', GRANT, '--digest', DIGEST], 'reviewer'),
            (['revoke', '--grant', GRANT, '--digest', DIGEST,
              '--reason', 'synthetic cancellation', '--request-id', 'cancel'], 'operator'),
        ):
            with self.subTest(role=role):
                code, _, connect, _ = self.run_cli(args)
                self.assertEqual(code, 0)
                connect.assert_called_once_with(cli.DIRECTORY / ('recovery-' + role + '.dsn'))

    def test_invalid_uuid_or_digest_does_not_open_a_connection(self):
        for name, invalid in (('--grant', 'actor-string'), ('--proof', 'actor-string'),
                              ('--digest', '0' * 64), ('--digest', 'A' * 64)):
            args = self.recovery_args()
            args[args.index(name) + 1] = invalid
            code, _, connect, output = self.run_cli(args)
            self.assertEqual(code, 1)
            connect.assert_not_called()
            self.assertEqual(output.strip(), 'RECOVERY_OPERATION_UNAVAILABLE')

    def test_untrusted_code_custody_denies_before_credentials_or_connection(self):
        with mock.patch.object(cli, 'verify_code_custody', side_effect=ValueError()), \
             mock.patch.object(cli, 'connect_protected') as connect, \
             mock.patch.object(cli, 'protected_read') as read, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(self.recovery_args()), 1)
        connect.assert_not_called()
        read.assert_not_called()

    def test_verifier_releases_read_locks_then_inspects_server_checkout(self):
        connection = mock.MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        description = {'schema': 'codestra.frozen-recovery.v2',
                       'action': 'RELEASE_STALE_WORKTREE_TO_FREE',
                       'grant_id': GRANT, 'request_digest': DIGEST,
                       'binding': {'server': 'trusted'}, 'dependencies': []}
        cursor.fetchone.side_effect = [(description,), ({'proof_id': PROOF},)]
        observed = {'materialization': 'observed independently'}

        def inspect(value):
            connection.commit.assert_called_once()
            self.assertEqual(value, description)
            return observed

        with mock.patch.object(cli, 'GitMaterializer') as materializer:
            materializer.return_value.inspect.side_effect = inspect
            result = cli.attest_repair(connection, GRANT, DIGEST, object())
        self.assertEqual(result, {'proof_id': PROOF})
        self.assertEqual(cursor.execute.call_args_list[0].args,
                         ('SELECT frozen_recovery.describe(%s)', (GRANT,)))
        self.assertEqual(cursor.execute.call_args_list[1].args[0],
                         'SELECT frozen_recovery.attest(%s,%s,%s)')
        self.assertEqual(cursor.execute.call_args_list[1].args[1][:2], (GRANT, DIGEST))
        self.assertEqual(cursor.execute.call_args_list[1].args[1][2].adapted, observed)

    def test_verifier_rejects_changed_request_before_observation(self):
        for change in ({'request_digest': 'b' * 64}, {'grant_id': PROOF},
                       {'schema': 'legacy'}, {'dependencies': [{'unrelated': True}]}):
            with self.subTest(change=change):
                connection = mock.MagicMock()
                description = dict(schema='codestra.frozen-recovery.v2',
                                   action='RELEASE_STALE_WORKTREE_TO_FREE',
                                   grant_id=GRANT, request_digest=DIGEST, dependencies=[])
                description.update(change)
                connection.cursor.return_value.__enter__.return_value.fetchone.return_value = (
                    description,)
                with mock.patch.object(cli, 'GitMaterializer') as materializer, \
                     self.assertRaises(ValueError):
                    cli.attest_repair(connection, GRANT, DIGEST, object())
                materializer.assert_not_called()

    def test_observer_failure_cannot_submit_a_proof(self):
        connection = mock.MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = ({
            'schema': 'codestra.frozen-recovery.v2',
            'action': 'RELEASE_STALE_WORKTREE_TO_FREE',
            'grant_id': GRANT, 'request_digest': DIGEST,
            'binding': {}, 'dependencies': []},)
        with mock.patch.object(cli, 'GitMaterializer') as materializer:
            materializer.return_value.inspect.side_effect = ValueError('fixture failure')
            with self.assertRaises(ValueError):
                cli.attest_repair(connection, GRANT, DIGEST, object())
        self.assertEqual(cursor.execute.call_count, 1)

    def test_authorization_reads_protected_manifest_only_as_operator(self):
        connection = mock.MagicMock()
        connection.cursor.return_value.__enter__.return_value.fetchone.return_value = (
            {'grant_id': GRANT},)
        with mock.patch.object(cli, 'verify_code_custody'), \
             mock.patch.object(cli, 'protected_read', return_value=b'{"fixture":"checkout"}') as read, \
             mock.patch.object(cli, 'connect_protected', return_value=connection) as connect, \
             contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(['authorize', '--workstation', 'synthetic-lane',
                             '--checkout-file', '/fixture/approved-checkout.json',
                             '--executor', 'fixture-executor', '--reviewer', 'fixture-reviewer',
                             '--verifier', 'fixture-verifier', '--request-id', 'synthetic'])
        self.assertEqual(code, 0)
        read.assert_called_once_with('/fixture/approved-checkout.json')
        connect.assert_called_once_with(cli.DIRECTORY / 'recovery-operator.dsn')
        call = connection.cursor.return_value.__enter__.return_value.execute.call_args
        self.assertEqual(call.args[0], 'SELECT frozen_recovery.authorize(%s,%s,%s,%s,%s,%s)')
        self.assertEqual(call.args[1][1].adapted, {'fixture': 'checkout'})
