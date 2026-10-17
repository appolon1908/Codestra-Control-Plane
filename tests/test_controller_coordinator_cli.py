"""CLI custody/output tests; no installed credentials or network connections."""
import contextlib
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from codestra_control import controller_coordinator as cli
from codestra_control.publisher_startup import verify_code_custody
from codestra_control.publisher_ownership import PublisherUnavailable


class CoordinatorCLITests(unittest.TestCase):
    args = ['prepare', '--task', 'fixture-task', '--repository', 'appolon1908/fixture', '--request-id', 'fixture-request']

    def test_builder_credential_only_and_rollback_is_default(self):
        connection = mock.MagicMock()
        with mock.patch.object(cli, 'verify_code_custody'), mock.patch.object(cli, 'connect_protected', return_value=connection) as connect, mock.patch.object(cli, 'coordinate', return_value={'state':'DRY_RUN','usable':False}) as coordinate, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(self.args), 0)
        connect.assert_called_once_with(cli.DIRECTORY/'lease-builder.dsn')
        self.assertFalse(coordinate.call_args.kwargs['apply'])
        self.assertIn('"usable": false', output.getvalue())
        connection.close.assert_called_once()

    def test_error_details_are_hidden_and_connection_is_closed(self):
        for error, expected in [(RuntimeError('synthetic-secret-dsn'), 'COORDINATOR_OPERATION_UNAVAILABLE'), (cli.AdmissionOutcomeUnknown('synthetic-secret-dsn'), 'ADMISSION_OUTCOME_UNKNOWN_USE_RECOVER')]:
            with self.subTest(error=type(error).__name__):
                connection = mock.MagicMock()
                with mock.patch.object(cli, 'verify_code_custody'), mock.patch.object(cli, 'connect_protected', return_value=connection), mock.patch.object(cli, 'coordinate', side_effect=error), contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(cli.main(self.args), 1)
                self.assertEqual(output.getvalue().strip(), expected)
                connection.close.assert_called_once()

    def test_failed_connection_does_not_expose_dsn(self):
        with mock.patch.object(cli, 'verify_code_custody'), mock.patch.object(cli, 'connect_protected', side_effect=RuntimeError('synthetic-password')), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(self.args), 1)
        self.assertEqual(output.getvalue().strip(), 'COORDINATOR_OPERATION_UNAVAILABLE')

    def test_success_is_printed_only_after_connection_close(self):
        connection = mock.MagicMock()
        output = io.StringIO()
        def close():
            self.assertEqual(output.getvalue(), '')
        connection.close.side_effect = close
        with mock.patch.object(cli, 'verify_code_custody'), mock.patch.object(cli, 'connect_protected', return_value=connection), mock.patch.object(cli, 'coordinate', return_value={'state': 'DRY_RUN', 'usable': False}), contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(self.args), 0)
        self.assertIn('"usable": false', output.getvalue())
        connection.close.assert_called_once()

    def test_close_failure_after_coordinate_does_not_print_success_or_escape(self):
        connection = mock.MagicMock()
        connection.close.side_effect = RuntimeError('synthetic-private-close-diagnostic')
        with mock.patch.object(cli, 'verify_code_custody'), mock.patch.object(cli, 'connect_protected', return_value=connection), mock.patch.object(cli, 'coordinate', return_value={'state': 'ADMITTED', 'usable': True}), contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()) as error_output:
            try:
                result = cli.main(self.args)
            except Exception:
                result = 'exception-escaped'
        self.assertEqual(result, 1)
        self.assertEqual(output.getvalue(), 'COORDINATOR_OPERATION_UNAVAILABLE\n')
        self.assertEqual(error_output.getvalue(), '')

    def test_cleanup_failure_preserves_original_safe_error_marker(self):
        for error, expected in ((RuntimeError('synthetic-private-operation-diagnostic'), 'COORDINATOR_OPERATION_UNAVAILABLE'),
                                (cli.AdmissionOutcomeUnknown('synthetic-private-operation-diagnostic'), 'ADMISSION_OUTCOME_UNKNOWN_USE_RECOVER')):
            with self.subTest(error=type(error).__name__):
                connection = mock.MagicMock()
                connection.close.side_effect = RuntimeError('synthetic-private-close-diagnostic')
                with mock.patch.object(cli, 'verify_code_custody'), mock.patch.object(cli, 'connect_protected', return_value=connection), mock.patch.object(cli, 'coordinate', side_effect=error), contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()) as error_output:
                    try:
                        result = cli.main(self.args)
                    except Exception:
                        result = 'exception-escaped'
                self.assertEqual(result, 1)
                self.assertEqual(output.getvalue(), expected + '\n')
                self.assertEqual(error_output.getvalue(), '')
                connection.close.assert_called_once()

    def test_writable_coordinator_entrypoint_fails_custody(self):
        original = Path.lstat
        def metadata(path):
            actual = original(path)
            return SimpleNamespace(st_mode=actual.st_mode & ~0o022, st_nlink=1,
                st_uid=12345 if path.name == 'codestra-coordinate' else 0)
        with mock.patch.object(Path, 'lstat', metadata):
            with self.assertRaisesRegex(PublisherUnavailable, 'UNTRUSTED_RUNTIME_CODE'):
                verify_code_custody()
