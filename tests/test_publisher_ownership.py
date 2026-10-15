"""Source-only process ownership and no-adapter denial regressions."""
import os
import contextlib
import subprocess
import sys
import test_publisher_rate_limits as helpers
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from codestra_control.publisher_ownership import PublisherUnavailable, exclusive_lock, require_designated_service, require_publication_adapter


class PublisherOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.lock = self.root / 'publisher.lock'
        self.lock.touch(mode=0o600)

    def test_default_publication_adapter_is_unavailable(self):
        with self.assertRaisesRegex(PublisherUnavailable, 'AUTHENTICATED_PUBLICATION_ADAPTER_UNAVAILABLE'):
            require_publication_adapter()

    def test_only_designated_kernel_service_membership_is_accepted(self):
        with mock.patch('pathlib.Path.read_text', return_value='0::/system.slice/codestra-control-plane-status.service\n'):
            require_designated_service()
        for cgroup in ('0::/user.slice/interactive\n', '0::/system.slice/codestra-github-statusd.service\n',
                       '0::/system.slice/codestra-control-plane-status.service/spoof\n'):
            with mock.patch('pathlib.Path.read_text', return_value=cgroup), self.assertRaises(PublisherUnavailable):
                require_designated_service()

    def test_one_process_descriptor_owns_lock_and_releases_it(self):
        with exclusive_lock(self.lock, expected_owner=os.geteuid()):
            with self.assertRaisesRegex(PublisherUnavailable, 'PUBLISHER_ALREADY_RUNNING'):
                with exclusive_lock(self.lock, expected_owner=os.geteuid()):
                    self.fail('second descriptor acquired ownership')
        with exclusive_lock(self.lock, expected_owner=os.geteuid()):
            pass

    def test_missing_lock_is_not_created(self):
        self.lock.unlink()
        with self.assertRaises(PublisherUnavailable):
            with exclusive_lock(self.lock, expected_owner=os.geteuid()): pass
        self.assertFalse(self.lock.exists())

    def test_symlink_hardlink_and_world_writable_lock_refused(self):
        self.lock.unlink();self.lock.symlink_to(self.root / 'missing')
        with self.assertRaises(PublisherUnavailable):
            with exclusive_lock(self.lock, expected_owner=os.geteuid()): pass
        self.lock.unlink();self.lock.touch(mode=0o600);os.link(self.lock, self.root / 'other')
        with self.assertRaises(PublisherUnavailable):
            with exclusive_lock(self.lock, expected_owner=os.geteuid()): pass
        (self.root / 'other').unlink();self.lock.chmod(0o666)
        with self.assertRaises(PublisherUnavailable):
            with exclusive_lock(self.lock, expected_owner=os.geteuid()): pass

    def test_replaceable_lock_directory_refused(self):
        self.root.chmod(0o777)
        with self.assertRaises(PublisherUnavailable):
            with exclusive_lock(self.lock, expected_owner=os.geteuid()): pass

    def test_entrypoint_and_direct_post_deny_before_database_or_network(self):
        fixture = helpers.PublisherRateLimitTests()
        fixture.setUp()
        main = fixture.module['main']
        with mock.patch.dict(main.__globals__, {'publisher_session': contextlib.nullcontext}):
            with self.assertRaisesRegex(SystemExit, 'AUTHENTICATED_PUBLICATION_ADAPTER_UNAVAILABLE'):
                main()
        read, write = mock.Mock(), mock.Mock()
        post = fixture.module['post']
        with mock.patch.dict(post.__globals__, {'gh_json': read, 'run': write}):
            with self.assertRaises(PublisherUnavailable):
                post('codestra-foundation', 'a' * 40, 'success', 'unverified', 'https://example.invalid')
        read.assert_not_called()
        write.assert_not_called()

    def test_retired_source_entrypoint_performs_no_command_work(self):
        script = Path(__file__).resolve().parents[1] / 'legacy/bin/github-status-sync'
        result = subprocess.run(['/bin/bash', str(script)], capture_output=True, text=True, env={'PATH': str(self.root)})
        self.assertEqual(result.returncode, 78)
        self.assertIn('PUBLICATION_REFUSED', result.stderr)

    def test_fifo_lock_refused_without_blocking(self):
        self.lock.unlink()
        os.mkfifo(self.lock, 0o600)
        code = """import os,sys
from codestra_control.publisher_ownership import exclusive_lock, PublisherUnavailable
try:
    with exclusive_lock(sys.argv[1], expected_owner=os.geteuid()):
        raise AssertionError('FIFO accepted')
except PublisherUnavailable:
    pass
"""
        result = subprocess.run([sys.executable, '-S', '-c', code, str(self.lock)],
                                env={'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'lib')},
                                capture_output=True, text=True, timeout=2)
        self.assertEqual(result.returncode, 0, result.stderr)
