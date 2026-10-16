"""Production composition tests use only private temporary files and local crypto."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
from codestra_control.publisher_startup import AppJWT,protected_read,run_operator_cycle
from codestra_control.publisher_ownership import PublisherUnavailable

class StartupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
    def test_protected_source_config_rejects_symlink_and_public_or_wrong_owner(self):
        p=self.root/'config';p.write_text('operator-only');p.chmod(0o600)
        self.assertEqual(protected_read(p,expected_owner=os.geteuid()),b'operator-only')
        p.chmod(0o644)
        with self.assertRaises(PublisherUnavailable):protected_read(p,expected_owner=os.geteuid())
        p.chmod(0o600)
        with self.assertRaises(PublisherUnavailable):protected_read(p,expected_owner=os.geteuid()+1)
        link=self.root/'link';link.symlink_to(p)
        with self.assertRaises(PublisherUnavailable):protected_read(link,expected_owner=os.geteuid())
    def test_real_local_rsa_signature_and_short_app_jwt(self):
        key=self.root/'app.pem'
        subprocess.run(['/usr/bin/openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',str(key)],check=True,capture_output=True)
        key.chmod(0o600)
        # This verifies protocol with a synthetic key, not acceptance of the CI host's toolchain.
        with mock.patch('codestra_control.publisher_startup.verify_system_tools'):
            jwt=AppJWT(key,7,clock=lambda:1000,expected_owner=os.geteuid())()
        head,payload,signature=jwt.split('.')
        decode=lambda value:base64.urlsafe_b64decode(value+'='*((-len(value))%4))
        self.assertEqual(json.loads(decode(head)),{'alg':'RS256','typ':'JWT'})
        self.assertEqual(json.loads(decode(payload)),{'iat':940,'exp':1540,'iss':'7'})
        pub=self.root/'public.pem';sig=self.root/'signature'
        pub.write_bytes(subprocess.check_output(['/usr/bin/openssl','pkey','-in',str(key),'-pubout']))
        sig.write_bytes(decode(signature))
        result=subprocess.run(['/usr/bin/openssl','dgst','-sha256','-verify',str(pub),'-signature',str(sig)],input=(head+'.'+payload).encode(),capture_output=True)
        self.assertEqual(result.returncode,0)
    def test_missing_config_refuses_before_database_or_github(self):
        import contextlib
        with mock.patch('codestra_control.publisher_startup.publisher_session',contextlib.nullcontext),mock.patch('codestra_control.publisher_startup.protected_read',side_effect=PublisherUnavailable('CONFIG_UNAVAILABLE')):
            with self.assertRaises(PublisherUnavailable):run_operator_cycle()
    def test_designated_service_check_precedes_configuration_read(self):
        with mock.patch('codestra_control.publisher_startup.publisher_session',side_effect=PublisherUnavailable('DESIGNATED_SERVICE_REQUIRED')),mock.patch('codestra_control.publisher_startup.protected_read') as read:
            with self.assertRaises(PublisherUnavailable):run_operator_cycle()
        read.assert_not_called()
    def test_system_tool_digest_mismatch_refuses_before_signing(self):
        from codestra_control.publisher_startup import verify_system_tools
        with mock.patch('codestra_control.publisher_startup.hashlib.sha256') as sha:
            sha.return_value.hexdigest.return_value='0'*64
            with self.assertRaises(PublisherUnavailable):verify_system_tools()
    def test_fifo_operator_file_refuses_without_blocking(self):
        p=self.root/'fifo';os.mkfifo(p,0o600)
        with self.assertRaises(PublisherUnavailable):protected_read(p,expected_owner=os.geteuid())
    def test_public_ca_can_be_read_but_not_from_writable_directory(self):
        p=self.root/'ca.pem';p.write_text('synthetic CA fixture');p.chmod(0o644)
        self.assertEqual(protected_read(p,expected_owner=os.geteuid(),allow_public=True),b'synthetic CA fixture')
        self.root.chmod(0o777)
        with self.assertRaises(PublisherUnavailable):protected_read(p,expected_owner=os.geteuid(),allow_public=True)
    def test_root_paths_reject_writable_or_symlinked_ancestors(self):
        from types import SimpleNamespace
        import stat
        p=self.root/'config';p.write_text('synthetic');p.chmod(0o600)
        def metadata(path):
            # TMPDIR may place the fixture outside /tmp. Exercise its actual
            # ancestor so refusal happens before touching a real directory.
            if path==self.root.parent:return SimpleNamespace(st_mode=stat.S_IFDIR|0o1777,st_uid=0)
            return SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0)
        with mock.patch.object(Path,'lstat',metadata):
            with self.assertRaisesRegex(PublisherUnavailable,'UNTRUSTED_OPERATOR_ANCESTOR'):protected_read(p)
    def test_current_development_tree_is_not_assumed_to_be_trusted_runtime(self):
        from codestra_control.publisher_startup import verify_code_custody
        # CI/test checkouts are writable non-root-owned developer source.
        with mock.patch('pathlib.Path.lstat') as metadata:
            import stat
            metadata.return_value.st_mode=stat.S_IFREG|0o644
            metadata.return_value.st_nlink=1;metadata.return_value.st_uid=12345
            with self.assertRaisesRegex(PublisherUnavailable,'UNTRUSTED_RUNTIME_CODE'):verify_code_custody()
    def test_concrete_startup_wires_protected_dsn_and_local_signer_without_live_calls(self):
        from codestra_control.publisher_startup import CONFIG,run_configured_cycle
        from codestra_control.publisher_adapter import PublicationResult
        import test_decision as fixture
        config=b'app_id=7\ninstallation_id=8\ncertificate_app_id=99\ncertificate_name="scope-certification"\napp_key_file="/fixture/app.pem"\ndatabase_dsn_file="/fixture/db.dsn"\nledger_file="/fixture/intents.sqlite"\n'
        dsn=b'host=authority.example dbname=registry user=publisher sslmode=verify-full sslrootcert=/fixture/ca.pem'
        def read(path,**kwargs):
            return {str(CONFIG):config,'/fixture/db.dsn':dsn,'/fixture/ca.pem':b'synthetic CA fixture'}[str(path)]
        service=mock.MagicMock();service._publisher.store.bindings.return_value=(fixture.REQUEST,)
        service._publisher.publish.return_value=PublicationResult('COMPLETE',())
        from codestra_control.publisher_github import ObservedPR
        b=fixture.REQUEST
        service._publisher.github.api.inventory.return_value=(ObservedPR(123,b.repository,9,b.source_ref,b.target_ref,b.source_sha,b.target_base_sha),)
        service._publisher.store.acquire.return_value.repository_id=123
        service._publisher.store.acquire.return_value.pr_number=9
        connection=mock.MagicMock()
        with mock.patch('codestra_control.publisher_startup.protected_read',side_effect=read),mock.patch('codestra_control.publisher_startup.verify_code_custody'),mock.patch('psycopg2.connect',return_value=connection) as connect,mock.patch('codestra_control.publisher_adapter.build_publisher_service',return_value=service) as build:
            self.assertEqual(run_configured_cycle(),('COMPLETE',))
        connect.assert_called_once_with(host='authority.example',dbname='registry',user='publisher',sslmode='verify-full',sslrootcert='/fixture/ca.pem')
        self.assertIsInstance(build.call_args.args[1],AppJWT)
        service._publisher.publish.assert_called_once_with(fixture.REQUEST)
        connection.close.assert_called_once_with()
    def test_empty_authority_inventory_is_explicitly_unavailable_not_healthy(self):
        from codestra_control.publisher_startup import reconcile_inventory
        publisher=mock.MagicMock();publisher.store.bindings.return_value=()
        publisher.github.api.inventory.return_value=()
        self.assertEqual(reconcile_inventory(publisher,7,8),('UNAVAILABLE_NO_ACTIVE_BINDINGS',))
        publisher.publish.assert_not_called()
    def test_open_pr_without_binding_is_reported_without_post(self):
        from codestra_control.publisher_startup import reconcile_inventory
        from codestra_control.publisher_github import ObservedPR
        import test_decision as fixture
        publisher=mock.MagicMock();publisher.store.bindings.return_value=()
        b=fixture.REQUEST
        publisher.github.api.inventory.return_value=(ObservedPR(123,b.repository,9,b.source_ref,b.target_ref,b.source_sha,b.target_base_sha),)
        outcomes=reconcile_inventory(publisher,7,8)
        self.assertIn('UNAVAILABLE_MISSING_BINDING',outcomes)
        publisher.publish.assert_not_called()
    def test_incomplete_github_inventory_prevents_every_status_effect(self):
        from codestra_control.publisher_startup import reconcile_inventory
        from codestra_control.publisher_adapter import PublicationDenied
        import test_decision as fixture
        publisher=mock.MagicMock();publisher.store.bindings.return_value=(fixture.REQUEST,)
        publisher.github.api.inventory.side_effect=PublicationDenied('INVENTORY_REPOSITORY_SCOPE_INCOMPLETE')
        with self.assertRaises(PublicationDenied):reconcile_inventory(publisher,7,8)
        publisher.publish.assert_not_called()
