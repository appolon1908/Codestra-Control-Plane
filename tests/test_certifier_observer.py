"""Credential-free observer IPC; local sockets and synthetic GitHub only."""
import importlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'lib'))


class ObserverTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module('codestra_control.certifier_observer')
        except ImportError:
            self.fail('Separate read-only certifier observer is missing')

    def test_only_accepted_identity_paths_are_forwarded_and_secrets_are_removed(self):
        m = self.module()
        upstream = Mock(return_value={'id': 99, 'slug': 'certifier', 'pem': 'SECRET', 'token': 'SECRET'})
        observer = m.CertifierObservationHandler(lambda: (99, 88, ('appolon1908/codestra',)), lambda: 'PRIVATE_JWT', request=upstream)
        self.assertEqual(observer.observe({'method': 'GET', 'path': '/app'}), {'id': 99})
        for request in ({'method': 'POST', 'path': '/app'},
                        {'method': 'GET', 'path': '/app/installations/999'},
                        {'method': 'GET', 'path': '/repos/other/repo/installation'},
                        {'method': 'GET', 'path': '/app?token=x'},
                        {'method': 'GET', 'path': '/app', 'token': 'injected'}):
            with self.subTest(request=request), self.assertRaises(m.PublicationDenied):
                observer.observe(request)
        self.assertEqual(upstream.call_count, 1)

    def test_acceptance_is_reread_and_revocation_prevents_upstream_call(self):
        m = self.module()
        accepted = Mock(side_effect=[(99, 88, ('appolon1908/codestra',)), m.PublicationDenied('REVOKED')])
        upstream = Mock(return_value={'id': 99})
        handler = m.CertifierObservationHandler(accepted, lambda: 'private', request=upstream)
        handler.observe({'method': 'GET', 'path': '/app'})
        with self.assertRaises(m.PublicationDenied):
            handler.observe({'method': 'GET', 'path': '/app'})
        self.assertEqual(upstream.call_count, 1)

    def test_installation_response_contains_public_identity_only(self):
        m = self.module()
        upstream = Mock(return_value={'id': 88, 'app_id': 99, 'suspended_at': None,
            'account': {'login': 'appolon1908', 'id': 1234, 'email': 'private'},
            'repository_selection': 'selected',
            'permissions': {'checks': 'write'}, 'access_tokens_url': 'secret-reference'})
        handler = m.CertifierObservationHandler(lambda: (99, 88, ('appolon1908/codestra',)), lambda: 'private', request=upstream)
        self.assertEqual(handler.observe({'method': 'GET', 'path': '/repos/appolon1908/codestra/installation'}),
                         {'id': 88, 'app_id': 99, 'suspended_at': None,
                          'account': {'login': 'appolon1908', 'id': 1234}, 'permissions': {'checks': 'write'},
                          'repository_selection': 'selected'})

    def test_real_local_ipc_returns_no_credential_and_refuses_non_get(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory)/'observer.sock')
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path); listener.listen(1)
            self.addCleanup(listener.close)
            handler = m.CertifierObservationHandler(lambda: (99, 88, ('appolon1908/codestra',)), lambda: 'never returned', request=Mock(return_value={'id': 99, 'token': 'secret'}))
            def serve():
                connection, _ = listener.accept()
                with connection:
                    m.serve_connection(connection, handler, allowed_uid=os.geteuid())
            thread = threading.Thread(target=serve); thread.start()
            client = m.CertifierObservationClient(path, expected_uid=os.geteuid())
            with patch.object(m, 'verify_socket_path'):
                self.assertEqual(client.request('GET', '/app', client.jwt_provider()), {'id': 99})
            thread.join(5)
            self.assertFalse(thread.is_alive())
            with self.assertRaises(m.PublicationDenied):
                client.request('POST', '/app', client.jwt_provider())

    def test_untrusted_socket_and_peer_are_denied(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'not-a-socket'; path.write_text('x')
            with self.assertRaises(m.PublicationDenied): m.verify_socket_path(path)
        left, right = socket.socketpair()
        self.addCleanup(left.close); self.addCleanup(right.close)
        handler = Mock()
        with self.assertRaises(m.PublicationDenied):
            m.serve_connection(left, handler, allowed_uid=os.geteuid()+1)
        handler.observe.assert_not_called()

    def test_overlong_or_unframed_response_denies(self):
        m = self.module()
        for response in (b'{}', b'x'*(m.MAX_MESSAGE+1)):
            left, right = socket.socketpair()
            with left, right:
                right.sendall(response); right.shutdown(socket.SHUT_WR)
                with self.assertRaises(m.PublicationDenied): m.receive_message(left)

    def test_missing_observer_config_never_reads_key_or_starts_server(self):
        m=self.module()
        from codestra_control.publisher_ownership import PublisherUnavailable
        with patch('codestra_control.publisher_startup.protected_read',side_effect=PublisherUnavailable('MISSING')),patch.object(m,'serve_observer') as serve:
            with self.assertRaises(PublisherUnavailable):m.run_configured_observer()
        serve.assert_not_called()

    def test_filtered_observer_responses_verify_real_producer_contract(self):
        """Exercise the real filter/schema boundary; synthetic HTTP only."""
        m=self.module()
        from dataclasses import replace
        import test_decision as fixture
        from test_authenticated_publisher import Store
        from test_publisher_acceptance import Transport,policy,raw
        from codestra_control.publisher_acceptance import AcceptedProducerVerifier
        from codestra_control.publisher_github import GitHubAppClient
        from codestra_control.publisher_provenance import verify_contract
        transport=Transport()
        handler=m.CertifierObservationHandler(lambda:(99,100,(fixture.REQUEST.repository,)),
                    lambda:'synthetic-certifier-jwt',request=transport)
        class ObserverPort:
            def jwt_provider(self):return None
            def request(self,method,path,handle):return handler.observe({'method':method,'path':path})
        acquired=Store().acquire(fixture.REQUEST)
        acquired=replace(acquired,snapshot=replace(acquired.snapshot,
                    certificate=replace(acquired.snapshot.certificate,receipt_id='check:10')))
        publisher=GitHubAppClient(lambda:'synthetic-publisher-jwt',request=transport,clock=lambda:fixture.NOW)
        verifier=AcceptedProducerVerifier(lambda:raw(policy()),publisher,certifier_api=ObserverPort())
        contract=verify_contract(verifier,acquired,fixture.NOW)
        self.assertEqual(contract.certificate_app_id,99)
        self.assertEqual(contract.repository_id,123)
        self.assertEqual(contract.controller_contexts,('codestra-control-plane','codestra/control-plane'))

    def test_certifier_signer_rechecks_root_only_custody_each_time(self):
        m=self.module()
        import stat
        from types import SimpleNamespace
        metadata=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)
        with patch.object(Path,'lstat',return_value=metadata),patch('codestra_control.publisher_startup.AppJWT',return_value=lambda:'synthetic-jwt'):
            signer=m.private_certifier_signer('/fixture/key.pem',99)
            self.assertEqual(signer(),'synthetic-jwt')
            metadata.st_mode=stat.S_IFREG|0o640
            with self.assertRaises(m.PublicationDenied):signer()


if __name__ == '__main__': unittest.main()
