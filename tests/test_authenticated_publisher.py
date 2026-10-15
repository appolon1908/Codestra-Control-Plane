"""Offline synthetic transports only; no live credentials or API writes."""
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import tempfile
import unittest
import test_decision as fixture
from codestra_control.publisher_adapter import Authority, Acquired, AuthenticatedPublisher, PublicationDenied
from codestra_control.publisher_effect import IntentLedger

class Store:
    def __init__(self):
        self.authority=Authority('Ralph L. Appolon','dev-desktop',7,8,1,fixture.NOW+timedelta(minutes=4),'custody:1',('appolon1908/Breero.com',))
        self.snapshot=fixture.ready()
    def acquire(self, binding): return Acquired(self.authority,self.snapshot,123,9,10)

class GitHub:
    def __init__(self): self.calls=[];self.revoked=False;self.failure=False;self.moved=False
    def verify(self, acquired, now):
        if self.revoked: raise PublicationDenied('REVOKED')
        if self.moved: raise PublicationDenied('TARGET_MOVED')
    def post(self, acquired, context, decision):
        self.calls.append(context)
        if self.failure: raise OSError('ambiguous transport')
        return 42
    def readback(self, acquired, context, receipt): return True

class AuthenticatedPublisherTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.ledger=IntentLedger(Path(self.temp.name)/'intents.sqlite')
        self.store=Store();self.github=GitHub()
        self.publisher=AuthenticatedPublisher(self.store,self.github,self.ledger,host='dev-desktop',clock=lambda:fixture.NOW)
    def test_complete_pair_and_no_second_effect_on_replay(self):
        result=self.publisher.publish(fixture.REQUEST)
        self.assertEqual(result.state,'COMPLETE');self.assertEqual(len(self.github.calls),2)
        with self.assertRaises(PublicationDenied):self.publisher.publish(fixture.REQUEST)
        self.assertEqual(len(self.github.calls),2)
    def test_wrong_host_expired_capability_missing_custody_denied(self):
        for values in ({'host':'other'},{'expires_at':fixture.NOW},{'custody_receipt':''}):
            self.store.authority=replace(Store().authority,**values)
            with self.assertRaises(PublicationDenied):self.publisher.publish(fixture.REQUEST)
        self.assertEqual(self.github.calls,[])
    def test_legacy_pass_and_missing_lease_cannot_publish(self):
        self.store.snapshot=replace(fixture.ready(),lease=None)
        with self.assertRaises(PublicationDenied):self.publisher.publish(fixture.REQUEST)
        self.assertEqual(self.github.calls,[])
    def test_revocation_between_contexts_stops_without_compensation(self):
        original=self.github.post
        def revoke(*args):
            receipt=original(*args);self.github.revoked=True;return receipt
        self.github.post=revoke
        result=self.publisher.publish(fixture.REQUEST)
        self.assertEqual(result.state,'PARTIAL');self.assertEqual(len(self.github.calls),1)
        self.github.revoked=False
        with self.assertRaises(PublicationDenied):self.publisher.publish(fixture.REQUEST)
        self.assertEqual(len(self.github.calls),1)
    def test_ambiguous_post_is_uncertain_and_durable_across_reopen(self):
        self.github.failure=True
        result=self.publisher.publish(fixture.REQUEST)
        self.assertEqual(result.state,'UNCERTAIN')
        other=AuthenticatedPublisher(self.store,self.github,IntentLedger(Path(self.temp.name)/'intents.sqlite'),host='dev-desktop',clock=lambda:fixture.NOW)
        with self.assertRaises(PublicationDenied):other.publish(fixture.REQUEST)
        self.assertEqual(len(self.github.calls),1)
    def test_target_move_before_first_write_denies_without_post(self):
        self.github.moved=True
        with self.assertRaises(PublicationDenied):self.publisher.publish(fixture.REQUEST)
        self.assertEqual(self.github.calls,[])
    def test_readback_failure_is_uncertain(self):
        self.github.readback=lambda *_:False
        self.assertEqual(self.publisher.publish(fixture.REQUEST).state,'UNCERTAIN')
        self.assertEqual(len(self.github.calls),1)
    def test_reserved_intent_from_process_death_stays_consumed(self):
        from codestra_control.publisher_adapter import binding_digest
        self.ledger.reserve(binding_digest(fixture.REQUEST),'1')
        with self.assertRaises(PublicationDenied):self.publisher.publish(fixture.REQUEST)
        self.assertEqual(self.github.calls,[])
    def test_symlinked_ledger_directory_denied(self):
        link=Path(self.temp.name)/'alias';link.symlink_to(Path(self.temp.name),target_is_directory=True)
        with self.assertRaises(ValueError):IntentLedger(link/'other.sqlite')
    def test_source_service_wrapper_requires_designated_session(self):
        from codestra_control.publisher_adapter import PublisherService
        import contextlib
        from unittest import mock
        session=mock.Mock(return_value=contextlib.nullcontext())
        with mock.patch('codestra_control.publisher_ownership.publisher_session',session):
            self.assertEqual(PublisherService(self.publisher).publish(fixture.REQUEST).state,'COMPLETE')
        session.assert_called_once_with()
    def test_lease_expiring_during_online_verification_never_posts(self):
        time=[fixture.NOW]
        self.publisher.clock=lambda:time[0]
        original=self.github.verify
        def slow(*args):
            original(*args);time[0]=fixture.NOW+timedelta(minutes=11)
        self.github.verify=slow
        with self.assertRaises(PublicationDenied):self.publisher.publish(fixture.REQUEST)
        self.assertEqual(self.github.calls,[])
    def test_authority_revoked_during_online_inventory_denies_before_intent(self):
        def revoked(*args):self.store.authority=replace(self.store.authority,epoch=2)
        self.github.verify=revoked
        with self.assertRaisesRegex(PublicationDenied,'AUTHORITY_CHANGED_DURING_VERIFICATION'):self.publisher.publish(fixture.REQUEST)
        self.assertEqual(self.github.calls,[])
