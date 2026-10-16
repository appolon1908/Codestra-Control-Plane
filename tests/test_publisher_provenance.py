"""Privileged provenance seams use synthetic fixtures; no real issuer is selected."""
from dataclasses import replace
from datetime import timedelta
import unittest
from unittest.mock import Mock
import test_decision as fixture
from test_authenticated_publisher import Store
from codestra_control.publisher_provenance import VerifiedProducerContract, verify_contract
from codestra_control.publisher_adapter import PublicationDenied,binding_digest
from codestra_control.publisher_acquisition import GitHubVerifier


def contract(acquired):
    return VerifiedProducerContract(binding_digest(acquired.snapshot.observed_binding),
        acquired.repository_id,acquired.pr_number,acquired.authority.app_id,
        acquired.issuer.app_id,acquired.issuer.name,('codestra-control-plane',),
        acquired.issuer.capability_receipt,acquired.issuer.expires_at,'STATUS_PUBLICATION')

class Provenance:
    def verify(self,acquired,now):return contract(acquired)

class ProvenanceTests(unittest.TestCase):
    def setUp(self):self.acquired=Store().acquire(fixture.REQUEST)
    def test_default_unset_denies_before_api_access(self):
        api=Mock()
        verifier=GitHubVerifier(api,certificate_name='scope-certification',certificate_app_id=99)
        with self.assertRaisesRegex(PublicationDenied,'PUBLISHER_PROVENANCE_UNCONFIGURED'):
            verifier.verify(self.acquired,fixture.NOW)
        self.assertEqual(api.mock_calls,[])
    def test_explicit_internal_fixture_contract_matches_bound_issuer(self):
        result=verify_contract(Provenance(),self.acquired,fixture.NOW)
        self.assertEqual(result.publisher_app_id,7)
        self.assertEqual(result.controller_contexts,('codestra-control-plane',))
    def test_every_provenance_binding_and_purpose_is_checked(self):
        good=contract(self.acquired)
        for field,value in [('binding_hash','a'*64),('repository_id',999),('pr_number',0),
             ('publisher_app_id',123),('certificate_app_id',7),('certificate_name','quality'),
             ('controller_contexts',()),('controller_contexts',('codestra-review-admission',)),
             ('receipt_ref',''),('expires_at',fixture.NOW),('purpose','REF_CREATION')]:
            verifier=Mock();verifier.verify.return_value=replace(good,**{field:value})
            with self.subTest(field=field),self.assertRaises(PublicationDenied):
                verify_contract(verifier,self.acquired,fixture.NOW)
    def test_json_booleans_and_authored_objects_are_not_verified_contracts(self):
        for value in (True,{}, {'approved':True},None):
            verifier=Mock();verifier.verify.return_value=value
            with self.assertRaises(PublicationDenied):verify_contract(verifier,self.acquired,fixture.NOW)
    def test_verifier_rejection_or_revocation_is_never_bypassed(self):
        verifier=Mock();verifier.verify.side_effect=PublicationDenied('REVOKED')
        with self.assertRaisesRegex(PublicationDenied,'REVOKED'):verify_contract(verifier,self.acquired,fixture.NOW)
    def test_contract_cannot_outlive_authority_or_issuer(self):
        verifier=Mock();verifier.verify.return_value=replace(contract(self.acquired),expires_at=self.acquired.issuer.expires_at+timedelta(seconds=1))
        with self.assertRaises(PublicationDenied):verify_contract(verifier,self.acquired,fixture.NOW)
    def test_status_contract_cannot_supply_first_ref_creation_or_parent_fence(self):
        good=contract(self.acquired)
        self.assertEqual(good.purpose,'STATUS_PUBLICATION')
        verifier=Mock();verifier.verify.return_value=replace(good,purpose='PREPUBLICATION')
        with self.assertRaises(PublicationDenied):verify_contract(verifier,self.acquired,fixture.NOW)

    def test_expiry_during_online_validation_denies_before_intent(self):
        from test_publisher_acquisition import API
        from codestra_control.publisher_adapter import AuthenticatedPublisher
        now=[fixture.NOW]
        store=Store()
        store.snapshot=replace(store.snapshot,certificate=replace(store.snapshot.certificate,receipt_id='check:10'))
        api=API()
        def threads(*args):now[0]=fixture.NOW+timedelta(seconds=2);return True
        api.threads_resolved=threads
        class ShortProvenance:
            def verify(self,acquired,at):
                return replace(contract(acquired),controller_contexts=('codestra-control-plane','codestra/control-plane'),expires_at=fixture.NOW+timedelta(seconds=1))
        verifier=GitHubVerifier(api,certificate_name='scope-certification',certificate_app_id=99,provenance_verifier=ShortProvenance())
        ledger=Mock()
        publisher=AuthenticatedPublisher(store,verifier,ledger,host='dev-desktop',clock=lambda:now[0])
        with self.assertRaisesRegex(PublicationDenied,'PROVENANCE_EXPIRED'):
            publisher._acquire(fixture.REQUEST)
        self.assertEqual(ledger.mock_calls,[])

    def test_any_ordinary_ci_producer_cannot_become_independent_certifier(self):
        from codestra_control.evidence import RequiredCheck
        acquired=replace(self.acquired,snapshot=replace(self.acquired.snapshot,
            required_checks=(RequiredCheck('quality','github-actions:99'),)))
        with self.assertRaisesRegex(PublicationDenied,'INDEPENDENT_PROVENANCE'):
            verify_contract(Provenance(),acquired,fixture.NOW)
