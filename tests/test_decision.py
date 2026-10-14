"""Offline decision tests: fixtures model trusted-reader output, not user JSON."""

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from codestra_control.decision import evaluate_promotion
from codestra_control.evidence import (
    CheckEvidence, LeaseEvidence, PromotionRequest, RequiredCheck,
    ReviewEvidence, ScopeCertificate, TrustedSnapshot,
)
from test_policy import BREERO

NOW = datetime(2026, 10, 7, 15, 30, tzinfo=timezone.utc)
REQUEST = PromotionRequest("appolon1908/Breero.com", "Breero", "staging",
                           "production/environment", "a" * 40, "b" * 40)


def ready():
    return TrustedSnapshot(
        mapping=BREERO, observed_binding=REQUEST, observed_at=NOW,
        evaluated_at=NOW, required_checks=(RequiredCheck("quality", "github-actions:15368"),),
        checks=(CheckEvidence(REQUEST, "quality", "github-actions:15368", "completed", "success", "run:123"),),
        reviews=(ReviewEvidence(REQUEST, "independent-reviewer", "APPROVED", "review:12", True, True),),
        author="author", last_pusher="pusher", unresolved_threads=0,
        review_inventory_complete=True, check_inventory_complete=True,
        require_codeowner=True, required_approvals=1,
        certificate=ScopeCertificate(REQUEST, "STAGING", "CERTIFIED", "a" * 40, "a" * 40, "receipt:34"),
        dependencies_complete=True, dependencies_certified=True,
        lease=LeaseEvidence(REQUEST, "owner", "owner", "ACTIVE", NOW + timedelta(minutes=10), "assignment:1"),
        production_go=False, live_capabilities_enabled=False, external_effects_enabled=False,
    )


class DecisionTests(unittest.TestCase):
    def assert_blocked(self, snapshot, reason, request=REQUEST):
        decision = evaluate_promotion(request, snapshot)
        self.assertFalse(decision.allowed, decision)
        self.assertEqual(decision.operation_kind, "PROMOTION")
        self.assertIn(reason, decision.reasons)

    def test_complete_current_evidence_allows_decision_only(self):
        result = evaluate_promotion(REQUEST, ready())
        self.assertTrue(result.allowed, result.reasons)
        self.assertEqual(result.operation_kind, "PROMOTION")
        self.assertEqual(result.reasons, ())
        with self.assertRaises(FrozenInstanceError):
            result.allowed = False

    def test_required_checks_missing_failed_pending_or_wrong_producer_block(self):
        base = ready()
        for changes, reason in (
            ({"checks": ()}, "REQUIRED_CHECK_MISSING:quality"),
            ({"checks": (replace(base.checks[0], conclusion="failure"),)}, "REQUIRED_CHECK_NOT_SUCCESS:quality"),
            ({"checks": (replace(base.checks[0], status="in_progress"),)}, "REQUIRED_CHECK_NOT_SUCCESS:quality"),
            ({"checks": (replace(base.checks[0], producer="attacker"),)}, "REQUIRED_CHECK_MISSING:quality"),
            ({"required_checks": ()}, "REQUIRED_CHECK_INVENTORY_MISSING"),
            ({"check_inventory_complete": False}, "CHECK_INVENTORY_INCOMPLETE"),
            ({"checks": base.checks + base.checks}, "REQUIRED_CHECK_AMBIGUOUS:quality"),
        ):
            with self.subTest(changes=changes):
                self.assert_blocked(replace(base, **changes), reason)

    def test_observed_repository_product_refs_and_both_shas_must_match(self):
        for field, value in (
            ("repository", "other/repo"), ("product", "Other"),
            ("source_ref", "testing"), ("target_ref", "main"),
            ("source_sha", "c" * 40), ("target_base_sha", "d" * 40),
        ):
            with self.subTest(field=field):
                self.assert_blocked(replace(ready(), observed_binding=replace(REQUEST, **{field: value})),
                                    "OBSERVED_BINDING_MISMATCH")

    def test_all_evidence_is_bound_to_source_and_current_target(self):
        base = ready()
        for field in ("repository", "source_ref", "target_ref", "source_sha", "target_base_sha"):
            stale = replace(REQUEST, **{field: "other/value" if "sha" not in field else "c" * 40})
            with self.subTest(kind="check", field=field):
                self.assert_blocked(replace(base, checks=(replace(base.checks[0], binding=stale),)),
                                    "CHECK_BINDING_MISMATCH:quality")
            with self.subTest(kind="review", field=field):
                self.assert_blocked(replace(base, reviews=(replace(base.reviews[0], binding=stale),)),
                                    "REVIEW_BINDING_MISMATCH")
            with self.subTest(kind="certificate", field=field):
                self.assert_blocked(replace(base, certificate=replace(base.certificate, binding=stale)),
                                    "CERTIFICATE_BINDING_MISMATCH")

    def test_independent_review_codeowner_and_resolved_threads_are_required(self):
        base = ready()
        for changes, reason in (
            ({"reviews": ()}, "INDEPENDENT_APPROVAL_MISSING"),
            ({"reviews": (replace(base.reviews[0], reviewer="author"),)}, "INDEPENDENT_APPROVAL_MISSING"),
            ({"reviews": (replace(base.reviews[0], reviewer="PUSHER"),)}, "INDEPENDENT_APPROVAL_MISSING"),
            ({"reviews": (replace(base.reviews[0], state="CHANGES_REQUESTED"),)}, "CHANGES_REQUESTED"),
            ({"reviews": (replace(base.reviews[0], codeowner=False),)}, "CODEOWNER_APPROVAL_MISSING"),
            ({"unresolved_threads": 1}, "UNRESOLVED_REVIEW_THREADS"),
            ({"unresolved_threads": None}, "REVIEW_THREADS_UNKNOWN"),
            ({"review_inventory_complete": False}, "REVIEW_INVENTORY_INCOMPLETE"),
            ({"required_approvals": 2}, "INDEPENDENT_APPROVAL_MISSING"),
            ({"reviews": base.reviews * 2}, "AMBIGUOUS_REVIEWER_STATE"),
        ):
            with self.subTest(changes=changes):
                self.assert_blocked(replace(base, **changes), reason)

    def test_scope_dependencies_lease_and_no_effect_policy_are_required(self):
        base = ready()
        for changes, reason in (
            ({"certificate": None}, "SCOPE_CERTIFICATE_MISSING"),
            ({"certificate": replace(base.certificate, scope_type="PRODUCTION")}, "CERTIFICATE_SCOPE_MISMATCH"),
            ({"certificate": replace(base.certificate, status="COMPLETE")}, "SCOPE_NOT_CERTIFIED"),
            ({"certificate": replace(base.certificate, certified_sha="c" * 40)}, "CERTIFICATE_SHA_MISMATCH"),
            ({"certificate": replace(base.certificate, remote_sha="c" * 40)}, "CERTIFICATE_SHA_MISMATCH"),
            ({"certificate": replace(base.certificate, receipt_id="")}, "CERTIFICATE_RECEIPT_MISSING"),
            ({"dependencies_complete": False}, "DEPENDENCY_INVENTORY_INCOMPLETE"),
            ({"dependencies_certified": False}, "DEPENDENCIES_NOT_CERTIFIED"),
            ({"lease": None}, "OWNED_ASSIGNMENT_MISSING"),
            ({"lease": replace(base.lease, owner="different-owner")}, "LEASE_NOT_OWNED"),
            ({"lease": replace(base.lease, expires_at=NOW)}, "LEASE_EXPIRED"),
            ({"lease": replace(base.lease, state="STALE")}, "LEASE_NOT_ACTIVE"),
            ({"production_go": True}, "PRODUCTION_EFFECT_POLICY_DRIFT"),
            ({"live_capabilities_enabled": True}, "PRODUCTION_EFFECT_POLICY_DRIFT"),
            ({"external_effects_enabled": True}, "PRODUCTION_EFFECT_POLICY_DRIFT"),
        ):
            with self.subTest(changes=changes):
                self.assert_blocked(replace(base, **changes), reason)

    def test_expired_future_or_naive_observations_block(self):
        for changes, reason in (
            ({"evaluated_at": NOW + timedelta(minutes=6)}, "EVIDENCE_SNAPSHOT_EXPIRED"),
            ({"observed_at": NOW + timedelta(seconds=1)}, "EVIDENCE_TIME_INVALID"),
            ({"evaluated_at": NOW.replace(tzinfo=None)}, "EVIDENCE_TIME_INVALID"),
        ):
            with self.subTest(changes=changes):
                self.assert_blocked(replace(ready(), **changes), reason)

    def test_circular_control_plane_status_cannot_be_required_ci(self):
        for name in ("codestra-control-plane", "codestra/control-plane", "promotion-gate"):
            self.assert_blocked(replace(ready(), required_checks=(RequiredCheck(name, "some-producer"),)),
                                "CIRCULAR_REQUIRED_CHECK")

    def test_malformed_and_legacy_pass_assertions_cannot_authorize(self):
        for value in ({"ci_exact_sha": "PASS", "review": "PASS", "status": "CERTIFIED", "trusted": True}, None):
            self.assert_blocked(value, "UNTRUSTED_SNAPSHOT_TYPE")
        self.assert_blocked(ready(), "INVALID_EXACT_SHA", replace(REQUEST, source_sha="abc"))
        self.assert_blocked(ready(), "REGISTRY_IDENTITY_MISMATCH", replace(REQUEST, repository="other/repo"))

    def test_dry_evaluation_has_zero_database_network_process_or_file_writes(self):
        with patch("socket.socket", side_effect=AssertionError("network")), \
             patch("subprocess.run", side_effect=AssertionError("process")), \
             patch("builtins.open", side_effect=AssertionError("file I/O")):
            result = evaluate_promotion(REQUEST, ready())
        self.assertTrue(result.allowed)

    def test_unprivileged_review_does_not_count_as_approval(self):
        snapshot = ready()
        self.assert_blocked(replace(snapshot, reviews=(replace(snapshot.reviews[0], eligible=False),)),
                            "INDEPENDENT_APPROVAL_MISSING")

    def test_one_review_receipt_cannot_count_as_two_approvals(self):
        snapshot = ready()
        contradictory = snapshot.reviews + (replace(snapshot.reviews[0], reviewer="second-reviewer"),)
        self.assert_blocked(replace(snapshot, required_approvals=2, reviews=contradictory),
                            "DUPLICATE_REVIEW_EVIDENCE")

    def test_one_check_receipt_cannot_satisfy_two_required_checks(self):
        snapshot = ready()
        self.assert_blocked(replace(snapshot,
            required_checks=snapshot.required_checks + (RequiredCheck("security", "github-actions:15368"),),
            checks=snapshot.checks + (replace(snapshot.checks[0], name="security"),)),
            "DUPLICATE_CHECK_EVIDENCE")

    def test_lease_is_bound_to_this_exact_promotion(self):
        snapshot = ready()
        self.assert_blocked(replace(snapshot, lease=replace(snapshot.lease, binding=replace(REQUEST, product="Other"))),
                            "LEASE_BINDING_MISMATCH")

    def test_malformed_nested_evidence_and_unknown_policy_fail_closed(self):
        snapshot = ready()
        for changes in (
            {"checks": [{"state": "PASS"}]}, {"checks": ({"state": "PASS"},)},
            {"reviews": (replace(snapshot.reviews[0], codeowner="true"),)},
            {"reviews": (replace(snapshot.reviews[0], reviewer=""),)},
            {"lease": {"state": "ACTIVE"}}, {"certificate": {"status": "CERTIFIED"}},
            {"production_go": "false"}, {"required_approvals": True},
            {"required_approvals": 0}, {"unresolved_threads": False},
            {"check_inventory_complete": "true"}, {"observed_binding": {}},
        ):
            with self.subTest(changes=changes):
                self.assert_blocked(replace(snapshot, **changes), "MALFORMED_SNAPSHOT")
