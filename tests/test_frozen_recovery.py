"""Offline recovery-contract tests; no filesystem/Git/SQL/network adapter."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
import sys
import unittest
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from codestra_control.frozen_recovery import (
    FrozenRecoveryRequest, RecoveryAttestation, VerifiedRecovery,
    inspect_frozen_recovery,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
KINDS = ("operator_grant", "independent_review", "frozen_state", "repaired_worktree", "replay_fence")


def request():
    return FrozenRecoveryRequest(
        repository="fixture/repository", product="fixture",
        workstation_id="fixture::section::lane", task_id="fixture-task",
        previous_owner="fixture-owner", worktree="/fixture/repaired",
        branch="subsection/section--lane", target_branch="section/section",
        head_sha="a" * 40, remote_sha="a" * 40,
        frozen_snapshot_id="snapshot-1", freeze_incident_id="incident-1",
        repair_evidence_id="repair-1", issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=1),
    )


def verified(binding):
    return VerifiedRecovery(**{
        kind: RecoveryAttestation(binding, kind, "fixture-" + kind)
        for kind in KINDS
    })


class FrozenRecoveryTests(unittest.TestCase):
    def inspect(self, binding=None, verifier=verified, clock=lambda: NOW):
        return inspect_frozen_recovery(binding or request(), verifier, clock=clock)

    def assert_inactive(self, result):
        self.assertFalse(result.authority)
        self.assertFalse(result.ready)
        self.assertFalse(result.released)

    def test_no_verifier_denies_without_issuing_authority(self):
        result = inspect_frozen_recovery(request(), clock=lambda: NOW)
        self.assertEqual(result.reason, "VERIFIER_UNAVAILABLE")
        self.assertFalse(result.bindings_validated)
        self.assert_inactive(result)

    def test_complete_fixture_binding_still_cannot_release_or_certify(self):
        result = self.inspect()
        self.assertEqual(result.reason, "INACTIVE_RECOVERY_INTERFACE")
        self.assertTrue(result.bindings_validated)
        self.assert_inactive(result)

    def test_declared_json_is_not_authenticated_verifier_output(self):
        for value in (None, True, {}, {"operator_grant": "PASS"}):
            with self.subTest(value=value):
                result = self.inspect(verifier=lambda _, value=value: value)
                self.assertEqual(result.reason, "AUTHORIZATION_UNAVAILABLE")
                self.assert_inactive(result)

    def test_every_receipt_binds_every_request_field(self):
        changes = {
            "repository": "another/repository", "product": "another",
            "workstation_id": "other-lane", "task_id": "other-task",
            "previous_owner": "other-owner", "worktree": "/other/worktree",
            "branch": "subsection/section--other", "target_branch": "section/other",
            "head_sha": "b" * 40, "remote_sha": "b" * 40,
            "frozen_snapshot_id": "snapshot-2", "freeze_incident_id": "incident-2",
            "repair_evidence_id": "repair-2", "issued_at": NOW - timedelta(seconds=2),
            "expires_at": NOW + timedelta(minutes=2),
        }
        for kind in KINDS:
            for field, value in changes.items():
                with self.subTest(kind=kind, field=field):
                    def verifier(binding, kind=kind, field=field, value=value):
                        changed = replace(binding, **{field: value})
                        if field in ("head_sha", "remote_sha"):
                            changed = replace(changed, head_sha=value, remote_sha=value)
                        return replace(verified(binding), **{
                            kind: RecoveryAttestation(changed, kind, "changed-receipt")
                        })
                    result = self.inspect(verifier=verifier)
                    self.assertEqual(result.reason, "ATTESTATION_MISMATCH")
                    self.assertFalse(result.bindings_validated)
                    self.assert_inactive(result)

    def test_missing_or_invalid_receipts_deny(self):
        for kind in KINDS:
            for value in (None, {}, RecoveryAttestation(request(), "wrong-kind", "receipt"),
                          RecoveryAttestation(request(), kind, "")):
                with self.subTest(kind=kind, value=value):
                    result = self.inspect(verifier=lambda b, kind=kind, value=value:
                                          replace(verified(b), **{kind: value}))
                    self.assertEqual(result.reason, "ATTESTATION_MISMATCH")
                    self.assert_inactive(result)

    def test_duplicate_receipt_identity_cannot_serve_as_independent_evidence(self):
        result = self.inspect(verifier=lambda b: VerifiedRecovery(**{
            kind: RecoveryAttestation(b, kind, "same-receipt") for kind in KINDS
        }))
        self.assertEqual(result.reason, "ATTESTATION_MISMATCH")
        self.assert_inactive(result)

    def test_malformed_request_never_calls_verifier(self):
        def forbidden(_):
            self.fail("verifier must not see invalid request")
        invalid = (
            replace(request(), task_id=""), replace(request(), previous_owner="unknown owner"),
            replace(request(), repository="../repository"),
            replace(request(), worktree="relative/path"),
            replace(request(), worktree="/fixture/../repaired"),
            replace(request(), branch="subsection/.hidden"),
            replace(request(), branch="subsection/lane.lock"),
            replace(request(), head_sha="0" * 40, remote_sha="0" * 40),
            replace(request(), remote_sha="b" * 40),
            replace(request(), frozen_snapshot_id=""), replace(request(), freeze_incident_id=""),
            replace(request(), repair_evidence_id=True),
            replace(request(), issued_at=NOW.replace(tzinfo=None)),
            replace(request(), expires_at=request().issued_at),
        )
        for binding in invalid:
            with self.subTest(binding=binding):
                result = self.inspect(binding, verifier=forbidden)
                self.assertEqual(result.reason, "INVALID_REQUEST")
                self.assert_inactive(result)

    def folded_request(self, issue_fold=0, expiry_fold=0):
        zone = ZoneInfo("America/New_York")
        return replace(request(),
                       issued_at=datetime(2026, 11, 1, 1, 10, tzinfo=zone, fold=issue_fold),
                       expires_at=datetime(2026, 11, 1, 1, 50, tzinfo=zone, fold=expiry_fold))

    def test_dst_fold_attestation_binds_distinct_utc_instants(self):
        binding = self.folded_request()
        changed = self.folded_request(1, 1)
        result = self.inspect(binding, verifier=lambda _: verified(changed),
                              clock=lambda: datetime(2026, 11, 1, 5, 30, tzinfo=timezone.utc))
        self.assertEqual(result.reason, "ATTESTATION_MISMATCH")
        self.assert_inactive(result)

    def test_dst_fold_clock_cannot_accept_expired_or_future_window(self):
        zone = ZoneInfo("America/New_York")
        for binding, fold in ((self.folded_request(), 1), (self.folded_request(1, 1), 0)):
            with self.subTest(window=binding, clock_fold=fold):
                result = self.inspect(binding,
                                      clock=lambda fold=fold: datetime(
                                          2026, 11, 1, 1, 30, tzinfo=zone, fold=fold))
                self.assertEqual(result.reason, "OUTSIDE_VALIDITY_WINDOW")
                self.assert_inactive(result)

    def test_equivalent_offset_representations_bind_same_instants(self):
        binding = request()
        zone = timezone(timedelta(hours=1))
        shifted = replace(binding, issued_at=binding.issued_at.astimezone(zone),
                          expires_at=binding.expires_at.astimezone(zone))
        result = self.inspect(binding, verifier=lambda _: verified(shifted))
        self.assertTrue(result.bindings_validated)
        self.assert_inactive(result)

    def test_dst_fold_reversed_interval_is_invalid(self):
        result = self.inspect(self.folded_request(1, 0),
                              clock=lambda: datetime(2026, 11, 1, 5, 30, tzinfo=timezone.utc))
        self.assertEqual(result.reason, "INVALID_REQUEST")
        self.assert_inactive(result)

    def test_broken_timezone_in_request_fails_closed(self):
        class BrokenTimezone(tzinfo):
            def utcoffset(self, value):
                raise RuntimeError("private timezone internals")
        binding = replace(request(), issued_at=NOW.replace(tzinfo=BrokenTimezone()))
        result = self.inspect(binding)
        self.assertEqual(result.reason, "INVALID_REQUEST")
        self.assert_inactive(result)

    def test_future_issue_and_exact_expiry_are_denied(self):
        for binding in (replace(request(), issued_at=NOW + timedelta(seconds=1)),
                        replace(request(), expires_at=NOW)):
            result = self.inspect(binding)
            self.assertEqual(result.reason, "OUTSIDE_VALIDITY_WINDOW")
            self.assertFalse(result.bindings_validated)
            self.assert_inactive(result)

    def test_slow_verification_cannot_validate_expired_evidence(self):
        ticks = iter((NOW, NOW + timedelta(minutes=1)))
        result = self.inspect(clock=lambda: next(ticks))
        self.assertEqual(result.reason, "OUTSIDE_VALIDITY_WINDOW")
        self.assertFalse(result.bindings_validated)
        self.assert_inactive(result)

    def test_verifier_and_clock_errors_fail_closed_without_leaking_details(self):
        def raises(*_):
            raise RuntimeError("private verifier internals")
        self.assertEqual(self.inspect(verifier=raises).reason, "VERIFIER_FAILED")
        self.assertEqual(self.inspect(clock=raises).reason, "CLOCK_UNAVAILABLE")
        self.assertEqual(self.inspect(clock=lambda: "now").reason, "CLOCK_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
