"""Exercise real lifecycle entry points with isolated database/Git boundaries."""
import copy
import json
import runpy
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
GATES = ("ci_exact_sha", "review", "regression", "security")


class DevctlLifecycleTests(unittest.TestCase):
    def setUp(self):
        driver = types.ModuleType("psycopg2")
        extras = types.ModuleType("psycopg2.extras")
        driver.connect = mock.Mock(side_effect=AssertionError("live database forbidden"))
        extras.RealDictCursor = object
        extras.Json = lambda value: value
        driver.extras = extras
        with mock.patch.dict(sys.modules, {"psycopg2": driver, "psycopg2.extras": extras}):
            self.module = runpy.run_path(str(ROOT / "bin/codestra-devctl"), run_name="offline_lifecycle")
        self.connection = mock.MagicMock()
        self.connection.__enter__.return_value = self.connection
        self.row = dict(workstation_id="fixture-lane", product="Fixture", worktree="/unused", branch="fixture",
                        parent_branch="fixture-parent", depends_on=[], required_gates=list(GATES), status="IN_PROGRESS",
                        agent="fixture-owner", current_atomic_task="fixture-task", lease_state="ACTIVE",
                        lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
                        local_sha=SHA, remote_sha=SHA,
                        evidence={"gates": {name: {"result": "PASS", "exact_sha": SHA} for name in GATES}})
        self.args = types.SimpleNamespace(workstation="fixture-lane", agent="fixture-owner", task="fixture-task",
                                          json=json.dumps({"tests": "offline fixture"}))
        self.events = mock.Mock()
        self.git = mock.Mock(side_effect=self.fake_git)
        self.patch = mock.patch.dict(self.module["claim"].__globals__, {
            "conn": lambda: self.connection,
            "get_ws": lambda c, wid, lock=False: copy.deepcopy(self.row),
            "event": self.events, "git": self.git,
        })
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def fake_git(self, path, *args, **kwargs):
        if args[0] == "status":
            return types.SimpleNamespace(returncode=0, stdout="")
        if args[0] == "rev-parse":
            return types.SimpleNamespace(returncode=0, stdout=SHA + "\n")
        if args[0] == "ls-remote":
            return types.SimpleNamespace(returncode=0, stdout=SHA + "\trefs/heads/fixture\n")
        raise AssertionError("unexpected Git effect: " + repr(args))

    def refused(self, command, reason):
        with self.assertRaisesRegex(SystemExit, reason):
            self.module[command](self.args)
        self.connection.cursor.assert_not_called()
        self.events.assert_not_called()

    def test_frozen_and_stale_claims_require_recovery_even_for_previous_owner(self):
        for state in ("FROZEN", "STALE"):
            with self.subTest(state=state):
                self.row["lease_state"] = state
                self.refused("claim", "LEASE_RECOVERY_REQUIRED")

    def test_warning_lease_cannot_be_taken_by_another_owner(self):
        self.row.update(lease_state="WARNING", agent="existing-owner")
        self.refused("claim", "LEASE_HELD")

    def test_expired_lease_cannot_be_claimed_without_recovery(self):
        self.row["lease_expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=1)
        self.refused("claim", "LEASE_RECOVERY_REQUIRED")

    def test_free_lane_can_be_claimed_through_existing_entrypoint(self):
        self.row.update(lease_state="FREE", agent=None, lease_expires_at=None)
        self.module["claim"](self.args)
        self.events.assert_called_once()
        self.assertEqual(self.events.call_args.args[2], "CLAIM")

    def test_owner_heartbeat_clears_warning_and_renews_lease(self):
        self.row["lease_state"] = "WARNING"
        self.module["heartbeat"](self.args)
        query = self.connection.cursor.return_value.__enter__.return_value.execute.call_args.args[0]
        self.assertIn("lease_state='ACTIVE'", query)
        self.assertIn("lease_expires_at=", query)

    def test_expired_warning_cannot_be_revived_by_heartbeat(self):
        self.row.update(lease_state="WARNING", lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        self.refused("heartbeat", "LEASE_EXPIRED")

    def test_missing_or_naive_expiry_is_not_valid_ownership(self):
        for expiry in (None, datetime.now()):
            with self.subTest(expiry=expiry):
                self.row["lease_expires_at"] = expiry
                self.refused("heartbeat", "LEASE_EXPIRED")

    def test_preflight_rejects_expired_owner_before_git_or_external_effects(self):
        self.row["lease_expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=1)
        self.refused("preflight", "LEASE_EXPIRED")
        self.git.assert_not_called()

    def test_non_owner_cannot_write_evidence_or_complete(self):
        self.row["agent"] = "existing-owner"
        for command in ("set_evidence", "complete"):
            with self.subTest(command=command):
                self.refused(command, "LEASE_NOT_OWNED")
        self.git.assert_not_called()

    def test_frozen_owner_cannot_write_evidence(self):
        self.row["lease_state"] = "FROZEN"
        self.refused("set_evidence", "LEASE_NOT_OWNED")

    def test_stale_or_unbound_pass_assertions_do_not_complete(self):
        for gate in ("PASS", {"result": "PASS", "exact_sha": "b" * 40}, {"result": "PASS"}):
            with self.subTest(gate=gate):
                self.row["evidence"]["gates"]["ci_exact_sha"] = gate
                self.refused("complete", "COMPLETE_REFUSED.*CI_EXACT_SHA")

    def test_bound_passes_allow_complete_for_owned_unexpired_lease(self):
        self.module["complete"](self.args)
        self.events.assert_called_once()
        self.assertEqual(self.events.call_args.args[2], "COMPLETE")

    def test_lease_expiring_during_remote_validation_prevents_completion_write(self):
        with mock.patch.dict(self.module["complete"].__globals__, {
            "lease_unexpired": mock.Mock(side_effect=[True, False]),
        }):
            self.refused("complete", "LEASE_EXPIRED")

    def test_lease_expiring_during_preflight_prevents_progress_write(self):
        def preflight_git(path, *args, **kwargs):
            if args[0] == "status":
                return types.SimpleNamespace(returncode=0, stdout="")
            if args[0] == "branch":
                return types.SimpleNamespace(returncode=0, stdout="fixture\n")
            if args[0] == "rev-list":
                return types.SimpleNamespace(returncode=0, stdout="0 0\n")
            if args[0] == "grep":
                return types.SimpleNamespace(returncode=1, stdout="")
            return types.SimpleNamespace(returncode=0, stdout=SHA + "\n")
        with mock.patch.dict(self.module["preflight"].__globals__, {
            "lease_unexpired": mock.Mock(side_effect=[True, False]), "git": preflight_git,
        }), mock.patch("os.path.isdir", return_value=True), \
                mock.patch("subprocess.run", return_value=types.SimpleNamespace(returncode=0)):
            self.refused("preflight", "LEASE_EXPIRED")

    def test_certificate_requires_recorded_owner(self):
        self.row.update(status="COMPLETE", lease_state="FREE", agent="existing-owner")
        self.refused("certify", "LEASE_NOT_OWNED")

    def test_frozen_or_stale_lane_cannot_certify_a_complete_record(self):
        for state in ("FROZEN", "STALE", "WARNING", "ACTIVE"):
            with self.subTest(state=state):
                self.row.update(status="COMPLETE", lease_state=state)
                self.refused("certify", "CERTIFY_REFUSED lease_not_released")

    def test_new_commit_cannot_inherit_previous_completion(self):
        self.row.update(status="COMPLETE", lease_state="FREE", local_sha="b" * 40, remote_sha="b" * 40)
        self.refused("certify", "CERTIFY_REFUSED completion_drift")

    def test_certificate_persists_the_exact_validated_commit(self):
        self.row.update(status="COMPLETE", lease_state="FREE")
        self.module["certify"](self.args)
        call = self.connection.cursor.return_value.__enter__.return_value.execute.call_args
        self.assertIn("exact_sha_certified=", call.args[0])
        self.assertIn(SHA, call.args[1])

    def test_certificate_rejects_unbound_or_stale_mandatory_gates(self):
        self.row.update(status="COMPLETE", lease_state="FREE")
        self.row["evidence"]["gates"]["review"] = "PASS"
        self.refused("certify", "CERTIFY_REFUSED.*review")


if __name__ == "__main__":
    unittest.main()
