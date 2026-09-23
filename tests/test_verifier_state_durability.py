"""Tests for M-1: single-instance enforcement + durable boot floor.

The verifier's nonce/rate/spend tables are in-memory. M-1 closes the
resulting replay-on-restart hole with a durable boot floor
(boot_ts persisted before serving; requests with ts < boot_ts are
denied) and enforces single-instance with an flock so the tables can
never diverge across writers. The deployment contract lives in
docs/deployment-constraints.md.
"""
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from services.verifier import app  # noqa: E402


class BootFloorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state_dir = os.path.join(self.tmp.name, "vstate")
        self._saved_boot_ts = app.STATE._boot_ts

    def tearDown(self):
        app.STATE.set_boot_ts(self._saved_boot_ts)
        self.tmp.cleanup()

    def _boot(self, now=None):
        return app._init_boot_state(self.state_dir, now=now)

    def test_boot_record_written_before_serving(self):
        instance_id, boot_ts = self._boot(now=1_700_000_000.0)
        path = os.path.join(self.state_dir, "verifier-boot.json")
        with open(path, encoding="utf-8") as f:
            rec = json.load(f)
        self.assertEqual(rec["boot_ts"], boot_ts)
        self.assertEqual(rec["instance_id"], instance_id)
        self.assertEqual(len(instance_id), 16)
        # A second boot gets a fresh instance id.
        instance_id2, _ = self._boot(now=1_700_000_001.0)
        self.assertNotEqual(instance_id2, instance_id)

    def test_boot_ts_monotonic_across_restarts(self):
        # A previous floor in the future (backward clock step) is kept:
        # the floor never moves backward, so no replay window reopens.
        _, boot1 = self._boot(now=2_000_000_000.0)
        _, boot2 = self._boot(now=1_000_000_000.0)
        self.assertEqual(boot2, boot1)

    def test_predated_request_denied(self):
        _, boot_ts = self._boot(now=1_700_000_000.0)
        decision, reason, lane, _c, _e = app.decide(
            {"ts": boot_ts - 10, "nonce": "n1"})
        self.assertEqual(decision, "deny")
        self.assertIn("predates verifier boot", reason)
        self.assertEqual(lane, "unverified")

    def test_fresh_request_passes_boot_floor(self):
        self._boot(now=1_700_000_000.0)
        # ts is fresh: the boot check passes and the request proceeds
        # to the normal nonce check (denied here for the missing nonce,
        # which proves we got PAST the boot floor).
        decision, reason, _l, _c, _e = app.decide({"ts": time.time()})
        self.assertEqual(decision, "deny")
        self.assertNotIn("predates verifier boot", reason)
        self.assertIn("nonce", reason)

    def test_restart_closes_replay_window(self):
        # Generation 1 boots and serves. An attacker captures a request.
        _, boot1 = self._boot(now=1_700_000_000.0)
        captured_ts = boot1 + 5
        # The verifier restarts: nonce table is wiped (fresh process
        # state), but the boot floor advances.
        _, boot2 = self._boot(now=1_700_000_060.0)
        self.assertGreaterEqual(boot2, boot1)
        app.STATE._nonces.clear()  # what a restart does to the table
        # The captured request is inside its CLOCK_SKEW timestamp window
        # and its nonce is "unknown" — without the floor it would verify.
        self.assertNotIn("captured-nonce", app.STATE._nonces)
        decision, reason, _l, _c, _e = app.decide(
            {"ts": captured_ts, "nonce": "captured-nonce"})
        self.assertEqual(decision, "deny")
        self.assertIn("predates verifier boot", reason)

    def test_allows_timestamp_rejects_garbage(self):
        self._boot(now=1_700_000_000.0)
        for bad in (None, "", "yesterday", object()):
            self.assertFalse(app.STATE.allows_timestamp(bad, time.time()))

    def test_default_floor_is_permissive_until_boot(self):
        # A VerifierState that never booted (floor 0.0) allows any
        # non-negative ts — existing unit tests driving decide()
        # directly are unaffected.
        st = app.VerifierState()
        self.assertTrue(st.allows_timestamp(1.0, time.time()))


class InstanceLockTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state_dir = os.path.join(self.tmp.name, "vstate")
        self.fds = []

    def tearDown(self):
        for fd in self.fds:
            try:
                os.close(fd)
            except OSError:
                pass
        self.tmp.cleanup()

    def test_second_instance_fails_fast(self):
        self.fds.append(app._acquire_instance_lock(self.state_dir))
        with self.assertRaises(SystemExit) as cm:
            app._acquire_instance_lock(self.state_dir)
        self.assertEqual(cm.exception.code, 2)

    def test_lock_released_when_holder_dies(self):
        fd = app._acquire_instance_lock(self.state_dir)
        os.close(fd)  # holder death releases the flock
        self.fds.append(app._acquire_instance_lock(self.state_dir))

    def test_state_dir_created_0700(self):
        self.fds.append(app._acquire_instance_lock(self.state_dir))
        self.assertEqual(
            os.stat(self.state_dir).st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
