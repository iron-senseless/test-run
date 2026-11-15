"""Public CVE-2026-98260 abstract state tests. Never execute a timer/exec syscall."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "jobs"))
from port_cpu_r1_a1_model import POST_SWAP_FAILURES, SCENARIOS, simulate

class TimerOwnershipTests(unittest.TestCase):
    def test_post_swap_failures_have_conditional_old_only_stale_node(self):
        for phase in POST_SWAP_FAILURES:
            with self.subTest(phase=phase):
                old = simulate("old", phase)
                fixed = simulate("fixed", phase)
                self.assertTrue(old.stale_node_after_exit)
                self.assertTrue(old.late_read_freed_node)
                self.assertFalse(fixed.stale_node_after_exit)
                self.assertFalse(fixed.late_read_freed_node)
                self.assertFalse(old.pid_lookup_valid)
                self.assertTrue(old.timer_freed)

    def test_precommit_error_not_fatal(self):
        for version in ("old", "fixed"):
            x = simulate(version, "pre_commit")
            self.assertTrue(x.node_queued)
            self.assertFalse(x.timer_freed)
            self.assertFalse(x.late_read_freed_node)
            self.assertTrue(x.pid_lookup_valid)

    def test_failed_dethread_before_swap_keeps_pid_mapping(self):
        for version in ("old", "fixed"):
            x = simulate(version, "de_thread_before_swap")
            self.assertFalse(x.stale_node_after_exit)
            self.assertFalse(x.node_queued)
            self.assertTrue(x.pid_lookup_valid)

    def test_leader_exec_does_not_reassign_thread_pid(self):
        for version in ("old", "fixed"):
            for phase in POST_SWAP_FAILURES:
                x = simulate(version, phase, nonleader=False)
                self.assertTrue(x.pid_lookup_valid)
                self.assertFalse(x.stale_node_after_exit)

    def test_no_armed_timer_no_uaf(self):
        for phase in SCENARIOS:
            for version in ("old", "fixed"):
                x = simulate(version, phase, armed=False)
                self.assertFalse(x.stale_node_after_exit)
                self.assertFalse(x.late_read_freed_node)

    def test_success_has_cleanup_for_both_versions(self):
        for version in ("old", "fixed"):
            x = simulate(version, "success")
            self.assertTrue(x.timer_freed)
            self.assertFalse(x.node_queued)
            self.assertFalse(x.late_read_freed_node)

    def test_late_failure_after_cleanup_is_negative(self):
        for version in ("old", "fixed"):
            x = simulate(version, "late_failure")
            self.assertFalse(x.stale_node_after_exit)
            self.assertFalse(x.late_read_freed_node)

    def test_no_reap_means_no_late_access_in_model(self):
        x = simulate("old", "exec_mmap", parent_reaps=False)
        self.assertTrue(x.stale_node_after_exit)
        self.assertFalse(x.late_read_freed_node)

    def test_queued_not_freed_if_early_precommit(self):
        x = simulate("old", "pre_commit", armed=True)
        self.assertEqual((x.node_queued, x.timer_freed), (True, False))

    def test_no_claim_of_uid0_for_any_variant(self):
        for phase in SCENARIOS:
            for version in ("old", "fixed"):
                x = simulate(version, phase)
                self.assertFalse(x.uid0_proved)
                self.assertEqual(x.evidence, "UPSTREAM_DERIVED_HOST_SYNTHETIC")

    def test_invalid_parameters_fail(self):
        with self.assertRaises(ValueError):
            simulate("patched?", "exec_mmap")
        with self.assertRaises(ValueError):
            simulate("old", "unknown")

if __name__ == "__main__":
    unittest.main()
