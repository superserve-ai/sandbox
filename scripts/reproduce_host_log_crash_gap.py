#!/usr/bin/env python3
"""Strict recovery regression for the deferred host-log delivery guarantee.

Run explicitly: python3 scripts/reproduce_host_log_crash_gap.py
The current direct-journald implementation is expected to FAIL this check.
Do not use an expectedFailure decorator or treat failure as rollout evidence.
"""
import tempfile
from pathlib import Path
import unittest

import test_host_logging_config as fixtures


class CrashRecoveryRequirement(unittest.TestCase):
    def test_retained_records_recover_after_queue_pressure_and_crash(self):
        fixtures.HostLoggingConfigChecks.setUpClass()
        fixture = fixtures.HostLoggingConfigChecks()
        with tempfile.TemporaryDirectory(prefix="host-log-recovery-") as directory:
            output = fixture._run_collector_fixture(
                fixture._render_templates(Path(directory)), outage=True, queue_pressure=True,
            )
        requests, self_logs = output.split("SELFLOGS", 1)
        self.assertIn("safe-info", requests, "retained INFO record skipped after queue pressure and crash")
        self.assertIn("proxy-safe", requests, "retained proxy record skipped after queue pressure and crash")
        self.assertIn("safe-warn", requests)
        self.assertIn("safe-error", requests)
        self.assertNotIn("SECRET_SENTINEL", output)


if __name__ == "__main__":
    unittest.main()
