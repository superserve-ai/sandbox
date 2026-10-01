import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify-host-logging.py")
spec = importlib.util.spec_from_file_location("verify_host_logging_script", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
ROOT = SCRIPT.parents[1]


class HostLoggingContractChecks(unittest.TestCase):
    def test_current_contract(self):
        self.assertEqual(module.verify(ROOT), [])

    def test_export_failure_messages_match_explicit_self_log_contract(self):
        for message in (
                "failed to flush chunk to exporter",
                "exporting failed: permission denied",
                "dropped 12 records from buffer",
                "drop while retrying export"):
            with self.subTest(message=message):
                self.assertTrue(module.export_failure_message_matches(message))

    def test_unrelated_self_log_messages_do_not_match_export_failure_contract(self):
        for message in (
                "logging module started",
                "checkpoint restored",
                "flush chunk completed",
                "buffer usage is below the configured limit"):
            with self.subTest(message=message):
                self.assertFalse(module.export_failure_message_matches(message))


if __name__ == "__main__":
    unittest.main()
