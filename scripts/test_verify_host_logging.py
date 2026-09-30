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


if __name__ == "__main__":
    unittest.main()
