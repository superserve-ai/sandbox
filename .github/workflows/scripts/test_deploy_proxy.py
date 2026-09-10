import unittest
from pathlib import Path


SOURCE = Path(__file__).with_name("deploy-proxy.py").read_text()


class DeployProxyOrderingTest(unittest.TestCase):
    def test_ssh_key_created_before_parallel_fanout(self):
        # Per-host deploys run in parallel, and gcloud generates the runner's
        # SSH key on first use. Two hosts starting together race ssh-keygen and
        # one fails before uploading anything, so the key must exist before
        # the pool starts.
        keygen = SOURCE.find('"ssh-keygen", "-q"')
        pool = SOURCE.find("ThreadPoolExecutor(max_workers=len(instances))")
        self.assertNotEqual(keygen, -1)
        self.assertNotEqual(pool, -1)
        self.assertLess(keygen, pool)


if __name__ == "__main__":
    unittest.main()
