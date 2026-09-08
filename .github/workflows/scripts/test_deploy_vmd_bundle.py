"""Every deploy/ file the remote script installs must ride in the bundle, or
the install fails on the host after the binaries were already copied. The
script checks this before touching any host; this pins the same property in
CI, and the wake-floor guard's own install paths.
"""

import re
import unittest
from pathlib import Path

SOURCE = Path(__file__).with_name("deploy-vmd.py").read_text()


def _bundle_files():
    block = re.search(r"BUNDLE_FILES = \[(.*?)\]", SOURCE, re.S).group(1)
    return set(re.findall(r'"([^"]+)"', block))


class DeployVmdBundleTests(unittest.TestCase):
    def test_every_installed_deploy_file_is_bundled(self):
        referenced = set(re.findall(r"\{extract_dir\}/(deploy/[A-Za-z0-9_.@-]+)", SOURCE))
        self.assertTrue(referenced)
        self.assertEqual(sorted(referenced - _bundle_files()), [])

    def test_wake_floor_guard_has_its_own_paths(self):
        # A drop-in and executable of their own, at names no earlier deploy
        # script writes, so a rollback that reinstalls that script's guard
        # leaves this one in place.
        self.assertIn("deploy/vmd-wake-floor-guard", _bundle_files())
        self.assertIn("deploy/superserve-vmd-wake-floor-guard.conf", _bundle_files())
        self.assertRegex(SOURCE, r"superserve-vmd\.service\.d/30-wake-floor-guard\.conf")
        self.assertRegex(SOURCE, r"\{install_dir\}/vmd-wake-floor-guard")

    def test_downgrade_is_checked_before_the_binary_lands(self):
        # The deploy runs the bundled guard against the new binary, so the
        # check has one source, and it runs before the binary is installed.
        check = SOURCE.index("deploy/vmd-wake-floor-guard {extract_dir}/bin/vmd")
        install = SOURCE.index("sudo install -m 0755 {extract_dir}/bin/vmd {install_dir}/vmd")
        self.assertLess(check, install)
