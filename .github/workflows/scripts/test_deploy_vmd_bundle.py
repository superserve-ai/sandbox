"""Every deploy/ file the remote script installs must ride in the bundle, or
the install fails on the host after the binaries were already copied. The
script checks this before touching any host; this pins the same property in
CI, and the wake-floor guard's own install paths.
"""

import re
import unittest
from pathlib import Path

SOURCE = Path(__file__).with_name("deploy-vmd.py").read_text()
WORKFLOW = (Path(__file__).parents[1] / "deploy-vmd.yml").read_text()


def _bundle_files():
    block = re.search(r"BUNDLE_FILES = \[(.*?)\]", SOURCE, re.S).group(1)
    return set(re.findall(r'"([^"]+)"', block))


class DeployVmdBundleTests(unittest.TestCase):
    def test_compatibility_preflight_changes_trigger_deployment(self):
        push_paths = re.search(
            r"(?m)^  push:\n(?:    .*\n)*?    paths:\n((?:      .*\n)+)", WORKFLOW
        ).group(1)
        self.assertIn("      - 'deploy/vmd-compatibility-preflight'\n", push_paths)

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

    def test_staged_intent_floor_guard_has_its_own_paths(self):
        # Its own executable and drop-in too: the revision that introduced
        # the wake floor reinstalls that guard when rolled back to, and would
        # erase a check added to it.
        self.assertIn("deploy/vmd-staged-intent-floor-guard", _bundle_files())
        self.assertIn("deploy/superserve-vmd-staged-intent-floor-guard.conf", _bundle_files())
        self.assertRegex(SOURCE, r"superserve-vmd\.service\.d/31-staged-intent-floor-guard\.conf")
        self.assertRegex(SOURCE, r"\{install_dir\}/vmd-staged-intent-floor-guard")
        check = SOURCE.index("deploy/vmd-compatibility-preflight {extract_dir}/bin/vmd")
        final_check = SOURCE.rindex("deploy/vmd-compatibility-preflight {extract_dir}/bin/vmd")
        install = SOURCE.index("sudo install -m 0755 {extract_dir}/bin/vmd {install_dir}/vmd")
        self.assertLess(final_check, install)
        # The guard is installed and loaded before the binary it fences lands,
        # so a deploy interrupted between the two never leaves a capable vmd
        # unguarded.
        guard = SOURCE.index("{install_dir}/vmd-staged-intent-floor-guard")
        retained_check = SOURCE.rindex("deploy/vmd-compatibility-preflight {extract_dir}/bin/vmd", 0, guard)
        self.assertLess(check, guard)
        self.assertLess(check, retained_check)
        self.assertLess(retained_check, guard)
        self.assertLess(guard, final_check)
        self.assertLess(SOURCE.index("systemctl daemon-reload", guard), final_check)

    def test_downgrade_is_checked_before_the_binary_lands(self):
        # Preflight runs both retained and bundled guards before any live change.
        check = SOURCE.index("deploy/vmd-compatibility-preflight {extract_dir}/bin/vmd")
        install = SOURCE.index("sudo install -m 0755 {extract_dir}/bin/vmd {install_dir}/vmd")
        self.assertLess(check, install)
