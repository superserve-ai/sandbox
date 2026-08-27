import hashlib
import importlib.util
import unittest.mock
import os
import tempfile
import unittest

_spec = importlib.util.spec_from_file_location(
    "deploy_firecracker",
    os.path.join(os.path.dirname(__file__), "deploy-firecracker.py"),
)
deploy_firecracker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(deploy_firecracker)


class InstallScriptSafetyTest(unittest.TestCase):
    """The install script's invariants, each of which has a failure mode that
    is silent rather than loud if it regresses."""

    def setUp(self):
        self.script = deploy_firecracker.install_script("v1.2.3", "a" * 64)
        # Comments legitimately name the pitfalls they warn about, so
        # command-level assertions look at executable lines only.
        self.commands = "\n".join(
            line for line in self.script.splitlines()
            if not line.lstrip().startswith("#")
        )

    def test_backup_is_chained_to_install(self):
        # An un-chained backup lets a FAILED backup be followed by an install
        # that overwrites the binary the backup was meant to preserve.
        self.assertRegex(
            self.commands,
            r"cp -n[^\n]*\\\n\s*&& sudo install",
            "backup must be &&-chained to the install",
        )

    def test_replaces_the_live_binary_by_rename(self):
        # Writing to the live pathname directly exposes a window where a
        # launching sandbox execs a half-written binary, and fails with
        # ETXTBSY while any sandbox is running from it.
        self.assertRegex(
            self.commands,
            r'install -m 0755 "\$staged" "\$incoming"',
            "install must write a temporary file, not the live path",
        )
        self.assertRegex(
            self.commands,
            r'mv -f "\$incoming" "\$live"',
            "the temporary file must be renamed over the live path",
        )
        self.assertNotRegex(
            self.commands,
            r'install -m 0755 "\$staged" "\$live"',
            "must never install straight onto the live path",
        )

    def test_backup_does_not_use_update_none(self):
        # `--update=none` needs coreutils >= 9.3 and fails on the older hosts.
        self.assertNotIn("--update=none", self.commands)

    def test_refuses_without_the_stock_backup(self):
        self.assertIn(deploy_firecracker.STOCK_BACKUP, self.script)
        self.assertRegex(self.script, r'test -f "\$stock" \|\|')

    def test_verifies_digest_before_and_after_install(self):
        # Before: the bytes that arrived are the bytes that were built.
        self.assertIn("sha256sum -c -", self.script)
        # After: the swap actually landed.
        self.assertIn("post-install digest", self.script)

    def test_checks_capability_while_still_staged(self):
        # The loader/capability pre-check must happen against the staged copy,
        # so a binary this host cannot run is rejected with the live one intact.
        staged_check = self.script.index('"$staged" --version')
        install = self.script.index("sudo install")
        self.assertLess(staged_check, install)
        self.assertIn(deploy_firecracker.REQUIRED_CAPABILITY, self.script)

    def test_is_idempotent_when_already_at_the_target(self):
        # Re-running must not manufacture a second backup of a binary that is
        # already the target.
        self.assertIn("already at $digest", self.script)


    def test_backup_is_named_after_the_digest_it_preserves(self):
        # A per-version name is wrong the second time a version is deployed:
        # `cp -n` keeps the older file and the real predecessor is lost.
        self.assertRegex(
            self.commands,
            r'backup="\$live\.pre-\$\(sha256sum < "\$live"',
            "the backup name must derive from the live binary's digest",
        )
        self.assertNotIn("pre-v1.2.3.bak", self.commands)


class RegionTest(unittest.TestCase):
    def test_an_unset_region_is_refused(self):
        # Cells share a project and a label, so no region means every cell at
        # once rather than the one being deployed.
        import io
        import contextlib
        env = {"GCP_PROJECT": "p", "VMD_LABEL": "l", "GCP_REGION": "  "}
        with unittest.mock.patch.dict(os.environ, env, clear=True), \
                unittest.mock.patch("sys.argv", ["x", "--version", "v1"]):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = deploy_firecracker.main()
        self.assertEqual(rc, 1)
        self.assertIn("GCP_REGION is unset", err.getvalue())


class DigestTest(unittest.TestCase):
    def test_sha256_of_matches_hashlib(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"firecracker bytes")
            path = f.name
        try:
            self.assertEqual(
                deploy_firecracker.sha256_of(path),
                hashlib.sha256(b"firecracker bytes").hexdigest(),
            )
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
