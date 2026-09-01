"""Regression guards for the vmd deploy-ordering that caused the
socket-activation double-restart incident.

The ordering is a shell sequence built into a heredoc by deploy-vmd.py, so it is
not a pure function; these assert on the rendered template text. Each test pins
one property whose violation reintroduces the incident.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).with_name("deploy-vmd.py").read_text()


def _gnu_sed_env(tmp_dir):
    # The rendered blocks below run through `sh -c` for real, and this
    # script's `sed -i PATTERN FILE` (no backup-suffix argument) is GNU
    # syntax — correct on the Linux deploy targets and the CI runner, but
    # BSD sed (stock on macOS) parses the pattern as a mandatory backup
    # suffix instead and silently no-ops. Shim `sed` to GNU sed (`gsed`
    # via Homebrew) when running locally on macOS so these tests validate
    # the same behavior contributors will see in CI, not a platform quirk.
    gnu_sed = shutil.which("sed")
    if gnu_sed:
        version = subprocess.run([gnu_sed, "--version"], capture_output=True, text=True)
        if "GNU sed" not in version.stdout:
            gnu_sed = shutil.which("gsed")
    if not gnu_sed or gnu_sed == shutil.which("sed"):
        return dict(os.environ)
    shim_dir = Path(tmp_dir) / "gnu-sed-shim"
    shim_dir.mkdir()
    (shim_dir / "sed").symlink_to(gnu_sed)
    return dict(os.environ, PATH="%s:%s" % (shim_dir, os.environ["PATH"]))


class DeployVmdOrderingTests(unittest.TestCase):
    def test_no_bare_service_stop(self):
        # The early service stop that opened the socket-activation window must
        # never be unconditional/bare: every stop of the vmd service also stops
        # superserve-vmd.socket (both-units form) so no connection can
        # socket-activate an interim vmd during the window.
        self.assertNotRegex(
            SOURCE,
            r"systemctl stop \{service\}",
            "found a bare `systemctl stop {service}`; every service stop must "
            "also stop superserve-vmd.socket",
        )

    def test_steady_state_stop_is_guarded_and_stops_both(self):
        # The steady-state early stop runs ONLY on a fresh socket migration
        # (socket inactive) or a socket-definition change, and stops BOTH units.
        self.assertRegex(
            SOURCE,
            r'if ! systemctl is-active --quiet superserve-vmd\.socket'
            r' \|\| \[ "\$SOCKET_CHANGED" = 1 \]; then\s*\n'
            r'\s*sudo systemctl stop superserve-vmd\.socket \{service\}',
        )

    def test_exactly_one_cutover_restart(self):
        # Steady state does exactly one service restart (the cutover). A second
        # is the double-restart this fix removed.
        self.assertEqual(len(re.findall(r"systemctl restart \{service\}", SOURCE)), 1)

    def test_waits_for_application_readiness_not_just_is_active(self):
        # Readiness gates on vmd's real request gate (startupReady, logged as
        # "gRPC serving requests"), scoped to the unit's CURRENT systemd
        # invocation — not a bare is-active (Type=simple only proves the process
        # forked) and not a prior/crashed invocation's line.
        self.assertRegex(SOURCE, r"-g 'gRPC serving requests'")
        self.assertIn("_SYSTEMD_INVOCATION_ID", SOURCE)
        # ...and must not gate readiness on a bare sleep + is-active.
        self.assertNotRegex(
            SOURCE,
            r"sleep 3\s*\n\s*sudo systemctl is-active --quiet \{service\}",
        )

    def test_readiness_scan_does_not_pipe_journalctl_to_grep(self):
        # Under `set -o pipefail`, grep closing the pipe on a match SIGPIPEs
        # journalctl and the pipeline reads non-zero even on success — a false
        # timeout. The readiness scan must capture output, not pipe to grep -q.
        self.assertNotRegex(SOURCE, r"journalctl[^\n]*\|\s*grep -q")

    def test_readiness_query_drives_off_exit_status_not_captured_output(self):
        # journalctl -g prints "-- No entries --" to stdout and exits nonzero on
        # no match; capturing that stdout (esp. with `|| true`) reads the marker
        # as a false-ready. The query must drive off exit status: --quiet, output
        # to /dev/null, and never `|| true` on the readiness journalctl.
        self.assertRegex(
            SOURCE,
            r"journalctl[^\n]*--quiet[^\n]*-g 'gRPC serving requests'[^\n]*>/dev/null",
        )
        self.assertNotRegex(SOURCE, r"journalctl[^\n]*gRPC serving requests[^\n]*\|\| true")

    def test_no_match_journalctl_is_not_ready(self):
        # Behavioral: a journalctl that prints the empty-result marker and exits
        # nonzero (the real no-match behavior) must make the exit-status query
        # read as not-ready; a matching one (exit 0) as ready.
        query = (
            "if journalctl --quiet -g 'gRPC serving requests' --no-pager "
            ">/dev/null 2>&1; then echo READY; else echo NOTREADY; fi"
        )
        for exit_code, stdout, expect in (
            (1, "-- No entries --", "NOTREADY"),
            (0, "match", "READY"),
        ):
            with tempfile.TemporaryDirectory() as d:
                fake = Path(d) / "journalctl"
                fake.write_text("#!/bin/sh\necho '%s'\nexit %d\n" % (stdout, exit_code))
                fake.chmod(0o755)
                env = dict(os.environ, PATH="%s:%s" % (d, os.environ["PATH"]))
                out = subprocess.run(
                    ["sh", "-c", query], env=env, capture_output=True, text=True
                ).stdout
                self.assertIn(expect, out, "exit=%d" % exit_code)


class BackupStagingDirRollbackTests(unittest.TestCase):
    # Regression guard for a rollback hazard: pre-this-var vmd binaries treat
    # BACKUP_STAGING_DIR as the single staging root, so a stale line left
    # behind by a prior deploy would silently move pause-hot-path staging
    # onto the dedicated disk on a rolled-back binary. The upsert must clear
    # stale host state even when the incoming value is empty, not just skip
    # writing new state.

    def _staging_dir_block(self):
        match = re.search(
            r"# Upsert BACKUP_STAGING_DIR.*?\n(?:.*\n)*?\s*fi\n", SOURCE
        )
        self.assertIsNotNone(match, "could not locate the BACKUP_STAGING_DIR upsert block")
        return match.group(0)

    def test_delete_is_not_gated_on_the_empty_value_guard(self):
        # The sed delete must run unconditionally: only the append (echo/tee)
        # may live inside `if [ -n ... ]; then ... fi`.
        block = self._staging_dir_block()
        guard = re.search(r"if \[ -n \{q_backup_staging\} \]; then\n(.*\n)*?\s*fi\n", block)
        self.assertIsNotNone(guard, "expected an `if [ -n {q_backup_staging} ]` guard")
        self.assertNotIn(
            "sed -i",
            guard.group(0),
            "the sed delete must run before/outside the empty-value guard, "
            "or an empty incoming value leaves a stale BACKUP_STAGING_DIR "
            "line on the host",
        )
        self.assertIn("sed -i", block)

    def test_empty_value_clears_a_stale_line_on_the_host(self):
        # Behavioral: render the block with an empty incoming value against a
        # fake vmd.env carrying a stale line from a prior deploy, and confirm
        # the line is actually gone afterward.
        block = self._staging_dir_block()
        rendered = block.replace("{q_backup_staging}", "''").replace(
            "{q_backup_staging_line}", "'unused'"
        )
        rendered = rendered.replace("sudo ", "")
        with tempfile.TemporaryDirectory() as d:
            env_file = Path(d) / "vmd.env"
            env_file.write_text("BACKUP_STAGING_DIR=/mnt/localssd/backup-staging\nOTHER=1\n")
            script = rendered.replace("/etc/sandbox/vmd.env", str(env_file))
            result = subprocess.run(
                ["sh", "-c", script], capture_output=True, text=True, env=_gnu_sed_env(d)
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("BACKUP_STAGING_DIR", env_file.read_text())
            self.assertIn("OTHER=1", env_file.read_text())

    def test_non_empty_value_replaces_a_stale_line_on_the_host(self):
        # Companion behavioral case: a new value still upserts correctly
        # (delete-then-append), not just delete-and-skip.
        block = self._staging_dir_block()
        rendered = block.replace("{q_backup_staging}", "'/mnt/new-disk/staging'").replace(
            "{q_backup_staging_line}", "'BACKUP_STAGING_DIR=/mnt/new-disk/staging'"
        )
        rendered = rendered.replace("sudo ", "")
        with tempfile.TemporaryDirectory() as d:
            env_file = Path(d) / "vmd.env"
            env_file.write_text("BACKUP_STAGING_DIR=/mnt/localssd/backup-staging\nOTHER=1\n")
            script = rendered.replace("/etc/sandbox/vmd.env", str(env_file))
            result = subprocess.run(
                ["sh", "-c", script], capture_output=True, text=True, env=_gnu_sed_env(d)
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            content = env_file.read_text()
            self.assertIn("BACKUP_STAGING_DIR=/mnt/new-disk/staging", content)
            self.assertNotIn("/mnt/localssd/backup-staging", content)
            self.assertIn("OTHER=1", content)


if __name__ == "__main__":
    unittest.main()
