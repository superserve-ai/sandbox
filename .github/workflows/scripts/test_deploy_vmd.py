#!/usr/bin/env python3
"""Focused tests for the optional staging data-disk deployment path.

The setup-script tests execute a transformed temporary copy with command
shims.  They exercise the real validation/refusal flow without root access,
mounts, or block devices; the repository script itself is never modified.
"""

import importlib.util
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[3]
DEPLOY_SCRIPT = Path(__file__).with_name("deploy-vmd.py")
SETUP_SCRIPT = REPO_ROOT / "scripts" / "setup-sandbox-data-disk.sh"


def load_deploy_module():
    spec = importlib.util.spec_from_file_location("deploy_vmd", DEPLOY_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


deploy_vmd = load_deploy_module()


class DeployVmdDataDiskTests(unittest.TestCase):
    def render_remote_script(self, data_disk_device=""):
        ssh_commands = []

        def fake_subprocess_run(command, *args, **kwargs):
            if command[:4] == ["gcloud", "compute", "instances", "list"]:
                return SimpleNamespace(
                    returncode=0,
                    stdout="staging-vmd,us-central1-a\n",
                    stderr="",
                )
            if command[:3] == ["gcloud", "compute", "ssh"]:
                ssh_commands.append(command[command.index("--command") + 1])
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            self.fail(f"unexpected subprocess.run command: {command!r}")

        environ = {
            "GCP_PROJECT": "test-project",
            "GCP_REGION": "us-central1",
            "VMD_LABEL": "component=vmd",
            "VMD_SERVICE": "superserve-vmd",
            "VMD_INSTALL_DIR": "/usr/local/bin",
            "SHA": "0123456789abcdef",
        }
        if data_disk_device:
            environ["SANDBOX_DATA_DISK_DEVICE"] = data_disk_device

        with mock.patch.dict(deploy_vmd.os.environ, environ, clear=True), mock.patch.object(
            deploy_vmd, "run_or_die"
        ), mock.patch.object(
            deploy_vmd.subprocess, "run", side_effect=fake_subprocess_run
        ), mock.patch.object(
            deploy_vmd.os.path, "getsize", return_value=123
        ):
            self.assertEqual(deploy_vmd.main(), 0)

        self.assertEqual(len(ssh_commands), 1)
        return ssh_commands[0]

    def test_data_disk_device_validation(self):
        valid = deploy_vmd.STAGING_DATA_DISK_DEVICE
        self.assertEqual(
            deploy_vmd.optional_data_disk_device(
                {"SANDBOX_DATA_DISK_DEVICE": f"  {valid}  "}
            ),
            valid,
        )
        self.assertEqual(deploy_vmd.optional_data_disk_device({}), "")

        invalid_values = (
            "/dev/sdb",
            "/dev/disk/by-id/scsi-superserve-sandbox-data",
            "/dev/disk/by-id/google-other-data-disk",
            "/dev/disk/by-id/google-data/partition",
            "/dev/disk/by-id/google-data; reboot",
            "/dev/disk/by-id/google-data $(id)",
        )
        for value in invalid_values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                deploy_vmd.optional_data_disk_device(
                    {"SANDBOX_DATA_DISK_DEVICE": value}
                )

    def test_bundle_and_staging_install_wiring(self):
        expected_bundle_files = {
            "deploy/sandbox-data-disk.service",
            "scripts/setup-sandbox-data-disk.sh",
        }
        self.assertTrue(expected_bundle_files.issubset(deploy_vmd.BUNDLE_FILES))
        for relative_path in expected_bundle_files:
            self.assertTrue((REPO_ROOT / relative_path).is_file(), relative_path)

        device = deploy_vmd.STAGING_DATA_DISK_DEVICE
        remote_script = self.render_remote_script(device)
        expected_fragments = (
            "sudo install -m 0755 /tmp/deploy-01234567/scripts/setup-sandbox-data-disk.sh /usr/local/bin/setup-sandbox-data-disk.sh",
            "sudo install -m 0644 /tmp/deploy-01234567/deploy/sandbox-data-disk.service /etc/systemd/system/sandbox-data-disk.service",
            f"DATA_DISK_EXPECTED_DEVICE={device}",
            f"DATA_DISK_REQUESTED_DEVICE={device}",
            'printf \'%s\\n\' "SANDBOX_DATA_DISK_DEVICE=$DATA_DISK_EXPECTED_DEVICE"',
            "sudo /usr/local/bin/setup-sandbox-data-disk.sh --verify-only",
            "sudo systemctl start sandbox-data-disk.service",
            "sudo systemctl enable --quiet sandbox-data-disk.service",
            "sudo systemctl disable --quiet sandbox-data-disk.service",
            'sudo rm -f "$DATA_DISK_CONFIG_FILE"',
            "sudo journalctl -u sandbox-data-disk.service --no-pager -n 160",
        )
        for fragment in expected_fragments:
            self.assertIn(fragment, remote_script)
        self.assertEqual(
            remote_script.count(
                "sudo systemctl enable --quiet sandbox-data-disk.service"
            ),
            1,
        )
        self.assertNotIn("restart sandbox-data-disk.service", remote_script)
        self.assertNotIn(
            "tee /etc/systemd/system/superserve-vmd.service.d", remote_script
        )

        first_start = remote_script.index(
            "sudo systemctl start sandbox-data-disk.service"
        )
        requested_branch = remote_script.index(
            'if [ -n "$DATA_DISK_REQUESTED_DEVICE" ]; then'
        )
        remote_allowlist = remote_script.index(
            'if [ "$DATA_DISK_REQUESTED_DEVICE" != '
            '"$DATA_DISK_EXPECTED_DEVICE" ]',
            requested_branch,
        )
        pre_authority_disable = remote_script.index(
            "sudo systemctl disable --quiet sandbox-data-disk.service",
            remote_allowlist,
        )
        first_asset_install_call = remote_script.index(
            "\n    install_data_disk_assets\n",
            pre_authority_disable,
        )
        durable_postcondition = remote_script.index(
            'if ! sudo test -f "$DATA_DISK_AUTHORITY_MARKER"'
        )
        first_enable = remote_script.index(
            "sudo systemctl enable --quiet sandbox-data-disk.service"
        )
        self.assertLess(remote_allowlist, pre_authority_disable)
        self.assertLess(pre_authority_disable, first_asset_install_call)
        self.assertLess(first_start, durable_postcondition)
        self.assertLess(durable_postcondition, first_enable)
        self.assertLess(
            remote_script.index("install_data_disk_assets"),
            remote_script.index("# Install vmd + template-builder binaries"),
        )

    def test_omitted_device_only_reconciles_authoritative_hosts(self):
        remote_script = self.render_remote_script()
        self.assertIn("DATA_DISK_REQUESTED_DEVICE=''", remote_script)
        authority_branch = remote_script.index(
            'elif [ "$DATA_DISK_HAD_AUTHORITY" = 1 ]; then'
        )
        stale_config_branch = remote_script.index(
            'elif [ "$DATA_DISK_HAD_CONFIG" = 1 ]; then',
            authority_branch,
        )
        authoritative_reconcile = remote_script[
            authority_branch:stale_config_branch
        ]
        self.assertIn("install_data_disk_assets", authoritative_reconcile)
        self.assertIn(
            "setup-sandbox-data-disk.sh --verify-only",
            authoritative_reconcile,
        )
        self.assertNotIn(
            "systemctl start sandbox-data-disk.service",
            authoritative_reconcile,
        )
        stale_config_cleanup = remote_script[
            stale_config_branch:remote_script.index(
                'if [ "$DATA_DISK_SETUP_ATTEMPTED" = 1 ]',
                stale_config_branch,
            )
        ]
        self.assertIn(
            "systemctl disable --quiet sandbox-data-disk.service",
            stale_config_cleanup,
        )
        self.assertIn('rm -f "$DATA_DISK_CONFIG_FILE"', stale_config_cleanup)
        self.assertNotIn("restart sandbox-data-disk.service", remote_script)

    def test_workflow_activation_is_manual_opt_in_and_staging_only(self):
        workflow = (REPO_ROOT / ".github/workflows/deploy-vmd.yml").read_text()
        self.assertEqual(
            workflow.count("\n          SANDBOX_DATA_DISK_DEVICE:"),
            1,
        )
        staging_job = workflow.index("deploy-staging:")
        production_job = workflow.index("deploy-production:")
        device_setting = workflow.index("SANDBOX_DATA_DISK_DEVICE:")
        self.assertLess(staging_job, device_setting)
        self.assertLess(device_setting, production_job)
        self.assertIn("activate_staging_snapshot_storage:", workflow)
        self.assertIn("staging_snapshot_storage_device:", workflow)
        self.assertIn("default: false", workflow)
        self.assertIn(
            "github.event_name == 'workflow_dispatch' && "
            "inputs.activate_staging_snapshot_storage",
            workflow,
        )
        self.assertIn(
            "staging_snapshot_storage_device is required when activation is enabled",
            workflow,
        )
        exact_guard = workflow.index(
            'if [[ "$SANDBOX_DATA_DISK_DEVICE" != '
            '"/dev/disk/by-id/google-superserve-sandbox-data" ]]'
        )
        deploy_call = workflow.index(
            "python3 .github/workflows/scripts/deploy-vmd.py",
            exact_guard,
        )
        self.assertLess(exact_guard, deploy_call)
        self.assertIn("unset SANDBOX_DATA_DISK_DEVICE", workflow)

    def test_workflow_tracks_saved_snapshot_deploy_inputs(self):
        workflow = (REPO_ROOT / ".github/workflows/deploy-vmd.yml").read_text()
        expected_paths = (
            "'proto/vmd.proto'",
            "'proto/vmdpb/**'",
            "'internal/vmdclient/**'",
            "'deploy/sandbox-data-disk.service'",
            "'scripts/setup-sandbox-data-disk.sh'",
            "'.github/workflows/scripts/test_deploy_vmd.py'",
        )
        for path in expected_paths:
            with self.subTest(path=path):
                self.assertIn(path, workflow)


class SetupSandboxDataDiskTests(unittest.TestCase):
    def write_shim(self, shim_dir, name, body):
        path = shim_dir / name
        path.write_text("#!/bin/sh\nset -eu\n" + body)
        path.chmod(0o755)

    def make_harness(self, root, allow_regular_device=False):
        source = SETUP_SCRIPT.read_text()
        vmd_env = str(root / "vmd.env")
        lock_root = str(root / "lock")
        self.assertEqual(source.count("/etc/sandbox/vmd.env"), 4)
        self.assertEqual(source.count("/run/lock"), 2)
        source = source.replace("/etc/sandbox/vmd.env", vmd_env)
        source = source.replace("/run/lock", lock_root)
        replacements = {
            "readonly CONFIG_FILE=/etc/sandbox/data-disk.env": (
                f"readonly CONFIG_FILE={shlex.quote(str(root / 'data-disk.env'))}"
            ),
            "readonly AUTHORITY_MARKER=/etc/sandbox/data-disk-authoritative": (
                f"readonly AUTHORITY_MARKER={shlex.quote(str(root / 'data-disk-authoritative'))}"
            ),
            "readonly MOUNT_ROOT=/mnt/sandbox-data": (
                f"readonly MOUNT_ROOT={shlex.quote(str(root / 'mount'))}"
            ),
            "readonly CANON_RUNDIR=/var/lib/sandbox/rundir": (
                f"readonly CANON_RUNDIR={shlex.quote(str(root / 'canonical-rundir'))}"
            ),
            "readonly CANON_SNAPSHOTS=/var/lib/sandbox/snapshots": (
                f"readonly CANON_SNAPSHOTS={shlex.quote(str(root / 'canonical-snapshots'))}"
            ),
            '[[ "$EUID" -eq 0 ]] || fail "must run as root"': (
                ": # root check disabled only in this temporary test copy"
            ),
        }
        if allow_regular_device:
            replacements.update(
                {
                    "readonly EXPECTED_DEVICE=/dev/disk/by-id/google-superserve-sandbox-data": (
                        'readonly EXPECTED_DEVICE="${TEST_DEVICE_PATH:-/dev/disk/by-id/google-superserve-sandbox-data}"'
                    ),
                    '[[ -b "$resolved_device" ]] || fail "configured path is not a block device: $configured_device"': (
                        '[[ -f "$resolved_device" ]] || fail "configured path is not a block device: $configured_device"'
                    ),
                }
            )

        for original, replacement in replacements.items():
            self.assertIn(original, source, f"test harness target drifted: {original}")
            source = source.replace(original, replacement, 1)

        harness = root / "setup-sandbox-data-disk.test.sh"
        harness.write_text(source)
        harness.chmod(0o755)
        return harness

    def make_shims(self, root):
        shim_dir = root / "shims"
        shim_dir.mkdir()
        self.write_shim(
            shim_dir,
            "findmnt",
            """if [ "$*" = "-n -T / -o SOURCE" ]; then
    printf '%s\\n' "$TEST_ROOT_DEVICE"
    exit 0
fi
exit 98
""",
        )
        self.write_shim(
            shim_dir,
            "lsblk",
            """case "$*" in
    *PKNAME*) exit 0 ;;
    *"-o TYPE"*) printf '%s\\n' disk ;;
    *"-o NAME"*) printf '%s\\n' fake-data-disk ;;
    *) exit 97 ;;
esac
""",
        )
        self.write_shim(
            shim_dir,
            "systemctl",
            """if [ "${1:-}" = list-units ]; then
    printf '%s\\n' 'firecracker@test-sandbox.service loaded active running test'
    exit 0
fi
if [ "${1:-}" = stop ]; then
    printf '%s\\n' "$0 $*" >> "$TEST_MUTATION_LOG"
    exit 0
fi
exit 96
""",
        )
        self.write_shim(shim_dir, "flock", "exit 0\n")
        self.write_shim(shim_dir, "mountpoint", "exit 1\n")
        mutation_body = """printf '%s\\n' "$0 $*" >> "$TEST_MUTATION_LOG"
exit 95
"""
        for command in (
            "blkid",
            "mkdir",
            "mkfs.xfs",
            "mount",
            "umount",
            "wipefs",
            "xfs_info",
        ):
            self.write_shim(shim_dir, command, mutation_body)
        return shim_dir

    def run_harness(self, root, harness, shim_dir, extra_env=None, args=()):
        root_device = root / "root-device"
        root_device.touch(exist_ok=True)
        (root / "vmd.env").touch(exist_ok=True)
        mutation_log = root / "mutations.log"
        env = os.environ.copy()
        env.pop("SANDBOX_DATA_DISK_DEVICE", None)
        env.update(
            {
                "PATH": f"{shim_dir}{os.pathsep}{env['PATH']}",
                "TEST_ROOT_DEVICE": str(root_device),
                "TEST_MUTATION_LOG": str(mutation_log),
            }
        )
        if extra_env:
            env.update(extra_env)
        result = subprocess.run(
            [shutil.which("bash") or "bash", str(harness), *args],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        return result, mutation_log

    def test_missing_device_config_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            harness = self.make_harness(root)
            shims = self.make_shims(root)
            result, mutation_log = self.run_harness(root, harness, shims)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "SANDBOX_DATA_DISK_DEVICE is not configured", result.stderr
            )
            self.assertFalse(mutation_log.exists())

    def test_config_file_rejects_unknown_and_duplicate_assignments(self):
        invalid_contents = (
            "OTHER=value\n",
            "SANDBOX_DATA_DISK_DEVICE=/dev/disk/by-id/google-one\n"
            "SANDBOX_DATA_DISK_DEVICE=/dev/disk/by-id/google-two\n",
        )
        for contents in invalid_contents:
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                harness = self.make_harness(root)
                shims = self.make_shims(root)
                (root / "data-disk.env").write_text(contents)
                result, mutation_log = self.run_harness(root, harness, shims)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("data-disk.env", result.stderr)
                self.assertFalse(mutation_log.exists())

    def test_non_allowlisted_device_is_rejected_before_host_mutation(self):
        invalid_devices = (
            "/tmp/not-a-stable-device",
            "/dev/disk/by-id/google-other-data-disk",
        )
        for invalid_device in invalid_devices:
            with self.subTest(device=invalid_device), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                harness = self.make_harness(root)
                shims = self.make_shims(root)
                result, mutation_log = self.run_harness(
                    root,
                    harness,
                    shims,
                    {"SANDBOX_DATA_DISK_DEVICE": invalid_device},
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "device must be exactly "
                    "/dev/disk/by-id/google-superserve-sandbox-data",
                    result.stderr,
                )
                self.assertFalse(mutation_log.exists())

    def test_exact_device_guard_precedes_filesystem_formatting(self):
        source = SETUP_SCRIPT.read_text()
        exact_guard = source.index(
            '[[ "$configured_device" == "$EXPECTED_DEVICE" ]]'
        )
        format_call = source.index("mkfs.xfs -m crc=1,reflink=1", exact_guard)
        self.assertLess(exact_guard, format_call)

    def test_active_firecracker_refuses_migration_before_host_mutation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            harness = self.make_harness(root, allow_regular_device=True)
            shims = self.make_shims(root)
            data_device = root / "data-device"
            data_device.touch()
            result, mutation_log = self.run_harness(
                root,
                harness,
                shims,
                {
                    "SANDBOX_DATA_DISK_DEVICE": str(data_device),
                    "TEST_DEVICE_PATH": str(data_device),
                },
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "data disk is not mounted and Firecracker is running; drain the host before setup",
                result.stderr,
            )
            self.assertIn("firecracker@test-sandbox.service", result.stderr)
            self.assertFalse(mutation_log.exists())

    def test_verify_only_ready_path_returns_before_service_mutation(self):
        source = SETUP_SCRIPT.read_text()
        ready_check = source.index('if [[ -f "$ACTIVATION_MARKER" ]] &&')
        ready_return = source.index("return 0", ready_check)
        verify_only_guard = source.index(
            '(( verify_only == 0 )) || fail "data-disk verification requested',
            ready_return,
        )
        first_service_stop = source.index(
            'systemctl stop "$VMD_SOCKET" ||', verify_only_guard
        )

        self.assertLess(ready_check, ready_return)
        self.assertLess(ready_return, verify_only_guard)
        self.assertLess(verify_only_guard, first_service_stop)

    def test_failed_direct_verification_stops_vmd_control_plane(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            harness = self.make_harness(root, allow_regular_device=True)
            shims = self.make_shims(root)
            data_device = root / "data-device"
            data_device.touch()
            result, mutation_log = self.run_harness(
                root,
                harness,
                shims,
                {
                    "SANDBOX_DATA_DISK_DEVICE": str(data_device),
                    "TEST_DEVICE_PATH": str(data_device),
                },
                ("--verify-only",),
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("verify-only mode requires an existing", result.stderr)
            self.assertIn(
                "systemctl stop superserve-vmd.socket superserve-vmd.service",
                mutation_log.read_text(),
            )

    def test_authority_gate_is_durable_before_atomic_commit(self):
        source = SETUP_SCRIPT.read_text()
        migration_block = source.index('if [[ ! -e "$DATA_ROOT" ]]')
        dependency_install = source.index(
            "install_fail_closed_dependencies", migration_block
        )
        authority_assignment = source.index(
            "data_authoritative=1", dependency_install
        )
        authority_marker = source.index("write_authority_marker", authority_assignment)
        atomic_commit = source.index('mv -- "$migration_tmp" "$DATA_ROOT"')

        self.assertLess(dependency_install, authority_assignment)
        self.assertLess(authority_assignment, authority_marker)
        self.assertLess(authority_marker, atomic_commit)

    def test_authoritative_cleanup_stops_runtime(self):
        source = SETUP_SCRIPT.read_text()
        cleanup = source.index("cleanup() {")
        cleanup_end = source.index("trap cleanup EXIT RETURN", cleanup)
        cleanup_source = source[cleanup:cleanup_end]

        self.assertIn("stop_vmd_control_plane_fail_closed", cleanup_source)
        self.assertIn("data_authoritative == 0", cleanup_source)


if __name__ == "__main__":
    unittest.main()
