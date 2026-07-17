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
    def render_remote_script(
        self,
        data_disk_device="",
        migration_probe_output=None,
        deploy_returncode=0,
        expected_result=0,
        return_events=False,
        lifecycle_fail_action=None,
        expect_lifecycle_exception=False,
    ):
        ssh_commands = []
        events = []

        if migration_probe_output is None:
            migration_probe_output = f"{deploy_vmd.DATA_DISK_READY}\n"

        def fake_run_or_die(command, _context):
            self.assertNotIn("DATABASE_URL", deploy_vmd.os.environ)
            if (
                command[:3] == ["gcloud", "compute", "ssh"]
                and command[command.index("--command") + 1]
                == deploy_vmd.DATA_DISK_MIGRATION_PROBE_SCRIPT
            ):
                events.append("probe")
                return SimpleNamespace(
                    returncode=0,
                    stdout=migration_probe_output,
                    stderr="",
                )
            if command[:3] == ["gcloud", "compute", "ssh"]:
                remote_command = command[command.index("--command") + 1]
                if remote_command == deploy_vmd.DATA_DISK_SET_PENDING_SCRIPT:
                    events.append("set-pending")
                elif remote_command == deploy_vmd.DATA_DISK_CLEAR_PENDING_SCRIPT:
                    events.append("clear-pending")
                elif remote_command == deploy_vmd.FIRECRACKER_DRAIN_PROBE_SCRIPT:
                    events.append("wait-firecracker")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        def fake_subprocess_run(command, *args, **kwargs):
            self.assertNotIn("DATABASE_URL", deploy_vmd.os.environ)
            if command[:4] == ["gcloud", "compute", "instances", "list"]:
                return SimpleNamespace(
                    returncode=0,
                    stdout="staging-vmd,us-central1-a\n",
                    stderr="",
                )
            if command[:3] == ["gcloud", "compute", "ssh"]:
                events.append("deploy")
                ssh_commands.append(command[command.index("--command") + 1])
                return SimpleNamespace(
                    returncode=deploy_returncode,
                    stdout="",
                    stderr="remote deploy failed" if deploy_returncode else "",
                )
            self.fail(f"unexpected subprocess.run command: {command!r}")

        def fake_drain_host(_psql, _database_url, _host_id):
            events.append("drain")
            if lifecycle_fail_action == "drain":
                raise RuntimeError("simulated drain failure")

        def fake_set_host_status(_psql, _database_url, _host_id, status):
            events.append(status)
            if status == lifecycle_fail_action:
                raise RuntimeError(f"simulated {status} failure")

        def fake_require_database(_database_url):
            events.append("require-psql")
            return "/usr/bin/psql"

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
            environ["DATABASE_URL"] = "postgresql://test:secret@db/staging"

        with mock.patch.dict(deploy_vmd.os.environ, environ, clear=True), mock.patch.object(
            deploy_vmd, "run_or_die", side_effect=fake_run_or_die
        ), mock.patch.object(
            deploy_vmd.subprocess, "run", side_effect=fake_subprocess_run
        ), mock.patch.object(
            deploy_vmd.os.path, "getsize", return_value=123
        ), mock.patch.object(
            deploy_vmd,
            "require_database_lifecycle",
            side_effect=fake_require_database,
        ), mock.patch.object(
            deploy_vmd,
            "drain_host_via_database",
            side_effect=fake_drain_host,
        ), mock.patch.object(
            deploy_vmd,
            "set_host_status",
            side_effect=fake_set_host_status,
        ):
            if expect_lifecycle_exception:
                with self.assertRaisesRegex(RuntimeError, "simulated"):
                    deploy_vmd.main()
            else:
                self.assertEqual(deploy_vmd.main(), expected_result)

        self.assertEqual(len(ssh_commands), 1)
        if return_events:
            return ssh_commands[0], events
        return ssh_commands[0]

    def test_data_disk_device_validation(self):
        valid = "/dev/disk/by-id/google-superserve-sandbox-data"
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

        device = "/dev/disk/by-id/google-superserve-sandbox-data"
        remote_script = self.render_remote_script(device)
        expected_fragments = (
            "sudo install -m 0755 /tmp/deploy-01234567/scripts/setup-sandbox-data-disk.sh /usr/local/bin/setup-sandbox-data-disk.sh",
            "sudo install -m 0644 /tmp/deploy-01234567/deploy/sandbox-data-disk.service /etc/systemd/system/sandbox-data-disk.service",
            f"SANDBOX_DATA_DISK_DEVICE={device}",
            "if sudo systemctl is-active --quiet sandbox-data-disk.service; then",
            "sudo /usr/local/bin/setup-sandbox-data-disk.sh --verify-only",
            "sudo systemctl start sandbox-data-disk.service",
            "sudo journalctl -u sandbox-data-disk.service --no-pager -n 160",
        )
        for fragment in expected_fragments:
            self.assertIn(fragment, remote_script)
        self.assertNotIn("restart sandbox-data-disk.service", remote_script)
        self.assertNotIn(
            "tee /etc/systemd/system/superserve-vmd.service.d", remote_script
        )

        self.assertLess(
            remote_script.index(
                "if sudo systemctl is-active --quiet sandbox-data-disk.service; then"
            ),
            remote_script.index("# Saved snapshots require mandatory CoW clones"),
        )
        subprocess.run(
            [shutil.which("bash") or "bash", "-n"],
            input=remote_script,
            text=True,
            check=True,
        )

    def test_initial_migration_drains_before_deploy_then_activates(self):
        device = "/dev/disk/by-id/google-superserve-sandbox-data"
        remote_script, events = self.render_remote_script(
            device,
            migration_probe_output=(
                f"{deploy_vmd.DATA_DISK_MIGRATION_PREFIX}default\n"
            ),
            return_events=True,
        )

        self.assertIn("setup-sandbox-data-disk.sh", remote_script)
        self.assertEqual(
            events,
            [
                "probe",
                "require-psql",
                "set-pending",
                "drain",
                "wait-firecracker",
                "deploy",
                "active",
                "clear-pending",
            ],
        )

    def test_failed_migration_deploy_leaves_host_draining(self):
        device = "/dev/disk/by-id/google-superserve-sandbox-data"
        _, events = self.render_remote_script(
            device,
            migration_probe_output=(
                f"{deploy_vmd.DATA_DISK_MIGRATION_PREFIX}default\n"
            ),
            deploy_returncode=1,
            expected_result=1,
            return_events=True,
        )

        self.assertEqual(
            events,
            [
                "probe",
                "require-psql",
                "set-pending",
                "drain",
                "wait-firecracker",
                "deploy",
            ],
        )

    def test_activation_failure_is_retried_without_a_second_drain(self):
        device = "/dev/disk/by-id/google-superserve-sandbox-data"
        _, failed_events = self.render_remote_script(
            device,
            migration_probe_output=(
                f"{deploy_vmd.DATA_DISK_MIGRATION_PREFIX}default\n"
            ),
            lifecycle_fail_action="active",
            expect_lifecycle_exception=True,
            return_events=True,
        )
        self.assertEqual(
            failed_events,
            [
                "probe",
                "require-psql",
                "set-pending",
                "drain",
                "wait-firecracker",
                "deploy",
                "active",
            ],
        )

        _, retry_events = self.render_remote_script(
            device,
            migration_probe_output=(
                f"{deploy_vmd.DATA_DISK_REACTIVATION_PENDING_PREFIX}default\n"
            ),
            return_events=True,
        )
        self.assertEqual(
            retry_events,
            ["probe", "require-psql", "deploy", "active", "clear-pending"],
        )

    def test_authoritative_steady_state_skips_host_lifecycle_calls(self):
        device = "/dev/disk/by-id/google-superserve-sandbox-data"
        _, events = self.render_remote_script(device, return_events=True)
        self.assertEqual(events, ["probe", "deploy"])

    def test_omitted_device_is_a_production_noop(self):
        remote_script, events = self.render_remote_script(return_events=True)
        forbidden_fragments = (
            "/etc/sandbox/data-disk.env",
            "/etc/systemd/system/sandbox-data-disk.service",
            "setup-sandbox-data-disk.sh",
            "sandbox-data-disk.conf",
            "start sandbox-data-disk.service",
            "restart sandbox-data-disk.service",
            "--verify-only",
        )
        for fragment in forbidden_fragments:
            self.assertNotIn(fragment, remote_script)
        self.assertEqual(events, ["deploy"])
        subprocess.run(
            [shutil.which("bash") or "bash", "-n"],
            input=remote_script,
            text=True,
            check=True,
        )

    def test_migration_probe_parsing_and_host_agreement(self):
        self.assertEqual(
            deploy_vmd.parse_data_disk_migration_probe(
                f"login banner\n{deploy_vmd.DATA_DISK_READY}\n"
            ),
            ("ready", None),
        )
        self.assertEqual(
            deploy_vmd.parse_data_disk_migration_probe(
                f"{deploy_vmd.DATA_DISK_MIGRATION_PREFIX}default\n"
            ),
            ("migration", "default"),
        )
        for output in (
            "",
            f"{deploy_vmd.DATA_DISK_MIGRATION_PREFIX}bad/id\n",
            f"{deploy_vmd.DATA_DISK_READY}\n{deploy_vmd.DATA_DISK_READY}\n",
        ):
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                deploy_vmd.parse_data_disk_migration_probe(output)

        instances = [
            {"name": "vmd-a", "zone": "us-central1-a"},
            {"name": "vmd-b", "zone": "us-central1-b"},
        ]
        with mock.patch.object(
            deploy_vmd,
            "probe_data_disk_migration",
            return_value=("migration", "default"),
        ):
            plan = deploy_vmd.data_disk_migration_plan(instances, "test-project")
            self.assertEqual(plan["host_id"], "default")
            self.assertTrue(plan["needs_drain"])
            self.assertEqual(plan["pending_instances"], instances)
            self.assertEqual(plan["new_pending_instances"], instances)
            self.assertEqual(plan["migration_instances"], instances)
        with mock.patch.object(
            deploy_vmd,
            "probe_data_disk_migration",
            side_effect=lambda inst, _project: ("migration", inst["name"]),
        ), self.assertRaisesRegex(RuntimeError, "disagree on HOST_ID"):
            deploy_vmd.data_disk_migration_plan(instances, "test-project")

        with mock.patch.object(
            deploy_vmd,
            "probe_data_disk_migration",
            return_value=("reactivation_pending", "default"),
        ):
            retry_plan = deploy_vmd.data_disk_migration_plan(
                instances, "test-project"
            )
            self.assertEqual(retry_plan["host_id"], "default")
            self.assertFalse(retry_plan["needs_drain"])
            self.assertEqual(retry_plan["new_pending_instances"], [])
            self.assertEqual(retry_plan["migration_instances"], [])

    def test_probe_reads_host_id_without_sourcing_env_file(self):
        probe = deploy_vmd.DATA_DISK_MIGRATION_PROBE_SCRIPT
        self.assertIn("/etc/sandbox/data-disk-authoritative", probe)
        self.assertIn("/etc/sandbox/data-disk-reactivation-pending", probe)
        self.assertIn("host_id=default", probe)
        self.assertIn("sudo awk", probe)
        self.assertNotIn("source /etc/sandbox/vmd.env", probe)
        subprocess.run(
            [shutil.which("bash") or "bash", "-n"],
            input=probe,
            text=True,
            check=True,
        )

        firecracker_probe = deploy_vmd.FIRECRACKER_DRAIN_PROBE_SCRIPT
        self.assertIn("firecracker@*.service", firecracker_probe)
        self.assertIn("pgrep -x firecracker", firecracker_probe)
        self.assertIn("Active/transitional systemd units:", firecracker_probe)
        self.assertIn("Firecracker process IDs:", firecracker_probe)
        self.assertIn('printf \'%s\\n\' "$units"', firecracker_probe)
        subprocess.run(
            [shutil.which("bash") or "bash", "-n"],
            input=firecracker_probe,
            text=True,
            check=True,
        )

    def test_lifecycle_sql_parses_url_without_putting_secret_in_command(self):
        database_url = (
            "postgresql://db-user:db%3Asecret@db.example:6543/staging"
            "?sslmode=require&application_name=vmd%20deploy"
        )
        completed = SimpleNamespace(
            returncode=0,
            stdout="draining\n",
            stderr="",
        )
        with mock.patch.object(
            deploy_vmd.subprocess, "run", return_value=completed
        ) as run:
            result = deploy_vmd.run_lifecycle_sql(
                "/usr/bin/psql",
                database_url,
                "default",
                "SELECT :'host_id';",
                "test query",
            )

        self.assertEqual(result, "draining")
        command = run.call_args.args[0]
        self.assertNotIn(database_url, command)
        self.assertNotIn(database_url, " ".join(command))
        child_env = run.call_args.kwargs["env"]
        self.assertEqual(child_env["PGHOST"], "db.example")
        self.assertEqual(child_env["PGPORT"], "6543")
        self.assertEqual(child_env["PGDATABASE"], "staging")
        self.assertEqual(child_env["PGUSER"], "db-user")
        self.assertEqual(child_env["PGPASSWORD"], "db:secret")
        self.assertEqual(child_env["PGSSLMODE"], "require")
        self.assertEqual(child_env["PGAPPNAME"], "vmd deploy")
        self.assertNotIn(database_url, child_env.values())
        self.assertNotIn("DATABASE_URL", child_env)
        self.assertEqual(
            run.call_args.kwargs["env"]["PGCONNECT_TIMEOUT"],
            str(deploy_vmd.PG_CONNECT_TIMEOUT_SECONDS),
        )
        self.assertIn(
            f"statement_timeout={deploy_vmd.PG_STATEMENT_TIMEOUT_MS}",
            run.call_args.kwargs["env"]["PGOPTIONS"],
        )
        self.assertIn(
            f"lock_timeout={deploy_vmd.PG_STATEMENT_TIMEOUT_MS}",
            run.call_args.kwargs["env"]["PGOPTIONS"],
        )
        self.assertEqual(
            run.call_args.kwargs["timeout"],
            deploy_vmd.PSQL_COMMAND_TIMEOUT_SECONDS,
        )
        self.assertEqual(run.call_args.kwargs["input"], "SELECT :'host_id';")

    def test_database_url_parser_rejects_ambiguous_or_unsupported_urls(self):
        invalid_urls = (
            "",
            "mysql://user:secret@db.example/staging",
            "postgresql://db.example/staging",
            "postgresql://user:secret@db.example/",
            "postgresql://user:secret@db.example/staging?unknown=value",
        )
        for database_url in invalid_urls:
            with self.subTest(database_url=database_url), self.assertRaises(
                ValueError
            ):
                deploy_vmd.database_url_connection_env(database_url)

    def test_lifecycle_sql_redacts_database_url_from_failures(self):
        database_url = "postgresql://db-user:db-secret@db.example/staging"
        completed = SimpleNamespace(
            returncode=2,
            stdout=f"bad database {database_url}",
            stderr=f"could not connect to {database_url}",
        )
        with mock.patch.object(
            deploy_vmd.subprocess, "run", return_value=completed
        ), self.assertRaises(RuntimeError) as raised:
            deploy_vmd.run_lifecycle_sql(
                "/usr/bin/psql",
                database_url,
                "default",
                "SELECT 1;",
                "test query",
            )

        self.assertNotIn(database_url, str(raised.exception))
        self.assertIn("[REDACTED]", str(raised.exception))

    def test_lifecycle_sql_timeout_is_bounded_and_redacted(self):
        database_url = "postgresql://db-user:db-secret@db.example/staging"
        timeout = subprocess.TimeoutExpired(
            cmd=["psql"],
            timeout=deploy_vmd.PSQL_COMMAND_TIMEOUT_SECONDS,
            output=f"connecting to {database_url}",
            stderr=f"waiting for {database_url}",
        )
        with mock.patch.object(
            deploy_vmd.subprocess, "run", side_effect=timeout
        ), self.assertRaisesRegex(RuntimeError, "timed out") as raised:
            deploy_vmd.run_lifecycle_sql(
                "/usr/bin/psql",
                database_url,
                "default",
                "SELECT 1;",
                "test query",
            )

        self.assertNotIn(database_url, str(raised.exception))
        self.assertIn("[REDACTED]", str(raised.exception))

    def test_database_drain_updates_status_and_polls_exact_activity_fence(self):
        calls = []

        def fake_sql(_psql, _database_url, _host_id, sql, _context):
            calls.append(sql)
            if "UPDATE host" in sql:
                return "draining"
            return "0"

        with mock.patch.object(
            deploy_vmd, "run_lifecycle_sql", side_effect=fake_sql
        ):
            deploy_vmd.drain_host_via_database(
                "/usr/bin/psql",
                "postgresql://secret",
                "default",
                timeout_seconds=0,
                poll_seconds=0,
            )

        self.assertIn("SET status = 'draining'", calls[0])
        self.assertIn("preserved AS", calls[0])
        self.assertIn("SET auto_delete_at = NULL", calls[0])
        self.assertIn("sandbox.destroyed_at IS NULL", calls[0])
        self.assertIn("sandbox.auto_delete_at IS NOT NULL", calls[0])
        self.assertIn("SELECT id FROM draining", calls[0])
        activity_sql = calls[1]
        self.assertIn("destroyed_at IS NULL", activity_sql)
        self.assertIn(
            "status IN ('starting', 'active', 'pausing', 'resuming')",
            activity_sql,
        )
        self.assertIn("snapshot_operation_id IS NOT NULL", activity_sql)
        self.assertIn("FROM snapshot", activity_sql)
        self.assertIn("kind = 'saved'", activity_sql)
        self.assertIn("status IN ('creating', 'deleting')", activity_sql)
        self.assertIn("FROM template_build", activity_sql)
        self.assertIn("vmd_host_id = :'host_id'", activity_sql)
        self.assertIn("status IN ('building', 'snapshotting')", activity_sql)

    def test_database_activation_does_not_change_auto_delete_deadlines(self):
        calls = []

        def fake_sql(_psql, _database_url, _host_id, sql, _context):
            calls.append(sql)
            return "active"

        with mock.patch.object(
            deploy_vmd, "run_lifecycle_sql", side_effect=fake_sql
        ):
            deploy_vmd.set_host_status(
                "/usr/bin/psql",
                "postgresql://secret",
                "default",
                "active",
            )

        self.assertEqual(len(calls), 1)
        self.assertIn("SET status = 'active'", calls[0])
        self.assertIn("status = 'draining'", calls[0])
        self.assertIn("lifecycle_fence AS MATERIALIZED", calls[0])
        self.assertIn("(SELECT remaining FROM lifecycle_fence) = 0", calls[0])
        self.assertIn("already_active AS", calls[0])
        self.assertIn("WHERE id = :'host_id' AND status = 'active'", calls[0])
        self.assertIn("WHERE NOT EXISTS (SELECT 1 FROM updated)", calls[0])
        self.assertIn("snapshot_operation_id IS NOT NULL", calls[0])
        self.assertIn("status IN ('creating', 'deleting')", calls[0])
        self.assertIn("status IN ('building', 'snapshotting')", calls[0])
        self.assertNotIn("auto_delete_at", calls[0])

    def test_database_activation_refuses_busy_draining_unhealthy_or_missing_host(self):
        with mock.patch.object(
            deploy_vmd, "run_lifecycle_sql", return_value=""
        ), self.assertRaisesRegex(RuntimeError, "host row was not updated"):
            deploy_vmd.set_host_status(
                "/usr/bin/psql",
                "postgresql://secret",
                "default",
                "active",
            )

    def test_database_drain_timeout_leaves_host_draining(self):
        with mock.patch.object(
            deploy_vmd, "set_host_status"
        ) as set_status, mock.patch.object(
            deploy_vmd, "count_host_lifecycle_activity", return_value=3
        ), self.assertRaisesRegex(RuntimeError, "host remains draining"):
            deploy_vmd.drain_host_via_database(
                "/usr/bin/psql",
                "postgresql://secret",
                "default",
                timeout_seconds=0,
                poll_seconds=0,
            )

        set_status.assert_called_once_with(
            "/usr/bin/psql",
            "postgresql://secret",
            "default",
            "draining",
        )

    def test_psql_is_required_only_for_migration_or_recovery(self):
        with mock.patch.object(deploy_vmd.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "psql is required"):
                deploy_vmd.require_database_lifecycle("postgresql://secret")
        with self.assertRaisesRegex(ValueError, "DATABASE_URL is required"):
            deploy_vmd.require_database_lifecycle("")

    def test_workflow_only_sets_device_for_staging(self):
        workflow = (REPO_ROOT / ".github/workflows/deploy-vmd.yml").read_text()
        self.assertEqual(workflow.count("SANDBOX_DATA_DISK_DEVICE:"), 1)
        self.assertEqual(workflow.count("DATABASE_URL:"), 1)
        self.assertIn(
            "DATABASE_URL: ${{ secrets.DATABASE_URL_STAGING }}",
            workflow,
        )
        self.assertNotIn("STAGING_INTERNAL_API_TOKEN", workflow)
        self.assertEqual(workflow.count("postgresql-client"), 1)
        self.assertEqual(workflow.count("command -v psql"), 1)
        staging_job = workflow.index("deploy-staging:")
        production_job = workflow.index("deploy-production:")
        device_setting = workflow.index("SANDBOX_DATA_DISK_DEVICE:")
        database_setting = workflow.index("DATABASE_URL:")
        self.assertLess(staging_job, device_setting)
        self.assertLess(device_setting, production_job)
        self.assertLess(staging_job, database_setting)
        self.assertLess(database_setting, production_job)
        self.assertEqual(
            workflow.count("python3 -u .github/workflows/scripts/deploy-vmd.py"),
            3,
        )


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
                    '[[ "$configured_device" =~ ^/dev/disk/by-id/google-[A-Za-z0-9._-]+$ ]] ||': (
                        '[[ "$configured_device" == "${TEST_DEVICE_PATH:-}" ]] ||'
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

    def test_invalid_device_path_is_rejected_before_host_mutation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            harness = self.make_harness(root)
            shims = self.make_shims(root)
            result, mutation_log = self.run_harness(
                root,
                harness,
                shims,
                {"SANDBOX_DATA_DISK_DEVICE": "/tmp/not-a-stable-device"},
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("device must be a stable Google by-id path", result.stderr)
            self.assertFalse(mutation_log.exists())

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
