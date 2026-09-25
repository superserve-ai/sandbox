"""Reject incompatible candidates before preparation and again before installation."""

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "deploy/vmd-compatibility-preflight"
BUNDLED_GUARDS = ("vmd-rollback-guard", "vmd-wake-floor-guard", "vmd-staged-intent-floor-guard")


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


preflight = load("vmd_compatibility_preflight", HELPER)
deployer = load("deploy_vmd_compatibility", Path(__file__).with_name("deploy-vmd.py"))


class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.resident = self.root / "usr/local/bin"
        self.dropins = self.root / "etc/systemd/system/superserve-vmd.service.d"
        self.bundle = self.root / "bundle/deploy"
        for directory in (self.resident, self.dropins, self.bundle):
            directory.mkdir(parents=True)
        self.candidate = self.root / "bundle/bin/vmd"
        self.candidate.parent.mkdir()
        self.executed = self.root / "candidate-executed"
        self.candidate.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(self.executed))}\n# compatible\n")
        self.candidate.chmod(0o755)
        self.calls = self.root / "guard-calls"
        for name in BUNDLED_GUARDS:
            self.guard(self.bundle / name, mode=0o644)
        (self.bundle / "superserve-vmd-staged-intent-floor-guard.conf").write_text(
            "[Service]\nExecStartPre=/usr/local/bin/vmd-staged-intent-floor-guard /usr/local/bin/vmd\n"
        )

    def guard(self, path, reject=False, mode=0o755):
        path.write_text(
            "#!/bin/sh\n"
            f"printf '%s:%s\\n' {shlex.quote(path.name)} \"$1\" >> {shlex.quote(str(self.calls))}\n"
            + ("exit 1\n" if reject else 'grep -q compatible "$1"\n')
        )
        path.chmod(mode)
        return path

    def check(self):
        return preflight.check(self.candidate, self.bundle, self.resident, self.dropins)

    def test_resident_rejection_wins_over_absent_or_permissive_bundle_guard(self):
        name = "vmd-next-format-floor-guard"
        self.guard(self.resident / name, reject=True)
        for incoming in (False, True):
            with self.subTest(incoming=incoming):
                if incoming:
                    self.guard(self.bundle / name)
                with self.assertRaises(subprocess.CalledProcessError):
                    self.check()
                self.assertFalse(self.executed.exists())

    def test_compatible_resident_guards_and_unrelated_start_hooks(self):
        for name in ("vmd-rollback-guard", "vmd-wake-floor-guard", "vmd-next-format-floor-guard"):
            self.guard(self.resident / name)
        unrelated = self.guard(self.resident / "vmd-start-generation", reject=True)
        (self.dropins / "20-start-generation.conf").write_text(f"[Service]\nExecStartPre={unrelated}\n")
        self.check()
        calls = self.calls.read_text()
        self.assertNotIn("vmd-start-generation", calls)
        self.assertEqual(len(calls.splitlines()), 6)
        self.assertTrue(all(line.endswith(str(self.candidate)) for line in calls.splitlines()))
        self.assertFalse(self.executed.exists())

    def test_clean_old_host_without_resident_guard_or_dropin_directories(self):
        self.resident.rmdir()
        self.dropins.rmdir()
        self.check()
        self.assertFalse(self.executed.exists())
        self.assertEqual(len(self.calls.read_text().splitlines()), 3)

    def test_bundled_guard_rejection_and_missing_required_bundle_guard(self):
        for name in BUNDLED_GUARDS:
            with self.subTest(guard=name):
                guard = self.guard(self.bundle / name, reject=True, mode=0o644)
                with self.assertRaises(subprocess.CalledProcessError):
                    self.check()
                guard.unlink()
                with self.assertRaises(FileNotFoundError):
                    self.check()
                self.guard(guard, mode=0o644)
        self.assertFalse(self.executed.exists())

    def test_missing_guard_required_by_retained_dropin_fails_closed(self):
        (self.dropins / "40-staged-intent-floor-guard.conf").write_text(
            "[Service]\nExecStartPre=/usr/local/bin/vmd-staged-intent-floor-guard /usr/local/bin/vmd\n"
        )
        with self.assertRaises(FileNotFoundError):
            self.check()

    def test_present_broken_guards_fail_closed(self):
        guard = self.resident / "vmd-staged-intent-floor-guard"
        guard.symlink_to(self.root / "missing")
        with self.assertRaises(FileNotFoundError):
            self.check()
        guard.unlink()
        self.guard(guard, mode=0o644)
        with self.assertRaises(ValueError):
            self.check()
        guard.write_text("#!/nonexistent/interpreter\n")
        guard.chmod(0o755)
        with self.assertRaises(OSError):
            self.check()
        guard.unlink()
        guard.mkdir()
        with self.assertRaises(ValueError):
            self.check()

    def test_lookup_read_access_and_execution_errors_fail_closed(self):
        self.guard(self.resident / "vmd-staged-intent-floor-guard")
        (self.dropins / "40-staged-intent-floor-guard.conf").write_text("[Service]\n")
        for method in ("iterdir", "read_text", "stat"):
            with self.subTest(method=method), patch.object(Path, method, side_effect=PermissionError("denied")):
                with self.assertRaises(PermissionError):
                    self.check()
        with patch.object(preflight.os, "access", return_value=False):
            with self.assertRaises(ValueError):
                self.check()
        for error in (OSError("cannot execute guard"), subprocess.TimeoutExpired("guard", 30)):
            with patch.object(preflight.subprocess, "run", side_effect=error):
                with self.assertRaises(type(error)):
                    self.check()

    def test_dangling_guard_directory_is_not_treated_as_an_old_host(self):
        self.resident.rmdir()
        self.resident.symlink_to(self.root / "missing")
        with self.assertRaises(FileNotFoundError):
            self.check()

    def render_installer(self, **overrides):
        scripts = []

        def run(args, **kwargs):
            output = ""
            if args[1:4] == ["compute", "instances", "list"]:
                output = "example-host,us-central1-a\n"
            if "--command" in args:
                scripts.append(args[args.index("--command") + 1])
            return subprocess.CompletedProcess(args, 0, stdout=output, stderr="")

        env = dict(GCP_PROJECT="example-project", SHA="12345678", CONTROL_PLANE_URL="https://example.test",
                   DATABASE_URL="postgres://example.test/db", INTERNAL_API_TOKEN="example-token",
                   BACKUP_JOURNAL_PATH="/mnt/example/journals/backup.db")
        env.update(overrides)
        with patch.dict(os.environ, env, clear=True), patch.object(deployer.subprocess, "run", side_effect=run), \
                patch.object(deployer.os.path, "getsize", return_value=100), \
                patch.object(deployer.os.path, "exists", return_value=True), patch("builtins.print"):
            self.assertEqual(deployer.main(), 0)
        self.assertEqual(len(scripts), 2)
        return scripts[-1]

    def test_full_installer_checks_guards_before_every_live_mutation(self):
        script = self.render_installer()
        gate = script.index("sudo python3 /tmp/deploy-12345678/deploy/vmd-compatibility-preflight")
        self.assertLess(script.index("tar xzf"), gate)
        for mutation in ('sudo install -d -m 0700 "$BJ_JOURNAL_DIR"', "sudo install -d -o root",
                         'sudo systemctl stop $fresh_units', "sudo install -m 0755 /tmp/deploy-12345678/bin/vmd",
                         "sudo systemctl stop superserve-vmd.socket", "sudo systemctl restart superserve-vmd"):
            with self.subTest(mutation=mutation):
                self.assertLess(gate, script.index(mutation))

    def test_full_installer_rechecks_immediately_before_installing_candidate(self):
        lines = self.render_installer().splitlines()
        gates = [index for index, line in enumerate(lines)
                 if "sudo python3 /tmp/deploy-12345678/deploy/vmd-compatibility-preflight" in line]
        self.assertEqual(len(gates), 3)
        self.assertEqual(lines[gates[0]], lines[gates[1]])
        self.assertEqual(lines[gates[0]], lines[gates[2]])
        guard_install = next(index for index, line in enumerate(lines)
                             if "sudo install -m 0755 /tmp/deploy-12345678/deploy/vmd-staged-intent-floor-guard" in line)
        guard_reload = next(index for index in range(guard_install, len(lines))
                            if lines[index].strip() == "sudo systemctl daemon-reload")
        self.assertLess(gates[1], guard_install)
        self.assertLess(guard_reload, gates[2])
        self.assertEqual(lines[gates[2] + 1].strip(),
                         "sudo install -m 0755 /tmp/deploy-12345678/bin/vmd /usr/local/bin/vmd")

    def test_full_installer_resident_rejection_preserves_configured_host(self):
        self.exercise_full_installer_rejection(configured=True)

    def test_full_installer_resident_rejection_preserves_fresh_host(self):
        self.exercise_full_installer_rejection(configured=False)

    def test_full_installer_rejects_resident_floor_raised_during_preparation(self):
        self.exercise_full_installer_rejection(configured=True, raised_floor="resident")

    def test_full_installer_rejects_bundled_floor_raised_during_preparation(self):
        self.exercise_full_installer_rejection(configured=True, raised_floor="bundled")

    def test_full_installer_rejects_floor_raised_after_guard_installation(self):
        self.exercise_full_installer_rejection(configured=True, raised_floor="resident_after_reload")

    def exercise_full_installer_rejection(self, configured, raised_floor=None):
        floor_at_reload = raised_floor == "resident_after_reload"
        guard_path = (self.bundle / "vmd-wake-floor-guard" if raised_floor == "bundled"
                      else self.resident / "vmd-next-format-floor-guard")
        guard = self.guard(guard_path, reject=raised_floor is None)
        floor = self.root / "raised-floor"
        if raised_floor:
            guard.write_text(guard.read_text() + f"test ! -e {shlex.quote(str(floor))}\n")
        helper = HELPER.read_text().replace('Path("/usr/local/bin")', repr(self.resident).replace("PosixPath", "Path"))
        helper = helper.replace('Path("/etc/systemd/system/superserve-vmd.service.d")',
                                repr(self.dropins).replace("PosixPath", "Path"))
        (self.bundle / HELPER.name).write_text(helper)
        envdir = self.root / "etc/sandbox"
        envdir.mkdir(parents=True)
        identity = dict(host_id="example-host", incarnation_id="73863d7a-26f8-4a41-9d89-d458421935e7",
                        project_id="example-project", instance_id="100")
        (envdir / "host-identity.json").write_text(json.dumps(identity))
        (envdir / "host-identity.env").write_text(f"HOST_ID=example-host\nHOST_IDENTITY_FILE={envdir}/host-identity.json\n")
        settings = "CONTROL_PLANE_URL=https://example.test\nINTERNAL_API_TOKEN=example-token\n"
        if raised_floor:
            for key, name in (("KERNEL_PATH", "kernel"), ("BASE_ROOTFS_PATH", "rootfs")):
                asset = self.root / name
                asset.write_text("provisioned artifact")
                settings += f"{key}={asset}\n"
        (envdir / "vmd.env").write_text(settings if configured else "PRESERVE=original\n")
        if configured:
            (envdir / "secretsproxy.env").write_text(
                "CONTROL_PLANE_URL=https://example.test\nDAEMON_AUTH_TOKEN=example-token\nDATABASE_URL=postgres://example.test/db\n"
            )
            cadir = self.root / "var/lib/secretsproxy"
            cadir.mkdir(parents=True)
            for name in ("ca.crt", "ca.key"):
                (cadir / name).write_text("existing-" + name)
        (self.resident / "vmd").write_text("previous binary")
        scratch = self.root / "tmp"
        scratch.mkdir()
        with tarfile.open(scratch / "deploy-bundle-12345678.tar.gz", "w:gz") as archive:
            archive.add(self.bundle.parent, arcname=".")
        script = self.render_installer(**({"BACKUP_JOURNAL_PATH": ""} if raised_floor else {}))
        # Relocate every host path, including the identity probe's expected value.
        for path in ("/etc/sandbox", "/etc/systemd", "/usr/local/bin", "/var/lib", "/tmp/deploy-", "/mnt/example"):
            script = script.replace(path, str(self.root) + path)
        mutations = self.root / "live-mutations"
        reloads = self.root / "daemon-reloads"
        preparation = ""
        reload_action = ":"
        if raised_floor:
            # The running daemon can persist new evidence while configuration
            # or guard metadata is prepared. Interleave that write with one of
            # those operations to exercise the two late compatibility checks.
            raise_floor = f"touch {shlex.quote(str(floor))}"
            chmod_action = ":" if floor_at_reload else raise_floor
            if floor_at_reload:
                reload_action = raise_floor
            preparation = f'''install|sed|tee) "$@" ;;
        chown) : ;;
        chmod) "$@"; {chmod_action} ;;
        '''
            script = script.replace("-o root -g root ", "")
        prelude = f'''sudo() {{
    case "$1" in
        python3|test|grep|systemctl|pgrep|ss) "$@" ;;
        rm) "$@" ;;
        {preparation}*) echo "$*" >> {shlex.quote(str(mutations))}; return 90 ;;
    esac
}}
systemctl() {{
    case "$1" in
        show) echo not-found ;;
        list-units) : ;;
        daemon-reload) echo reloaded >> {shlex.quote(str(reloads))}; {reload_action} ;;
        *) echo "$*" >> {shlex.quote(str(mutations))}; return 90 ;;
    esac
}}
pgrep() {{ return 1; }}
ss() {{ :; }}
'''
        before = {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        result = subprocess.run(["bash", "-c", prelude + script], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("VMD compatibility preflight failed; refusing candidate installation", result.stderr)
        self.assertFalse(mutations.exists(), result.stderr)
        self.assertFalse(self.executed.exists())
        self.assertEqual(reloads.exists(), floor_at_reload)
        if raised_floor:
            self.assertTrue(floor.exists(), "floor must rise after the initial successful check")
            self.assertEqual(self.calls.read_text().count(guard.name + ":"), 3 if floor_at_reload else 2)
            self.assertEqual((self.resident / "vmd").read_text(), "previous binary")
        if floor_at_reload:
            self.assertEqual((self.resident / "vmd-staged-intent-floor-guard").read_bytes(),
                             (self.bundle / "vmd-staged-intent-floor-guard").read_bytes())
            self.assertEqual((self.dropins / "31-staged-intent-floor-guard.conf").read_bytes(),
                             (self.bundle / "superserve-vmd-staged-intent-floor-guard.conf").read_bytes())
        else:
            for path, content in before.items():
                self.assertEqual(Path(path).read_bytes(), content, path)


if __name__ == "__main__":
    unittest.main()
