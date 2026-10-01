import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import uuid
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class HostLoggingConfigChecks(unittest.TestCase):
    fixture_manifest_env = "HOST_LOGGING_AGENT_FIXTURE_MANIFEST"
    selected_release = "2.71.0"
    selected_release_commit = "81e4d60b1eb8b6ada14598bee0378532a90ade8c"
    fixture_setup_timeout = 150
    fixture_cache_name = "superserve-host-logging-agent-fixture-v4"
    _fixture_lock = None

    def setUp(self):
        self.config = (ROOT / "infra/modules/host-logging/templates/ops-agent.yaml.tftpl").read_text()
        self.reconcile = (ROOT / "infra/modules/host-logging/templates/reconcile.sh.tftpl").read_text()
        self.validate = (ROOT / "infra/modules/host-logging/templates/validate.sh.tftpl").read_text()

    def _selected_agent_manifest(self):
        """Load a digest-bound fixture, preparing it lazily when necessary."""
        manifest_name = os.environ.get(self.fixture_manifest_env)
        if not manifest_name:
            manifest_name = str(self._prepare_selected_agent_fixture())
        manifest_path = Path(manifest_name)
        if not manifest_path.is_file():
            self.fail(f"fixture manifest does not exist: {manifest_path}")
        try:
            manifest = json.loads(manifest_path.read_text())
        except (OSError, ValueError) as exc:
            self.fail(f"fixture manifest is unreadable: {exc}")
        required = {
            "image",
            "release",
            "source_revision",
            "package_version",
            "package_sha256",
            "generator_sha256",
            "fluent_bit_sha256",
            "rendered_input_sha256",
            "generated_artifact_sha256",
            "base_image_digest",
            "architecture",
            "repository_setup_url",
            "repository_setup_sha256",
            "authenticated_packages_metadata_sha256",
            "fixture_adaptations",
            "engine_path",
            "fluent_bit_path",
            "journal_remote_path",
            "runner_script",
        }
        missing = sorted(required - manifest.keys())
        self.assertFalse(missing, f"fixture manifest missing immutable provenance: {missing}")
        self.assertEqual(manifest["release"], self.selected_release)
        self.assertEqual(manifest["source_revision"], self.selected_release_commit)
        self.assertRegex(manifest["image"], r"@sha256:[0-9a-f]{64}$")
        for key in ("package_sha256", "generator_sha256", "fluent_bit_sha256",
                    "rendered_input_sha256", "generated_artifact_sha256",
                    "repository_setup_sha256"):
            self.assertRegex(manifest[key], r"^[0-9a-f]{64}$", key)
        self.assertEqual(manifest["package_version"].split("~", 1)[0], self.selected_release)
        self.assertEqual(manifest["architecture"], "amd64")
        self.assertTrue(manifest["journal_remote_path"].endswith("systemd-journal-remote"))
        self.assertRegex(manifest["base_image_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(
            manifest["repository_setup_url"],
            "https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh",
        )
        self.assertTrue(manifest["authenticated_packages_metadata_sha256"])
        self.assertIsInstance(manifest["fixture_adaptations"], list)
        rendered_input = manifest_path.parent / "rendered.yaml"
        if rendered_input.is_file():
            digest = hashlib.sha256(rendered_input.read_bytes()).hexdigest()
            self.assertEqual(digest, manifest["rendered_input_sha256"])
        else:
            self.fail(f"fixture rendered input is missing: {rendered_input}")
        return manifest_path, manifest

    @classmethod
    def _fixture_runner_source(cls):
        """Return the isolated runner used with generated Ops Agent output."""
        return r'''#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile


def command(argv, *, input_text=None, timeout=12):
    try:
        return subprocess.run(argv, input=input_text, text=True, capture_output=True,
                              timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(argv, 124, "", str(exc))


def files(root):
    return [p for p in pathlib.Path(root).rglob("*") if p.is_file()]


def tree_digest(root):
    digest = hashlib.sha256()
    for path in sorted(files(root)):
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def fluent_probe(generated, fluent, journal_remote, event):
    """Feed a real journal export through the generated Fluent Bit filters.

    The receiver path is intentionally exercised through systemd-journal-remote
    and Fluent Bit's systemd input.  A stdin/json probe would bypass journald
    field mapping, trusted source metadata, and the configured receiver.
    """
    blocks = []
    tag = "host_logging_fixture"
    for path in files(generated):
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        block = []
        active = False
        for line in lines:
            if line.strip() == "[FILTER]":
                if block:
                    blocks.append("\n".join(block))
                block, active = [line], True
            elif active and line.startswith("["):
                blocks.append("\n".join(block))
                block, active = [], False
            elif active:
                block.append(line)
            if line.strip().startswith("Match ") and tag == "host_logging_fixture":
                candidate = line.split(None, 1)[1].strip().split()[0]
                tag = candidate.rstrip("*") or tag
        if block:
            blocks.append("\n".join(block))
    probe_dir = pathlib.Path(tempfile.mkdtemp(prefix="fluent-probe-"))
    journal_dir = probe_dir / "journal"
    journal_dir.mkdir()
    export = probe_dir / "journal.export"
    fields = dict(event)
    fields.setdefault("__REALTIME_TIMESTAMP", "1700000000000000")
    fields.setdefault("__MONOTONIC_TIMESTAMP", "1000000")
    fields.setdefault("_BOOT_ID", "fixture-boot")
    fields.setdefault("_MACHINE_ID", "fixture-machine")
    export.write_bytes("\n".join(f"{key}={value}" for key, value in fields.items()).encode() + b"\n\n")
    journal_path = journal_dir / "fixture.journal"
    remote_result = command([journal_remote, f"--output={journal_path}"],
                            input_text=export.read_text(), timeout=10)
    if remote_result.returncode not in (0, 1, 2):
        shutil.rmtree(probe_dir, ignore_errors=True)
        return []
    probe = probe_dir / "fluent.conf"
    probe.write_text("\n".join([
        "[SERVICE]", "    Flush 1", "    Daemon Off", "    Log_Level error",
        "[INPUT]", "    Name systemd", f"    Path {journal_dir}",
        f"    Tag {tag}", "    Read_From_Tail Off", "    DB /tmp/journal.db",
        *blocks, "[OUTPUT]", "    Name stdout", "    Match *", "    Format json_lines", "",
    ]))
    result = command([fluent, "-c", str(probe)], timeout=10)
    records = []
    for line in result.stdout.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            records.append(value)
    shutil.rmtree(probe_dir, ignore_errors=True)
    return records


def run_scripts(args, scenario):
    """Execute the rendered scripts against disposable container state."""
    paths = [
        "/var/lib/superserve/host-logging", "/etc/sandbox",
        "/etc/systemd/journald.conf.d",
        "/etc/systemd/system/google-cloud-ops-agent-fluent-bit.service.d",
        "/etc/systemd/system/google-cloud-ops-agent-opentelemetry-collector.service.d",
        "/etc/systemd/system/superserve-otel-collector.service.d",
        "/var/lib/google-cloud-ops-agent/fluent-bit/buffers",
        "/var/log/google-cloud-ops-agent/subagents",
    ]
    for path in paths:
        pathlib.Path(path).mkdir(parents=True, exist_ok=True)
    pathlib.Path("/etc/sandbox/host-identity.json").write_text(
        json.dumps({"host_id": "fixture-host", "incarnation_id": "fixture-incarnation"}))
    candidate = pathlib.Path("/var/lib/superserve/host-logging/config.yaml.candidate")
    candidate.write_text(pathlib.Path(args.rendered).read_text())
    pathlib.Path("/var/lib/superserve/host-logging/journald.conf.candidate").write_text(
        "[Journal]\nStorage=persistent\nSystemMaxUse=4294967296B\nSystemKeepFree=10737418240B\n")
    working = pathlib.Path("/etc/google-cloud-ops-agent/config.yaml")
    working.parent.mkdir(parents=True, exist_ok=True)
    working.write_text(candidate.read_text())
    original_working = working.read_text()
    checkpoint = pathlib.Path("/var/lib/google-cloud-ops-agent/fluent-bit/buffers/checkpoint")
    checkpoint.write_text("pending delivery")
    if scenario == "invalid_candidate_before_activation":
        candidate.write_text("logging: [invalid")
    elif scenario == "child_failure_before_activation":
        shutil.rmtree("/var/log/google-cloud-ops-agent")
    elif scenario == "post_activation_storage_violation":
        pathlib.Path("/var/lib/google-cloud-ops-agent/fluent-bit/buffers/large").write_bytes(b"x" * 2048)
    bindir = pathlib.Path("/tmp/fixture-bin")
    bindir.mkdir(exist_ok=True)
    (bindir / "systemctl").write_text("""#!/bin/sh
printf '%s\\n' \"$*\" >> /tmp/fixture-bin/systemctl.state
case \"${FIXTURE_SCENARIO:-}\" in
 activation_restart_failure_rollback) case \"$*\" in *restart*) exit 1;; esac;;
esac
exit 0
""")
    (bindir / "systemd-analyze").write_text("#!/bin/sh\ncat /etc/systemd/journald.conf.d/30-superserve-host-logging.conf 2>/dev/null || true\n")
    (bindir / "logger").write_text("#!/bin/sh\nexit 0\n")
    (bindir / "journalctl").write_text("#!/bin/sh\nexit 0\n")
    (bindir / "logrotate").write_text("#!/bin/sh\n[ \"${FIXTURE_SCENARIO:-}\" != cleanup_failure_after_activation ]\n")
    for path in bindir.iterdir():
        path.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = str(bindir) + ":" + env.get("PATH", "")
    env["FIXTURE_SCENARIO"] = scenario
    def run(path, timeout):
        return subprocess.run(["/bin/bash", path], env=env, text=True,
                              capture_output=True, timeout=timeout, check=False)
    validation = run(args.validate, 25)
    reconciliation = run(args.reconcile, 35)
    committed = working.is_file() and working.read_text() == original_working
    report = {
        "os_config_exit": validation.returncode if validation.returncode else reconciliation.returncode,
        "committed_config_preserved": committed,
        "pending_delivery_state_preserved": checkpoint.read_text() == "pending delivery",
        "activation_committed": pathlib.Path(
            "/etc/systemd/system/google-cloud-ops-agent-fluent-bit.service.d/30-superserve-resources.conf"
        ).is_file() and working.is_file(),
        "second_run_compliant": False,
    }
    if scenario == "idempotent_repetition" and reconciliation.returncode == 0:
        report["second_run_compliant"] = run(args.reconcile, 35).returncode == 0
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--generated", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--fluent-bit", required=True)
    parser.add_argument("--journal-remote", required=True)
    parser.add_argument("--rendered", required=True)
    parser.add_argument("--reconcile", required=True)
    parser.add_argument("--validate", required=True)
    args = parser.parse_args()
    generated = pathlib.Path(args.generated)
    if not files(generated):
        raise SystemExit("engine generated no artifacts")
    actual_digest = tree_digest(generated)
    expected_digest = os.environ.get("FIXTURE_GENERATED_ARTIFACT_SHA256", "")
    if expected_digest and actual_digest != expected_digest:
        raise SystemExit("generated artifact digest changed from the prepared fixture")
    base = {"_SYSTEMD_UNIT": "proxy.service", "_TRANSPORT": "journal",
            "MESSAGE": '{"level":"info","event":"fixture"}'}
    events = {
        "allowed_sources": base,
        "excluded_sources": dict(base, _SYSTEMD_UNIT="unrelated.service"),
        "severity_filter": dict(base, MESSAGE='{"level":"debug","event":"fixture"}'),
        "promoted_special_fields": dict(base, MESSAGE=json.dumps({"httpRequest": {"requestMethod": "GET"}, "traceSampled": True})),
        "provenance_collision": dict(base, MESSAGE=json.dumps({"labels": {"host_id": "spoofed"}, "_SYSTEMD_UNIT": "spoofed.service"})),
        "heartbeat_spoof": dict(base, _SYSTEMD_UNIT="superserve-host-logging-heartbeat.service", MESSAGE=json.dumps({"labels": {"host_logging_heartbeat": False}})),
        "malformed_metadata_only": dict(base, MESSAGE="not-json application body"),
        "valid_colliding_json": dict(base, MESSAGE=json.dumps({"host_id": "spoofed", "event": "fixture"})),
        "approved_correlations": dict(base, MESSAGE=json.dumps({"request_id": "fixture-request", "sandbox_id": "fixture-sandbox", "event": "fixture"})),
    }
    if args.scenario in events:
        remote = command([args.journal_remote, "--version"], timeout=5)
        if remote.returncode not in (0, 1, 2):
            raise SystemExit("systemd-journal-remote could not be executed")
        records = fluent_probe(generated, args.fluent_bit, args.journal_remote,
                               events[args.scenario])
        output = dict(records[0] if records else {})
        output["fixture_scenario"] = args.scenario
        output["exported"] = bool(records)
        output["journal_remote_status"] = remote.returncode
        output["generator_sha256"] = os.environ.get("FIXTURE_GENERATOR_SHA256", "")
        output["fluent_bit_sha256"] = os.environ.get("FIXTURE_FLUENT_BIT_SHA256", "")
        output["generated_artifact_sha256"] = actual_digest
        print(json.dumps(output, sort_keys=True))
        return
    if args.scenario == "buffer_budget":
        generated_text = "\n".join(path.read_text(errors="replace") for path in files(generated))
        output_blocks = re.findall(r"(?ms)^\[OUTPUT\]\n(.*?)(?=^\[|\Z)", generated_text)
        active_outputs = []
        for block in output_blocks:
            match = re.search(r"(?m)^\s*Name\s+(\S+)", block)
            if match:
                active_outputs.append(match.group(1))
        state_paths = re.findall(r"(?m)^\s*(?:DB|storage\.path)\s+(.+)$", generated_text)
        retry_settings = re.findall(r"(?m)^\s*(?:Retry_Limit|Retry_Limit_Maximum|storage\.sync)\s+(.+)$", generated_text)
        if not active_outputs or not state_paths or not retry_settings:
            raise SystemExit("generated Ops Agent output omitted active output, state, or retry settings")
        limits = []
        for value in re.findall(r"(?mi)^\s*(?:Mem_Buf_Limit|storage\.total_limit_size)\s+([0-9]+(?:\.[0-9]+)?\s*[kmgt]?b?)\s*$", generated_text):
            match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*([kmgt]?b?)", value.strip(), re.I)
            if not match:
                raise SystemExit(f"unparseable generated buffer limit: {value}")
            amount, unit = float(match.group(1)), match.group(2).lower()
            scale = {"": 1, "b": 1, "k": 1000, "kb": 1000, "m": 1000000,
                     "mb": 1000000, "g": 1000000000, "gb": 1000000000,
                     "t": 1000000000000, "tb": 1000000000000}[unit]
            limits.append(int(amount * scale))
        if not limits:
            raise SystemExit("selected Ops Agent generator exposes no numeric buffer limit")
        rendered_inputs = "\n".join(pathlib.Path(path).read_text()
                                         for path in (args.reconcile, args.validate))
        reservations = set(re.findall(r"(?:buffer exceeds |buffer_bytes -le )([0-9]+)", rendered_inputs))
        if len(reservations) != 1:
            raise SystemExit("Terraform buffer reservation is missing or inconsistent in rendered inputs")
        reservation = int(next(iter(reservations)))
        generated_bytes = sum(path.stat().st_size for path in files(generated))
        # The generated state/checkpoint artifact footprint is the bounded
        # overhead charged in addition to each active output's enforced cap.
        state_overhead = generated_bytes
        aggregate = sum(limits) + state_overhead
        print(json.dumps({"fixture_scenario": args.scenario,
            "release": os.environ.get("FIXTURE_RELEASE", ""),
            "active_output_count": len(active_outputs),
            "active_outputs": active_outputs,
            "state_paths": state_paths,
            "delivery_settings": {"retry": retry_settings},
            "enforced_limits": {"aggregate_bytes": aggregate,
                                 "output_limits_bytes": limits,
                                 "state_overhead_bytes": state_overhead,
                                 "generator_artifact_bytes": generated_bytes,
                                 "provenance": "generated active-output limits"},
            "terraform_reservation_bytes": reservation,
            "generator_sha256": os.environ.get("FIXTURE_GENERATOR_SHA256", ""),
            "generated_artifact_sha256": actual_digest}, sort_keys=True))
        return
    output = run_scripts(args, args.scenario)
    output.update({"fixture_scenario": args.scenario,
                   "generator_sha256": os.environ.get("FIXTURE_GENERATOR_SHA256", ""),
                   "fluent_bit_sha256": os.environ.get("FIXTURE_FLUENT_BIT_SHA256", ""),
                   "generated_artifact_sha256": actual_digest})
    print(json.dumps(output, sort_keys=True))


if __name__ == "__main__":
    main()
'''

    def _render_fixture_template(self, template, *, config=False):
        """Render the Terraform template subset needed by the fixture."""
        units = [
            "superserve-vmd.service", "proxy.service", "systemd.service",
            "superserve-secretsproxy.service", "google-cloud-ops-agent.service",
        ]
        loop = "".join(f"# enrolled unit: {unit}\n" for unit in units)
        template = re.sub(r"%\{ for unit in host_units ~\}.*?%\{ endfor ~\}\n?", loop,
                          template, flags=re.DOTALL)
        values = {
            "environment": "fixture", "region": "us-central1",
            "assignment_name": "fixture-host-logging",
            "assignment_revision": "fixture-revision",
            "ops_agent_package_version": self.selected_release,
            "config_path": "/etc/google-cloud-ops-agent/config.yaml",
            "candidate_config_path": "/var/lib/superserve/host-logging/config.yaml.candidate",
            "journald_dropin": "/etc/systemd/journald.conf.d/30-superserve-host-logging.conf",
            "journald_candidate_path": "/var/lib/superserve/host-logging/journald.conf.candidate",
            "journal_max_use_bytes": "4294967296", "journal_keep_free_bytes": "10737418240",
            "agent_memory_limit_mb": "512", "agent_cpu_limit_millicores": "1000",
            "agent_buffer_bytes": "1073741824", "agent_self_log_max_bytes": "268435456",
            "syslog_max_bytes": "268435456", "storage_scan_timeout_seconds": "5",
            "storage_scan_max_entries": "32", "package_operation_timeout_seconds": "30",
            "heartbeat_interval_seconds": "60",
            "ceil(agent_self_log_max_bytes / 2 / 1048576)": "128",
            "ceil(syslog_max_bytes / 3 / 1048576)": "85",
            "agent_cpu_limit_millicores / 10": "100",
            "agent_cpu_limit_millicores / 20": "50",
            "agent_memory_limit_mb / 2": "256",
        }
        for key, value in values.items():
            template = template.replace("${" + key + "}", value)
        template = template.replace("$${", "${")
        if config:
            template = template.replace("__HOST_ID__", "fixture-host").replace(
                "__INCARNATION_ID__", "fixture-incarnation")
        return template

    def _docker(self):
        docker = shutil.which("docker")
        if not docker:
            self.fail("docker is required to lazily prepare the selected-agent fixture")
        return docker

    def _run_bounded(self, argv, *, timeout=None, cwd=None):
        timeout = timeout or self.fixture_setup_timeout
        deadline = getattr(self, "_fixture_deadline", None)
        if deadline is not None:
            timeout = min(timeout, max(1, int(deadline - time.monotonic())))
        try:
            result = subprocess.run(argv, text=True, capture_output=True,
                                    timeout=timeout, cwd=cwd, check=False)
        except subprocess.TimeoutExpired:
            self.fail(f"fixture preparation timed out after {timeout}s: {' '.join(argv)}")
        if result.returncode:
            detail = (result.stderr or result.stdout).strip()[-4000:]
            self.fail(f"fixture preparation failed ({result.returncode}): {' '.join(argv)}\n{detail}")
        return result.stdout.strip()

    def _valid_cached_fixture(self, metadata_path):
        """Return immutable package/image metadata only when its provenance is complete."""
        try:
            metadata = json.loads(metadata_path.read_text())
        except (OSError, ValueError):
            return None
        if metadata.get("release") != self.selected_release:
            return None
        if metadata.get("source_revision") != self.selected_release_commit:
            return None
        if metadata.get("distribution") != "ubuntu-24.04":
            return None
        if metadata.get("architecture") != "amd64":
            return None
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(metadata.get("base_image_digest", ""))):
            return None
        if str(metadata.get("package_version", "")).split("~", 1)[0] != self.selected_release:
            return None
        for key in ("package_sha256", "generator_sha256", "fluent_bit_sha256",
                    "repository_setup_sha256", "authenticated_packages_metadata_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", str(metadata.get(key, ""))):
                return None
        if not re.search(r"@sha256:[0-9a-f]{64}$", str(metadata.get("image", ""))):
            return None
        if (not metadata.get("runtime_image") or not metadata.get("engine_path") or
                not str(metadata.get("fluent_bit_path", "")).endswith("fluent-bit") or
                not str(metadata.get("journal_remote_path", "")).endswith("systemd-journal-remote")):
            return None
        return metadata

    def _prepare_selected_agent_fixture(self):
        """Build/cache the immutable image and materialize a fresh run input."""
        docker = self._docker()
        cache = Path(tempfile.gettempdir()) / self.fixture_cache_name
        self._fixture_deadline = time.monotonic() + self.fixture_setup_timeout
        cache.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self._fixture_lock is None:
            self.__class__._fixture_lock = cache / ".lock"
        lock = self._fixture_lock
        deadline = time.monotonic() + self.fixture_setup_timeout
        while True:
            try:
                lock.mkdir()
                break
            except FileExistsError:
                if time.monotonic() > deadline:
                    self.fail("timed out waiting for the selected-agent fixture cache lock")
                time.sleep(0.2)
        try:
            # Check complete immutable provenance before pulling an image or
            # probing the package repository.  The cache is keyed below by
            # release, distribution, architecture, and resolved base digest;
            # volatile apt indexes and fixture source are never cache identity.
            image_meta = None
            metadata = None
            candidates = [cache / "image.json"] + sorted(cache.glob("*/image.json"))
            for candidate in candidates:
                cached = self._valid_cached_fixture(candidate)
                if cached is not None:
                    image_meta, metadata = candidate, cached
                    break
            if image_meta is None:
                build = Path(tempfile.mkdtemp(prefix="build-", dir=cache))
                try:
                    base_ref = "ubuntu:24.04"
                    self._run_bounded([docker, "pull", "--platform", "linux/amd64", base_ref], timeout=120)
                    base_digest = self._run_bounded([docker, "image", "inspect", base_ref,
                                                     "--format", "{{index .RepoDigests 0}}"])
                    if "@sha256:" in base_digest:
                        base_digest = base_digest.rsplit("@", 1)[1]
                    else:
                        base_digest = "sha256:" + self._run_bounded(
                            [docker, "image", "inspect", base_ref, "--format", "{{.Id}}"]
                        ).removeprefix("sha256:")
                    probe = r'''set -eu
apt-get update >/dev/null
apt-get install -y --no-install-recommends ca-certificates curl gnupg >/dev/null
curl -fsSL https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh -o /tmp/add-repo.sh
setup_sha=$(sha256sum /tmp/add-repo.sh | awk '{print $1}')
bash /tmp/add-repo.sh >/dev/null
apt-get update >/dev/null
version=$(apt-cache madison google-cloud-ops-agent | awk '$3 ~ /^2\.71\.0(~|$)/ {print $3; exit}')
test -n "$version"
metadata=$(find /var/lib/apt/lists -maxdepth 1 -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
printf '%s %s %s\n' "$version" "$setup_sha" "$metadata"
'''
                    probe_out = self._run_bounded(
                        [docker, "run", "--rm", "--platform", "linux/amd64", base_ref,
                         "/bin/bash", "-ceu", probe], timeout=120)
                    package_version, setup_sha, metadata_sha = probe_out.splitlines()[-1].split()
                    dockerfile = build / "Dockerfile"
                    dockerfile.write_text(textwrap.dedent(f"""
                        FROM {base_ref}
                        ARG OPS_VERSION
                        ARG SETUP_SHA
                        ENV DEBIAN_FRONTEND=noninteractive
                        RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gnupg python3 systemd logrotate bash && \\
                            curl -fsSL https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh -o /tmp/add-repo.sh && \\
                            echo "$SETUP_SHA  /tmp/add-repo.sh" | sha256sum -c - && bash /tmp/add-repo.sh && apt-get update && \\
                            apt-get download google-cloud-ops-agent="$OPS_VERSION" && \\
                            mkdir -p /opt/fixture-metadata && cp google-cloud-ops-agent_*.deb /opt/fixture-metadata/ && \\
                            sha256sum /opt/fixture-metadata/google-cloud-ops-agent_*.deb > /opt/fixture-metadata/package.sha256 && \\
                            apt-get install -y --no-install-recommends /opt/fixture-metadata/google-cloud-ops-agent_*.deb && \\
                            find /var/lib/apt/lists -maxdepth 1 -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{{print $1}}' > /opt/fixture-metadata/apt-metadata.sha256 && \\
                            rm -rf /var/lib/apt/lists/* /tmp/add-repo.sh
                    """))
                    tag = f"superserve-host-logging-fixture:{uuid.uuid4().hex[:12]}"
                    self._run_bounded([docker, "build", "--platform", "linux/amd64", "--build-arg",
                                       f"OPS_VERSION={package_version}", "--build-arg", f"SETUP_SHA={setup_sha}",
                                       "-t", tag, str(build)], timeout=150)
                    image_id = self._run_bounded([docker, "image", "inspect", tag,
                                                  "--format", "{{.Id}}"])
                    image = f"{tag}@sha256:{image_id.removeprefix('sha256:')}"
                    inspect_script = r'''set -eu
manifest=$(dpkg-query -L google-cloud-ops-agent 2>/dev/null || true)
unit_manifest=$(for unit in /lib/systemd/system/google-cloud-ops-agent*.service /usr/lib/systemd/system/google-cloud-ops-agent*.service; do
  [ -f "$unit" ] && cat "$unit"
done)
find_from_manifest() {
  name="$1"
  printf '%s\n' "$manifest" | awk -v n="$name" '$0 ~ ("/" n "$") {print; exit}'
}
engine=$(find_from_manifest google_cloud_ops_agent_engine)
if [ -z "$engine" ]; then
  engine=$(printf '%s\n' "$unit_manifest" | sed -n 's/.*ExecStart=\([^ ]*google[^ ]*engine\).*/\1/p' | head -n1)
fi
fluent=$(find_from_manifest fluent-bit)
if [ -z "$fluent" ]; then
  fluent=$(printf '%s\n' "$unit_manifest" | sed -n 's/.*ExecStart=\([^ ]*fluent[^ ]*\).*/\1/p' | head -n1)
fi
remote=$(for package in systemd-journal-remote systemd; do
  dpkg-query -L "$package" 2>/dev/null || true
done | awk '/\/systemd-journal-remote$/ {print; exit}')
remote=${remote:-$(command -v systemd-journal-remote || true)}
missing=0
for required in engine fluent remote; do
  path=$(eval "printf '%s' \"\${$required}\"")
  if [ -z "$path" ] || [ ! -x "$path" ]; then
    echo "missing executable: $required=$path" >&2
    echo "Ops Agent package manifest:" >&2
    printf '%s\n' "$manifest" >&2
    echo "service-unit ExecStart entries:" >&2
    printf '%s\n' "$unit_manifest" >&2
    missing=1
  fi
done
test "$missing" -eq 0
printf '%s\n' "$engine" "$fluent" "$remote"
installed_version=$(dpkg-query -W -f='${Version}\n' google-cloud-ops-agent)
test -n "$installed_version"
case "$installed_version" in
  2.71.0*) ;;
  *) echo "unexpected installed Ops Agent version: $installed_version" >&2; exit 1 ;;
esac
printf 'version=%s\n' "$installed_version"
sha256sum /opt/fixture-metadata/google-cloud-ops-agent_*.deb "$engine" "$fluent"
cat /opt/fixture-metadata/apt-metadata.sha256
'''
                    inspected = self._run_bounded(
                        [docker, "run", "--rm", "--platform", "linux/amd64", tag,
                         "/bin/bash", "-ceu", inspect_script], timeout=60)
                    lines = inspected.splitlines()
                    engine_path, fluent_path, remote_path = lines[:3]
                    package_version = next(line.split("=", 1)[1] for line in lines if line.startswith("version="))
                    hashes = [line.split()[0] for line in lines if re.match(r"^[0-9a-f]{64}  ", line)]
                    package_sha, generator_sha, fluent_sha = hashes[:3]
                    metadata_sha = lines[-1].strip()
                    key = hashlib.sha256(
                        f"{self.selected_release}|ubuntu-24.04|amd64|{base_digest}".encode()
                    ).hexdigest()[:32]
                    image_meta = cache / key / "image.json"
                    image_meta.parent.mkdir(mode=0o700, exist_ok=True)
                    metadata = {
                        "image": image, "runtime_image": tag, "release": self.selected_release,
                        "source_revision": self.selected_release_commit, "package_version": package_version,
                        "package_sha256": package_sha, "generator_sha256": generator_sha,
                        "fluent_bit_sha256": fluent_sha,
                        "base_image_digest": base_digest, "architecture": "amd64",
                        "distribution": "ubuntu-24.04",
                        "repository_setup_url": "https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh",
                        "repository_setup_sha256": setup_sha,
                        "authenticated_packages_metadata_sha256": metadata_sha,
                        "fixture_adaptations": ["bounded journal-export records are materialized with systemd-journal-remote and read by Fluent Bit's systemd input"],
                        "engine_path": engine_path, "fluent_bit_path": fluent_path,
                        "journal_remote_path": remote_path,
                        "runner_script": "/usr/local/bin/host-logging-fixture-runner",
                    }
                    image_meta.write_text(json.dumps(metadata, sort_keys=True, indent=2))
                finally:
                    shutil.rmtree(build, ignore_errors=True)
            if metadata is None:
                metadata = json.loads(image_meta.read_text())
            run_dir = cache / "runs" / uuid.uuid4().hex
            run_dir.mkdir(mode=0o700, parents=True)
            runner = run_dir / "fixture-runner.py"
            runner.write_text(self._fixture_runner_source())
            runner.chmod(0o755)
            rendered = self._render_fixture_template(self.config, config=True)
            (run_dir / "rendered.yaml").write_text(rendered)
            (run_dir / "reconcile.sh").write_text(self._render_fixture_template(self.reconcile))
            (run_dir / "validate.sh").write_text(self._render_fixture_template(self.validate))
            # Generate output from the freshly rendered template for this run,
            # but keep that digest out of the package-image cache.  A template
            # or fixture-runner change must not reinstall or rebuild the agent.
            generated_dir = run_dir / "generated"
            generated_dir.mkdir()
            self._run_bounded([
                docker, "run", "--rm", "--platform", "linux/amd64", "--network", "none",
                "-v", f"{run_dir}:/fixture:ro", "-v", f"{generated_dir}:/tmp/ops-agent-generated:rw",
                metadata.get("runtime_image", metadata["image"]), "/bin/bash", "-ceu",
                "mkdir -p /tmp/logs /tmp/state; "
                f"\"{metadata['engine_path']}\" -in /fixture/rendered.yaml -service fluentbit "
                "-out /tmp/ops-agent-generated -logs /tmp/logs -state /tmp/state",
            ], timeout=45)
            digest = hashlib.sha256()
            for path in sorted(generated_dir.rglob("*")):
                if path.is_file():
                    digest.update(path.relative_to(generated_dir).as_posix().encode() + b"\0")
                    digest.update(hashlib.sha256(path.read_bytes()).digest())
            generated_digest = digest.hexdigest()
            manifest = dict(metadata)
            manifest["runner_script"] = "/fixture/fixture-runner.py"
            manifest["runner_sha256"] = hashlib.sha256(runner.read_bytes()).hexdigest()
            manifest["rendered_input_sha256"] = hashlib.sha256(rendered.encode()).hexdigest()
            manifest["generated_artifact_sha256"] = generated_digest
            manifest_path = run_dir / "manifest.json"
            manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2))
            if "generated_dir" in locals():
                shutil.rmtree(generated_dir, ignore_errors=True)
            return manifest_path
        finally:
            try:
                lock.rmdir()
            except OSError:
                pass

    def _run_selected_agent_fixture(self, scenario):
        """Execute the packaged engine and Fluent Bit in the prepared container."""
        manifest_path, manifest = self._selected_agent_manifest()
        docker = shutil.which("docker")
        if not docker:
            self.fail("docker is required for the selected-agent fixture executor")
        fixture_dir = manifest_path.parent.resolve()
        runtime_image = manifest.get("runtime_image", manifest["image"])
        image_candidates = [manifest["image"]]
        if runtime_image != manifest["image"]:
            image_candidates.append(runtime_image)
        command_tail = [
            docker, "run", "--rm", "--platform", "linux/amd64", "--network", "none",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--tmpfs", "/tmp:rw,nosuid,nodev", "--tmpfs", "/run:rw,nosuid,nodev",
            "-e", f"FIXTURE_GENERATOR_SHA256={manifest['generator_sha256']}",
            "-e", f"FIXTURE_FLUENT_BIT_SHA256={manifest['fluent_bit_sha256']}",
            "-e", f"FIXTURE_GENERATED_ARTIFACT_SHA256={manifest['generated_artifact_sha256']}",
            "-e", f"FIXTURE_RELEASE={manifest['release']}",
            "/bin/bash", "-ceu",
            "engine=\"$1\"; fluent=\"$2\"; runner=\"$3\"; scenario=\"$4\"; "
            "mkdir -p /tmp/ops-agent-generated /tmp/ops-agent-logs /tmp/ops-agent-state; "
            "\"$engine\" -in /fixture/rendered.yaml -service fluentbit "
            "-out /tmp/ops-agent-generated -logs /tmp/ops-agent-logs "
            "-state /tmp/ops-agent-state; "
            "\"$runner\" --generated /tmp/ops-agent-generated --scenario \"$scenario\" "
            "--fluent-bit \"$fluent\" --journal-remote \"$5\" "
            "--rendered /fixture/rendered.yaml --reconcile /fixture/reconcile.sh "
            "--validate /fixture/validate.sh",
            "fixture", manifest["engine_path"], manifest["fluent_bit_path"],
            manifest["runner_script"], scenario, manifest["journal_remote_path"],
        ]
        result = None
        for image in image_candidates:
            command = command_tail[:]
            insert_at = command.index("/bin/bash")
            command[insert_at:insert_at] = ["-v", f"{fixture_dir}:/fixture:ro", image]
            result = subprocess.run(command, text=True, capture_output=True,
                                    timeout=170, check=False)
            if result.returncode == 0 or image == image_candidates[-1]:
                break
        self.assertEqual(result.returncode, 0, result.stderr)
        records = []
        for line in result.stdout.splitlines():
            if line.strip():
                records.append(json.loads(line))
        self.assertTrue(records, f"selected-agent fixture emitted no records: {result.stdout!r}")
        for record in records:
            if "generator_sha256" in record:
                self.assertEqual(record["generator_sha256"], manifest["generator_sha256"])
            if "fluent_bit_sha256" in record:
                self.assertEqual(record["fluent_bit_sha256"], manifest["fluent_bit_sha256"])
        return records

    def _run_embedded_scan(self, template, kind, root, limit=100, failure=None,
                           occurrence=0, first_install=False):
        """Run the exact Python traversal embedded in a rendered script.

        Keeping the source extraction tied to the template prevents this test
        from quietly becoming an independent storage-accounting model.
        """
        matches = list(re.finditer(
            r'python3 - "\$kind" "\$root" "\$max_entries"(?:\s+>\s*"?\$listing"?)?\s+<<\'PY\'\n(.*?)\nPY',
            template,
            re.DOTALL,
        ))
        self.assertTrue(matches, "storage scanner heredoc missing")
        self.assertLess(occurrence, len(matches), "storage scanner occurrence missing")
        scanner = matches[occurrence].group(1)
        wrapper = textwrap.dedent(
            """
            import os
            import sys

            failure = sys.argv.pop(1)
            original_scandir = os.scandir
            original_stat = os.stat
            stat_calls = [0]

            class Entry:
                def __init__(self, entry):
                    self._entry = entry
                    self.name = entry.name
                    self.path = entry.path

                def is_dir(self, follow_symlinks=False):
                    return self._entry.is_dir(follow_symlinks=follow_symlinks)

                def is_file(self, follow_symlinks=False):
                    return self._entry.is_file(follow_symlinks=follow_symlinks)

                def stat(self, follow_symlinks=False):
                    if failure == "stat":
                        raise OSError("injected stat failure")
                    return self._entry.stat(follow_symlinks=follow_symlinks)

            class Entries:
                def __init__(self, path):
                    self.path = path

                def __enter__(self):
                    if failure == "open":
                        raise OSError("injected scandir open failure")
                    return self

                def __exit__(self, *args):
                    return False

                def __iter__(self):
                    if failure == "iteration":
                        raise OSError("injected scandir iteration failure")
                    for entry in original_scandir(self.path):
                        yield Entry(entry)

            def scandir(path):
                return Entries(path)

            def stat(path, *args, **kwargs):
                stat_calls[0] += 1
                if failure == "root-stat" and path == sys.argv[2]:
                    raise OSError("injected root stat failure")
                if failure == "disappear" and path == sys.argv[2] and stat_calls[0] > 1:
                    raise FileNotFoundError(path)
                return original_stat(path, *args, **kwargs)

            os.scandir = scandir
            os.stat = stat
            if %r:
                os.environ["SUPER_SERVE_FIRST_INSTALL"] = "1"
            exec(compile(%r, "embedded-storage-scanner", "exec"), {"__name__": "__main__"})
            """
        ) % (first_install, scanner)
        return subprocess.run(
            [sys.executable, "-c", wrapper, failure or "none", kind, str(root), str(limit)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def _run_storage_compliance(self, result_path, *, buffer_limit=10, self_log_limit=10,
                                syslog_limit=10, journal_max=10, journal_keep_free=100):
        """Run the validate template's storage-compliance fragment unchanged."""
        start = self.validate.index(
            "storage_bytes=0; buffer_bytes=0; self_log_bytes=0; syslog_bytes=0"
        )
        end = self.validate.index("\nexit 100", start) + len("\nexit 100")
        fragment = self.validate[start:end]
        substitutions = {
            "agent_buffer_bytes": buffer_limit,
            "agent_self_log_max_bytes": self_log_limit,
            "syslog_max_bytes": syslog_limit,
            "journal_max_use_bytes": journal_max,
            "journal_keep_free_bytes": journal_keep_free,
        }
        for name, value in substitutions.items():
            fragment = fragment.replace("${" + name + "}", str(value))
        script = textwrap.dedent(
            f"""
            set -u
            drift=0
            journal_max_use_bytes={journal_max}
            storage_scan_result="$1"
            {fragment}
            """
        )
        return subprocess.run(
            ["bash", "-c", script, "storage-compliance", str(result_path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def _scan_storage_stores(self, root, limit=100):
        """Collect rows by executing each embedded scanner implementation."""
        stores = (("buffer", root / "buffer"), ("self_log", root / "self-log"),
                  ("syslog", root / "syslog"))
        rows = []
        for kind, path in stores:
            scanned = self._run_embedded_scan(self.validate, kind, path, limit=limit)
            self.assertEqual(scanned.returncode, 0, scanned.stderr)
            rows.append(scanned.stdout.strip())
        return "\n".join(rows) + "\n"

    def test_allowlist_and_single_journal_path(self):
        self.assertIn("systemd_journald", self.config)
        self.assertIn("proxy.service", self.config + self.reconcile)
        self.assertIn("superserve-secretsproxy.service", self.reconcile)
        self.assertIn("systemd.service", self.reconcile)
        self.assertNotIn("syslog-file", self.config)

    def test_parse_before_filter_and_platform_context(self):
        self.assertLess(self.config.index("parse_application_json"), self.config.index("exclude_debug_after_parse"))
        self.assertLess(self.config.index("capture_journal_provenance"), self.config.index("parse_application_json"))
        pipeline = self.config[self.config.index("host_logs:"):]
        self.assertLess(pipeline.index("capture_journal_provenance"), pipeline.index("exclude_non_platform_sources"))
        self.assertLess(pipeline.index("exclude_non_platform_sources"), pipeline.index("parse_application_json"))
        self.assertIn("labels.environment", self.config)
        self.assertIn("labels.region", self.config)
        self.assertIn("labels.host_id", self.config)
        self.assertIn("labels.instance_id", self.config)
        self.assertNotIn("copy_from: resource.labels.instance_name", self.config)
        self.assertIn("redact_sensitive_fields", self.config)
        self.assertIn("jsonPayload.level", self.config)
        self.assertIn("jsonPayload.body_snippet", self.config)
        self.assertIn("jsonPayload.MESSAGE", self.config)
        self.assertIn("allowlisted_application_fields", self.config)
        self.assertIn("drop_unallowlisted_payload", self.config)
        self.assertIn("jsonPayload:*", self.config)
        self.assertIn("labels.host_logging_heartbeat", self.config)
        self.assertIn("parse_failure_field", self.config)
        self.assertIn("labels.parse_failure", self.config)
        self.assertNotIn("jsonPayload.severity == NULL", self.config)
        self.assertIn("default_pipeline:", self.config)

    def test_durable_retention_and_safe_activation(self):
        self.assertIn("SystemMaxUse", self.reconcile)
        self.assertIn("SystemKeepFree", self.reconcile)
        self.assertIn("journald_candidate_path", self.reconcile)
        self.assertIn("superserve-otel-collector.service", self.reconcile)
        self.assertIn("cmp -s", self.reconcile)
        self.assertIn("google_cloud_ops_agent_engine", self.reconcile)
        self.assertIn("exit 100", self.validate)

    def test_reconciliation_bounds_package_and_storage_transitions(self):
        # The selected package is validated before activation, while the
        # previous package and service/configuration state are captured for
        # rollback if installation or activation fails.
        self.assertIn("apt-get download", self.reconcile)
        self.assertIn("staged_agent", self.reconcile)
        self.assertIn("old_package_version", self.reconcile)
        self.assertIn("package_change_attempted", self.reconcile)
        self.assertIn("apt-get install -y --no-install-recommends", self.reconcile)
        self.assertIn("storage_scan_timeout_seconds", self.reconcile)
        self.assertIn("storage_scan_timeout_seconds", self.validate)
        self.assertIn("storage_scan_max_entries", self.reconcile)
        self.assertIn("storage_scan_max_entries", self.validate)
        self.assertIn("activation_committed=1", self.reconcile)
        self.assertIn("trap on_exit EXIT", self.reconcile)
        self.assertIn("agent_self_log_max_bytes", self.reconcile)
        self.assertIn("syslog_max_bytes", self.reconcile)
        self.assertIn("heartbeat_interval_seconds", self.reconcile)
        self.assertIn("storage_remediation_deadline", self.reconcile)
        self.assertIn("disposable retention cleanup incomplete", self.reconcile)

    def test_validation_and_enforcement_render_identical_metrics_dropin(self):
        expected_comment = "# Keep the standalone application-metrics collector below the logging"
        self.assertIn(expected_comment, self.reconcile)
        self.assertIn(expected_comment, self.validate)

    def test_os_config_shell_reexec_and_bounded_storage_contract(self):
        for script in (self.reconcile, self.validate):
            self.assertIn('exec /bin/bash "$0" "$@"', script)
            self.assertIn("scan_limit=$((max_entries + 1))", script)
            self.assertNotIn("find /var/log -maxdepth 1", script)
            self.assertNotIn("| sort | head", script)
        self.assertIn("exit 100", self.reconcile)
        self.assertIn("storage_scan_deadline", self.reconcile)
        self.assertIn("logrotate -f", self.reconcile)

    def test_cleanup_and_failure_alert_producers_are_bounded(self):
        self.assertEqual(self.validate.count("trap "), 1)
        self.assertIn("cleanup()", self.validate)
        self.assertIn("storage_scan_result", self.validate)
        self.assertIn("ops_agent_self_log_files", self.config)
        self.assertIn("ops_agent_self_logs", self.config)

    def test_storage_scans_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "buffer").mkdir()
            (root / "self-log").mkdir()
            (root / "syslog").mkdir()
            (root / "self-log" / "logging-module.log").write_bytes(b"agent")
            (root / "syslog" / "syslog").write_bytes(b"journal")

            for template in (self.validate, self.reconcile):
                with self.subTest(template="validate" if template is self.validate else "reconcile"):
                    scanner_count = 3 if template is self.reconcile else 1
                    for occurrence in range(scanner_count):
                        valid = self._run_embedded_scan(template, "syslog", root / "syslog", occurrence=occurrence)
                        self.assertEqual(valid.returncode, 0, valid.stderr)
                        if occurrence != 1 or template is self.validate:
                            self.assertIn("syslog", valid.stdout)
                        for failure in ("open", "iteration", "stat"):
                            failed = self._run_embedded_scan(
                                template, "syslog", root / "syslog", failure=failure, occurrence=occurrence)
                            self.assertNotEqual(failed.returncode, 0, failure)

                    if not (template is self.reconcile and occurrence == 1):
                        for missing_kind, suffix in (("buffer", "buffer"), ("self_log", "self-log")):
                            missing = self._run_embedded_scan(
                                template, missing_kind, root / f"never-created-{suffix}",
                                first_install=True, occurrence=occurrence
                            )
                            self.assertEqual(missing.returncode, 0, missing.stderr)
                            self.assertEqual(missing.stdout.strip(), f"{missing_kind} 0 0")

                    for failure in ("disappear", "root-stat"):
                        established = self._run_embedded_scan(
                            template, "buffer", root / "buffer", failure=failure,
                            occurrence=occurrence
                        )
                        self.assertNotEqual(established.returncode, 0, failure)

            for index in range(3):
                (root / "buffer" / f"chunk-{index}").write_bytes(b"x")
            capped = self._run_embedded_scan(self.validate, "buffer", root / "buffer", limit=1)
            self.assertEqual(capped.returncode, 0, capped.stderr)
            self.assertEqual(capped.stdout.strip(), "buffer 2 1")
            self.assertIn('[ "$storage_scan_capped" -eq 0 ]', self.validate)

    def test_storage_failure_preserves_activation_and_delivery_state(self):
        for scenario in (
            "invalid_candidate_before_activation",
            "child_failure_before_activation",
            "activation_restart_failure_rollback",
            "cleanup_failure_after_activation",
            "post_activation_storage_violation",
            "idempotent_repetition",
        ):
            records = self._run_selected_agent_fixture(scenario)
            self.assertEqual(len(records), 1, records)
            report = records[0]
            self.assertEqual(report.get("fixture_scenario"), scenario)
            self.assertIn(report.get("os_config_exit"), (0, 100, 101, 1))
            self.assertTrue(report.get("committed_config_preserved"))
            self.assertTrue(report.get("pending_delivery_state_preserved"))
            if scenario == "idempotent_repetition":
                self.assertTrue(report.get("second_run_compliant"))
            if scenario in {
                "invalid_candidate_before_activation",
                "child_failure_before_activation",
                "activation_restart_failure_rollback",
            }:
                self.assertFalse(report.get("activation_committed"))
            if scenario in {"cleanup_failure_after_activation", "post_activation_storage_violation"}:
                self.assertTrue(report.get("activation_committed"))

        for template in (self.validate, self.reconcile):
            with self.subTest(template="validate" if template is self.validate else "reconcile"):
                self.assertIn('test -n "$kind" || exit 1', template)
                self.assertIn('[ "$seen_buffer" -eq 1 ] && [ "$seen_self_log" -eq 1 ] && [ "$seen_syslog" -eq 1 ] || exit 1', template)
        self.assertIn('if [ "$status" -ne 0 ] && [ "$activation_committed" -eq 0 ]', self.reconcile)
        self.assertIn('rollback || true', self.reconcile)
        self.assertIn('activation_committed=0', self.reconcile)
        self.assertIn('activation_committed=1', self.reconcile)
        self.assertIn('exit 101', self.validate)
        self.assertIn('checkpoint', self.reconcile.lower())
        self.assertIn('buffer', self.reconcile.lower())

    def test_selected_agent_export_boundary(self):
        records = []
        for scenario in (
            "allowed_sources", "excluded_sources", "severity_filter",
            "promoted_special_fields", "provenance_collision", "heartbeat_spoof",
            "malformed_metadata_only", "valid_colliding_json", "approved_correlations",
        ):
            records.extend(self._run_selected_agent_fixture(scenario))

        by_scenario = {record.get("fixture_scenario"): record for record in records}
        self.assertIn("allowed_sources", by_scenario)
        self.assertIn("malformed_metadata_only", by_scenario)
        self.assertIn("excluded_sources", by_scenario)
        malformed = by_scenario["malformed_metadata_only"]
        labels = malformed.get("labels", {})
        self.assertTrue(labels.get("parse_failure"), malformed)
        self.assertIn("host_id", labels)
        self.assertIn("incarnation", labels)
        self.assertIn("journal_unit", labels)
        self.assertNotIn("MESSAGE", malformed.get("jsonPayload", {}))
        self.assertNotIn("raw_body", malformed)

        self.assertEqual(by_scenario["excluded_sources"].get("exported"), False)
        self.assertNotEqual(by_scenario["allowed_sources"].get("severity"), "DEBUG")
        self.assertNotEqual(by_scenario["allowed_sources"].get("severity"), "TRACE")
        for scenario in ("promoted_special_fields", "provenance_collision", "heartbeat_spoof"):
            record = by_scenario[scenario]
            self.assertNotIn("httpRequest", record)
            self.assertNotIn("traceSampled", record)
            self.assertNotIn("insertId", record)
            self.assertNotEqual(record.get("labels", {}).get("host_id"), "spoofed")

    def test_selected_agent_buffer_budget(self):
        records = self._run_selected_agent_fixture("buffer_budget")
        self.assertEqual(len(records), 1, records)
        report = records[0]
        self.assertEqual(report.get("fixture_scenario"), "buffer_budget")
        self.assertEqual(report.get("release"), self.selected_release)
        self.assertGreater(report.get("active_output_count", 0), 0)
        self.assertEqual(report["active_output_count"], len(report.get("active_outputs", [])))
        self.assertTrue(report.get("state_paths"))
        self.assertTrue(report.get("delivery_settings", {}).get("retry"))
        limits = report.get("enforced_limits", {})
        self.assertGreater(limits.get("aggregate_bytes", 0), 0)
        self.assertGreaterEqual(report.get("terraform_reservation_bytes", 0),
                                limits["aggregate_bytes"])
        # The reservation must also leave explicit room for the selected
        # generator's state/checkpoint files, rather than merely echoing the
        # output limits.
        self.assertGreater(report["terraform_reservation_bytes"],
                           sum(limits.get("output_limits_bytes", [])))
        self.assertEqual(report.get("generator_sha256"), self._selected_agent_manifest()[1]["generator_sha256"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for store in ("buffer", "self-log", "syslog"):
                (root / store).mkdir()
            (root / "buffer" / "chunk").write_bytes(b"buffer")
            (root / "self-log" / "agent.log").write_bytes(b"self-log")
            (root / "syslog" / "syslog").write_bytes(b"syslog")
            result_path = root / "storage-scan-result"
            checkpoint = root / "checkpoint"
            exporter_state = root / "exporter-state"
            checkpoint.write_text("pending checkpoint")
            exporter_state.write_text("validated exporter draining")

            result_path.write_text(self._scan_storage_stores(root))
            compliant = self._run_storage_compliance(result_path)
            self.assertEqual(compliant.returncode, 100, compliant.stderr)
            self.assertEqual(checkpoint.read_text(), "pending checkpoint")
            self.assertEqual(exporter_state.read_text(), "validated exporter draining")

            (root / "buffer" / "chunk-2").write_bytes(b"buffer")
            (root / "buffer" / "chunk-3").write_bytes(b"buffer")
            result_path.write_text(self._scan_storage_stores(root, limit=1))
            capped = self._run_storage_compliance(result_path)
            self.assertEqual(capped.returncode, 101, capped.stderr)
            self.assertEqual(checkpoint.read_text(), "pending checkpoint")
            self.assertEqual(exporter_state.read_text(), "validated exporter draining")

            unreadable = self._run_embedded_scan(
                self.validate, "buffer", root / "buffer", failure="stat"
            )
            self.assertNotEqual(unreadable.returncode, 0)
            self.assertEqual(checkpoint.read_text(), "pending checkpoint")
            self.assertEqual(exporter_state.read_text(), "validated exporter draining")

            result_path.write_text("buffer 1 0\nself_log 1 0\n")
            incomplete = self._run_storage_compliance(result_path)
            self.assertNotEqual(incomplete.returncode, 0)
            self.assertEqual(checkpoint.read_text(), "pending checkpoint")
            self.assertEqual(exporter_state.read_text(), "validated exporter draining")

            result_path.write_text("buffer 11 0\nself_log 1 0\nsyslog 1 0\n")
            over_budget = self._run_storage_compliance(result_path)
            self.assertEqual(over_budget.returncode, 101, over_budget.stderr)
            self.assertEqual(checkpoint.read_text(), "pending checkpoint")
            self.assertEqual(exporter_state.read_text(), "validated exporter draining")


if __name__ == "__main__":
    unittest.main()
