"""Linux contract fixtures for the managed host-log collector.

The runtime checks deliberately fail when Docker, Terraform, the pinned
release, or the journal tooling cannot be acquired. A static substring check
must not turn an unavailable collector into a passing privacy or persistence
claim. The outer workflow supplies the supported Linux/Docker environment.
"""

import json
import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "infra/modules/host-logging"
IMAGE = os.environ.get("SUPER_SERVE_OTEL_FIXTURE_IMAGE", "ubuntu:24.04")
FIXTURE_PLATFORM = os.environ.get("SUPER_SERVE_OTEL_FIXTURE_PLATFORM", "linux/amd64")
FIXTURE_IMAGE_TAG = os.environ.get(
    "SUPER_SERVE_OTEL_FIXTURE_IMAGE_TAG", "superserve-host-logging-fixture:ubuntu-24.04-v1"
)


class HostLoggingConfigChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.variables = (MODULE / "variables.tf").read_text()
        release = re.search(r'variable "otel_release_version"[\s\S]*?default\s*=\s*"([^"]+)"', cls.variables)
        digest = re.search(r'variable "otel_release_sha256"[\s\S]*?default\s*=\s*"([0-9a-f]{64})"', cls.variables)
        cls.release = release.group(1) if release else ""
        cls.digest = digest.group(1) if digest else ""
        if not cls.release or not cls.digest:
            raise AssertionError("the Terraform module must pin a release and SHA-256 digest")

    def _render_templates(self, root):
        """Render every artifact through Terraform's real templatefile()."""
        values = {
            "environment": "fixture",
            "region": "us-central1",
            "assignment_name": "fixture-host-logging",
            "assignment_revision": "fixture-revision",
            "release_version": self.release,
            "host_units": [
                "superserve-vmd.service", "proxy.service", "proxy-generation.service",
                "systemd-journald.service", "systemd-logind.service",
                "google-osconfig-agent.service", "google-guest-agent.service",
                "superserve-otel-logs.service", "unbound.service", "secretsproxy.service",
                "superserve-host-logging-heartbeat.service",
            ],
            "cursor_dir": "/var/lib/superserve/host-logging/cursor",
            "queue_dir": "/var/lib/superserve/host-logging/export-queue",
            "binary_path": "/opt/superserve/otelcol-contrib/bin/otelcol-contrib",
            "config_path": "/etc/superserve/host-logging/otel-logs.yaml",
            "queue_max_bytes": 2147483648,
            "memory_limit_mb": 512,
            "cpu_limit": "100%",
            "candidate_config_path": "/var/lib/superserve/host-logging/otel-logs.yaml.candidate",
            "candidate_service_path": "/var/lib/superserve/host-logging/otel-logs.service.candidate",
            "journald_dropin": "/etc/systemd/journald.conf.d/30-superserve-host-logging.conf",
            "journald_candidate_path": "/var/lib/superserve/host-logging/journald.conf.candidate",
            "state_dir": "/var/lib/superserve/host-logging",
            "journal_max_use_bytes": 4294967296,
            "journal_keep_free_bytes": 10737418240,
            "otel_config": "fixture",
            "otel_service": "fixture",
            "otel_release_version": self.release,
            "otel_release_url": f"https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v{self.release}/otelcol-contrib_{self.release}_linux_amd64.tar.gz",
            "otel_release_sha256": self.digest,
            "otel_binary_path": "/opt/superserve/otelcol-contrib/bin/otelcol-contrib",
            "package_operation_timeout_seconds": 120,
            "heartbeat_interval_seconds": 60,
            "otel_queue_max_bytes": 2147483648,
        }
        templates = {
            "config": MODULE / "templates/otel-logs.yaml.tftpl",
            "service": MODULE / "templates/otel-logs.service.tftpl",
            "reconcile": MODULE / "templates/reconcile.sh.tftpl",
            "validate": MODULE / "templates/validate.sh.tftpl",
        }
        # JSON is valid Terraform expression syntax and avoids a second,
        # incomplete implementation of Terraform interpolation in this test.
        main = []
        for name, template in templates.items():
            main.append(f"locals {{ rendered_{name} = templatefile({json.dumps(str(template))}, {json.dumps(values)}) }}")
        (root / "main.tf").write_text("\n".join(main) + "\n")
        rendered = {}
        for name in templates:
            result = subprocess.run(
                ["terraform", "-chdir=" + str(root), "console", "-input=false"],
                input=f"local.rendered_{name}\n",
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            if result.returncode:
                self.fail(f"Terraform templatefile rendering failed for {name}: {result.stderr}")
            lines = result.stdout.splitlines()
            if len(lines) < 3 or lines[0] != "<<EOT" or lines[-1] != "EOT":
                self.fail(f"unexpected terraform console output for {name}: {result.stdout[:200]}")
            rendered[name] = "\n".join(lines[1:-1]) + "\n"
        return rendered

    def _docker(self, name, fixture, script, timeout=300):
        """Run one named, self-cleaning Linux fixture with a bounded mount."""
        probe = subprocess.run(["docker", "info"], text=True, capture_output=True, timeout=20)
        if probe.returncode:
            self.fail("Docker daemon is required for the host-logging Linux fixture: docker info failed")
        image = self._fixture_image()
        cache = self._release_cache()
        cache.mkdir(mode=0o700, parents=True, exist_ok=True)
        cmd = [
            "docker", "run", "--rm", "--platform", FIXTURE_PLATFORM, "--name", name,
            "-v", f"{fixture}:/fixture:rw", "-v", f"{cache}:/fixture/immutable-cache:rw",
            image, "bash", "-euo", "pipefail", "-c", script,
        ]
        try:
            result = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False)
        finally:
            subprocess.run(["docker", "rm", "-f", name], text=True, capture_output=True, timeout=20, check=False)
        if result.returncode:
            self.fail(f"Linux fixture {name} failed (exit {result.returncode}):\n{result.stdout}\n{result.stderr}")
        return result.stdout

    def _release_cache(self):
        """Use one host cache for the authenticated release across selectors/processes."""
        cache_root = os.environ.get("SUPER_SERVE_OTEL_FIXTURE_CACHE")
        if cache_root:
            return Path(cache_root)
        return Path(tempfile.gettempdir()) / f"superserve-otel-cache-{self.release}-{self.digest}"

    def _fixture_image(self):
        """Build the tool-complete fixture image once, then reuse Docker's immutable layer cache."""
        if os.environ.get("SUPER_SERVE_OTEL_FIXTURE_IMAGE"):
            return IMAGE
        inspect = subprocess.run(
            ["docker", "image", "inspect", "--platform", FIXTURE_PLATFORM, FIXTURE_IMAGE_TAG],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if inspect.returncode == 0:
            return FIXTURE_IMAGE_TAG
        dockerfile = """\
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \\
    && apt-get install -y --no-install-recommends ca-certificates curl gzip tar systemd systemd-journal-remote \\
    && rm -rf /var/lib/apt/lists/*
"""
        build = subprocess.run(
            ["docker", "build", "--platform", FIXTURE_PLATFORM, "-t", FIXTURE_IMAGE_TAG, "-"],
            input=dockerfile,
            text=True,
            capture_output=True,
            timeout=300,
            check=False,
        )
        if build.returncode:
            self.fail(f"Linux fixture image build failed:\n{build.stdout}\n{build.stderr}")
        return FIXTURE_IMAGE_TAG

    def _acquire_release(self, fixture):
        archive = f"otelcol-contrib_{self.release}_linux_amd64.tar.gz"
        # Goreleaser publishes the manifest under the distribution-qualified
        # name; the shorter legacy name is not present on current releases.
        checksums = "opentelemetry-collector-releases_otelcol-contrib_checksums.txt"
        return textwrap.dedent(f"""
            mkdir -p /fixture/immutable-cache /fixture/bin
            archive=/fixture/immutable-cache/{archive}
            checksums=/fixture/immutable-cache/{checksums}
            archive_url='https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v{self.release}/{archive}'
            checksums_url='https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v{self.release}/{checksums}'
            fetch() {{
              url="$1"; destination="$2"
              printf 'acquiring pinned OTel fixture asset: %s\\n' "$url" >&2
              tmp="$destination.tmp.$$"
              curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 "$url" -o "$tmp"
              test -s "$tmp"
              mv -f "$tmp" "$destination"
            }}
            if [ ! -s "$archive" ] || [ "$(sha256sum "$archive" | awk '{{print $1}}')" != '{self.digest}' ]; then
              fetch "$archive_url" "$archive"
            fi
            if [ ! -s "$checksums" ] || ! grep -Eq '[[:space:]]{archive}$' "$checksums"; then
              fetch "$checksums_url" "$checksums"
            fi
            grep -E '[[:space:]]{archive}$' "$checksums" > /tmp/otel-checksum-line
            (cd /fixture/immutable-cache && sha256sum -c /tmp/otel-checksum-line)
            test "$(sha256sum "$archive" | awk '{{print $1}}')" = '{self.digest}'
            tar -xzf "$archive" -C /fixture/bin
            test -x /fixture/bin/otelcol-contrib
            /fixture/bin/otelcol-contrib --version | grep -F '{self.release}'
            /fixture/bin/otelcol-contrib components | grep -E 'journald|file_storage|googlecloud|transform|filter'
        """).strip()

    def _run_collector_fixture(self, rendered):
        with tempfile.TemporaryDirectory(prefix="host-logging-otel-") as directory:
            fixture = Path(directory)
            (fixture / "config.yaml").write_text(rendered["config"])
            # Local output is an explicit debug-exporter substitute. The
            # exact rendered googlecloud mapping is validated before this
            # substitution; no labels or records are fabricated after capture.
            runtime = re.sub(
                r"(?ms)^exporters:\n.*?^service:\n",
                "exporters:\n  debug:\n    verbosity: detailed\n\nservice:\n",
                rendered["config"],
            ).replace("exporters: [googlecloud]", "exporters: [debug]")
            if "googlecloud:" not in rendered["config"] or "exporters: [debug]" not in runtime:
                self.fail("runtime fixture did not preserve the rendered exporter mapping before explicit capture substitution")
            (fixture / "runtime.yaml").write_text(runtime)
            script = self._acquire_release(fixture) + textwrap.dedent("""
                mkdir -p /var/lib/superserve/host-logging/cursor /var/lib/superserve/host-logging/export-queue /var/log/journal
                export HOST_ID=fixture-host INSTANCE_ID=fixture-instance INCARNATION_ID=fixture-incarnation
                timeout 25s /fixture/bin/otelcol-contrib --config /fixture/runtime.yaml > /fixture/collector.log 2>&1 &
                collector=$!
                sleep 3
                now=$(date +%s)000000
                emit() {
                  unit="$1"; transport="$2"; priority="$3"; message="$4"
                  { printf '__REALTIME_TIMESTAMP=%s\\n' "$now"; printf '_BOOT_ID=11111111111111111111111111111111\\n'; printf '_HOSTNAME=fixture-host\\n'; printf '_PID=42\\n'; printf 'PRIORITY=%s\\n' "$priority"; [ -z "$unit" ] || printf '_SYSTEMD_UNIT=%s\\n' "$unit"; printf '_TRANSPORT=%s\\n' "$transport"; printf 'MESSAGE=%s\\n\\n' "$message"; }
                }
                : > /fixture/journal.export
                emit superserve-vmd.service journal 6 '{"level":"INFO","message":"safe-info","request_id":"req-1","host_id":"evil-host","labels":{"authorization":"SECRET_NESTED"}}' >> /fixture/journal.export
                emit superserve-vmd.service journal 6 '{"level":"DEBUG","message":"debug-only"}' >> /fixture/journal.export
                emit proxy-generation.service journal 6 '{"level":"INFO","message":"proxy-safe","sandbox_id":"sandbox-1"}' >> /fixture/journal.export
                emit proxy.service journal 6 'malformed SECRET_SENTINEL authorization=Bearer-SECRET' >> /fixture/journal.export
                emit systemd-journald.service journal 5 'trusted-systemd-diagnostic' >> /fixture/journal.export
                emit '' kernel 5 'trusted-kernel-diagnostic' >> /fixture/journal.export
                emit other.service journal 6 'drop-me' >> /fixture/journal.export
                emit '' journal 6 'missing-unit-drop' >> /fixture/journal.export
                # Ubuntu's package installs this helper outside PATH in some
                # releases. Resolve the installed package path instead of
                # substituting a text fixture for the journal binary format.
                journal_remote=$(command -v systemd-journal-remote || true)
                if [ -z "$journal_remote" ]; then
                  journal_remote=$(find /usr/lib /lib -type f -name systemd-journal-remote -perm -u+x -print -quit 2>/dev/null || true)
                fi
                test -n "$journal_remote" && test -x "$journal_remote"
                "$journal_remote" --output=/var/log/journal/fixture.journal - < /fixture/journal.export
                sleep 10
                kill -TERM "$collector" 2>/dev/null || true
                wait "$collector" || true
                test -s /fixture/collector.log
                cat /fixture/collector.log
            """)
            return self._docker("superserve-host-logging-runtime", fixture, script, timeout=360)

    def test_allowlist_and_single_journal_path(self):
        with tempfile.TemporaryDirectory(prefix="host-logging-render-") as directory:
            rendered = self._render_templates(Path(directory))
            config = rendered["config"]
            self.assertIn("journald:", config)
            self.assertIn("filter/approved_sources:", config)
            self.assertIn("filter/info_plus:", config)
            self.assertIn("parse_application_message", config)
            self.assertIn("clear_untrusted_body", config)
            self.assertIn("host_logging.parse_outcome", config)
            self.assertNotIn("filelog/", config)
            self.assertNotIn("ops-agent", config.lower())
            self.assertEqual(config.count("receivers: [journald]"), 1)
            self.assertIn("googlecloud:", config)
            self.assertIn("journal.priority", config)
            self.assertIn('attributes["journal.unit"] == nil', config)
            self._run_collector_fixture(rendered)

    def test_trusted_metadata_and_collision_resistance_contract(self):
        with tempfile.TemporaryDirectory(prefix="host-logging-render-") as directory:
            rendered = self._render_templates(Path(directory))
            config = rendered["config"]
            for field in ("host_id", "provider_instance_id", "incarnation", "environment", "region", "unit", "generation"):
                self.assertIn(field, config)
            for field in (
                'delete_key(attributes["application"], "host_id")',
                'delete_key(attributes["application"], "labels")',
                'delete_key(attributes["application"], "parse_outcome")',
                'delete_key(attributes["application"], "httpRequest")',
            ):
                self.assertIn(field, config)
            self.assertIn("raw_body_discarded", config)
            output = self._run_collector_fixture(rendered)
            self.assertIn("safe-info", output)
            self.assertIn("proxy-safe", output)
            self.assertIn("application parse failure", output)
            self.assertNotIn("debug-only", output)
            self.assertNotIn("drop-me", output)
            self.assertNotIn("missing-unit-drop", output)
            self.assertNotIn("SECRET_SENTINEL", output)
            self.assertNotIn("SECRET_NESTED", output)
            self.assertNotIn("evil-host", output)
            self.assertIn("fixture-host", output)
            self.assertIn("fixture-incarnation", output)

    def test_release_and_state_are_pinned_and_separate(self):
        self.assertRegex(self.variables, r'otel_release_version[^\n]+')
        self.assertRegex(self.variables, r'default\s+=\s+"0\.119\.0"')
        self.assertRegex(self.variables, r'default\s+=\s+"[0-9a-f]{64}"')
        with tempfile.TemporaryDirectory(prefix="host-logging-render-") as directory:
            rendered = self._render_templates(Path(directory))
            config = rendered["config"]
            self.assertIn("file_storage/cursor", config)
            self.assertIn("file_storage/queue", config)
            self.assertIn("on_start: true", config)
            self.assertIn("directory: /var/lib/superserve/host-logging/export-queue/compaction", config)
            self.assertIn("/var/lib/superserve/host-logging/cursor", rendered["service"])
            self.assertIn("/var/lib/superserve/host-logging/export-queue", rendered["service"])
            self.assertNotIn("superserve-otel-collector.service", rendered["service"])
            with tempfile.TemporaryDirectory(prefix="host-logging-acquire-") as fixture_dir:
                fixture = Path(fixture_dir)
                (fixture / "config.yaml").write_text(config)
                script = self._acquire_release(fixture) + textwrap.dedent("""
                    mkdir -p /fixture/state/cursor /fixture/state/export-queue /var/log/journal
                    /fixture/bin/otelcol-contrib validate --config /fixture/config.yaml
                """)
                self._docker("superserve-host-logging-release", fixture, script, timeout=360)

    def _assert_reconcile_failure_preserves_state(self, rendered, mode):
        with tempfile.TemporaryDirectory(prefix="host-logging-reconcile-") as directory:
            fixture = Path(directory)
            (fixture / "reconcile.sh").write_text(rendered["reconcile"])
            script = textwrap.dedent(f"""
                mkdir -p /fixture/bin /var/lib/superserve/host-logging /etc/superserve/host-logging /etc/systemd/system /etc/systemd/journald.conf.d /etc/sandbox /opt/superserve/otelcol-contrib/bin /var/lib/superserve/host-logging/cursor /var/lib/superserve/host-logging/export-queue
                cat > /fixture/bin/systemctl <<'EOF'
                #!/bin/sh
                case "$1" in
                  is-active|is-enabled) exit 0;;
                  *) printf '%s\n' "$*" >> /fixture/systemctl.calls; exit 0;;
                esac
                EOF
                cat > /fixture/bin/df <<'EOF'
                #!/bin/sh
                if [ "{mode}" = storage ]; then echo 'Filesystem 1024-blocks Used Available Capacity Mounted on'; echo 'fixture 1 1 1024 1% /'; else echo 'Filesystem 1024-blocks Used Available Capacity Mounted on'; echo 'fixture 1 1 999999999 1% /'; fi
                EOF
                chmod +x /fixture/bin/systemctl /fixture/bin/df
                if [ "{mode}" = checksum ]; then
                  cat > /fixture/bin/curl <<'EOF'
                #!/bin/sh
                out=""
                while [ "$#" -gt 0 ]; do
                  [ "$1" = -o ] && {{ shift; out="$1"; }}
                  shift
                done
                printf 'intentionally-invalid-archive' > "$out"
                EOF
                  chmod +x /fixture/bin/curl
                fi
                export PATH=/fixture/bin:$PATH
                cat > /var/lib/superserve/host-logging/otel-logs.yaml.candidate <<'EOF'
                candidate
                EOF
                cat > /var/lib/superserve/host-logging/otel-logs.service.candidate <<'EOF'
                candidate-service
                EOF
                cat > /etc/superserve/host-logging/otel-logs.yaml <<'EOF'
                active
                EOF
                cat > /etc/systemd/system/superserve-otel-logs.service <<'EOF'
                active-service
                EOF
                printf 'old-cursor' > /var/lib/superserve/host-logging/cursor/state
                printf 'old-queue' > /var/lib/superserve/host-logging/export-queue/state
                printf '{{"host_id":"fixture-host","instance_id":"fixture-instance","incarnation_id":"fixture-incarnation"}}\n' > /etc/sandbox/host-identity.json
                printf 'HOST_ID=fixture-host\nINSTANCE_ID=fixture-instance\nINCARNATION_ID=fixture-incarnation\n' > /etc/sandbox/host-logging-identity.env
                if [ "{mode}" != storage ]; then
                  cat > /opt/superserve/otelcol-contrib/bin/otelcol-contrib <<'EOF'
                #!/bin/sh
                [ "$1" = --version ] && echo 'otelcol-contrib version {self.release}' && exit 0
                [ "$1" = validate ] && [ "{mode}" = config ] && exit 1
                [ "$1" = validate ] && exit 0
                EOF
                  chmod +x /opt/superserve/otelcol-contrib/bin/otelcol-contrib
                fi
                set +e
                bash /fixture/reconcile.sh
                rc=$?
                set -e
                test "$rc" -ne 0
                cmp /etc/superserve/host-logging/otel-logs.yaml <(printf 'active\n')
                cmp /etc/systemd/system/superserve-otel-logs.service <(printf 'active-service\n')
                test "$(cat /var/lib/superserve/host-logging/cursor/state)" = old-cursor
                test "$(cat /var/lib/superserve/host-logging/export-queue/state)" = old-queue
            """)
            self._docker(f"superserve-host-logging-reconcile-{mode}", fixture, script, timeout=180)

    def test_candidate_validation_and_failure_preservation(self):
        with tempfile.TemporaryDirectory(prefix="host-logging-render-") as directory:
            rendered = self._render_templates(Path(directory))
            validate = rendered["validate"]
            reconcile = rendered["reconcile"]
            self.assertIn("validate --config", reconcile)
            self.assertIn("sha256sum -c", reconcile)
            self.assertIn("trap rollback EXIT", reconcile)
            self.assertIn("activation_committed=1", reconcile)
            self.assertIn("cmp -s", reconcile)
            self.assertIn("host-identity.json", reconcile)
            self.assertIn("host-logging-identity.env", reconcile)
            self.assertIn("superserve-host-logging-heartbeat.timer", reconcile)
            self.assertIn("OnBootSec=60s", reconcile)
            self.assertIn("storage: file_storage/cursor", validate)
            self.assertIn("storage: file_storage/queue", validate)
            self.assertIn("CPUQuota=", rendered["service"])
            self.assertIn("CPUQuota=100%", rendered["service"])
            # Fresh collector-owned outputs are repairable (101), while a
            # malformed authoritative identity remains fail-closed (1).
            with tempfile.TemporaryDirectory(prefix="host-logging-validate-") as fixture_dir:
                fixture = Path(fixture_dir)
                (fixture / "validate.sh").write_text(validate)
                script = textwrap.dedent("""
                    mkdir -p /fixture/bin
                    cat > /fixture/bin/systemctl <<'EOF'
                    #!/bin/sh
                    exit 0
                    EOF
                    chmod +x /fixture/bin/systemctl
                    export PATH=/fixture/bin:$PATH
                    # A valid authoritative identity is required even on a
                    # fresh host; only collector-owned outputs are absent.
                    mkdir -p /etc/sandbox
                    printf '{"host_id":"fixture-host","instance_id":"fixture-instance","incarnation_id":"fixture-incarnation"}\n' > /etc/sandbox/host-identity.json
                    printf 'HOST_ID=fixture-host\nINSTANCE_ID=fixture-instance\nINCARNATION_ID=fixture-incarnation\n' > /etc/sandbox/host-logging-identity.env
                    set +e
                    bash /fixture/validate.sh
                    fresh=$?
                    set -e
                    test "$fresh" -eq 101
                    printf '{"host_id":' > /etc/sandbox/host-identity.json
                    set +e
                    bash /fixture/validate.sh
                    invalid=$?
                    set -e
                    test "$invalid" -eq 1
                """)
                self._docker("superserve-host-logging-validate-fresh", fixture, script, timeout=120)
            for mode in ("config", "checksum", "storage"):
                self._assert_reconcile_failure_preserves_state(rendered, mode)


if __name__ == "__main__":
    unittest.main()
