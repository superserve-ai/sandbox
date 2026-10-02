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
import time
import unittest
import uuid
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "infra/modules/host-logging"
IMAGE = os.environ.get("SUPER_SERVE_OTEL_FIXTURE_IMAGE", "ubuntu:24.04")
FIXTURE_PLATFORM = os.environ.get("SUPER_SERVE_OTEL_FIXTURE_PLATFORM", "linux/amd64")
FIXTURE_IMAGE_TAG = os.environ.get(
    "SUPER_SERVE_OTEL_FIXTURE_IMAGE_TAG", "superserve-host-logging-fixture:ubuntu-24.04-v2"
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
            "legacy_enabled": 0,
            "project_id": "example-project",
            "zone": "us-central1-a",
            "queue_capacity_bytes": 536870912,
            "environment": "fixture",
            "region": "us-central1",
            "assignment_name": "fixture-host-logging",
            "assignment_revision": "fixture-revision",
            "release_version": self.release,
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
        name = name + "-" + uuid.uuid4().hex[:10]
        probe = subprocess.run(["docker", "info"], text=True, capture_output=True, timeout=20)
        if probe.returncode:
            self.fail("Docker daemon is required for the host-logging Linux fixture: docker info failed")
        image = self._fixture_image()
        cache = self._release_cache()
        cache.mkdir(mode=0o700, parents=True, exist_ok=True)
        cmd = [
            "docker", "run", "--rm", "--platform", FIXTURE_PLATFORM, "--name", name,
            "-e", f"FIXTURE_UID={os.getuid()}", "-e", f"FIXTURE_GID={os.getgid()}",
            "-v", f"{fixture}:/fixture:rw", "-v", f"{cache}:/immutable-cache:rw",
            image, "bash", "-euo", "pipefail", "-c",
            # Isolate fixture-specific traps so they cannot replace ownership cleanup.
            'trap \'chown -R "$FIXTURE_UID:$FIXTURE_GID" /fixture /immutable-cache\' EXIT\n(\n' + script + '\n)\n',
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
    && apt-get install -y --no-install-recommends ca-certificates curl gzip tar python3 systemd systemd-journal-remote \\
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
            mkdir -p /immutable-cache /fixture/bin
            archive=/immutable-cache/{archive}
            checksums=/immutable-cache/{checksums}
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
            (cd /immutable-cache && sha256sum -c /tmp/otel-checksum-line)
            test "$(sha256sum "$archive" | awk '{{print $1}}')" = '{self.digest}'
            tar -xzf "$archive" -C /fixture/bin
            test -x /fixture/bin/otelcol-contrib
            /fixture/bin/otelcol-contrib --version | grep -F '{self.release}'
            /fixture/bin/otelcol-contrib components | grep -E 'journald|file_storage|googlecloud|transform|filter'
        """).strip()

    def _run_collector_fixture(self, rendered, outage=False, queue_pressure=False):
        with tempfile.TemporaryDirectory(prefix="host-logging-otel-") as directory:
            fixture = Path(directory)
            (fixture / "config.yaml").write_text(rendered["config"])
            # Keep the real OTLP exporter, queue, encoding and retry settings.
            # Only authentication and destination change for the local endpoint.
            runtime = rendered["config"].replace(
                "endpoint: https://telemetry.googleapis.com", "endpoint: http://127.0.0.1:4318"
            ).replace("    auth:\n      authenticator: googleclientauth\n", "")
            runtime = re.sub(r"(?m)^  googleclientauth:\n(?:    .*\n)+", "", runtime)
            runtime = runtime.replace("[googleclientauth, file_storage", "[file_storage")
            shutil.copy(ROOT / "scripts/fixtures/host_logging_endpoint.py", fixture / "endpoint.py")
            if outage:
                capacity = 2048 if queue_pressure else 131072
                runtime = runtime.replace("queue_size: 536870912", f"queue_size: {capacity}").replace("max_size: 2147483648", "max_size: 1048576").replace("min_size: 65536", "min_size: 1024").replace("max_size: 262144\n        flush", "max_size: 2048\n        flush")
                (fixture / "unavailable").touch()
            (fixture / "requests.jsonl").touch()
            (fixture / "runtime.yaml").write_text(runtime)
            script = self._acquire_release(fixture) + textwrap.dedent("""
                trap 'rc=$?; if [ "$rc" -ne 0 ] && [ -f /fixture/collector.log ]; then cat /fixture/collector.log >&2; fi' EXIT
                mkdir -p /var/lib/superserve/host-logging/cursor /var/lib/superserve/host-logging/export-queue /var/log/journal
                export HOST_ID=fixture-host INSTANCE_ID=fixture-instance INCARNATION_ID=fixture-incarnation
                python3 /fixture/endpoint.py > /fixture/endpoint.log 2>&1 &
                endpoint=$!
                now=1700000000123456
                emit() {
                  unit="$1"; transport="$2"; priority="$3"; message="$4"
                  { printf '__REALTIME_TIMESTAMP=%s\\n' "$now"; printf '_BOOT_ID=11111111111111111111111111111111\\n'; printf '_HOSTNAME=fixture-host\\n'; printf '_PID=42\\n'; printf 'PRIORITY=%s\\n' "$priority"; [ -z "$unit" ] || printf '_SYSTEMD_UNIT=%s\\n' "$unit"; printf '_TRANSPORT=%s\\n' "$transport"; printf 'MESSAGE=%s\\n\\n' "$message"; }
                }
                : > /fixture/journal.export
                emit superserve-vmd.service journal 6 '{"level":"INFO","message":"safe-info","request_id":"req-1","host_id":"evil-host","incarnation":"evil-incarnation","provider_instance_id":"evil-instance","parse_outcome":"failure","journal_unit":"evil.service","source":"evil-source","host_logging_heartbeat":"true","host_logging_export_error":"true","severity_number":1,"resource":{"host.id":"evil-resource"},"attributes":{"log.name":"evil-log"},"labels":{"authorization":"SECRET_NESTED"}}' >> /fixture/journal.export
                emit superserve-vmd.service journal 6 '{"level":"DEBUG","message":"debug-only"}' >> /fixture/journal.export
                emit proxy-generation.service journal 6 '{"level":"INFO","message":"proxy-safe","sandbox_id":"sandbox-1"}' >> /fixture/journal.export
                emit superserve-vmd.service journal 6 '{"level":"WARN","message":"safe-warn"}' >> /fixture/journal.export
                emit superserve-vmd.service journal 6 '{"level":"ERROR","message":"safe-error"}' >> /fixture/journal.export
                emit superserve-vmd.service journal 4 '{"level":"SECRET_LEVEL","message":"unknown-level"}' >> /fixture/journal.export
                emit superserve-vmd.service journal 3 '{"severity":"SECRET_SEVERITY","message":"unknown-severity"}' >> /fixture/journal.export
                emit superserve-vmd.service journal 6 "$(python3 -c 'import json; print(json.dumps({"level": "SECRET_LONG" * 256, "message": "long-level"}))')" >> /fixture/journal.export
                emit superserve-vmd.service journal 6 '{"severity":"WaRnInG","message":"severity-alias"}' >> /fixture/journal.export
                emit proxy.service journal 6 'malformed SECRET_SENTINEL authorization=Bearer-SECRET' >> /fixture/journal.export
                emit systemd-journald.service journal 5 'trusted-systemd-diagnostic' >> /fixture/journal.export
                emit '' kernel 5 'trusted-kernel-diagnostic' >> /fixture/journal.export
                emit superserve-host-logging-heartbeat.service journal 6 'host-logging-heartbeat' >> /fixture/journal.export
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
                /fixture/bin/otelcol-contrib --config /fixture/runtime.yaml > /fixture/collector.log 2>&1 &
                collector=$!
                sleep 8
                if [ -e /fixture/unavailable ]; then
                  test -n "$(find /var/lib/superserve/host-logging/cursor -type f -size +0c -print -quit)"
                  test -n "$(find /var/lib/superserve/host-logging/export-queue -type f -size +0c -print -quit)"
                  kill -KILL "$collector"
                  wait "$collector" 2>/dev/null || true
                  /fixture/bin/otelcol-contrib --config /fixture/runtime.yaml >> /fixture/collector.log 2>&1 &
                  collector=$!
                  sleep 3
                  rm /fixture/unavailable
                  sleep 12
                  find /var/lib/superserve/host-logging/export-queue -type f -printf '%s\n' > /fixture/queue-sizes
                  while read -r size; do test "$size" -le 1048576; done < /fixture/queue-sizes
                fi
                kill -TERM "$collector" 2>/dev/null || true
                wait "$collector" || true
                test -s /fixture/collector.log
                cat /fixture/requests.jsonl
                printf "\nSELFLOGS\n"
                cat /fixture/collector.log
                kill "$endpoint"
            """)
            return self._docker("superserve-host-logging-runtime", fixture, script, timeout=360)

    def test_trusted_metadata_and_collision_resistance_contract(self):
        with tempfile.TemporaryDirectory(prefix="host-logging-render-") as directory:
            output = self._run_collector_fixture(self._render_templates(Path(directory)))
        requests, self_logs = output.split("SELFLOGS", 1)
        records = []
        resources = []
        for line in requests.splitlines():
            if not line.startswith('{'):
                continue
            for resource in json.loads(line)["resourceLogs"]:
                resources.append(self._attributes(resource["resource"].get("attributes", [])))
                for scope in resource["scopeLogs"]:
                    records.extend(scope["logRecords"])
        self.assertEqual(len(records), 12, output)
        bodies = [self._value(record.get("body", {})) for record in records]
        self.assertIn({"message": "safe-info", "request_id": "req-1"}, bodies)
        self.assertIn({"message": "proxy-safe", "sandbox_id": "sandbox-1"}, bodies)
        self.assertIn({"message": "safe-warn"}, bodies)
        self.assertIn({"message": "safe-error"}, bodies)
        self.assertIn({}, bodies)
        extra_severities = {"unknown-level": 13, "unknown-severity": 17, "long-level": 9, "severity-alias": 13}
        for message in extra_severities:
            matches = [record for record in records if self._value(record.get("body", {})) == {"message": message}]
            self.assertEqual(len(matches), 1, (message, bodies))
            record = matches[0]
            self.assertEqual(record.get("severityText", ""), "")
        for marker in ("secret_level", "secret_severity", "secret_long"):
            self.assertNotIn(marker, output.lower())
        for record in records:
            attributes = self._attributes(record["attributes"])
            self.assertEqual(attributes["host_id"], "fixture-host")
            self.assertEqual(attributes["incarnation"], "fixture-incarnation")
            self.assertEqual(attributes["log.name"], "superserve_host_logs")
            self.assertEqual(int(record["timeUnixNano"]), 1700000000123456000)
            self.assertEqual(attributes["provider_instance_id"], "fixture-instance")
            if attributes.get("journal_unit") == "superserve-host-logging-heartbeat.service":
                self.assertEqual(attributes["host_logging_heartbeat"], "true")
                self.assertLess(int(record["timeUnixNano"]) / 1e9, time.time() - 300)
            else:
                self.assertNotIn("host_logging_heartbeat", attributes)
                self.assertNotIn("host_logging_retained_history_lag_seconds", attributes)
            self.assertNotIn("host_logging_export_error", attributes)
            if attributes.get("journal_unit") == "superserve-vmd.service":
                self.assertEqual(attributes["parse_outcome"], "success")
                self.assertEqual(attributes["source"], "journal")
                self.assertEqual(record["severityNumber"], {"safe-info": 9, "safe-warn": 13, "safe-error": 17, **extra_severities}[self._value(record["body"])["message"]])
            if attributes.get("journal_unit") == "proxy.service":
                self.assertEqual(attributes["parse_outcome"], "failure")
                self.assertEqual(self._value(record["body"]), {})
        for resource in resources:
            self.assertEqual(resource["cloud.platform"], "gcp_compute_engine")
            self.assertEqual(resource["host.id"], "fixture-instance")
            self.assertEqual(resource["gcp.project_id"], "example-project")
        for forbidden in ["debug-only", "drop-me", "missing-unit-drop", "SECRET_SENTINEL", "SECRET_NESTED", "evil-host", "evil-incarnation", "evil-instance", "evil.service", "evil-source", "evil-resource", "evil-log"]:
            self.assertNotIn(forbidden, output)
        shutdown_seen = False
        for line in self_logs.splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            if entry.get("msg") == "Received signal from OS":
                self.assertEqual(entry.get("signal"), "terminated")
                shutdown_seen = True
            if entry.get("level") == "error":
                self.assertTrue(shutdown_seen, entry)
                self.assertEqual(entry.get("otelcol.component.id"), "journald", entry)
                self.assertEqual(entry.get("msg"), "journalctl command exited", entry)
                self.assertIn(entry.get("error"), ("signal: terminated", "signal: killed"), entry)
        self.assertTrue(shutdown_seen)

    def test_accepted_queue_records_survive_outage_restart(self):
        with tempfile.TemporaryDirectory(prefix="host-logging-render-") as directory:
            output = self._run_collector_fixture(self._render_templates(Path(directory)), outage=True)
        requests, self_logs = output.split("SELFLOGS", 1)
        messages = []
        for line in requests.splitlines():
            if not line.startswith('{'):
                continue
            for resource in json.loads(line)["resourceLogs"]:
                for scope in resource["scopeLogs"]:
                    messages.extend(self._value(record["body"]) for record in scope["logRecords"])
        self.assertIn({"message": "safe-info", "request_id": "req-1"}, messages)
        self.assertIn({"message": "proxy-safe", "sandbox_id": "sandbox-1"}, messages)
        self.assertIn({}, messages)
        self.assertGreaterEqual(len(messages), 8)
        self.assertLessEqual(len(messages), 16)
        self.assertIn("503", self_logs)
        self.assertNotIn("SECRET_SENTINEL", output)

    @classmethod
    def _value(cls, value):
        if "kvlistValue" in value:
            return cls._attributes(value["kvlistValue"].get("values", []))
        return next(iter(value.values()), None)

    @classmethod
    def _attributes(cls, values):
        return {item["key"]: cls._value(item["value"]) for item in values}

    def test_release_and_state_are_pinned_and_separate(self):
        self.assertRegex(self.variables, r'otel_release_version[^\n]+')
        self.assertRegex(self.variables, r'default\s+=\s+"0\.156\.0"')
        self.assertRegex(self.variables, r'default\s+=\s+"[0-9a-f]{64}"')
        with tempfile.TemporaryDirectory(prefix="host-logging-render-") as directory:
            rendered = self._render_templates(Path(directory))
            config = rendered["config"]
            self.assertIn("file_storage/cursor", config)
            self.assertIn("file_storage/queue", config)
            self.assertIn("max_size: 2147483648", config)
            self.assertIn("max_elapsed_time: 0s", config)
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
            script = textwrap.dedent(rf"""
                mkdir -p /fixture/bin /var/lib/superserve/host-logging /etc/superserve/host-logging /etc/systemd/system /etc/systemd/journald.conf.d /etc/sandbox /opt/superserve/otelcol-contrib/bin /var/lib/superserve/host-logging/cursor /var/lib/superserve/host-logging/export-queue
                cat > /fixture/bin/systemctl <<'EOF'
                #!/bin/sh
                case "$1" in
                  is-active|is-enabled|show) exit 0;;
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
                touch /fixture/checksum-attempted
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
                if [ "{mode}" = config ]; then
                  cat > /opt/superserve/otelcol-contrib/bin/otelcol-contrib <<'EOF'
                #!/bin/sh
                [ "$1" = --version ] && echo 'otelcol-contrib version {self.release}' && exit 0
                [ "$1" = validate ] && touch /fixture/config-validation-attempted && exit 1
                [ "$1" = validate ] && exit 0
                EOF
                  chmod +x /opt/superserve/otelcol-contrib/bin/otelcol-contrib
                fi
                set +e
                bash /fixture/reconcile.sh
                rc=$?
                set -e
                test "$rc" -ne 0
                case "{mode}" in
                  checksum) test -e /fixture/checksum-attempted;;
                  config) test -e /fixture/config-validation-attempted;;
                esac
                test ! -e /fixture/systemctl.calls
                cmp /etc/superserve/host-logging/otel-logs.yaml <(printf 'active\n')
                cmp /etc/systemd/system/superserve-otel-logs.service <(printf 'active-service\n')
                test "$(cat /var/lib/superserve/host-logging/cursor/state)" = old-cursor
                test "$(cat /var/lib/superserve/host-logging/export-queue/state)" = old-queue
                touch /fixture/reconcile-failure-complete
            """)
            self._docker(f"superserve-host-logging-reconcile-{mode}", fixture, script, timeout=180)
            self.assertTrue((fixture / "reconcile-failure-complete").is_file())

    def test_reconcile_converges_and_is_idempotent(self):
        self._exercise_reconciliation(False)

    def test_post_activation_failure_restores_active_state(self):
        self._exercise_reconciliation(True)

    def test_partial_metrics_limit_failure_restores_runtime_properties(self):
        self._exercise_reconciliation(True, metrics_failure=True)

    def test_metrics_oom_failure_restores_configured_priority(self):
        self._exercise_reconciliation(True, oom_failure=True)

    def test_metrics_oom_timeout_restores_configured_priority(self):
        self._exercise_reconciliation(True, oom_failure=True, oom_timeout=True)

    def _exercise_reconciliation(self, activation_failure, metrics_failure=False, oom_failure=False, oom_timeout=False):
        with tempfile.TemporaryDirectory(prefix="host-logging-render-") as directory:
            rendered = self._render_templates(Path(directory))
            with tempfile.TemporaryDirectory(prefix="host-logging-converged-") as work:
                fixture = Path(work)
                for name, content in rendered.items():
                    (fixture / name).write_text(content)
                if activation_failure:
                    (fixture / "test-rollback").touch()
                if metrics_failure:
                    (fixture / "test-metrics-failure").touch()
                if oom_failure:
                    (fixture / "test-oom-failure").touch()
                if oom_timeout:
                    (fixture / "test-oom-timeout").touch()
                script = self._acquire_release(fixture) + textwrap.dedent(r"""
                    mkdir -p /var/lib/superserve/host-logging /etc/sandbox /opt/superserve/otelcol-contrib/bin
                    cp /fixture/bin/otelcol-contrib /opt/superserve/otelcol-contrib/bin/otelcol-contrib
                    cp /fixture/config /var/lib/superserve/host-logging/otel-logs.yaml.candidate
                    cp /fixture/service /var/lib/superserve/host-logging/otel-logs.service.candidate
                    cp /fixture/reconcile /var/lib/superserve/host-logging/reconcile.sh
                    printf '{"host_id":"fixture-host","instance_id":"123","incarnation_id":"fixture-incarnation"}\n' > /etc/sandbox/host-identity.json
                    cat > /fixture/bin/systemctl <<'EOF'
                    #!/bin/bash
                    if [ "$1" = show ]; then
                      if [ "$3" = --property=MainPID ]; then cat /fixture/metrics.pid 2>/dev/null || echo 0; exit 0; fi
                      if [ "$3" = --property=OOMScoreAdjust ]; then awk -F= '/^OOMScoreAdjust=/ {print $2}' /etc/systemd/system/superserve-otel-collector.service.d/30-host-logging-priority.conf; exit 0; fi
                      if [ -e /fixture/metrics.properties ]; then cat /fixture/metrics.properties; else printf 'CPUWeight=100\nIOWeight=100\nMemoryHigh=infinity\nMemoryMax=infinity\n'; fi
                      exit 0
                    fi
                    if [ "$1" = set-property ]; then
                      printf '%s\n' "${@:4}" | sed -e 's/MemoryHigh=192M/MemoryHigh=201326592/' -e 's/MemoryMax=256M/MemoryMax=268435456/' > /fixture/metrics.properties
                      printf '%s\n' "$*" >> /fixture/systemctl.calls
                      if [ -e /fixture/fail-metrics ]; then rm /fixture/fail-metrics; exit 1; fi
                      exit 0
                    fi
                    if [ "$1 $2" = 'restart superserve-otel-collector.service' ]; then
                      if [ -e /fixture/metrics.pid ]; then kill "$(cat /fixture/metrics.pid)" 2>/dev/null || true; fi
                      score=$(awk -F= '/^OOMScoreAdjust=/ {print $2}' /etc/systemd/system/superserve-otel-collector.service.d/30-host-logging-priority.conf)
                      if [ -e /fixture/fail-oom-score ]; then rm /fixture/fail-oom-score; score=0; fi
                      bash -c 'sleep 0.15; echo "$1" > /proc/self/oom_score_adj; exec sleep 300' bash "$score" 9>&- >/dev/null 2>&1 &
                      pid=$!; echo "$pid" > /fixture/metrics.pid
                      printf '%s\n' "$*" >> /fixture/systemctl.calls
                      if [ -e /fixture/fail-oom ]; then rm /fixture/fail-oom; exit 1; fi
                      exit 0
                    fi
                    if [ "$1" = is-active ] && [ "$3" = superserve-otel-collector.service ]; then
                      test -e /fixture/metrics.pid && kill -0 "$(cat /fixture/metrics.pid)"; exit $?
                    fi
                    if [ "$1 $2" = 'restart superserve-otel-logs.service' ] && [ -e /fixture/fail-activation ]; then
                      rm /fixture/fail-activation
                      printf 'injected activation failure\n' >&2
                      exit 1
                    fi
                    case "$1" in
                      is-active|is-enabled) test -e /fixture/active; exit $?;;
                      *) printf '%s\n' "$*" >> /fixture/systemctl.calls; touch /fixture/active; exit 0;;
                    esac
                    EOF
                    cat > /fixture/bin/df <<'EOF'
                    #!/bin/sh
                    echo 'Filesystem 1024-blocks Used Available Capacity Mounted on'
                    echo 'fixture 1 1 999999999 1% /'
                    EOF
                    cat > /fixture/bin/journalctl <<'EOF'
                    #!/bin/sh
                    test "$1" = --flush
                    EOF
                    chmod +x /fixture/bin/systemctl /fixture/bin/df /fixture/bin/journalctl
                    export PATH=/fixture/bin:$PATH
                    result() {
                      expected="$1"; shift
                      set +e
                      "$@"
                      rc=$?
                      set -e
                      [ "$rc" -eq "$expected" ] || { echo "expected=$expected actual=$rc" >&2; exit 1; }
                    }
                    mkdir -p /etc/systemd/system/superserve-otel-collector.service.d
                    printf '[Service]\nOOMScoreAdjust=0\n' > /etc/systemd/system/superserve-otel-collector.service.d/30-host-logging-priority.conf
                    systemctl restart superserve-otel-collector.service
                    result 101 bash /fixture/validate
                    mkdir /var/lib/superserve/host-logging/.attempt.interrupted
                    printf 'orphan candidate' > /var/lib/superserve/host-logging/.attempt.interrupted/release.tar.gz
                    result 100 bash /fixture/reconcile
                    test ! -e /var/lib/superserve/host-logging/.attempt.interrupted
                    test "$(cat /proc/$(cat /fixture/metrics.pid)/oom_score_adj)" -eq 800
                    printf 'cursor-sentinel' > /var/lib/superserve/host-logging/cursor/sentinel
                    printf 'queue-sentinel' > /var/lib/superserve/host-logging/export-queue/sentinel
                    cp /fixture/systemctl.calls /fixture/calls.before
                    find /etc/superserve/host-logging /etc/sandbox /etc/systemd/system /etc/systemd/journald.conf.d /opt/superserve/otelcol-contrib/bin /var/lib/superserve/host-logging/cursor /var/lib/superserve/host-logging/export-queue -type f -exec sha256sum {} + > /fixture/files.before
                    result 100 bash /fixture/validate
                    result 100 bash /fixture/reconcile
                    cmp /fixture/calls.before /fixture/systemctl.calls
                    find /etc/superserve/host-logging /etc/sandbox /etc/systemd/system /etc/systemd/journald.conf.d /opt/superserve/otelcol-contrib/bin /var/lib/superserve/host-logging/cursor /var/lib/superserve/host-logging/export-queue -type f -exec sha256sum {} + > /fixture/files.after
                    cmp /fixture/files.before /fixture/files.after
                    if [ ! -e /fixture/test-rollback ]; then
                      kill "$(cat /fixture/metrics.pid)"
                      sleep 300 >/dev/null 2>&1 &
                      echo "$!" > /fixture/metrics.pid
                      result 101 bash /fixture/validate
                      result 100 bash /fixture/reconcile
                      test "$(cat /proc/$(cat /fixture/metrics.pid)/oom_score_adj)" -eq 800
                      cp /fixture/systemctl.calls /fixture/calls.before
                      result 100 bash /fixture/reconcile
                      cmp /fixture/calls.before /fixture/systemctl.calls
                      kill "$(cat /fixture/metrics.pid)"
                      rm /fixture/metrics.pid
                      printf '\n# changed while metrics inactive\n' >> /var/lib/superserve/host-logging/otel-logs.yaml.candidate
                      : > /fixture/systemctl.calls
                      result 100 bash /fixture/reconcile
                      test ! -e /fixture/metrics.pid
                      ! grep -q 'superserve-otel-collector.service' /fixture/systemctl.calls
                    fi
                    if [ -e /fixture/test-rollback ]; then
                      printf '\n# changed candidate\n' >> /var/lib/superserve/host-logging/otel-logs.yaml.candidate
                      : > /fixture/systemctl.calls
                      if [ -e /fixture/test-oom-failure ]; then
                        printf '[Service]\nOOMScoreAdjust=0\n' > /etc/systemd/system/superserve-otel-collector.service.d/30-host-logging-priority.conf
                        systemctl restart superserve-otel-collector.service
                        printf '[Service]\nOOMScoreAdjust=120\n' > /etc/systemd/system/superserve-otel-collector.service.d/30-host-logging-priority.conf
                        find /etc/superserve/host-logging /etc/sandbox /etc/systemd/system /etc/systemd/journald.conf.d /opt/superserve/otelcol-contrib/bin /var/lib/superserve/host-logging/cursor /var/lib/superserve/host-logging/export-queue -type f -exec sha256sum {} + > /fixture/files.before
                        : > /fixture/systemctl.calls
                        if [ -e /fixture/test-oom-timeout ]; then touch /fixture/fail-oom-score; else touch /fixture/fail-oom; fi
                      elif [ -e /fixture/test-metrics-failure ]; then
                        printf 'CPUWeight=123\nIOWeight=234\nMemoryHigh=500000000\nMemoryMax=600000000\n' > /fixture/metrics.properties
                        cp /fixture/metrics.properties /fixture/metrics.before
                        touch /fixture/fail-metrics
                      else
                        touch /fixture/fail-activation
                      fi
                      result 1 bash /fixture/reconcile
                      find /etc/superserve/host-logging /etc/sandbox /etc/systemd/system /etc/systemd/journald.conf.d /opt/superserve/otelcol-contrib/bin /var/lib/superserve/host-logging/cursor /var/lib/superserve/host-logging/export-queue -type f -exec sha256sum {} + > /fixture/files.rollback
                      cmp /fixture/files.before /fixture/files.rollback
                      grep -q '^restart superserve-otel-logs.service$' /fixture/systemctl.calls
                      if [ -e /fixture/test-oom-failure ]; then
                        test "$(cat /proc/$(cat /fixture/metrics.pid)/oom_score_adj)" -eq 120
                        test "$(grep -c '^restart superserve-otel-collector.service$' /fixture/systemctl.calls)" -eq 2
                      elif [ -e /fixture/test-metrics-failure ]; then
                        cmp /fixture/metrics.before /fixture/metrics.properties
                        test "$(grep -c '^set-property ' /fixture/systemctl.calls)" -eq 2
                      else
                        ! grep -q 'superserve-otel-collector.service' /fixture/systemctl.calls
                      fi
                      test -e /fixture/active
                    fi
                    rm /etc/sandbox/host-identity.json
                    result 1 bash /fixture/validate
                    touch /fixture/reconcile-complete
                """)
                self._docker("host-logging-converged", fixture, script)
                self.assertTrue((fixture / "reconcile-complete").is_file())

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
                (fixture / "reconcile.sh").write_text(reconcile)
                script = textwrap.dedent(r"""
                    mkdir -p /fixture/bin /var/lib/superserve/host-logging
                    cp /fixture/reconcile.sh /var/lib/superserve/host-logging/reconcile.sh
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
                    touch /fixture/validate-fresh-complete
                """)
                self._docker("superserve-host-logging-validate-fresh", fixture, script, timeout=120)
                self.assertTrue((fixture / "validate-fresh-complete").is_file())
            for mode in ("config", "checksum", "storage"):
                self._assert_reconcile_failure_preserves_state(rendered, mode)


if __name__ == "__main__":
    unittest.main()
