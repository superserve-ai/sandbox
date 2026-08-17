import importlib.util
import subprocess
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("deploy-otel-collector.py")
SPEC = importlib.util.spec_from_file_location("deploy_otel_collector", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class DeployOtelCollectorTests(unittest.TestCase):
    def test_probe_parser_returns_architecture_and_unique_staging_directory(self):
        self.assertEqual(
            MODULE._parse_remote_probe(
                "noise\n__OTEL_ARCH__=x86_64\n__OTEL_STAGING__=/tmp/otel-collector.Ab12_-\n",
                "",
            ),
            ("x86_64", "/tmp/otel-collector.Ab12_-"),
        )

    def test_probe_parser_rejects_shared_or_untrusted_staging_path(self):
        with self.assertRaisesRegex(RuntimeError, "safe remote staging"):
            MODULE._parse_remote_probe(
                "__OTEL_ARCH__=x86_64\n__OTEL_STAGING__=/tmp/collector-gmp.yaml\n", "probe stderr"
            )

    def test_command_failure_preserves_captured_output(self):
        error = MODULE._command_failure(
            "upload artifact",
            ["gcloud", "compute", "scp", "artifact", "host:/tmp/file"],
            subprocess.CalledProcessError(1, ["gcloud"], output="out", stderr="permission denied"),
        )
        self.assertIn("upload artifact failed (exit 1)", str(error))
        self.assertIn("out", str(error))
        self.assertIn("permission denied", str(error))

    def run_health(self, curl_mode="healthy", systemd_mode="active"):
        functions = f'''
        sudo() {{ "$@"; }}
        systemctl() {{
          if [ "$1" = is-active ] && [ "{systemd_mode}" != active ]; then
            echo "inactive (dead)"; return 3
          fi
          return 0
        }}
        journalctl() {{ :; }}
        curl() {{
          case "$2" in
            http://127.0.0.1:13133/) [ "{curl_mode}" = health-fail ] && {{ echo "health refused"; return 7; }}; echo ok ;;
            http://127.0.0.1:8888/metrics) [ "{curl_mode}" = metrics-fail ] && {{ echo "metrics refused"; return 7; }}; [ "{curl_mode}" = no-metric ] || echo otelcol_process_uptime 1 ;;
          esac
        }}
        '''
        return subprocess.run(
            ["bash", "-euo", "pipefail", "-c", functions + MODULE._health_check_script()],
            capture_output=True, text=True,
        )

    def test_health_checks_consume_full_metrics_response_under_pipefail(self):
        result = self.run_health()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_health_check_diagnostics_identify_failed_stage(self):
        self.assertIn("13133", self.run_health("health-fail").stderr)
        self.assertIn("8888", self.run_health("metrics-fail").stderr)
        self.assertIn("systemd active", self.run_health(systemd_mode="inactive").stderr)
        self.assertIn("assertion", self.run_health("no-metric").stderr)


if __name__ == "__main__":
    unittest.main()
