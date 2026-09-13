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
    def test_ssh_key_created_before_parallel_fanout(self):
        # Per-host deploys run in parallel, and gcloud generates the runner's
        # SSH key on first use. Two hosts starting together race ssh-keygen and
        # one fails before uploading anything, so the key must exist before
        # the pool starts.
        source = SCRIPT.read_text()
        keygen = source.find('"ssh-keygen", "-q"')
        pool = source.find("ThreadPoolExecutor(max_workers=len(instances))")
        self.assertNotEqual(keygen, -1)
        self.assertNotEqual(pool, -1)
        self.assertLess(keygen, pool)

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
          if [ "$1" = is-enabled ]; then echo enabled; return 0; fi
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



class OtelTargetSelectionTests(unittest.TestCase):
    def selected_env(self, event='workflow_dispatch', target='standby'):
        import os
        workflow = (SCRIPT.parents[1] / 'deploy-otel-collector.yml').read_text()
        staging = workflow.split('  deploy-staging:', 1)[1].split('  deploy-production:', 1)[0]
        self.assertIn('DEPLOY_EVENT: ${{ github.event_name }}', staging)
        self.assertIn('DEPLOY_TARGET: ${{ inputs.target }}', staging)
        self.assertIn('DEPLOY_CELL: staging', staging)
        body = staging.split('        run: |', 1)[1]
        self.assertLess(body.index('source .github/workflows/scripts/select-deploy-target.sh'), body.index('python3'))
        result = subprocess.run(
            ['bash', '-ec', 'source .github/workflows/scripts/select-deploy-target.sh; env -0'],
            cwd=SCRIPT.parents[3], capture_output=True,
            env=dict(os.environ, DEPLOY_EVENT=event, DEPLOY_TARGET=target,
                     DEPLOY_CELL='staging', GCP_PROJECT='example-project',
                     GCP_REGION='us-central1', VMD_LABEL='component=vmd'),
            check=True,
        )
        return dict(item.split('=', 1) for item in result.stdout.decode().split('\0') if '=' in item)

    def deploy_selection(self, env, rows):
        from concurrent.futures import Future
        from unittest.mock import patch
        selected = []

        class Executor:
            def __init__(self, **kwargs): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def submit(self, fn, instance):
                selected.append(instance['name'])
                future = Future()
                future.set_result(None)
                return future

        with patch.dict(MODULE.os.environ, env, clear=True), \
             patch.object(MODULE.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, rows, '')) as run, \
             patch.object(MODULE, 'prepare_collector_binaries', return_value={}) as prepare, \
             patch.object(MODULE.os.path, 'exists', return_value=True), \
             patch.object(MODULE, 'ThreadPoolExecutor', Executor):
            result = MODULE.main()
        return result, selected, run.call_args_list, prepare.called

    def test_staging_standby_uses_shared_label_and_never_deploys_serving_host(self):
        env = self.selected_env()
        self.assertEqual(env['VMD_LABEL'], 'component=vmd-staging-standby')
        standby = env['EXPECTED_STANDBY_HOST']
        result, selected, calls, _ = self.deploy_selection(env, standby + ',us-central1-a\n')
        self.assertEqual(result, 0)
        self.assertEqual(selected, [standby])
        self.assertIn('--filter=labels.component=vmd-staging-standby AND status=RUNNING', calls[0].args[0])
        for rows in ('', 'serving-host,us-central1-a\n', standby + ',us-central1-a\nserving-host,us-central1-a\n', standby + ',us-west2-a\n'):
            result, selected, _, prepared = self.deploy_selection(env, rows)
            self.assertEqual(result, 1)
            self.assertEqual(selected, [])
            self.assertFalse(prepared)

    def test_push_and_explicit_serving_preserve_serving_selection(self):
        for event, target in [('push', 'standby'), ('workflow_dispatch', 'serving')]:
            env = self.selected_env(event, target)
            self.assertEqual(env['VMD_LABEL'], 'component=vmd')
            self.assertNotIn('EXPECTED_STANDBY_HOST', env)
            result, selected, _, _ = self.deploy_selection(env, 'serving-host,us-central1-a\n')
            self.assertEqual(result, 0)
            self.assertEqual(selected, ['serving-host'])

    def test_production_filter_fanout_is_unchanged(self):
        env = {'GCP_PROJECT': 'example-project', 'GCP_REGION': 'us-west2',
               'VMD_FILTER': 'labels.sandbox_role=vmd AND labels.environment=production AND labels.region=us-west2'}
        result, selected, calls, _ = self.deploy_selection(env, 'host-a,us-west2-a\nhost-b,us-west2-b\n')
        self.assertEqual(result, 0)
        self.assertEqual(selected, ['host-a', 'host-b'])
        self.assertIn('--filter=' + env['VMD_FILTER'] + ' AND status=RUNNING', calls[0].args[0])



class OtelRenderedDeploymentTests(unittest.TestCase):
    def exercise(self, fail='', existing=False):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            staging = root / 'staging'
            staging.mkdir()
            binary = '#!/bin/sh\necho otelcol-contrib ' + MODULE.OTEL_COLLECTOR_VERSION + '\n'
            for name, data in [('otelcol-contrib', binary), ('collector-gmp.yaml', 'receivers: {}\n'),
                               ('superserve-otel-collector.service', '[Install]\nWantedBy=multi-user.target\n')]:
                (staging/name).write_text(data)
            (root/'usr/local/bin').mkdir(parents=True)
            if existing:
                (root/'usr/local/bin/otelcol-contrib').write_text(binary)
                (root/'usr/local/bin/otelcol-contrib').chmod(0o755)
            script = MODULE._deploy_script(str(staging), 'example-project', 'us-central1-a', 'example-host')
            script = script.replace('/usr/local/bin', str(root/'usr/local/bin')).replace('/etc/', str(root/'etc') + '/')
            prelude = '''
sudo() { "$@"; }
sleep() { :; }
systemctl() {
    echo "$*" >> "$CALLS"
    if [ "$1" = "$FAIL" ]; then echo "requested failure" >&2; return 1; fi
    case "$1" in
      enable) touch "$STATE/enabled" ;;
      restart) touch "$STATE/active" ;;
      is-enabled) if [ "$FAIL" = runtime-only ]; then echo enabled-runtime; else test -f "$STATE/enabled" && echo enabled; fi ;;
      is-active) test -f "$STATE/active" ;;
    esac
}
curl() {
    if [ "$FAIL" = health ]; then return 1; fi
    echo otelcol_process_uptime 1
}
journalctl() { :; }
'''
            result = subprocess.run(['bash', '-c', prelude + script], capture_output=True, text=True,
                                    env=dict(os.environ, FAIL=fail, STATE=tmp, CALLS=str(root/'calls')))
            env_file = root/'etc/sandbox/otel/collector.env'
            self.assertEqual(env_file.read_text(), 'GCP_PROJECT=example-project\nGCP_ZONE=us-central1-a\nHOST_ID=example-host\n')
            self.assertEqual(env_file.stat().st_mode & 0o777, 0o644)
            self.assertFalse(staging.exists(), 'staging cleanup must run')
            calls = (root/'calls').read_text()
            if result.returncode == 0:
                self.assertTrue((root/'enabled').exists())
                self.assertTrue((root/'active').exists())
                self.assertIn('is-enabled superserve-otel-collector.service', calls)
                self.assertIn('is-active superserve-otel-collector', calls)
            return result, calls

    def test_complete_script_enables_and_starts_fresh_and_existing_hosts(self):
        for existing in (False, True):
            result, calls = self.exercise(existing=existing)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertLess(calls.index('daemon-reload'), calls.index('enable '))
            self.assertLess(calls.index('enable '), calls.index('restart '))

    def test_enable_start_or_readiness_failure_cannot_report_success(self):
        for fail in ('enable', 'restart', 'is-active', 'runtime-only', 'health'):
            with self.subTest(fail=fail):
                result, _ = self.exercise(fail=fail)
                self.assertNotEqual(result.returncode, 0)

if __name__ == "__main__":
    unittest.main()
