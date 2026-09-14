"""Exercise manual selection and production step guards without cloud access."""

import importlib.util
import os
from pathlib import Path
import re
import subprocess
import unittest
from concurrent.futures import Future
from types import SimpleNamespace
from unittest.mock import patch


SCRIPTS = Path(__file__).parent


class DeployTargetTests(unittest.TestCase):
    def test_automatic_rollouts_enforce_identity_gates(self):
        for kind in ('vmd', 'proxy'):
            workflow = (SCRIPTS.parent / f'deploy-{kind}.yml').read_text()
            # Read the gate up to the next job, preserving its nested steps.
            gate = re.split(r'^  [a-z][a-z-]*:\n', workflow.split('  migration-gate:\n', 1)[1], maxsplit=1, flags=re.M)[0]
            self.assertIn('ROLLOUT_READY: ${{ vars.HOST_IDENTITY_ROLLOUT_READY }}', gate)
            script = gate.split('        run: |\n', 1)[1]
            staging = workflow.split('  deploy-staging:\n', 1)[1].split('    steps:', 1)[0]
            self.assertRegex(staging, r'needs: \[[^\]]*migration-gate[^\]]*\]')
            cases = [(event, ready, int(event == 'push' and ready != 'true'))
                     for event in ('push', 'workflow_dispatch')
                     for ready in (None, '', 'false', 'true', 'TRUE', '1', 'tru', ' true ')]
            for event, ready, expected in cases:
                with self.subTest(kind=kind, event=event, ready=ready):
                    env = dict(os.environ, DEPLOY_EVENT=event)
                    env.pop('ROLLOUT_READY', None)
                    if ready is not None:
                        env['ROLLOUT_READY'] = ready
                    result = subprocess.run(['bash', '-eu', '-c', script], capture_output=True,
                                            env=env, text=True)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    if expected:
                        if kind == 'proxy' or ready is not None:
                            self.assertIn('use the coordinated manual rollout procedure', result.stderr)

    def deploy_selection(self, rows, region="us-central1", expected="example-standby"):
        spec = importlib.util.spec_from_file_location("deploy_selection", SCRIPTS / "deploy-vmd.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        selected = []

        class Executor:
            def __init__(self, **kwargs): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def submit(self, fn, instance):
                selected.append(instance["name"])
                future = Future()
                future.set_result(None)
                return future

        env = dict(GCP_PROJECT="example-project", GCP_REGION=region, SHA="12345678",
                   VMD_LABEL="component=vmd-staging-standby", EXPECTED_STANDBY_HOST=expected)
        with patch.dict(os.environ, env, clear=True), \
             patch.object(module, "run_or_die"), \
             patch.object(module.os.path, "getsize", return_value=0), \
             patch.object(module.os.path, "exists", return_value=True), \
             patch.object(module.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, rows, "")) as run, \
             patch.object(module, "ThreadPoolExecutor", Executor):
            result = module.main()
        self.assertEqual(len(run.call_args_list), 1, "selection must not contact any host")
        self.assertEqual(run.call_args.args[0][:4], ["gcloud", "compute", "instances", "list"])
        return result, selected

    def test_standby_discovery_rejects_unexpected_ambiguous_or_unscoped_hosts(self):
        for rows, region in (
            ("", "us-central1"),
            ("other-host,us-central1-a\n", "us-central1"),
            ("example-standby,us-central1-a\nother-host,us-central1-b\n", "us-central1"),
            ("example-standby,us-west2-a\n", "us-central1"),
            ("example-standby,us-central1-a\n", ""),
        ):
            with self.subTest(rows=rows, region=region):
                self.assertEqual(self.deploy_selection(rows, region), (1, []))

    def test_standby_discovery_accepts_only_expected_host_in_selected_region(self):
        rows = "example-standby,projects/example-project/zones/us-central1-a\nother-host,us-west2-a\n"
        self.assertEqual(self.deploy_selection(rows), (0, ["example-standby"]))

    def test_serving_discovery_retains_multiple_host_fanout(self):
        rows = "example-primary,us-central1-a\nexample-secondary,us-central1-b\n"
        self.assertEqual(self.deploy_selection(rows, expected=""),
                         (0, ["example-primary", "example-secondary"]))

    def select(self, **overrides):
        env = dict(os.environ, DEPLOY_EVENT="workflow_dispatch", DEPLOY_TARGET="",
                   DEPLOY_PRODUCTION_CELL="", DEPLOY_CELL="staging",
                   GCP_REGION="us-central1", VMD_LABEL="component=legacy",
                   PEER_IDENTITY_HOSTS="legacy-host", EXPECTED_STANDBY_HOST="",
                   VMD_STANDBY_HOST_USE4="",
                   PEER_ROUTING_ENABLED="0", PEER_PROXY_LISTEN_ADDR="auto")
        env.update(overrides)
        return subprocess.run(
            ["bash", "-ec", 'source "$1"; printf "%s\\n" "$VMD_LABEL" '
             '"$PEER_IDENTITY_HOSTS" "$EXPECTED_STANDBY_HOST" '
             '"$PEER_ROUTING_ENABLED" "$PEER_PROXY_LISTEN_ADDR"',
             "select", str(SCRIPTS / "select-deploy-target.sh")],
            env=env, capture_output=True, text=True,
        )

    def test_exact_standby_mappings_and_defaults(self):
        for cell, region, host in (
            ("staging", "us-central1", "superserve-vmd-staging-2"),
            ("usw2", "us-west2", "superserve-vmd-usw2-2"),
        ):
            for target in ("", "standby"):
                with self.subTest(cell=cell, target=target):
                    result = self.select(DEPLOY_CELL=cell, GCP_REGION=region,
                                         DEPLOY_PRODUCTION_CELL="",
                                         DEPLOY_TARGET=target)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.splitlines(),
                                     [f"component=vmd-{cell}-standby", host, host, "0", "auto"])

    def test_serving_preserves_existing_peer_configuration(self):
        for cell in ("staging", "use4", "usw2"):
            result = self.select(DEPLOY_TARGET="serving", DEPLOY_CELL=cell,
                                 DEPLOY_PRODUCTION_CELL="use4" if cell == "use4" else "usw2")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["component=vmd", "legacy-host", "", "0", "auto"])

    def test_use4_standby_is_unconfigured_and_blocks_deployment(self):
        for target in ("", "standby"):
            result = self.select(DEPLOY_TARGET=target, DEPLOY_CELL="use4",
                                 DEPLOY_PRODUCTION_CELL="use4", GCP_REGION="us-east4",
                                 EXPECTED_STANDBY_HOST="legacy-host")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("No standby identity host configured", result.stderr)
            # Nothing after sourcing the selector may run, even with a stale host override.
            self.assertEqual(result.stdout, "")

    def test_push_ignores_selectors_and_preserves_environment(self):
        for cell in ("staging", "use4", "usw2"):
            result = self.select(DEPLOY_EVENT="push", DEPLOY_TARGET="invalid", DEPLOY_CELL=cell,
                                 GCP_REGION="", PEER_ROUTING_ENABLED="1",
                                 VMD_STANDBY_HOST_USE4="example-replacement")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["component=legacy", "legacy-host", "", "1", "auto"])

    def test_use4_standby_uses_deployment_configuration(self):
        result = self.select(DEPLOY_CELL="use4", DEPLOY_PRODUCTION_CELL="use4",
                             GCP_REGION="us-east4", VMD_STANDBY_HOST_USE4="example-replacement")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(),
                         ["component=vmd-use4-standby", "example-replacement",
                          "example-replacement", "0", "auto"])

    def test_manual_rejects_invalid_or_unscoped_selection(self):
        for override in ({"DEPLOY_TARGET": "component=vmd"}, {"DEPLOY_PRODUCTION_CELL": "all"},
                         {"GCP_REGION": ""}, {"DEPLOY_CELL": "other"},
                         {"DEPLOY_CELL": "use4", "DEPLOY_PRODUCTION_CELL": "usw2"}):
            with self.subTest(override=override):
                result = self.select(**override)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_workflow_cell_guards_and_staging_dependency(self):
        for kind in ("vmd", "proxy"):
            workflow = (SCRIPTS.parent / f"deploy-{kind}.yml").read_text()
            production = workflow.split("  deploy-production:\n", 1)[1]
            self.assertIn("    needs: [deploy-staging]\n", production)
            self.assertIn("if: github.event_name == 'push' || github.event.inputs.environment == 'production'", production)
            steps = [s for s in re.split(r"^      - name: ", workflow, flags=re.M)
                     if f"python3 .github/workflows/scripts/deploy-{kind}.py" in s]
            self.assertEqual(len(steps), 3)
            self.assertIn("VMD_STANDBY_HOST_USE4: ${{ vars.VMD_STANDBY_HOST_USE4 }}", steps[1])
            for step in steps:
                self.assertLess(step.index("source .github/workflows/scripts/select-deploy-target.sh"),
                                step.index(f"python3 .github/workflows/scripts/deploy-{kind}.py"))
            for event in ("push", "workflow_dispatch"):
                for target in ("serving", "standby"):
                    for cell in ("", "use4", "usw2"):
                        for enabled in ("", "configured"):
                            selected = []
                            for step in steps[1:]:
                                condition = re.search(r"^        if: (.+)$", step, re.M)[1]
                                context = dict(github=SimpleNamespace(event_name=event),
                                               inputs=SimpleNamespace(production_cell=cell, cell=cell, target=target),
                                               vars=SimpleNamespace(CLOUD_RUN_SERVICE_USW=enabled))
                                if eval(condition.replace("&&", " and ").replace("||", " or "),
                                        {"__builtins__": {}}, context):
                                    selected.append(re.search(r"DEPLOY_CELL: (\w+)", step)[1])
                            expected = ([cell or "usw2"] if event == "workflow_dispatch" and (kind == "vmd" or target == "standby")
                                        else (["use4", "usw2"] if enabled else ["use4"]))
                            self.assertEqual(selected, expected, (kind, event, target, cell, enabled))

    def test_zero_matches_never_retry_serving_or_upload(self):
        for kind in ("vmd", "proxy"):
            spec = importlib.util.spec_from_file_location("deploy_under_test", SCRIPTS / f"deploy-{kind}.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            env = dict(GCP_PROJECT="example-project", GCP_REGION="us-east4", SHA="12345678",
                       VMD_LABEL="component=vmd-use4-standby", PROXY_DOMAIN="sandbox.example.test")
            calls = []

            def run(args, **kwargs):
                calls.append(args)
                self.assertEqual(args[:4], ["gcloud", "compute", "instances", "list"])
                self.assertIn("--filter=labels.component=vmd-use4-standby AND status=RUNNING", args)
                return subprocess.CompletedProcess(args, 0, "", "")

            with patch.dict(os.environ, env, clear=True), patch.object(module.subprocess, "run", side_effect=run):
                if kind == "vmd":
                    with patch.object(module, "run_or_die"), patch.object(module.os.path, "getsize", return_value=0):
                        self.assertEqual(module.main(), 1)
                else:
                    self.assertEqual(module.main(), 1)
            self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
