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
                   GCP_PROJECT="example-project", MOCK_ROLE_ROWS="", GCP_REGION="us-central1",
                   VMD_LABEL="component=legacy",
                   PEER_IDENTITY_HOSTS="legacy-host", EXPECTED_STANDBY_HOST="",
                   PEER_ROUTING_ENABLED="0", PEER_PROXY_LISTEN_ADDR="auto")
        env.update(overrides)
        return subprocess.run(
            ["bash", "-ec", 'gcloud() { '
             '[ "$*" = "compute instances list --project=$GCP_PROJECT --filter=labels.component=vmd-$DEPLOY_CELL-standby --format=csv[no-heading](name,zone)" ] || return 2; '
             'printf "%s" "$MOCK_ROLE_ROWS"; return ${MOCK_ROLE_STATUS:-0}; }; '
             'source "$1"; printf "%s\\n" "$VMD_LABEL" '
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
                                         DEPLOY_TARGET=target, MOCK_ROLE_ROWS=f"{host},{region}-a\n")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.splitlines(),
                                     [f"component=vmd-{cell}-standby",
                                      host if cell == "staging" else "legacy-host", host, "0", "auto"])

    def test_serving_preserves_existing_peer_configuration(self):
        for cell in ("staging", "use4", "usw2"):
            result = self.select(DEPLOY_TARGET="serving", DEPLOY_CELL=cell,
                                 DEPLOY_PRODUCTION_CELL="use4" if cell == "use4" else "usw2")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["component=vmd", "legacy-host", "", "0", "auto"])

    def test_missing_standby_role_blocks_deployment(self):
        for target in ("", "standby"):
            result = self.select(DEPLOY_TARGET=target, DEPLOY_CELL="use4",
                                 DEPLOY_PRODUCTION_CELL="use4", GCP_REGION="us-east4",
                                 EXPECTED_STANDBY_HOST="legacy-host")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Standby role requires exactly one host", result.stderr)
            # Nothing after sourcing the selector may run, even with a stale host override.
            self.assertEqual(result.stdout, "")

    def test_push_ignores_selectors_and_preserves_environment(self):
        for cell in ("staging", "use4", "usw2"):
            result = self.select(DEPLOY_EVENT="push", DEPLOY_TARGET="invalid", DEPLOY_CELL=cell,
                                 GCP_REGION="", PEER_ROUTING_ENABLED="1",
                                 MOCK_ROLE_ROWS="example-replacement,us-east4-a\n")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["component=legacy", "legacy-host", "", "1", "auto"])

    def test_use4_standby_uses_live_role(self):
        result = self.select(DEPLOY_CELL="use4", DEPLOY_PRODUCTION_CELL="use4",
                             GCP_REGION="us-east4", MOCK_ROLE_ROWS="example-replacement,us-east4-a\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(),
                         ["component=vmd-use4-standby", "legacy-host",
                          "example-replacement", "0", "auto"])

    def test_promotion_and_rollback_follow_roles_in_both_cells(self):
        for cell, region in (("usw2", "us-west2"), ("use4", "us-east4")):
            for serving, inactive in (("example-host-1", "example-host-2"),
                                      ("example-host-2", "example-host-1")):
                with self.subTest(cell=cell, serving=serving):
                    result = self.select(DEPLOY_CELL=cell, DEPLOY_PRODUCTION_CELL=cell,
                                         GCP_REGION=region, MOCK_ROLE_ROWS=f"{inactive},{region}-a\n",
                                         PEER_IDENTITY_HOSTS="example-host-2")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.splitlines()[1:3], ["example-host-2", inactive])
                    self.assertEqual(self.deploy_selection(f"{inactive},{region}-a\n", region, inactive),
                                     (0, [inactive]))
                    # A role change between selection and discovery must fail closed.
                    self.assertEqual(self.deploy_selection(f"{serving},{region}-a\n", region, inactive), (1, []))
                    result = self.select(DEPLOY_TARGET="serving", DEPLOY_CELL=cell,
                                         DEPLOY_PRODUCTION_CELL=cell, GCP_REGION=region)
                    self.assertEqual(result.stdout.splitlines()[0], "component=vmd")
                    self.assertEqual(self.deploy_selection(f"{serving},{region}-a\n", region, ""), (0, [serving]))

    def test_role_discovery_rejects_ambiguous_wrong_region_and_failed_queries(self):
        for rows, status in (("", "0"), ("example-a,us-west2-a\nexample-b,us-west2-b\n", "0"),
                             ("example-a,us-east4-a\n", "0"), ("example-a,us-west2-a\n", "1")):
            result = self.select(DEPLOY_CELL="usw2", GCP_REGION="us-west2",
                                 MOCK_ROLE_ROWS=rows, MOCK_ROLE_STATUS=status)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")

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
            if kind == "proxy":
                self.assertIn("    needs: [deploy-staging, migration-gate]\n", production)
            else:
                self.assertIn("    needs: [deploy-staging, wait-for-ci, migration-gate]\n", production)
            steps = [s for s in re.split(r"^      - name: ", workflow, flags=re.M)
                     if f"python3 .github/workflows/scripts/deploy-{kind}.py" in s]
            self.assertEqual(len(steps), 3)
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
                            expected = ([cell or "usw2"] if event == "workflow_dispatch"
                                        else (["use4", "usw2"] if enabled else ["use4"]))
                            self.assertEqual(selected, expected, (kind, event, target, cell, enabled))

    def test_vmd_staging_bypass_is_only_manual_production_standby(self):
        self.check_staging_bypass('vmd')

    def test_proxy_staging_bypass_is_only_manual_production_standby(self):
        self.check_staging_bypass('proxy')

    def check_staging_bypass(self, kind):
        from itertools import product

        workflow = (SCRIPTS.parent / f'deploy-{kind}.yml').read_text()
        staging = workflow.split('  deploy-staging:\n', 1)[1].split('    runs-on:', 1)[0]
        production = workflow.split('  deploy-production:\n', 1)[1]
        staging_condition = re.search(r'if: \$\{\{ (.+) \}\}', staging)[1]
        production_condition = production.split('    if: >-\n', 1)[1].split('    needs:', 1)[0]

        def evaluate(expression, context):
            expression = expression.replace('&&', ' and ').replace('||', ' or ')
            expression = re.sub(r'!(?!=)', ' not ', expression)
            expression = re.sub(r'needs\.([a-z-]+)\.result', r'needs["\1"]', expression)
            return eval(' '.join(expression.split()), {"__builtins__": {}}, context)

        for event, environment, target, result, ci, migration, cancelled in product(
                ('push', 'workflow_dispatch'), ('', 'staging', 'production'),
                ('', 'standby', 'serving'), ('success', 'skipped', 'failure', 'cancelled'),
                ('success', 'failure', 'skipped', 'cancelled'),
                ('success', 'failure', 'skipped', 'cancelled'), (False, True)):
            bypass = event == 'workflow_dispatch' and environment == 'production' and target == 'standby'
            context = dict(github=SimpleNamespace(event_name=event),
                           inputs=SimpleNamespace(environment=environment, target=target),
                           needs={'deploy-staging': result, 'wait-for-ci': ci, 'migration-gate': migration},
                           cancelled=lambda: cancelled)
            with self.subTest(event=event, environment=environment, target=target,
                              staging=result, ci=ci, migration=migration, cancelled=cancelled):
                self.assertEqual(evaluate(staging_condition, context), not bypass)
                expected = (not cancelled and migration == 'success'
                            and (kind != 'vmd' or ci == 'success')
                            and (event == 'push' or environment == 'production')
                            and (result == 'success' or bypass))
                self.assertEqual(evaluate(production_condition, context), expected)

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
