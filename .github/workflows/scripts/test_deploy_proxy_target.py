"""Exercise proxy selection through the shared selector and cloud discovery."""

import importlib.util
import json
from itertools import product
import os
from pathlib import Path
import re
import subprocess
import unittest
from concurrent.futures import Future
from types import SimpleNamespace
from unittest.mock import patch

SCRIPTS = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("proxy_target", SCRIPTS / "deploy-proxy.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
WORKFLOW = (SCRIPTS.parent / "deploy-proxy.yml").read_text()
STEPS = [s for s in re.split(r"^      - name: ", WORKFLOW, flags=re.M)
         if "python3 .github/workflows/scripts/deploy-proxy.py" in s]


class ProxyTargetTests(unittest.TestCase):
    def select(self, rows="", **overrides):
        env = dict(PATH=os.environ["PATH"], GCP_PROJECT="example-project",
                   GCP_REGION="us-west2", SHA="12345678", PROXY_DOMAIN="sandbox.example.test",
                   VMD_LABEL="component=vmd", DEPLOY_EVENT="workflow_dispatch",
                   DEPLOY_TARGET="standby", DEPLOY_ENVIRONMENT="production",
                   DEPLOY_PRODUCTION_CELL="usw2", DEPLOY_CELL="usw2")
        env["MOCK_ROLE_ROWS"] = rows or ""
        env.update(overrides)
        step = next(s for s in STEPS if f'DEPLOY_CELL: {env["DEPLOY_CELL"]}' in s)
        if env["DEPLOY_CELL"] == "use4":
            env["PEER_IDENTITY_HOSTS"] = re.search(r"PEER_IDENTITY_HOSTS: ([^\n]+)", step)[1]
        identity_policy = env.get("PEER_IDENTITY_HOSTS", "")
        if env["DEPLOY_CELL"] != "staging":
            expression = re.search(r"PEER_PROXY_LISTEN_ADDR: \$\{\{ (.+) \}\}", step)[1]
            context = dict(github=SimpleNamespace(event_name=env["DEPLOY_EVENT"]),
                           inputs=SimpleNamespace(target=env["DEPLOY_TARGET"]),
                           vars=SimpleNamespace(PEER_ROUTING_ENABLED_USE4=env.get("PEER_ROUTING_ENABLED", ""),
                                                PEER_ROUTING_ENABLED_USW=env.get("PEER_ROUTING_ENABLED", ""),
                                                PEER_INGRESS_ENABLED_PROD=env.get("PEER_INGRESS_ENABLED", ""),
                                                PEER_INGRESS_ENABLED_USW=env.get("PEER_INGRESS_ENABLED", "")))
            env["PEER_PROXY_LISTEN_ADDR"] = eval(
                expression.replace("&&", " and ").replace("||", " or "),
                {"__builtins__": {}}, context)
            self.assertIn('PEER_PROXY_TARGET_ADDR: "127.0.0.1:5010"', step)
        # Execute the workflow's actual selection prefix, without secret access or deployment.
        prefix = step.split("        run: |\n")[1].split('          : "${GCP_REGION:?', 1)[0]
        result = subprocess.run(["bash", "-eu", "-c", 'gcloud() { printf "%s" "$MOCK_ROLE_ROWS"; };\n' + prefix + '\npython3 -c "import json, os; print(json.dumps(dict(os.environ)))"'],
                                cwd=SCRIPTS.parents[2], env=env, capture_output=True, text=True)
        if result.returncode:
            return 1, []
        env = json.loads(result.stdout)
        self.selected_identity_policy = env.get("PEER_IDENTITY_HOSTS", "")
        standby = env["DEPLOY_EVENT"] == "workflow_dispatch" and env["DEPLOY_TARGET"] == "standby"
        self.assertEqual(env["VMD_LABEL"], f'component=vmd-{env["DEPLOY_CELL"]}-standby' if standby else "component=vmd")
        if env["DEPLOY_CELL"] != "staging":
            self.assertEqual(env["PEER_PROXY_LISTEN_ADDR"], "auto" if standby or env.get("PEER_ROUTING_ENABLED") == "1" or env.get("PEER_INGRESS_ENABLED") == "1" else "")
            if standby:
                self.assertEqual(env.get("PEER_IDENTITY_HOSTS", ""), identity_policy)
        selected = []

        class Executor:
            def __init__(self, **kwargs): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def submit(self, fn, inst):
                selected.append(inst["name"])
                future = Future()
                future.set_result(None)
                return future

        def discover(args, **kwargs):
            self.assertEqual(args[:4], ["gcloud", "compute", "instances", "list"])
            self.assertIn(f'--filter=labels.{env["VMD_LABEL"]}' + ('' if env.get('EXPECTED_STANDBY_HOST') else ' AND status=RUNNING'), args)
            if rows is None:
                raise subprocess.CalledProcessError(1, args)
            return subprocess.CompletedProcess(args, 0, rows, "")

        with patch.dict(os.environ, env, clear=True), patch.object(MODULE.subprocess, "run", side_effect=discover), \
             patch.object(MODULE.os.path, "exists", return_value=True), patch.object(MODULE, "ThreadPoolExecutor", Executor):
            return MODULE.main(), selected

    def test_serving_and_push_keep_normal_fanout(self):
        for event, target in (("workflow_dispatch", "serving"), ("push", "serving"), ("push", "")):
            for cell, region in (("usw2", "us-west2"), ("use4", "us-east4")):
                self.assertEqual(self.select(f"example-serving,{region}-a\nexample-other,europe-west1-b\n",
                                             DEPLOY_EVENT=event, DEPLOY_TARGET=target,
                                             DEPLOY_CELL=cell, GCP_REGION=region),
                                 (0, ["example-serving"]))

    def test_routing_enabled_push_preserves_serving_ingress(self):
        for cell, region in (("usw2", "us-west2"), ("use4", "us-east4")):
            self.assertEqual(self.select(f"example-serving,{region}-a\n",
                                         DEPLOY_EVENT="push", DEPLOY_TARGET="serving",
                                         DEPLOY_CELL=cell, GCP_REGION=region,
                                         PEER_ROUTING_ENABLED="1",
                                         PROXY_DATABASE_URL="postgres://routing:example@db.example.test/db"),
                             (0, ["example-serving"]))

    def test_cell_routing_and_ingress_are_independent(self):
        routing_vars = dict(staging="PEER_ROUTING_ENABLED", use4="PEER_ROUTING_ENABLED_USE4",
                            usw2="PEER_ROUTING_ENABLED_USW")
        database_secrets = dict(staging="PROXY_DATABASE_URL_STAGING", use4="PROXY_DATABASE_URL_PROD",
                                usw2="PROXY_DATABASE_URL_USWEST")
        for step in STEPS:
            cell = re.search(r"DEPLOY_CELL: (\w+)", step)[1]
            routing_expression = re.search(r"PEER_ROUTING_ENABLED: \$\{\{ (.+) \}\}", step)[1]
            listener_expression = re.search(r"PEER_PROXY_LISTEN_ADDR: \$\{\{ (.+) \}\}", step)[1]
            self.assertEqual(routing_expression, f"vars.{routing_vars[cell]}")
            self.assertIn("PROXY_DATABASE_URL: ${{ secrets." + database_secrets[cell] + " }}", step)
            for staging, east, west, east_ingress, west_ingress, staging_listener, event, target in product(
                    ("", "0", "1"), ("", "0", "1"), ("", "0", "1"), ("", "1"), ("", "1"),
                    ("", "auto"), ("push", "workflow_dispatch"), ("serving", "standby")):
                variables = dict(PEER_ROUTING_ENABLED=staging, PEER_ROUTING_ENABLED_USE4=east,
                                 PEER_ROUTING_ENABLED_USW=west, PEER_INGRESS_ENABLED_PROD=east_ingress,
                                 PEER_INGRESS_ENABLED_USW=west_ingress,
                                 PEER_PROXY_LISTEN_ADDR_STAGING=staging_listener)
                context = dict(github=SimpleNamespace(event_name=event),
                               inputs=SimpleNamespace(target=target), vars=SimpleNamespace(**variables))
                with self.subTest(cell=cell, variables=variables, event=event, target=target):
                    routing = eval(routing_expression, {"__builtins__": {}}, context)
                    self.assertEqual(routing, dict(staging=staging, use4=east, usw2=west)[cell])
                    listener = eval(listener_expression.replace("&&", " and ").replace("||", " or "),
                                    {"__builtins__": {}}, context)
                    if cell == "staging":
                        expected = "auto" if staging == "1" else staging_listener
                    else:
                        ingress = east_ingress if cell == "use4" else west_ingress
                        expected = "auto" if routing == "1" or ingress == "1" or (
                            event == "workflow_dispatch" and target == "standby") else ""
                    self.assertEqual(listener, expected)

    def test_ingress_first_and_routing_disable_preserve_listener(self):
        for cell, region in (("use4", "us-east4"), ("usw2", "us-west2")):
            for routing in ("0", "1", "0"):
                for event in ("push", "workflow_dispatch"):
                    self.assertEqual(self.select(f"example-serving,{region}-a\n",
                                                 DEPLOY_EVENT=event, DEPLOY_TARGET="serving",
                                                 DEPLOY_CELL=cell, GCP_REGION=region,
                                                 PEER_INGRESS_ENABLED="1", PEER_ROUTING_ENABLED=routing,
                                                 PROXY_DATABASE_URL="postgres://routing:example@db.example.test/db"),
                                     (0, ["example-serving"]))

    def test_west_and_east_standby_follow_role_labels(self):
        self.assertEqual(self.select("superserve-vmd-usw2-2,us-west2-a,RUNNING\n"),
                         (0, ["superserve-vmd-usw2-2"]))
        self.assertEqual(self.select("superserve-vmd-use4-3,us-east4-a,RUNNING\n",
                                    DEPLOY_CELL="use4", DEPLOY_PRODUCTION_CELL="use4", GCP_REGION="us-east4"), (0, ["superserve-vmd-use4-3"]))

    def test_east_identity_policy_stays_with_host_three_across_role_swaps(self):
        for target in ("serving", "standby"):
            for host in ("superserve-vmd-use4-2", "superserve-vmd-use4-3"):
                with self.subTest(target=target, host=host):
                    self.assertEqual(self.select(f"{host},us-east4-a,RUNNING\n",
                                                 DEPLOY_CELL="use4", DEPLOY_PRODUCTION_CELL="use4",
                                                 GCP_REGION="us-east4", DEPLOY_TARGET=target), (0, [host]))
                    self.assertEqual(self.selected_identity_policy, "superserve-vmd-use4-3")
                    self.assertEqual(host in self.selected_identity_policy.split(","),
                                     host == "superserve-vmd-use4-3")

    def test_missing_unconfigured_wrong_or_stopped_production_standby_fails(self):
        for rows in ("", "superserve-vmd-usw2-2,us-east4-a,RUNNING\n",
                     "superserve-vmd-usw2-2,us-west2-a,TERMINATED\n",
                     "superserve-vmd-usw2-2,us-west2-a,RUNNING\nother-host,us-west2-b,RUNNING\n"):
            self.assertEqual(self.select(rows), (1, []))
        self.assertEqual(self.select(DEPLOY_CELL="use4", DEPLOY_PRODUCTION_CELL="use4", GCP_REGION="us-east4"), (1, []))

    def test_staging_absence_only_skips_for_production_standby(self):
        self.assertEqual(self.select(DEPLOY_CELL="staging", GCP_REGION="us-central1"), (0, []))
        self.assertEqual(self.select(DEPLOY_CELL="staging", GCP_REGION="us-central1",
                                    DEPLOY_ENVIRONMENT="staging"), (1, []))
        self.assertEqual(self.select("superserve-vmd-staging-2,us-central1-a,RUNNING\n",
                                    DEPLOY_CELL="staging", GCP_REGION="us-central1"), (0, ["superserve-vmd-staging-2"]))
        self.assertEqual(self.select("superserve-vmd-staging-2,us-central1-a,TERMINATED\n",
                                    DEPLOY_CELL="staging", GCP_REGION="us-central1"), (1, []))
        with self.assertRaises(subprocess.CalledProcessError):
            self.select(None, DEPLOY_CELL="staging", GCP_REGION="us-central1")

    def test_wrong_region_staging_standby_fails_before_absence_skip(self):
        for zone in ("us-east4-a", "projects/example-project/zones/us-east4-a"):
            with self.subTest(zone=zone):
                self.assertEqual(self.select(f"superserve-vmd-staging-2,{zone},RUNNING\n",
                                            DEPLOY_CELL="staging", GCP_REGION="us-central1"), (1, []))

    def test_unrelated_host_in_another_region_does_not_block_staging_skip(self):
        self.assertEqual(self.select("example-other-host,us-east4-a,RUNNING\n",
                                    DEPLOY_CELL="staging", GCP_REGION="us-central1"), (0, []))

    def test_region_required_for_every_target(self):
        for event in ("push", "workflow_dispatch"):
            for target in ("serving", "standby"):
                for region in ("", " "):
                    self.assertEqual(self.select(GCP_REGION=region, DEPLOY_EVENT=event, DEPLOY_TARGET=target), (1, []))

    def test_workflow_guards_select_requested_manual_cell_and_preserve_push(self):
        self.assertIn("DEPLOY_TARGET: ${{ inputs.target || 'serving' }}", WORKFLOW)
        self.assertIn("needs: [deploy-staging, migration-gate]", WORKFLOW)
        for event in ("push", "workflow_dispatch"):
            for target in ("", "serving", "standby"):
                for cell in ("", "use4", "usw2"):
                    for enabled in ("", "configured"):
                        context = dict(github=SimpleNamespace(event_name=event),
                                       inputs=SimpleNamespace(target=target, production_cell=cell),
                                       vars=SimpleNamespace(CLOUD_RUN_SERVICE_USW=enabled))
                        selected = []
                        for step in STEPS[1:]:
                            condition = re.search(r"^        if: (.+)$", step, re.M)[1]
                            if eval(condition.replace("&&", " and ").replace("||", " or "), {"__builtins__": {}}, context):
                                selected.append(re.search(r"DEPLOY_CELL: (\w+)", step)[1])
                        expected = [cell or "usw2"] if event == "workflow_dispatch" else (["use4", "usw2"] if enabled else ["use4"])
                        self.assertEqual(selected, expected)


if __name__ == "__main__":
    unittest.main()
